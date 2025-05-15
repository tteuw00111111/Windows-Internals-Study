# Processes

### Creating a Process
Windows API provides many ways of creating a process, the simplest way is through ``CreateProcess``, which attempts to create a process with the same token access as the creating access.
Think like you have different "menus" (API functions) that let you specify what you want and under which "credentials"(access token) you want it delivered, eventually under the hood they all goes to the same kitchen(kernel).

#### CreateProcess
Launches a new program using your own security toke(current user's identity)
Use when you don't need to change who you are.
```cpp
bool sucess = CreateProcess(
	L"C:\\Program Files\\MyApp.exe, //program to run
	L"", //command-line args
	... //other params
);
```

#### POC
https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa

https://learn.microsoft.com/en-us/windows/win32/procthread/creating-processes

To launch a new process, Windows provides the `CreateProcessW` API:

```cpp
STARTUPINFO si{ sizeof(si) };
PROCESS_INFORMATION pi{};
BOOL ok = CreateProcessW(
  L"C:\\Windows\\System32\\notepad.exe",
  nullptr, nullptr, nullptr,
  FALSE, 0, nullptr, nullptr,
  &si, &pi
);
```

**Full demo code**: [create_process.cpp](../pocs/process-creation/create_process.cpp)

#### Be Someone Else
Sometimes you want to launch a process as a different user(like run a schedule task or install a software). Windows give you two flavors in ``advapi32.dll``

What is a "``token handle``"?
Windows processes run "as" some security token, a kernel object that says "Im Alice, i belong to group X, i have these privileges...". A token handle is just an opaque handle, that points at one of those token objects.


| Function                | What it does                                       | Caller Requirements                                                                     |
| ----------------------- | -------------------------------------------------- | --------------------------------------------------------------------------------------- |
| CreateProcessAsUser     | When you already have a token handle; use it       | You must hold the “Act as part of the OS” or “Replace a process level token” privilege. |
| CreateProcessWithTokenW | Give a token handle and i'll use it.               | Similar privileges to CreateProcessAsUser, but slightly less strict.                    |
| CreateProcessWithLogonW | Give username/password and i'll log in and launch. | No special privileges, but behind the scenes start the Secondary Logon service          |

#### POC CreateProcessAsUser
“Obtain a token via ``LogonUser``, then spawn via ``CreateProcessAsUser``.”

https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasusera

https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw

This is a unreal POC, meaning it's not safe since it hardcodes the username and password. But there is also a version that i use Windows Credential UI that most tools uses and is safe.

```cpp
	LPCWSTR username = L"OtherUser";
	LPCWSTR domain = L"MYDOMAIN"; //nullptr for local account
	LPCWSTR password = L"P@ssword!";

	HANDLE hToken = nullptr;
	BOOL ok = LogonUserW(
		username,
		domain,
		password,
		LOGON32_LOGON_INTERACTIVE
		LOGON32_PROVIDER_DEFAULT,
		&hToken
	);
```

**Full demo code**: [create_process_as_user.cpp](../pocs/process-creation/create-process-as-user.cpp)

Using Windows Credential UI:
```cpp
bool PromptForCredentials(
    std::wstring& user,
    std::wstring& domain,
    std::wstring& password
)
{
    CREDUI_INFOW ui{};
    ui.cbSize = sizeof(ui);
    ui.pszCaptionText = L"Run as..";
    ui.pszMessageText = L"Credentials to launch target process";


    WCHAR usr[CREDUI_MAX_USERNAME_LENGTH + 1] = {};
    WCHAR pwd[CREDUI_MAX_PASSWORD_LENGTH + 1] = {};
    BOOL save = FALSE;
    DWORD flags = CREDUI_FLAGS_DO_NOT_PERSIST | CREDUI_FLAGS_EXCLUDE_CERTIFICATES;
```
**Full demo code**: [create-process-as-user-wincredui.cpp](../pocs/process-creation/create-process-as-user-wincredui.cpp)



### Shell Shortcut: ShellExecute[Ex]
If you hand a document like ("``report.docx``"), it:
Look up which app handles ".docx" in the registry (word)
Builds a proper command line("winword.exe" "report.docx")
Call **CreateProcess** for you.
Works like asking "Open this file for me", rather than "Run this program"

#### POC ShellExecuteW & ShellExecuteExW
1) Creates a dummy text file (if it doesn’t already exist).
2) Opens it with the user’s default “.txt” handler via ShellExecuteW.
3) Opens it again via ShellExecuteExW so we can grab the PROCESS_INFORMATION for fun (PID, wait, etc.).
   
```cpp
  HINSTANCE hInst = ShellExecuteW(
      nullptr,        // hwnd      no parent window
      L"open",        // lpVerb    "open" is default could be "edit
      filePath,       // lpFile    file or URL
      nullptr,        // lpParameters N/A for a plain doc
      nullptr,        // lpDirectory  current dir for the child
      SW_SHOWNORMAL   // nShowCmd   normal window
  );

```

**Full demo code:** pocs/process-creation/shell_poc.cpp

### Kitchen
No matter which API is used, when it's time to actually spin up the new process, it all funnels into:
1. **CreateProcessInternal**(inside ``kernel32.dll/ ntdll.dll``)
2. **NtCreateUserProcess**(in ``ntdll.dll``)
3. **NtCreateUserPorcess**(in the ``kernel/Executive``)

At this point into kernel mode, and Windows:
* Create the new process object
* Assigns it the chosen security token
* Sets up the address space, initial thread, handles, etc
* Return you a PROCESS handle so it can be controlled or watched.

- **CreateProcess** = “Run this EXE as me.”
- **…AsUser / WithTokenW / WithLogonW** = “Run it as somebody else; here’s how to get their token.”
- **ShellExecute** = “Open this file however Windows usually does.”
- **Under the hood** → everyone ends up in **NtCreateUserProcess**, which switches into kernel mode to finish the job.
#### CreateProcess* functions arguments
- **Who runs it?** - token / credentials
- **What to run?** - exe path + command line
- **Lock it down?** - security attributes
- **Share my toys?** - handle inheritance flag
- **Special launch rules?** - creation flags
- **What’s in its room?** - environment + current dir
- **Window & extras?** - STARTUPINFO/EX
- **Receipt of birth** - PROCESS_INFORMATION handles & IDs



## EPROCESS
Additional information necessary for the overall management of a process.
### Process Internals
Each running program in Windows is like a little universe of its own, at level Kernel, Windows keeps track of all these universes in a giant table of "process books" one for each process called an ``EPROCESS``.
Inside ``EPROCESS`` you will find everything the OS needs to manage, secure, schedule, and inspect that process.

#### Finding the Process
* ActiveProcessLinks
  All EPROCESS blocks are tied together in a doubly-linked list, anchored at PsActiveProcessHead(Anchor point for a big, doubly-linked list of all the live processes in the system, each time Windows creates a new process, it allocated an EPROCESS block for it and stick this block into this list). 
It's possible to unlink the process from that list, doing so, it hide from tools like Task Manager.
But for that we would need to write a Kernel Driver, because EPROCESS  & PsActiveProcessHead live in ring-0(kernel memory), so user-mode code (normal executables) cannot read or write code in kernel, and furthermore there is no official Win32 API that hides the process, only a driver running in ring-0 can.
Realistically speaking, Windows enforces driver signature, meaning only tursted-signed .sys load.
There is a test-signing mode on a lab VM we could to try these self-signed drivers.
PatchGuard will detect unauthorized kernel modifications like EPROCESS unlinking.

```cpp

VOID HideProcess(PEPROCESS Process)
{
    PLIST_ENTRY list = &Process->ActiveProcessLinks;
    PLIST_ENTRY prev = list->Blink;
    PLIST_ENTRY next = list->Flink;

    prev->Flink = next;
    next->Blink = prev;

    list->Flink = list;
    list->Blink = list;
}
```

**Full demo code:** pocs/process-creation/process_hider_kernel.cpp


#### Identifiers & Metadata
* **UniqueProcessId(PID) && ParentProcessId(PPID)**
  Numeric ID that is visible in tools like Task Manger, is a unique identifier of the process.
  PID spoofing or PPID manipulation is possible.
  
* **ImageFileName / ImageBaseAddress / SectionObject**
  **ImageFileName**: On-disk EXE name (notepad.exe)
  **ImageBaseAdddress**: Where the EXE code is mapped in the process virtual memory.
  **SectionObject**: The kernel's handle to that mapped image, how Windows enforces code pages
  
* **ProcessFlags / Creation & Exit times**
  Flags indicate system/user process, breakpoints, heap-type, etc
  Timestamps tell exactly when the process was born and died, is possible to set fake creation times("living off the land") to evade-time based detection.
  
Simple POC, that uses NtQuerySystemInformation(or Win32 snapshot APIs) to dump:
* **PID & PPID**
* **Image name**
* **Base address of the main code**
* **Creation time**

```cpp

	PROCESSENTRY32 pe = {
		sizeof(pe)
	};

	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snap == INVALID_HANDLE_VALUE) {
		return 1;
	}

	if (Process32First(snap, &pe)) { //fills PROCESSENTRY32 with data for the first process in the snapshot
		do {
			printf("PID=%5lu PPID=%5lu Name=%-20ls", pe.th32ProcessID, pe.th32ParentProcessID, pe.szExeFile);		
```
**Full demo code:** pocs/process-creation/dump_pid&ppid.cpp


Module = one loaded PE file(EXE or DLL) in a process
HMODULE = handle == base address of that loaded image
MODULEINFO= metada about that image(size, entrypoint, etc)

#### Security & Privilege
- **PrimaryAccessToken → TOKEN**  
    Every process carries a “token” that says who you are (user, groups, privileges).
    - **Privilege escalation:** You can **steal** or **duplicate** another process’s token (e.g. SYSTEM) to run with higher rights.
        
    - **Detection:** Look for unexpected token duplicates with Sysinternals or WinDbg’s `!token` command.
      
- **Job this Process Belongs to → EJOB**  
    Jobs can constrain CPU/memory and even block process creation. Some sandbox tools wrap malware in a job object.
    
- **Security/Exception/Debug Ports**  
    Channels used by debuggers, the kernel exception dispatcher, or SEH. Malware sometimes tampers here to prevent debugging.

#### User-mode View: the PEB
- **Process Environment Block (PEB) → PEB**  
    Lives in user-mode memory. Contains pointers to:
    - **Loader data** (the list of loaded DLLs)
    - **Command-line arguments**
    - **Environment variables**
    - **Image path** again
    - **Tip:** PEB fields are a favorite for rootkits to hook (e.g. hide loaded DLLs or alter the command-line that forensic scanners see).

#### Threads & Execution
- **ThreadListHead → ETHREAD → ETHREAD…**  
    Each process has one or more kernel thread objects. You create threads to inject code or execute payloads.
    - **Tip:** Unlinking an ETHREAD object hides threads from debuggers and forensic thread-enumeration tools.
        
- **KPROCESS** (inside the EPROCESS)  
    The scheduler’s view of your process: priority, CPU affinity, time slices. You can tweak this to hide CPU spikes or disable interrupts.

#### Windows-Subsystem Extras
- **W32PROCESS**  
    Created when you call any USER/GDI API (e.g. `CreateWindow`), tracks GUI objects and hooks into `win32k.sys`.
    - **Evasion:** Headless malware can avoid loading User32 to stay under the radar.
        
- **EWOW64PROCESS** (on 64-bit systems)  
    Tracks Wow64 (32-bit) processes.
    - Red-teamers can abuse the Wow64 transition helpers to smuggle 32-bit shellcode inside a 64-bit host.
        
- **DXGPROCESS / Protection Level & Signature**  
    Related to DirectX & code integrity on Win10. Generally not targeted by most malware—but advanced runners use DXGPROCESS counters to detect GPU virtualization or sandboxes.

 
## KPROCESS
Used by Windows kernel to manage the execution of a process at the kernel level.
Under the hood every Windows process is represented by EPROCESS object in kernel memory, the very first thing inside a EPROCESS is a KPROCESS sub-object(sometimes called "pcb").

This is all about scheduling, timing, and the process’s own page tables.

|Offset|Name|What it means…|
|---|---|---|
|+0x000|**DispatcherHeader**|Base for all dispatcher objects (threads, timers, events). Contains the type tag and wait queues.|
|+0x028|**DirectoryTableBase**|The CR3 value—the physical address of this process’s top‐level page table. (Used for address translation.)|
|+0x030|**ThreadListHead**|A doubly-linked list of all KTHREADs in this process. Walk it to enumerate threads.|
|+0x040|**ProcessLock**|A simple spinlock used when the scheduler or other kernel code needs to serialize access.|
|+0x26c|**KernelTime**|Cumulative time (in 100 ns ticks) that all threads in this process have spent in kernel mode.|
|+0x270|**UserTime**|Same, but in user mode.|
|+0x274|**CycleTime**|Total CPU cycles consumed. (More precise than the 100 ns timers.)|
|–|**BasePriority**|Base scheduling priority for all its threads. (Threads inherit from this unless they boost.)|
|–|**ProcessAffinity**|Which CPUs this process is allowed to run on. (Bitmask of processors.)|
|–|**ProcessFlags**|A bitfield: e.g. whether it’s “protected”, whether address space sharing is disabled, etc.|
|–|**IdealNode**|On NUMA systems, your “preferred” memory node for allocations.|
|–|**ThreadSeed**|Used to pseudo-randomize which thread you pick next on a multiprocessor.|

> **Why you care**:
> - **CR3** is what you spoof if you want your injected code to run with a different view of memory.
>     
> - **ThreadListHead** is how you’ll find every thread to suspend, resume, or patch.
>     
> - **Time fields** can give away hidden threads doing work in the background (high cycle counts).
>     
> - **Affinity/Priority** tweaks can help you hide behind legit processes.

#### The “outer” EPROCESS fields
Once you step past the KPROCESS (at offset +0x000 … +0x2d8), you get process-specific data:

|Offset|Name|What it means…|
|---|---|---|
|+0x2e8|**UniqueProcessId**|PID. Every process gets one.|
|+0x2f0|**ActiveProcessLinks**|Doubly-linked list of every EPROCESS in the system. (Headed off `PsActiveProcessHead`.)|
|+0x3a8|**Win32Process**|If this process has a user-mode win32 subsystem block, you get a pointer here (rarely useful to kernel code).|
|+0x418|**ObjectTable**|Pointer to the process’s handle table. Enumerate or stomping handles lives here.|
|+0x420|**DebugPort**|If a debugger is attached, this points at the debug object.|
|+0x428|**WoW64Process**|For 32-bit processes on 64-bit Windows, points at their 32-bit emulation block.|
|+0x760|**SharedCommitChargeLock**|Lock protecting shared commit counts. (Not often relevant.)|
|+0x768|**SharedCommitLinks**|Linked list of processes that share commit charges.|
|...|**Win32WindowStation, Job, ...**|Pointers to various job objects, window stations, session objects, etc.|
- **Token**  
    The security token gives you the user’s SID, privileges, and groups. If you patch or steal this, you can elevate or impersonate.
- **ImageFileName**  
    A fixed length (15-character) name of the EXE. Handy for identifying a process in a dump.
- **SectionObject**  
    The control section for the process image. Malware loaders will fiddle with this to remap or unmap images.
- **Peb**  
    Pointer to the user‐mode Process Environment Block. From there you get the full command line, environment, loaded DLL list, etc.
- **VadRoot** (or VadRootWhatever)  
    A balanced tree of all user-mode memory allocations (VAD = Virtual Address Descriptors). Kernel rootkits will tamper with this to hide injected code pages.

#### Red-team workflow
- **Locate your target EPROCESS** by PID or by walking `PsActiveProcessHead`.
    
- **Peek KPROCESS.DirectoryTableBase** if you need to read/write memory in the context of that process (set CR3).
    
- **Walk ThreadListHead** to find threads and suspend or hijack them.

- **Inspect Token** if you want to duplicate or steal privileges.

- **Unlink ActiveProcessLinks** and/or **patch VadRoot** to hide your process or injected memory regions.

- **Hook InstrumentationCallback** or **modify ProcessFlags** (e.g. clear the “can be debugged” bit) to evade user-mode or kernel-mode detection hooks.

- **KPROCESS** = “how Windows schedules and accounts time for this process” (threads, CR3, times, priority).
    
- **EPROCESS** = “all the rest of the process’s state” (PID, handles, security token, image, PEB, memory map, debug port).
  
## Protected Processes
By default any admin(process holding the ``SeDebugPrivilege`` token) can reach into any other user-mode process and do pretty much anything, read/write its memory, suspend its thread, inject code.
Originally created to protect DRM media stream.

Windows Vista introduced the "protected processes" they are still user-mode processes but with extra kernel checks that restrict even an admin from poking at them in most ways.

To request "protected" status, a processes's executable must be signed with a special Microsoft "media" format, most of the real work happens in the kernel process creation path, special flags get set in the new processes ``EPROCESS`` structure before even starts running.

Once a process is marked as "protected", Windows kernel will deny nearly all standard access rights.
* **Allowed**:
	* ``PROCESS_QUERY_LIMITED_INFORMATION`` (basic stats)
	* ``PROCESS_SET_LIMITED_INFORMATION`` (tweak basic resource limits)
	* ``PROCESS_TERMINATE``(kill the process)
	* ``PROCESS_SUSPEND_RESUME``(freeze or thaw its threads)
* **Denied**:
	* Reading or writing arbitrary memory.
	* Injecting code or DLL
	* Enumerate internal handles or threads, beyond the limited info

System Process that are Protected:
- **Audio Device Graph (Audiodg.exe):** decodes protected audio streams
    
- **Media Foundation Pipeline (Mfpmp.exe):** handles other high-value media flows
    
- **Windows Error Reporting (WerFaultSecure.exe):** can inspect protected processes if one crashes
    
- **System process:** holds kernel handles and stores some decryption keys in user-mode memory

Tools like Process Explorer or most user-mode debuggers will be unable to inspect or tamper with these protected processes. You’ll see truncated information or “access denied” errors.

If you’re designing malware that needs to hook or hook-inject into another process, you can’t target a protected process from user mode—your payload simply won’t attach.

## Protected Process Light (PPL)
Now besides keeping media stream safe, this is about protecting Windows Store apps, code integrity, licensing services, all has the same "even admin can't poke me". Now it has a "trust level" tag so some system services get a bit less locked-down that core media engines, but still off-limits to user-mode snooping.

Unlike protected processes, PPLs have ranked signer levels that grant or deny specific rights(some can't even be terminated)

#### Signer Level & Trust Tiers
Every PPL gets two flags in its **``EPROCESS``**:
**``Protection Level:``** "ProtectedLight", "Protected"
**``Signer``**: Who signed, Windows, TCB, Antimalware

|Signer Name|Level|Common Use|Notes|
|---|---|---|---|
|**WinSystem**|7|Kernel‐spawned minimal processes (e.g. Memory Compression)|Top of the pyramid|
|**WinTcb**|6|Core system services (smss, csrss, services, wininit)|PROCESS_TERMINATE is _denied_|
|**WinTcb-Light**|5|When Windows wants “TCB” w/o full block|Slightly lower than full TCB|
|**Windows**|5|Store licensing, Software Protection svc (sppsvc.exe)||
|**Windows-Light**|4|Lesser Windows components||
|**Lsa-Light**|4|lsass.exe (when configured)||
|**Anti-Malware-Light**|3|AV/EDR services|PROCESS_TERMINATE is _denied_|
|**CodeGen**|2|.NET NGen runners||
|**Authenticode-Light**|1|DRM-style signing, user-mode fonts||
|**None**|0|no protection|
#### DLL Integrity
**SignatureLevel vs. SectionSignatureLevel:** PPL checks that every DLL you load is signed at least as “high” as your process.
Even if you trick a protected process into loading a malicious DLL file, Code Integrity will refuse it unless that DLL carries equal or higher trust.

## Flow of CreateProcess
Takes CreateProcess parameters(path, flags like CREATE_SUSPENDED, attributes, environment, etc) and make sure they are all fine. It translates higher-level flags("start minimized") into the kernel's native form.

**Stage 1**
Internally it does an **``NtCreateSection``** on the **``.exe``** file, then maps that section into the new process's virtual memory address space with **``NtMapViewOfSection``**.

If you call the lower‐level APIs (NtCreateProcessEx, NtCreateSection, etc.) directly, you can skip a lot of the overhead here—Windows didn’t design those NT APIs for public consumption, but they let you go straight to the “good stuff” and avoid triggering some user-mode hooks.

**Stage 2**
This is where the raw bytes of the EXE land in memory, if you're doing reflective PE injection or any form of in-memory "loading" of a payload, you are re implementing part of this stage, allocating a block in the target VA space and copying your PE headers + sections in.

**Stage 3**
The kernel creates an executive process object (`EPROCESS`), which holds all the bookkeeping: handle tables, VADs (virtual address descriptors), security context, job associations, etc.

It then creates a thread object (`ETHREAD`), allocates its stack and context structure, but doesn’t yet let it run.

If you ask for `CREATE_SUSPENDED`, Windows stops right here. You can then inject your shellcode, patch the entry point, or hijack the startup thread before it ever executes a single instruction of the legit program.

Again, if you call `NtCreateThreadEx` from your own code in the target, you can inject without leaving traces in Kernel32.dll’s import table that AV/EDR hooks often monitor.

**Stage 4**
Creation of a “pure” executive process/object is one thing; making it a **Windows GUI/console process** is another. The Client-side runtime (Kernel32) talks to `Csrss.exe` (“Win32 subsystem”) over an LPC port to:
- Build the PEB (Process Environment Block)
- Create the thread’s TEB (Thread Environment Block)
- Flood in GUI/shared-heap structures, console buffers, etc.
If you want a “bare” process (no windowing, no subsystem), you could launch it as a native image or use direct NT calls to never touch CSRSS, reducing your footprint.

**Stage 5**
Unless you asked for `CREATE_SUSPENDED`, it resumes that initial thread. At this point it starts executing at ntdll’s loader stub, which eventually jumps into your EXE’s entry point.
This is the moment AV/EDR sees the new process “come alive.” If you’ve already patched the entry point or implanted run-on-load hooks in the section from Stage 2, your code fires here.

**Stage 6**
Now running in the _context_ of the new process, the loader:
1. Walks the Import Address Table → `LoadLibrary` each DLL you link against
2. Calls their `DllMain(DLL_PROCESS_ATTACH)` callbacks
3. Processes TLS callbacks, resource initialization, etc.
4. Finally jumps to your `main` / `WinMain` / whichever entry point you asked for.
   
- **IAT hooks / shim injection:** If you can tamper with the import table before or during this step, you’ll get your hooks in every subsequent API call.
- **PE loader callbacks:** Some red-team frameworks register shadow TLS callbacks to execute very early.

- **Stage 1 (Validate)** → Hackers rarely touch this; go direct to NT APIs to dodge user-mode hooks.
    
- **Stage 2 (Section Object)** → Reimplement with in-memory PE mapping (reflective injectors).
    
- **Stage 3/4 (Proc & Thread)** → Use `CREATE_SUSPENDED` or `NtCreateThreadEx` to inject before anything runs.
    
- **Stage 5 (CSRSS)** → Avoid or minimize talking to CSRSS if you want stealth; it’s heavily monitored.
    
- **Stage 6 (Resume)** → Triggers detection; prep your code by now.
    
- **Stage 7 (Loader inside)** → IAT hooks, TLS callbacks, delay-load tricks—your last big chance to seed persistence in the target’s import chain.
