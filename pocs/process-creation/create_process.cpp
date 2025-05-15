#include <windows.h>
#include <iostream>

int main(){
	//required structs
	STARTUPINFO si = { //tell windows how to configure the new process main windows and its standar I/O handles
		sizeof(si)
	};

	PROCESS_INFORMATION pi = {}; //gives you back who you created, after a successful call, it memebers are filled in by the kernel. It's a handle

	//call CreateProcess
	/*BOOL CreateProcessA(
	[in, optional]      LPCSTR                lpApplicationName,
		[in, out, optional] LPSTR                 lpCommandLine,
		[in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes,
		[in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes,
		[in]                BOOL                  bInheritHandles,
		[in]                DWORD                 dwCreationFlags,
		[in, optional]      LPVOID                lpEnvironment,
		[in, optional]      LPCSTR                lpCurrentDirectory,
		[in]                LPSTARTUPINFOA        lpStartupInfo,
		[out]               LPPROCESS_INFORMATION lpProcessInformation
		);*/

	
	bool ok = CreateProcessW(
		L"C:\\Windows\\System32\\notepad.exe", //lpApplicationName
		nullptr, //lpCommandLine(can be nullptr if only the exe is needed
		nullptr, //lpProcessAttributes
		nullptr, //lpThreadAttributes
		FALSE, //bInheritHandles
		0, //dwCreationFlags (0 = default)
		nullptr, //lpEnvironment(nullptr = inherit yours)
		nullptr, //lpCurrentDirectory(nullptr = inherit yours)
		&si,
		&pi
	);

	if (!ok) {
		std::cerr << "CreateProcess failed, error " << GetLastError() << "\n";
		return 1;
	}

	std::cout << "Launched notepad.exe as your user, PID = " << pi.dwProcessId << "\n";

	//wait for it to exit before the program continues
	WaitForSingleObject(pi.hProcess, INFINITE);

	//clean up handles
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	return 0;
}
