//“obtain a token via LogonUser, then spawn via CreateProcessAsUser.”

#include <windows.h>
#include <userenv.h>
#include <iostream>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Userenv.lib")

int main()
{
	LPCWSTR username = L"OtherUser";
	LPCWSTR domain = L"MYDOMAIN"; //nullptr for local account
	LPCWSTR password = L"P@ssword!";

	HANDLE hToken = nullptr; //will receive the new user's token

	//log on and get primary token

	/* https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonuserw */

	BOOL ok = LogonUserW(
		username,
		domain,
		password,
		LOGON32_LOGON_INTERACTIVE,       //typical desktop logon
		LOGON32_PROVIDER_DEFAULT,
		&hToken                           //OUT parameter
	);

	if (!ok) {
		std::wcerr << L"LogonUser failed: " << GetLastError() << std::endl;
		return 1;  //cant continue without a token
	}


	//create a process under that token
	STARTUPINFOW si = {
		sizeof(si)
	};


	//ask windows to start notepad as that user
	PROCESS_INFORMATION pi = {};
	ok = CreateProcessAsUserW(
		hToken, //received token
		L"C:\\Windows\\System32\\notepad.exe", //program
		nullptr, //cmdline(nullptr = just the exe)
		nullptr, //proc attrs
		nullptr, //thread attrs
		FALSE, //inherit handles
		0, //creation flag
		nullptr, //env block
		nullptr, //cwd
		&si,&pi);

	if (!ok) {
		std::wcerr << L"CreateProcessAsUserW failed: " << GetLastError() << L"\n";
		CloseHandle(hToken);
		return 1;
	}

	std::wcout << L"Launched Notepads as " << username << L", PID = " << pi.dwProcessId << std::endl;


	//clean up 
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	CloseHandle(hToken);
	return 0;
}
