/*
   shell_poc.cpp
   POC: demonstrate ShellExecuteW and ShellExecuteExW.
*/

#include <windows.h>
#include <shellapi.h>   //ShellExecute / ShellExecuteEx
#include <fstream>
#include <iostream>

#pragma comment(lib, "Shell32.lib")

//make sure the file exists so the Shell has something to open
void EnsureDemoFile(const wchar_t* path)
{
    std::ifstream fin(path, std::ios::binary);
    if (!fin.good())
    {
        std::wofstream fout(path, std::ios::binary);
        fout << L"Hello from ShellExecute POC!\r\n";
        std::wcout << L"Created " << path << L"\n";
    }
}

int wmain()
{
    const wchar_t* filePath = L"C:\\Temp\\demo.txt";
    EnsureDemoFile(filePath);


    HINSTANCE hInst = ShellExecuteW(
        nullptr,        // hwnd      no parent window
        L"open",        // lpVerb    "open" is default could be "edit
        filePath,       // lpFile    file or URL
        nullptr,        // lpParameters N/A for a plain doc
        nullptr,        // lpDirectory  current dir for the child
        SW_SHOWNORMAL   // nShowCmd   normal window
    );

    if ((UINT_PTR)hInst <= 32)
    {
        std::wcerr << L"ShellExecuteW failed, code " << (UINT_PTR)hInst << L"\n";
    }
    else
    {
        std::wcout << L"ShellExecuteW succeeded (handle = " << (UINT_PTR)hInst
            << L") – look for the editor window.\n";
    }


    SHELLEXECUTEINFO sei{};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS; //ask the Shell to give hProcess
    sei.hwnd = nullptr;
    sei.lpVerb = L"open";
    sei.lpFile = filePath;
    sei.nShow = SW_SHOWNORMAL;

    if (ShellExecuteExW(&sei))
    {
        std::wcout << L"ShellExecuteExW launched, PID = "
            << GetProcessId(sei.hProcess) << L"\n";

        //wait for the user to close the editor
        WaitForSingleObject(sei.hProcess, INFINITE);

        std::wcout << L"Editor closed, exit code ";
        DWORD exitCode = 0;
        if (GetExitCodeProcess(sei.hProcess, &exitCode))
            std::wcout << exitCode << L"\n";
        CloseHandle(sei.hProcess);
    }
    else
    {
        std::wcerr << L"ShellExecuteExW failed, error " << GetLastError() << L"\n";
    }

    return 0;
}
