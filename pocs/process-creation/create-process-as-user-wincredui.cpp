#include <windows.h>|
#include <iostream>
#include <wincred.h>
#include <userenv.h>
#include <strsafe.h>
#include <string>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Userenv.lib")
#pragma comment(lib, "Credui.lib")


//show CredUI, return user/domain/password in std::wstrings
bool PromptForCredentials(
    std::wstring& user,
    std::wstring& domain,
    std::wstring& password
)
{
    //structure used to pass infromation to the CredUIPromptForCredentials function that creadtes a dialog box used to obtain credentials information
    CREDUI_INFOW ui{};
    ui.cbSize = sizeof(ui);
    ui.pszCaptionText = L"Run as..";
    ui.pszMessageText = L"Credentials to launch target process";


    //CredUIParseUserName
    /* https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-creduipromptforcredentialsw */
    WCHAR usr[CREDUI_MAX_USERNAME_LENGTH + 1] = {}; //save the username
    WCHAR pwd[CREDUI_MAX_PASSWORD_LENGTH + 1] = {}; //save the password
    BOOL save = FALSE;
    DWORD flags = CREDUI_FLAGS_DO_NOT_PERSIST | CREDUI_FLAGS_EXCLUDE_CERTIFICATES;


    //function creates and displays a configurable dialog box that accepts credentials information from a user.
    DWORD res = CredUIPromptForCredentialsW(
        &ui, //pointer to CREDUI_INFO strucutre(info for customizing the apperance of the dialog box)
        L"", //target name (blank = generic)
        nullptr, //reserved
        0, //auth error (0 = none)
        usr, ARRAYSIZE(usr),
        pwd, ARRAYSIZE(pwd),
        &save,
        flags);


    if (res != ERROR_SUCCESS) //used clicked cancel or error
        return false;
  
    //CredUI always return DOMAIN\user or .\user, split it
    WCHAR parsedUser[CREDUI_MAX_USERNAME_LENGTH + 1] = {};
    WCHAR parsedDomain[CREDUI_MAX_USERNAME_LENGTH + 1] = {};


    /* https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-creduiparseusernamew */
  
    //the CredUIParseUserName function extracts the domain and user account name from a fully user name
    CredUIParseUserNameW(usr,
        parsedUser, ARRAYSIZE(parsedUser),
        parsedDomain, ARRAYSIZE(parsedDomain));

    user.assign(parsedUser);
    domain.assign(parsedDomain);
    password.assign(pwd);

    SecureZeroMemory(usr, sizeof(usr));   //scrub originals
    SecureZeroMemory(pwd, sizeof(pwd));
    return true;

}

int wmain()
{
    //collect credentials
    std::wstring user, domain, password;
    if (!PromptForCredentials(user, domain, password))
    {
        std::wcout << L"Aborted by user.\n";
        return 0;
    }

    //exchange creds for a primary access token
    /* https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonuserw */
    HANDLE hToken = nullptr;
    if (!LogonUserW(
        user.c_str(),
        domain.c_str(),
        password.c_str(),
        LOGON32_LOGON_INTERACTIVE,
        LOGON32_PROVIDER_DEFAULT,
        &hToken
    ))
    {
        std::wcerr << L"LogonUser failed: " << GetLastError() << L"\n";
        return 1;
    }

    //child-process settings(default)
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    //launch notepad as the captured user
    if (!CreateProcessAsUserW(
        hToken,
        L"C:\\Windows\\System32\\notepad.exe",   // payload EXE
        nullptr,                                 // full cmd-line (none)
        nullptr, nullptr,                        // default security
        FALSE,                                   // no handle inherit
        CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT,
        nullptr,                                 // inherit our env
        nullptr,                                 // inherit our cwd
        &si, &pi))
    {
        std::wcerr << L"CreateProcessAsUser failed: "
            << GetLastError() << L"\n";
        CloseHandle(hToken);
        return 1;
    }

    std::wcout << L"Launched PID " << pi.dwProcessId
        << L" under " << domain << L"\\" << user << L"\n";

    //house-keeping
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(hToken);
    return 0;
}

/*
┌─────────────────┐
│ CredUI dialog   │  ← user types DOMAIN\Bob + [password]
└──────┬──────────┘
       │ writes into
       ▼
WCHAR usr[514]  ← "DOMAIN\Bob\0"
WCHAR pwd[256]  ← "S3cr3t!\0"

CredUIParseUserNameW splits usr:
   parsedDomain = "DOMAIN"
   parsedUser   = "Bob"

std::wstring domain = L"DOMAIN";
std::wstring user   = L"Bob";
std::wstring pass   = L"S3cr3t!";

LogonUserW( user.c_str(), domain.c_str(), pass.c_str(), … )
        ↓
   → primary token
CreateProcessAsUserW( token, … )  → Notepad running as DOMAIN\Bob


*/
