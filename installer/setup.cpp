// simplewall Personal Edition — Native Windows Installer & Uninstaller
// Properly installs to Program Files\simplewall and registers with Windows & Revo Uninstaller

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commctrl.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <string>
#include <cwctype>
#include <algorithm>
#include "../src/app.h"

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "advapi32.lib")

static constexpr wchar_t kInstallDir[] = L"C:\\Program Files\\simplewall";
static constexpr wchar_t kUninstallKey[] = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\simplewall";

std::wstring ToLower (const std::wstring &s)
{
    std::wstring r = s;
    std::transform (r.begin (), r.end (), r.begin (), [] (wchar_t c) { return (wchar_t)towlower (c); });
    return r;
}

void StopRunningSimplewall ()
{
    DWORD selfPid = GetCurrentProcessId ();
    HANDLE snap = CreateToolhelp32Snapshot (TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof (pe);
    if (Process32FirstW (snap, &pe))
    {
        do
        {
            if (pe.th32ProcessID == selfPid) continue;
            if (_wcsicmp (pe.szExeFile, L"simplewall.exe") == 0)
            {
                HANDLE h = OpenProcess (PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pe.th32ProcessID);
                if (h)
                {
                    TerminateProcess (h, 0);
                    WaitForSingleObject (h, 4000);
                    CloseHandle (h);
                }
            }
        } while (Process32NextW (snap, &pe));
    }
    CloseHandle (snap);
    Sleep (350);
}

bool ExtractResourceToFile (UINT resId, const std::wstring &destPath)
{
    HMODULE hMod = GetModuleHandleW (nullptr);
    HRSRC hRes = FindResourceW (hMod, MAKEINTRESOURCEW (resId), RT_RCDATA);
    if (!hRes) return false;
    HGLOBAL hData = LoadResource (hMod, hRes);
    if (!hData) return false;
    DWORD sz = SizeofResource (hMod, hRes);
    const void *ptr = LockResource (hData);
    if (!ptr || sz == 0) return false;

    HANDLE hFile = CreateFileW (destPath.c_str (), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    DWORD written = 0;
    BOOL ok = WriteFile (hFile, ptr, sz, &written, nullptr);
    CloseHandle (hFile);
    return ok && written == sz;
}

bool CreateShortcut (const std::wstring &lnkPath, const std::wstring &targetPath, const std::wstring &workDir, const std::wstring &desc)
{
    IShellLinkW *psl = nullptr;
    HRESULT hr = CoCreateInstance (CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS (&psl));
    if (FAILED (hr) || !psl) return false;

    psl->SetPath (targetPath.c_str ());
    psl->SetWorkingDirectory (workDir.c_str ());
    psl->SetDescription (desc.c_str ());
    psl->SetIconLocation (targetPath.c_str (), 0);

    IPersistFile *ppf = nullptr;
    hr = psl->QueryInterface (IID_PPV_ARGS (&ppf));
    if (SUCCEEDED (hr) && ppf)
    {
        hr = ppf->Save (lnkPath.c_str (), TRUE);
        ppf->Release ();
    }
    psl->Release ();
    return SUCCEEDED (hr);
}

std::wstring GetStartMenuShortcutPath ()
{
    PWSTR p = nullptr;
    std::wstring res;
    if (SUCCEEDED (SHGetKnownFolderPath (FOLDERID_CommonPrograms, 0, nullptr, &p)) && p)
    {
        res = std::wstring (p) + L"\\simplewall.lnk";
        CoTaskMemFree (p);
    }
    return res;
}

std::wstring GetDesktopShortcutPath ()
{
    PWSTR p = nullptr;
    std::wstring res;
    if (SUCCEEDED (SHGetKnownFolderPath (FOLDERID_PublicDesktop, 0, nullptr, &p)) && p)
    {
        res = std::wstring (p) + L"\\simplewall.lnk";
        CoTaskMemFree (p);
    }
    return res;
}

bool WriteRegStr (HKEY hKey, const wchar_t *name, const std::wstring &val)
{
    return RegSetValueExW (hKey, name, 0, REG_SZ, (const BYTE *)val.c_str (), (DWORD)((val.size () + 1) * sizeof (wchar_t))) == ERROR_SUCCESS;
}

bool WriteRegDword (HKEY hKey, const wchar_t *name, DWORD val)
{
    return RegSetValueExW (hKey, name, 0, REG_DWORD, (const BYTE *)&val, sizeof (val)) == ERROR_SUCCESS;
}

int RunUninstall ()
{
    TASKDIALOGCONFIG tdc = {};
    tdc.cbSize = sizeof (tdc);
    tdc.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION;
    tdc.dwCommonButtons = TDCBF_YES_BUTTON | TDCBF_NO_BUTTON;
    tdc.pszWindowTitle = L"Uninstall simplewall";
    tdc.pszMainIcon = TD_WARNING_ICON;
    tdc.pszMainInstruction = L"Uninstall simplewall?";
    tdc.pszContent = L"This will remove simplewall from Program Files and unregister it from Windows.\n\nYour saved allowed/blocked app list in AppData will be kept unless you check the box below.";
    tdc.pszVerificationText = L"Also delete saved firewall profile & settings";

    int btn = 0;
    BOOL deleteProfile = FALSE;
    TaskDialogIndirect (&tdc, &btn, nullptr, &deleteProfile);
    if (btn != IDYES) return 0;

    StopRunningSimplewall ();

    // Remove Start Menu & Desktop shortcuts
    std::wstring sm = GetStartMenuShortcutPath ();
    if (!sm.empty ()) DeleteFileW (sm.c_str ());
    std::wstring dk = GetDesktopShortcutPath ();
    if (!dk.empty ()) DeleteFileW (dk.c_str ());

    // Remove Windows Uninstall registry key (so Revo / Settings reflect clean removal)
    RegDeleteKeyExW (HKEY_LOCAL_MACHINE, kUninstallKey, KEY_WOW64_64KEY, 0);

    // Delete installed files
    DeleteFileW ((std::wstring (kInstallDir) + L"\\simplewall.exe").c_str ());
    DeleteFileW ((std::wstring (kInstallDir) + L"\\simplewall.exe.bak").c_str ());
    DeleteFileW ((std::wstring (kInstallDir) + L"\\profile_internal.sp").c_str ());

    if (deleteProfile)
    {
        PWSTR appData = nullptr;
        if (SUCCEEDED (SHGetKnownFolderPath (FOLDERID_RoamingAppData, 0, nullptr, &appData)) && appData)
        {
            std::wstring profDir = std::wstring (appData) + L"\\Henry++\\simplewall";
            CoTaskMemFree (appData);
            std::wstring cmd = L"cmd.exe /c rmdir /s /q \"" + profDir + L"\"";
            STARTUPINFOW si = {sizeof (si)};
            PROCESS_INFORMATION pi = {};
            if (CreateProcessW (nullptr, cmd.data (), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
            {
                WaitForSingleObject (pi.hProcess, 3000);
                CloseHandle (pi.hThread);
                CloseHandle (pi.hProcess);
            }
        }
    }

    // Schedule self-removal of uninstall.exe and empty folder
    std::wstring selfCmd = L"cmd.exe /c ping 127.0.0.1 -n 2 > nul & del /f /q \"" + std::wstring (kInstallDir) + L"\\uninstall.exe\" & rmdir \"" + std::wstring (kInstallDir) + L"\"";
    STARTUPINFOW si = {sizeof (si)};
    PROCESS_INFORMATION pi = {};
    if (CreateProcessW (nullptr, selfCmd.data (), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
    {
        CloseHandle (pi.hThread);
        CloseHandle (pi.hProcess);
    }

    MessageBoxW (nullptr, L"simplewall has been uninstalled cleanly.", L"simplewall Uninstall", MB_OK | MB_ICONINFORMATION);
    return 0;
}

int RunInstall ()
{
    TASKDIALOGCONFIG tdc = {};
    tdc.cbSize = sizeof (tdc);
    tdc.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION | TDF_VERIFICATION_FLAG_CHECKED;
    tdc.pszWindowTitle = L"simplewall " APP_VERSION L" Setup";
    tdc.hInstance = GetModuleHandleW (nullptr);
    tdc.pszMainIcon = MAKEINTRESOURCEW (100);
    tdc.pszMainInstruction = L"Install simplewall v" APP_VERSION;
    tdc.pszContent = L"This will install simplewall cleanly into:\n"
        L"C:\\Program Files\\simplewall\\\n\n"
        L"• Registers properly in Windows Installed Apps & Revo Uninstaller\n"
        L"• Creates a Start Menu shortcut with your new shield icon\n"
        L"• Keeps all your existing allowed & blocked apps safe";
    tdc.pszVerificationText = L"Create a Desktop shortcut";

    TASKDIALOG_BUTTON buttons[] = {
        { IDOK, L"Install Now" },
        { IDCANCEL, L"Cancel" }
    };
    tdc.pButtons = buttons;
    tdc.cButtons = 2;
    tdc.nDefaultButton = IDOK;

    int btn = 0;
    BOOL createDesktop = TRUE;
    TaskDialogIndirect (&tdc, &btn, nullptr, &createDesktop);
    if (btn != IDOK) return 0;

    StopRunningSimplewall ();

    SHCreateDirectoryExW (nullptr, kInstallDir, nullptr);

    std::wstring exePath = std::wstring (kInstallDir) + L"\\simplewall.exe";
    std::wstring spPath = std::wstring (kInstallDir) + L"\\profile_internal.sp";
    std::wstring uninstPath = std::wstring (kInstallDir) + L"\\uninstall.exe";

    if (!ExtractResourceToFile (200, exePath))
    {
        MessageBoxW (nullptr, L"Could not write simplewall.exe to Program Files.\nPlease close any running copy of simplewall and try again.", L"simplewall Setup", MB_OK | MB_ICONERROR);
        return 1;
    }

    ExtractResourceToFile (201, spPath);

    // Copy self as uninstall.exe so Windows & Revo Uninstaller have a real uninstaller!
    WCHAR selfPath[MAX_PATH] = {};
    GetModuleFileNameW (nullptr, selfPath, MAX_PATH);
    CopyFileW (selfPath, uninstPath.c_str (), FALSE);

    // Register in Windows Add/Remove Programs (64-bit HKLM) — recognized by Windows Settings & Revo Uninstaller
    HKEY hKey = nullptr;
    if (RegCreateKeyExW (HKEY_LOCAL_MACHINE, kUninstallKey, 0, nullptr, 0, KEY_WRITE | KEY_WOW64_64KEY, nullptr, &hKey, nullptr) == ERROR_SUCCESS)
    {
        WriteRegStr (hKey, L"DisplayName", L"simplewall");
        WriteRegStr (hKey, L"DisplayVersion", APP_VERSION);
        WriteRegStr (hKey, L"Publisher", L"StrokeDot / Henry++");
        WriteRegStr (hKey, L"InstallLocation", kInstallDir);
        WriteRegStr (hKey, L"DisplayIcon", exePath);
        WriteRegStr (hKey, L"UninstallString", L"\"" + uninstPath + L"\" /uninstall");
        WriteRegStr (hKey, L"URLInfoAbout", L"https://github.com/StrokeDot/simplewall");
        WriteRegDword (hKey, L"EstimatedSize", 2600);
        WriteRegDword (hKey, L"NoModify", 1);
        WriteRegDword (hKey, L"NoRepair", 1);
        RegCloseKey (hKey);
    }

    // Create Start Menu & optional Desktop shortcuts
    std::wstring sm = GetStartMenuShortcutPath ();
    if (!sm.empty ())
        CreateShortcut (sm, exePath, kInstallDir, L"simplewall Personal Firewall");

    if (createDesktop)
    {
        std::wstring dk = GetDesktopShortcutPath ();
        if (!dk.empty ())
            CreateShortcut (dk, exePath, kInstallDir, L"simplewall Personal Firewall");
    }

    // Launch installed simplewall immediately
    ShellExecuteW (nullptr, L"open", exePath.c_str (), nullptr, kInstallDir, SW_SHOWNORMAL);

    MessageBoxW (
        nullptr,
        L"simplewall v" APP_VERSION L" has been installed to C:\\Program Files\\simplewall and registered with Windows!\n\nIt is now launching automatically.",
        L"simplewall Setup Complete",
        MB_OK | MB_ICONINFORMATION
    );
    return 0;
}

int WINAPI wWinMain (HINSTANCE, HINSTANCE, LPWSTR cmdLine, int)
{
    CoInitializeEx (nullptr, COINIT_APARTMENTTHREADED);
    INITCOMMONCONTROLSEX icc = {sizeof (icc), ICC_STANDARD_CLASSES};
    InitCommonControlsEx (&icc);

    std::wstring args = cmdLine ? ToLower (cmdLine) : L"";
    int rc = (args.find (L"/uninstall") != std::wstring::npos || args.find (L"-uninstall") != std::wstring::npos)
        ? RunUninstall ()
        : RunInstall ();

    CoUninitialize ();
    return rc;
}
