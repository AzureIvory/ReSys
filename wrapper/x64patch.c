#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <shlwapi.h>
#include <stdio.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shlwapi.lib")

static void PrintLastErrorW(const wchar_t* where) {
    (void)where; // 禁用所有错误打印
}

static BOOL PathIsDirW2(const wchar_t* path) {
    DWORD attr = GetFileAttributesW(path);
    return (attr != INVALID_FILE_ATTRIBUTES) && (attr & FILE_ATTRIBUTE_DIRECTORY);
}

static BOOL EnsureDirExistsW2(const wchar_t* path) {
    // 递归创建目录
    wchar_t tmp[MAX_PATH * 4];
    wcsncpy(tmp, path, _countof(tmp) - 1);
    tmp[_countof(tmp) - 1] = L'\0';

    // 跳过盘符根
    wchar_t* p = tmp;
    if (wcslen(tmp) >= 3 && tmp[1] == L':' && (tmp[2] == L'\\' || tmp[2] == L'/')) {
        p = tmp + 3;
    }

    for (; *p; ++p) {
        if (*p == L'\\' || *p == L'/') {
            wchar_t old = *p;
            *p = L'\0';
            if (wcslen(tmp) > 0 && !PathIsDirW2(tmp)) {
                if (!CreateDirectoryW(tmp, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
                    PrintLastErrorW(L"CreateDirectory");
                    return FALSE;
                }
            }
            *p = old;
        }
    }

    if (!PathIsDirW2(tmp)) {
        if (!CreateDirectoryW(tmp, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
            PrintLastErrorW(L"CreateDirectory(final)");
            return FALSE;
        }
    }
    return TRUE;
}

static BOOL CopyOneFileW2(const wchar_t* src, const wchar_t* dst) {
    // 目标目录确保存在
    wchar_t dstDir[MAX_PATH * 4];
    wcsncpy(dstDir, dst, _countof(dstDir) - 1);
    dstDir[_countof(dstDir) - 1] = L'\0';
    PathRemoveFileSpecW(dstDir);
    if (!EnsureDirExistsW2(dstDir)) return FALSE;

    // CopyFile 覆盖
    if (!CopyFileW(src, dst, FALSE)) {
        // 有时候目标文件只读，尝试去掉只读属性再拷
        DWORD attr = GetFileAttributesW(dst);
        if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_READONLY)) {
            SetFileAttributesW(dst, attr & ~FILE_ATTRIBUTE_READONLY);
        }
        if (!CopyFileW(src, dst, FALSE)) {
            PrintLastErrorW(L"CopyFile");
            return FALSE;
        }
    }
    return TRUE;
}

static BOOL CopyDirRecursiveW2(const wchar_t* srcDir, const wchar_t* dstDir) {
    if (!PathIsDirW2(srcDir)) {
        return FALSE;
    }
    if (!EnsureDirExistsW2(dstDir)) return FALSE;

    wchar_t pattern[MAX_PATH * 4];
    swprintf(pattern, _countof(pattern), L"%s\\*", srcDir);

    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) {
        PrintLastErrorW(L"FindFirstFile(dir)");
        return FALSE;
    }

    BOOL ok = TRUE;
    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
            continue;

        wchar_t srcPath[MAX_PATH * 4];
        wchar_t dstPath[MAX_PATH * 4];
        swprintf(srcPath, _countof(srcPath), L"%s\\%s", srcDir, fd.cFileName);
        swprintf(dstPath, _countof(dstPath), L"%s\\%s", dstDir, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (!CopyDirRecursiveW2(srcPath, dstPath)) ok = FALSE;
        } else {
            if (!CopyOneFileW2(srcPath, dstPath)) ok = FALSE;
        }
    } while (FindNextFileW(h, &fd));

    FindClose(h);
    return ok;
}

static BOOL CopyWildcardFilesW2(const wchar_t* srcDir, const wchar_t* pattern, const wchar_t* dstDir) {
    if (!EnsureDirExistsW2(dstDir)) return FALSE;

    wchar_t search[MAX_PATH * 4];
    swprintf(search, _countof(search), L"%s\\%s", srcDir, pattern);

    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(search, &fd);
    if (h == INVALID_HANDLE_VALUE) {
        return TRUE;
    }

    BOOL ok = TRUE;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;

        wchar_t srcPath[MAX_PATH * 4];
        wchar_t dstPath[MAX_PATH * 4];
        swprintf(srcPath, _countof(srcPath), L"%s\\%s", srcDir, fd.cFileName);
        swprintf(dstPath, _countof(dstPath), L"%s\\%s", dstDir, fd.cFileName);

        if (!CopyOneFileW2(srcPath, dstPath)) ok = FALSE;
    } while (FindNextFileW(h, &fd));

    FindClose(h);
    return ok;
}

static BOOL GetExeDirW2(wchar_t* outDir, size_t cchOut) {
    wchar_t path[MAX_PATH * 4];
    DWORD n = GetModuleFileNameW(NULL, path, (DWORD)_countof(path));
    if (n == 0 || n >= _countof(path)) return FALSE;

    wcsncpy(outDir, path, cchOut - 1);
    outDir[cchOut - 1] = L'\0';
    PathRemoveFileSpecW(outDir);
    return TRUE;
}

static BOOL IsNative64BitSystem(void) {
    // GetNativeSystemInfo 在 WOW64 下返回原生架构
    typedef VOID(WINAPI* PFN_GetNativeSystemInfo)(LPSYSTEM_INFO);
    PFN_GetNativeSystemInfo p = (PFN_GetNativeSystemInfo)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetNativeSystemInfo");

    SYSTEM_INFO si = { 0 };
    if (p) p(&si);
    else GetSystemInfo(&si);

    return (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
            si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64);
}

static BOOL RegSetSZ64Aware(HKEY root, const wchar_t* subkey, const wchar_t* valueNameOrNullForDefault,
                           const wchar_t* data, BOOL native64) {
    HKEY h = NULL;
    REGSAM sam = KEY_SET_VALUE | KEY_CREATE_SUB_KEY;
    if (native64) sam |= KEY_WOW64_64KEY; // 关键：32位进程写64位视图

    LONG r = RegCreateKeyExW(root, subkey, 0, NULL, 0, sam, NULL, &h, NULL);
    if (r != ERROR_SUCCESS) {
        SetLastError((DWORD)r);
        PrintLastErrorW(L"RegCreateKeyEx");
        return FALSE;
    }

    const wchar_t* vn = valueNameOrNullForDefault ? valueNameOrNullForDefault : L"";
    DWORD cb = (DWORD)((wcslen(data) + 1) * sizeof(wchar_t));
    r = RegSetValueExW(h, vn, 0, REG_SZ, (const BYTE*)data, cb);
    RegCloseKey(h);

    if (r != ERROR_SUCCESS) {
        SetLastError((DWORD)r);
        PrintLastErrorW(L"RegSetValueEx(REG_SZ)");
        return FALSE;
    }
    return TRUE;
}

static BOOL RegSetBIN1_64Aware(HKEY root, const wchar_t* subkey, const wchar_t* valueName,
                              BYTE b, BOOL native64) {
    HKEY h = NULL;
    REGSAM sam = KEY_SET_VALUE | KEY_CREATE_SUB_KEY;
    if (native64) sam |= KEY_WOW64_64KEY;

    LONG r = RegCreateKeyExW(root, subkey, 0, NULL, 0, sam, NULL, &h, NULL);
    if (r != ERROR_SUCCESS) {
        SetLastError((DWORD)r);
        PrintLastErrorW(L"RegCreateKeyEx");
        return FALSE;
    }

    r = RegSetValueExW(h, valueName, 0, REG_BINARY, &b, 1);
    RegCloseKey(h);

    if (r != ERROR_SUCCESS) {
        SetLastError((DWORD)r);
        PrintLastErrorW(L"RegSetValueEx(REG_BINARY)");
        return FALSE;
    }
    return TRUE;
}

static BOOL ApplyImportRegLikeBat(BOOL native64) {
    // --- CRT policy key ---
    const wchar_t* k_policy_crt =
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\SideBySide\\Winners\\"
        L"amd64_policy.8.0.microsoft.vc80.crt_1fc8b3b9a1e18e3b_none_a0fbb53a85bbf8e1";
    const wchar_t* k_policy_crt_80 =
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\SideBySide\\Winners\\"
        L"amd64_policy.8.0.microsoft.vc80.crt_1fc8b3b9a1e18e3b_none_a0fbb53a85bbf8e1\\8.0";

    if (!RegSetSZ64Aware(HKEY_LOCAL_MACHINE, k_policy_crt, NULL, L"8.0", native64)) return FALSE;
    if (!RegSetSZ64Aware(HKEY_LOCAL_MACHINE, k_policy_crt_80, NULL, L"8.0.50727.762", native64)) return FALSE;
    if (!RegSetBIN1_64Aware(HKEY_LOCAL_MACHINE, k_policy_crt_80, L"8.0.50727.6910", 0x01, native64)) return FALSE;
    if (!RegSetBIN1_64Aware(HKEY_LOCAL_MACHINE, k_policy_crt_80, L"8.0.50727.4053", 0x01, native64)) return FALSE;
    if (!RegSetBIN1_64Aware(HKEY_LOCAL_MACHINE, k_policy_crt_80, L"8.0.50727.6195", 0x01, native64)) return FALSE;
    if (!RegSetBIN1_64Aware(HKEY_LOCAL_MACHINE, k_policy_crt_80, L"8.0.50727.762", 0x01, native64)) return FALSE;

    // --- CRT component key ---
    const wchar_t* k_crt =
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\SideBySide\\Winners\\"
        L"amd64_microsoft.vc80.crt_1fc8b3b9a1e18e3b_none_751bbd257fdbc422";
    const wchar_t* k_crt_80 =
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\SideBySide\\Winners\\"
        L"amd64_microsoft.vc80.crt_1fc8b3b9a1e18e3b_none_751bbd257fdbc422\\8.0";

    if (!RegSetSZ64Aware(HKEY_LOCAL_MACHINE, k_crt_80, NULL, L"8.0.50727.762", native64)) return FALSE;
    if (!RegSetBIN1_64Aware(HKEY_LOCAL_MACHINE, k_crt_80, L"8.0.50727.6910", 0x01, native64)) return FALSE;
    if (!RegSetBIN1_64Aware(HKEY_LOCAL_MACHINE, k_crt_80, L"8.0.50727.4053", 0x01, native64)) return FALSE;
    if (!RegSetBIN1_64Aware(HKEY_LOCAL_MACHINE, k_crt_80, L"8.0.50727.6195", 0x01, native64)) return FALSE;
    if (!RegSetBIN1_64Aware(HKEY_LOCAL_MACHINE, k_crt_80, L"8.0.50727.762", 0x01, native64)) return FALSE;

    // --- MFC component key ---
    const wchar_t* k_mfc =
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\SideBySide\\Winners\\"
        L"amd64_microsoft.vc80.mfc_1fc8b3b9a1e18e3b_none_758c8a477f89a995";
    const wchar_t* k_mfc_80 =
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\SideBySide\\Winners\\"
        L"amd64_microsoft.vc80.mfc_1fc8b3b9a1e18e3b_none_758c8a477f89a995\\8.0";

    if (!RegSetSZ64Aware(HKEY_LOCAL_MACHINE, k_mfc_80, NULL, L"8.0.50727.762", native64)) return FALSE;
    if (!RegSetBIN1_64Aware(HKEY_LOCAL_MACHINE, k_mfc_80, L"8.0.50727.762", 0x01, native64)) return FALSE;
    if (!RegSetBIN1_64Aware(HKEY_LOCAL_MACHINE, k_mfc_80, L"8.0.50727.42", 0x01, native64)) return FALSE;
    if (!RegSetBIN1_64Aware(HKEY_LOCAL_MACHINE, k_mfc_80, L"8.0.50727.4027", 0x01, native64)) return FALSE;

    // --- MFC policy key ---
    const wchar_t* k_policy_mfc =
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\SideBySide\\Winners\\"
        L"amd64_policy.8.0.microsoft.vc80.mfc_1fc8b3b9a1e18e3b_none_a1b2894e85334056";
    const wchar_t* k_policy_mfc_80 =
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\SideBySide\\Winners\\"
        L"amd64_policy.8.0.microsoft.vc80.mfc_1fc8b3b9a1e18e3b_none_a1b2894e85334056\\8.0";

    if (!RegSetSZ64Aware(HKEY_LOCAL_MACHINE, k_policy_mfc, NULL, L"8.0", native64)) return FALSE;
    if (!RegSetSZ64Aware(HKEY_LOCAL_MACHINE, k_policy_mfc_80, NULL, L"8.0.50727.762", native64)) return FALSE;
    if (!RegSetBIN1_64Aware(HKEY_LOCAL_MACHINE, k_policy_mfc_80, L"8.0.50727.762", 0x01, native64)) return FALSE;
    if (!RegSetBIN1_64Aware(HKEY_LOCAL_MACHINE, k_policy_mfc_80, L"8.0.50727.42", 0x01, native64)) return FALSE;
    if (!RegSetBIN1_64Aware(HKEY_LOCAL_MACHINE, k_policy_mfc_80, L"8.0.50727.4027", 0x01, native64)) return FALSE;

    return TRUE;
}

static int RunAndWaitW2(const wchar_t* exePath) {
    DWORD attr = GetFileAttributesW(exePath);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        return 2;
    }

    wchar_t cmd[MAX_PATH * 4];
    swprintf(cmd, _countof(cmd), L"\"%s\"", exePath);

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);

    if (!CreateProcessW(exePath, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        PrintLastErrorW(L"CreateProcess");
        return 3;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return (int)exitCode;
}

int wmain(void) {
    wchar_t exeDir[MAX_PATH * 4];
    if (!GetExeDirW2(exeDir, _countof(exeDir))) {
        PrintLastErrorW(L"GetExeDir");
        return 1;
    }
    SetCurrentDirectoryW(exeDir);

    BOOL native64 = IsNative64BitSystem();

    wchar_t winDir[MAX_PATH * 4];
    if (!GetWindowsDirectoryW(winDir, (UINT)_countof(winDir))) {
        PrintLastErrorW(L"GetWindowsDirectory");
        return 1;
    }

    //复制 WinSxS 目录：  <exeDir>\WinSxS  =>  %windir%\WinSxS
    wchar_t srcWinSxS[MAX_PATH * 4];
    wchar_t dstWinSxS[MAX_PATH * 4];
    PathCombineW(srcWinSxS, exeDir, L"WinSxS");
    PathCombineW(dstWinSxS, winDir, L"WinSxS");

    CopyDirRecursiveW2(srcWinSxS, dstWinSxS);

    //复制 mfc*.dll / msvc*.dll 到指定 WinSxS 子目录
    wchar_t dstMfc[MAX_PATH * 4];
    wchar_t dstCrt[MAX_PATH * 4];

    PathCombineW(dstMfc, dstWinSxS,
        L"amd64_microsoft.vc80.mfc_1fc8b3b9a1e18e3b_8.0.50727.762_none_c46a533c8a667ee7");
    PathCombineW(dstCrt, dstWinSxS,
        L"amd64_microsoft.vc80.crt_1fc8b3b9a1e18e3b_8.0.50727.762_none_c905be8887838ff2");

    CopyWildcardFilesW2(exeDir, L"mfc*.dll", dstMfc);
    CopyWildcardFilesW2(exeDir, L"msvc*.dll", dstCrt);

    // 写注册表 regedit /s import.reg
    ApplyImportRegLikeBat(native64);

    //原生架构运行 SetupGreen32/64
    const wchar_t* setupName = native64 ? L"SetupGreen64.exe" : L"SetupGreen32.exe";
    wchar_t setupPath[MAX_PATH * 4];
    PathCombineW(setupPath, exeDir, setupName);

    return RunAndWaitW2(setupPath);
}
