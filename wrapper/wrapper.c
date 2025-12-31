#define UNICODE
#define _UNICODE
#include <windows.h>
#include <shellapi.h>   // SHFileOperationW
#include <shlwapi.h>    // PathRemoveFileSpecW
#include <stdio.h>
#include <wchar.h>

#pragma comment(lib, "Shlwapi.lib")

#define MKRFILE L".pa_wrapper_marker"
#define RUNDIR  L"pa_runtime"
#define PAYFILE L"payload.7z"

static void die(const wchar_t* msg) {
    fwprintf(stderr, L"%s\n", msg);
    ExitProcess(2);
}

static int fexist(const wchar_t* p) {
    DWORD a = GetFileAttributesW(p);
    return (a != INVALID_FILE_ATTRIBUTES) && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

static int dexist(const wchar_t* p) {
    DWORD a = GetFileAttributesW(p);
    return (a != INVALID_FILE_ATTRIBUTES) && (a & FILE_ATTRIBUTE_DIRECTORY);
}

static void mk_dir(const wchar_t* p) {
    if (CreateDirectoryW(p, NULL)) return;

    if (GetLastError() == ERROR_ALREADY_EXISTS && dexist(p)) return;

    die(L"mk_dir fail");
}

static void mk_mark(const wchar_t* dir) {
    wchar_t path[MAX_PATH];
    wsprintfW(path, L"%s\\%s", dir, MKRFILE);

    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) die(L"mk_mark fail");

    DWORD w = 0;
    WriteFile(h, "ok\n", 3, &w, NULL);
    CloseHandle(h);
}

static int has_mark(const wchar_t* dir) {
    wchar_t path[MAX_PATH];
    wsprintfW(path, L"%s\\%s", dir, MKRFILE);
    return fexist(path);
}

static void rm_dir(const wchar_t* dir) {
    if (!has_mark(dir)) return;

    wchar_t from[MAX_PATH + 2];
    lstrcpynW(from, dir, MAX_PATH + 1);
    int n = lstrlenW(from);
    from[n + 1] = L'\0'; // 双 0 结尾

    SHFILEOPSTRUCTW op = {0};
    op.wFunc  = FO_DELETE;
    op.pFrom  = from;
    op.fFlags = FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT;
    SHFileOperationW(&op);
}

static void exe_dir(wchar_t* out, size_t cap) {
    if (!GetModuleFileNameW(NULL, out, (DWORD)cap)) die(L"exe_dir fail");
    out[cap - 1] = L'\0';
    PathRemoveFileSpecW(out);
}

static void res_out(const wchar_t* dst) {
    HRSRC hrs = FindResourceW(NULL, MAKEINTRESOURCEW(101), RT_RCDATA);
    if (!hrs) die(L"res find fail");

    HGLOBAL hg = LoadResource(NULL, hrs);
    if (!hg) die(L"res load fail");

    DWORD sz = SizeofResource(NULL, hrs);
    void* dat = LockResource(hg);
    if (!dat || sz == 0) die(L"res lock fail");

    HANDLE h = CreateFileW(dst, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) die(L"res file fail");

    DWORD wr = 0;
    if (!WriteFile(h, dat, sz, &wr, NULL) || wr != sz) {
        CloseHandle(h);
        die(L"res write fail");
    }
    CloseHandle(h);
}

static DWORD run_wait(const wchar_t* app, wchar_t* cmd, const wchar_t* wdir) {
    STARTUPINFOW si = {0};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {0};

    if (!CreateProcessW(app, cmd, NULL, NULL, TRUE, 0, NULL, wdir, &si, &pi))
        return (DWORD)-1;

    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return code;
}

static const wchar_t* sk_ws(const wchar_t* s) {
    while (*s == L' ' || *s == L'\t') s++;
    return s;
}

static const wchar_t* tail1(const wchar_t* cmd) {
    cmd = sk_ws(cmd);
    if (*cmd == L'"') {
        cmd++;
        while (*cmd && *cmd != L'"') cmd++;
        if (*cmd == L'"') cmd++;
    } else {
        while (*cmd && *cmd != L' ' && *cmd != L'\t') cmd++;
    }
    return sk_ws(cmd);
}

static wchar_t* mk_cmd(const wchar_t* paPath) {
    const wchar_t* raw  = GetCommandLineW();
    const wchar_t* tail = tail1(raw);

    size_t len = wcslen(paPath) + 3 + wcslen(tail) + 2;
    wchar_t* buf = (wchar_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                       len * sizeof(wchar_t));
    if (!buf) return NULL;

    if (tail && *tail) {
        swprintf_s(buf, len, L"\"%s\" %s", paPath, tail);
    } else {
        swprintf_s(buf, len, L"\"%s\"", paPath);
    }
    return buf;
}

int wmain(void) {
    wchar_t exedir[MAX_PATH];
    exe_dir(exedir, MAX_PATH);

    wchar_t outdir[MAX_PATH];
    wsprintfW(outdir, L"%s\\%s", exedir, RUNDIR);

    wchar_t zpath[MAX_PATH];
    wsprintfW(zpath, L"%s\\7z.exe", exedir);
    if (!fexist(zpath)) die(L"no 7z.exe");

    mk_dir(outdir);
    mk_mark(outdir);

    wchar_t paypth[MAX_PATH];
    wsprintfW(paypth, L"%s\\%s", outdir, PAYFILE);
    res_out(paypth);

    wchar_t cmd7z[32768];
    swprintf_s(cmd7z, 32768, L"\"%s\" x -y -aoa -o\"%s\" \"%s\"",
               zpath, outdir, paypth);

    DWORD c7z = run_wait(zpath, cmd7z, exedir);
    if (c7z == (DWORD)-1 || c7z != 0) {
        rm_dir(outdir);
        die(L"7z fail");
    }

    wchar_t papth[MAX_PATH];
    wsprintfW(papth, L"%s\\partassist.exe", outdir);
    if (!fexist(papth)) {
        rm_dir(outdir);
        die(L"no partassist.exe");
    }

    wchar_t* cmdpa = mk_cmd(papth);
    if (!cmdpa) {
        rm_dir(outdir);
        die(L"mk_cmd fail");
    }

    DWORD cpa = run_wait(papth, cmdpa, outdir);
    HeapFree(GetProcessHeap(), 0, cmdpa);

    rm_dir(outdir);
    ExitProcess(cpa);
}
