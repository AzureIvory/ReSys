#define UNICODE
#define _UNICODE
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <shellapi.h>   // SHFileOperationW, ShellExecuteExW
#include <shlwapi.h>    // PathRemoveFileSpecW, PathIsRelativeW, PathFindFileNameW
#include <shlobj.h>     // SHGetSpecialFolderPathW, CSIDL_DESKTOPDIRECTORY
#include <winternl.h>   // RTL_OSVERSIONINFOW
#include <objbase.h>    // CoInitialize, CoCreateInstance
#include <shobjidl.h>   // IShellLinkW, IPersistFile
#include <stdio.h>
#include <wchar.h>
#include <stdint.h>
#include <stdlib.h>
#include <wctype.h>

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Ole32.lib")

#define MKRFILE    L".pa_wrapper_marker"
#define IDFILE     L".pa_payload_id"
#define EXOKFILE   L".pa_extracted_ok"
#define CLEANFILE  L".pa_cleanup_token"

#define PAYFILE    L"payload.7z"

#define MAX_RUN   64
#define MAX_LNK   64
#define MAX_MAP   64
#define MAX_LINE  4096

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

static void mk_dir_tree(const wchar_t* p) {
    int rc = SHCreateDirectoryExW(NULL, p, NULL);
    if (rc == ERROR_SUCCESS || rc == ERROR_ALREADY_EXISTS) return;
    die(L"mk_dir_tree fail");
}

static void mk_mark(const wchar_t* dir) {
    wchar_t path[MAX_PATH];
    wsprintfW(path, L"%s\\%s", dir, MKRFILE);

    HANDLE h = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS,
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

static void rm_dir_best_effort(const wchar_t* dir) {
    if (!has_mark(dir)) return;

    wchar_t from[MAX_PATH + 2];
    lstrcpynW(from, dir, MAX_PATH + 1);
    int n = lstrlenW(from);
    from[n + 1] = L'\0'; // 双 0 结尾

    SHFILEOPSTRUCTW op = { 0 };
    op.wFunc = FO_DELETE;
    op.pFrom = from;
    op.fFlags = FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT;
    (void)SHFileOperationW(&op);
}

static void exe_dir(wchar_t* out, size_t cap) {
    if (!GetModuleFileNameW(NULL, out, (DWORD)cap)) die(L"exe_dir fail");
    out[cap - 1] = L'\0';
    PathRemoveFileSpecW(out);
}

static void exe_path(wchar_t* out, size_t cap) {
    if (!GetModuleFileNameW(NULL, out, (DWORD)cap)) die(L"exe_path fail");
    out[cap - 1] = L'\0';
}

// 只隐藏“自己创建出来的控制台窗口”，避免从 cmd 启动时把用户的 cmd 隐藏掉
static void hide_own_console_if_any(void) {
    HWND h = GetConsoleWindow();
    if (!h) return;

    DWORD pids[2] = { 0 };
    DWORD n = GetConsoleProcessList(pids, 2);
    if (n == 1) ShowWindow(h, SW_HIDE);
}

// ---------------- CRC32 ----------------
static uint32_t crc32_calc(const void* data, size_t len) {
    static uint32_t table[256];
    static int inited = 0;
    if (!inited) {
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t c = i;
            for (int k = 0; k < 8; k++) {
                c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            }
            table[i] = c;
        }
        inited = 1;
    }

    uint32_t c = 0xFFFFFFFFu;
    const uint8_t* p = (const uint8_t*)data;
    for (size_t i = 0; i < len; i++) {
        c = table[(c ^ p[i]) & 0xFFu] ^ (c >> 8);
    }
    return c ^ 0xFFFFFFFFu;
}

// ---------------- 小文件读写（ASCII 内容） ----------------
static void write_textA(const wchar_t* path, const char* s) {
    HANDLE h = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD wr = 0;
    (void)WriteFile(h, s, (DWORD)lstrlenA(s), &wr, NULL);
    CloseHandle(h);
}

static int read_textA(const wchar_t* path, char* out, DWORD cap) {
    HANDLE h = CreateFileW(path, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;

    DWORD rd = 0;
    if (!ReadFile(h, out, cap - 1, &rd, NULL)) {
        CloseHandle(h);
        return 0;
    }
    out[rd] = '\0';
    CloseHandle(h);
    return 1;
}

static void path_join(wchar_t* out, size_t cap, const wchar_t* dir, const wchar_t* name) {
    (void)cap;
    wsprintfW(out, L"%s\\%s", dir, name);
}

static void write_payload_idfile(const wchar_t* dir, uint32_t crc, uint32_t sz) {
    wchar_t p[MAX_PATH];
    path_join(p, MAX_PATH, dir, IDFILE);

    char buf[128];
    sprintf_s(buf, sizeof(buf), "crc=%08X\nsz=%u\n", (unsigned)crc, (unsigned)sz);
    write_textA(p, buf);
}

static int read_payload_idfile(const wchar_t* dir, uint32_t* crc, uint32_t* sz) {
    wchar_t p[MAX_PATH];
    path_join(p, MAX_PATH, dir, IDFILE);

    char buf[128];
    if (!read_textA(p, buf, (DWORD)sizeof(buf))) return 0;

    unsigned c = 0, s = 0;
    if (sscanf_s(buf, "crc=%x\nsz=%u", &c, &s) != 2) return 0;
    *crc = (uint32_t)c;
    *sz = (uint32_t)s;
    return 1;
}

static void write_exok(const wchar_t* dir) {
    wchar_t p[MAX_PATH];
    path_join(p, MAX_PATH, dir, EXOKFILE);
    write_textA(p, "ok\n");
}

static int has_exok(const wchar_t* dir) {
    wchar_t p[MAX_PATH];
    path_join(p, MAX_PATH, dir, EXOKFILE);
    return fexist(p);
}

// ---------------- 运行进程：不弹控制台 + 可静默（stdout/stderr -> NUL） ----------------
static DWORD run_wait_ex(const wchar_t* app, wchar_t* cmd, const wchar_t* wdir, int silent) {
    STARTUPINFOW si = { 0 };
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = { 0 };

    HANDLE hNullIn = NULL, hNullOut = NULL, hNullErr = NULL;
    SECURITY_ATTRIBUTES sa = { 0 };
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    DWORD flags = CREATE_NO_WINDOW;
    BOOL inherit = FALSE;

    if (silent) {
        hNullIn = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        hNullOut = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        hNullErr = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

        if (hNullIn && hNullIn != INVALID_HANDLE_VALUE &&
            hNullOut && hNullOut != INVALID_HANDLE_VALUE &&
            hNullErr && hNullErr != INVALID_HANDLE_VALUE) {
            si.dwFlags |= STARTF_USESTDHANDLES;
            si.hStdInput = hNullIn;
            si.hStdOutput = hNullOut;
            si.hStdError = hNullErr;
            inherit = TRUE;
        }
        else {
            inherit = FALSE;
        }
    }

    if (!CreateProcessW(app, cmd, NULL, NULL, inherit, flags, NULL, wdir, &si, &pi)) {
        if (hNullIn && hNullIn != INVALID_HANDLE_VALUE) CloseHandle(hNullIn);
        if (hNullOut && hNullOut != INVALID_HANDLE_VALUE) CloseHandle(hNullOut);
        if (hNullErr && hNullErr != INVALID_HANDLE_VALUE) CloseHandle(hNullErr);
        return (DWORD)-1;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    if (hNullIn && hNullIn != INVALID_HANDLE_VALUE) CloseHandle(hNullIn);
    if (hNullOut && hNullOut != INVALID_HANDLE_VALUE) CloseHandle(hNullOut);
    if (hNullErr && hNullErr != INVALID_HANDLE_VALUE) CloseHandle(hNullErr);

    return code;
}

static DWORD run_shell_wait(const wchar_t* file, const wchar_t* params, const wchar_t* wdir) {
    SHELLEXECUTEINFOW sei = { 0 };
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = L"open";
    sei.lpFile = file;
    sei.lpParameters = (params && *params) ? params : NULL;
    sei.lpDirectory = (wdir && *wdir) ? wdir : NULL;
    sei.nShow = SW_SHOWNORMAL;

    if (!ShellExecuteExW(&sei)) return (DWORD)-1;

    if (sei.hProcess) {
        WaitForSingleObject(sei.hProcess, INFINITE);
        DWORD code = 0;
        GetExitCodeProcess(sei.hProcess, &code);
        CloseHandle(sei.hProcess);
        return code;
    }
    return 0;
}

// ---------------- 命令行 tail（用于 Forward） ----------------
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
    }
    else {
        while (*cmd && *cmd != L' ' && *cmd != L'\t') cmd++;
    }
    return sk_ws(cmd);
}

// ---------------- cleanup 子进程 ----------------
static void write_cleanup_token(const wchar_t* dir, const wchar_t* token) {
    wchar_t p[MAX_PATH];
    path_join(p, MAX_PATH, dir, CLEANFILE);

    char buf[64] = { 0 };
    size_t n = wcslen(token);
    if (n >= sizeof(buf)) n = sizeof(buf) - 1;
    for (size_t i = 0; i < n; i++) buf[i] = (char)token[i];
    buf[n] = '\0';
    write_textA(p, buf);
}

static int read_cleanup_token(const wchar_t* dir, wchar_t* out, size_t cap) {
    wchar_t p[MAX_PATH];
    path_join(p, MAX_PATH, dir, CLEANFILE);

    char buf[64];
    if (!read_textA(p, buf, (DWORD)sizeof(buf))) return 0;

    for (int i = 0; buf[i]; i++) {
        if (buf[i] == '\r' || buf[i] == '\n') { buf[i] = '\0'; break; }
    }

    size_t n = strlen(buf);
    if (n + 1 > cap) return 0;

    for (size_t i = 0; i < n; i++) out[i] = (wchar_t)(unsigned char)buf[i];
    out[n] = L'\0';
    return 1;
}

static void spawn_cleanup_self(const wchar_t* exepath, const wchar_t* exedir,
    const wchar_t* outdir, const wchar_t* token,
    DWORD delay_ms) {
    wchar_t cmd[4096];
    swprintf_s(cmd, 4096, L"\"%s\" --cleanup \"%s\" \"%s\" %u",
        exepath, outdir, token, (unsigned)delay_ms);

    STARTUPINFOW si = { 0 };
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = { 0 };

    DWORD flags = CREATE_NO_WINDOW | DETACHED_PROCESS;

    wchar_t* cmdline = _wcsdup(cmd);
    if (!cmdline) return;

    if (CreateProcessW(exepath, cmdline, NULL, NULL, FALSE, flags, NULL, exedir, &si, &pi)) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    free(cmdline);
}

static int cleanup_main(int argc, wchar_t** argv) {
    if (argc < 5) return 0;

    const wchar_t* dir = argv[2];
    const wchar_t* token = argv[3];
    DWORD delay = (DWORD)wcstoul(argv[4], NULL, 10);

    Sleep(delay);

    wchar_t cur[64];
    if (!read_cleanup_token(dir, cur, 64)) return 0;
    if (lstrcmpW(cur, token) != 0) return 0;

    rm_dir_best_effort(dir);
    return 0;
}

// ---------------- overlay：查找 config / payload ----------------
static size_t find_bytes(const uint8_t* hay, size_t haylen, const char* needle, size_t nlen) {
    if (!hay || !needle || nlen == 0 || haylen < nlen) return (size_t)-1;
    const uint8_t first = (uint8_t)needle[0];
    for (size_t i = 0; i + nlen <= haylen; i++) {
        if (hay[i] != first) continue;
        if (memcmp(hay + i, needle, nlen) == 0) return i;
    }
    return (size_t)-1;
}

typedef struct {
    const uint8_t* base;
    size_t size;
    size_t cfg_off;
    size_t cfg_len;
    size_t pay_off;
    size_t pay_len;
    HANDLE hFile;
    HANDLE hMap;
} SELF_OVERLAY;

static int open_self_overlay(const wchar_t* selfpath, SELF_OVERLAY* ov) {
    ZeroMemory(ov, sizeof(*ov));

    HANDLE hf = CreateFileW(selfpath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) return 0;

    LARGE_INTEGER li;
    if (!GetFileSizeEx(hf, &li) || li.QuadPart <= 0) { CloseHandle(hf); return 0; }
    if (li.QuadPart > (LONGLONG)(SIZE_T)-1) { CloseHandle(hf); return 0; }

    HANDLE hm = CreateFileMappingW(hf, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hm) { CloseHandle(hf); return 0; }

    void* view = MapViewOfFile(hm, FILE_MAP_READ, 0, 0, 0);
    if (!view) { CloseHandle(hm); CloseHandle(hf); return 0; }

    ov->base = (const uint8_t*)view;
    ov->size = (size_t)li.QuadPart;
    ov->hFile = hf;
    ov->hMap = hm;

    const char* BEGIN = ";!@Install@!UTF-8!";
    const char* END = ";!@InstallEnd@!";

    size_t bpos = find_bytes(ov->base, ov->size, BEGIN, strlen(BEGIN));
    if (bpos == (size_t)-1) return 1; // 没找到 markers：允许返回，但后续会报 no payload

    // 找 begin 行尾
    size_t after_begin = bpos;
    while (after_begin < ov->size && ov->base[after_begin] != '\n') after_begin++;
    if (after_begin < ov->size && ov->base[after_begin] == '\n') after_begin++;

    size_t epos = find_bytes(ov->base + after_begin, ov->size - after_begin, END, strlen(END));
    if (epos == (size_t)-1) return 1;
    epos += after_begin;

    ov->cfg_off = after_begin;
    ov->cfg_len = (epos > after_begin) ? (epos - after_begin) : 0;

    size_t pay = epos + strlen(END);
    while (pay < ov->size) {
        uint8_t c = ov->base[pay];
        if (c == '\r' || c == '\n' || c == ' ' || c == '\t') { pay++; continue; }
        break;
    }
    ov->pay_off = pay;
    ov->pay_len = (pay <= ov->size) ? (ov->size - pay) : 0;

    return 1;
}

static void close_self_overlay(SELF_OVERLAY* ov) {
    if (ov->base) UnmapViewOfFile(ov->base);
    if (ov->hMap) CloseHandle(ov->hMap);
    if (ov->hFile && ov->hFile != INVALID_HANDLE_VALUE) CloseHandle(ov->hFile);
    ZeroMemory(ov, sizeof(*ov));
}

static int write_payload_from_overlay(const SELF_OVERLAY* ov, const wchar_t* dst) {
    if (!ov || !ov->base || ov->pay_len == 0) return 0;

    HANDLE h = CreateFileW(dst, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;

    const uint8_t* p = ov->base + ov->pay_off;
    size_t left = ov->pay_len;
    while (left) {
        DWORD chunk = (left > (1u << 20)) ? (1u << 20) : (DWORD)left; // 1MB
        DWORD wr = 0;
        if (!WriteFile(h, p, chunk, &wr, NULL) || wr != chunk) {
            CloseHandle(h);
            return 0;
        }
        p += chunk;
        left -= chunk;
    }
    CloseHandle(h);
    return 1;
}

// ---------------- 平台识别：返回 "Windows7 32" / "Windows11 64" / "Windows10 ARM64" ----------------
typedef LONG(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);

static int get_os_version(DWORD* major, DWORD* minor, DWORD* build) {
    HMODULE h = GetModuleHandleW(L"ntdll.dll");
    if (!h) h = LoadLibraryW(L"ntdll.dll");
    if (!h) return 0;

    RtlGetVersionPtr p = (RtlGetVersionPtr)GetProcAddress(h, "RtlGetVersion");
    if (!p) return 0;

    RTL_OSVERSIONINFOW v = { 0 };
    v.dwOSVersionInfoSize = sizeof(v);
    if (p(&v) != 0) return 0;

    *major = v.dwMajorVersion;
    *minor = v.dwMinorVersion;
    *build = v.dwBuildNumber;
    return 1;
}

static const wchar_t* win_nameW(DWORD major, DWORD minor, DWORD build) {
    (void)build;
    if (major == 10 && minor == 0) return (build >= 22000) ? L"Windows11" : L"Windows10";
    if (major == 6 && minor == 3)  return L"Windows8.1";
    if (major == 6 && minor == 2)  return L"Windows8";
    if (major == 6 && minor == 1)  return L"Windows7";
    if (major == 6 && minor == 0)  return L"WindowsVista";
    if (major == 5 && minor == 1)  return L"WindowsXP";
    return L"Windows";
}

static const wchar_t* arch_nameW(void) {
    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    switch (si.wProcessorArchitecture) {
    case PROCESSOR_ARCHITECTURE_AMD64:
    case PROCESSOR_ARCHITECTURE_IA64:
        return L"64";
#ifdef PROCESSOR_ARCHITECTURE_ARM64
    case PROCESSOR_ARCHITECTURE_ARM64:
        return L"ARM64";
#endif
    case PROCESSOR_ARCHITECTURE_ARM:
        return L"ARM";
    default:
        return L"32";
    }
}

static void get_platform_label(wchar_t* out, size_t cap) {
    DWORD major = 0, minor = 0, build = 0;
    if (!get_os_version(&major, &minor, &build)) {
        swprintf_s(out, cap, L"Windows %s", arch_nameW());
        return;
    }
    swprintf_s(out, cap, L"%s %s", win_nameW(major, minor, build), arch_nameW());
}

// ---------------- config 解析：支持 CSV 列表 / 转义 / PathName 清洗 ----------------
typedef struct {
    wchar_t Title[256];
    wchar_t BeginPrompt[2048];

    wchar_t Directory[MAX_PATH];          // 默认 .\
    wchar_t ExecuteFile[1024];
    wchar_t ExecuteParameters[2048];

    int Forward;                          // 默认 0
    int TimeOut;                          // 秒；<0 不删
    wchar_t Path[MAX_PATH];               // 默认 %temp%
    wchar_t PathName[256];                // 默认 WrapperTemp

    int Cover;                            // 0 覆盖；非0 跳过

    wchar_t RunProgram[MAX_RUN][MAX_LINE];
    int RunCount;

    wchar_t LnkSpec[MAX_LNK][MAX_LINE];
    int LnkCount;

    // 平台映射： "Windows7 32:win732\PartAssist.exe"
    wchar_t MapKey[MAX_MAP][128];
    wchar_t MapCmd[MAX_MAP][MAX_LINE];
    int MapCount;
} CFG;

static void cfg_defaults(CFG* c) {
    ZeroMemory(c, sizeof(*c));
    c->Forward = 0;
    c->TimeOut = 0;
    c->Cover = 0;
    lstrcpyW(c->Directory, L".\\");
    lstrcpyW(c->Path, L"%temp%");
    lstrcpyW(c->PathName, L"WrapperTemp");
}

static void trim_w(wchar_t* s) {
    if (!s) return;
    wchar_t* p = s;
    while (*p == L' ' || *p == L'\t' || *p == L'\r' || *p == L'\n') p++;
    if (p != s) memmove(s, p, (wcslen(p) + 1) * sizeof(wchar_t));
    size_t n = wcslen(s);
    while (n && (s[n - 1] == L' ' || s[n - 1] == L'\t' || s[n - 1] == L'\r' || s[n - 1] == L'\n')) {
        s[n - 1] = 0; n--;
    }
}

static int keyeq(const wchar_t* a, const wchar_t* b) {
    return lstrcmpiW(a, b) == 0;
}

// 支持：\\ \" \n \r \t
static void unescape_inplace(wchar_t* v) {
    wchar_t out[MAX_LINE];
    size_t oi = 0;
    for (size_t i = 0; v[i] && oi + 1 < MAX_LINE; i++) {
        if (v[i] == L'\\' && v[i + 1]) {
            wchar_t n = v[i + 1];
            if (n == L'\\' || n == L'"') { out[oi++] = n; i++; continue; }
            if (n == L'n') { out[oi++] = L'\n'; i++; continue; }
            if (n == L'r') { out[oi++] = L'\r'; i++; continue; }
            if (n == L't') { out[oi++] = L'\t'; i++; continue; }
        }
        out[oi++] = v[i];
    }
    out[oi] = 0;
    lstrcpyW(v, out);
}

static void unquote_and_unescape(wchar_t* v) {
    trim_w(v);
    size_t n = wcslen(v);
    if (n >= 2 && v[0] == L'"' && v[n - 1] == L'"') {
        v[n - 1] = 0;
        memmove(v, v + 1, (n - 1) * sizeof(wchar_t));
    }
    unescape_inplace(v);
}

static int is_invalid_name_ch(wchar_t c) {
    // Windows 文件名非法字符：<>:"/\|?* 以及控制字符
    if (c < 32) return 1;
    switch (c) {
    case L'<': case L'>': case L':': case L'"':
    case L'/': case L'\\': case L'|':
    case L'?': case L'*':
        return 1;
    default:
        return 0;
    }
}

static void sanitize_dirname(wchar_t* s, const wchar_t* fallback) {
    wchar_t out[256];
    size_t oi = 0;
    for (size_t i = 0; s[i] && oi + 1 < _countof(out); i++) {
        if (is_invalid_name_ch(s[i])) continue; // 跳过非法符号
        out[oi++] = s[i];
    }
    out[oi] = 0;

    // 去掉末尾的点和空格（Windows 不允许）
    while (oi && (out[oi - 1] == L'.' || out[oi - 1] == L' ')) {
        out[--oi] = 0;
    }

    if (out[0] == 0) {
        lstrcpynW(s, fallback, 256);
    }
    else {
        lstrcpynW(s, out, 256);
    }
}

// CSV 解析：返回多个 item（支持 "a","b"；引号内允许逗号；\" 支持）
static int csv_split_items(const wchar_t* in, wchar_t items[][MAX_LINE], int max_items) {
    int cnt = 0;
    const wchar_t* p = in;
    while (p && *p) {
        while (*p == L' ' || *p == L'\t' || *p == L'\r' || *p == L'\n' || *p == L',') p++;
        if (!*p) break;

        wchar_t buf[MAX_LINE] = { 0 };
        size_t bi = 0;

        if (*p == L'"') {
            p++; // skip first quote
            while (*p && bi + 1 < MAX_LINE) {
                if (*p == L'"') { // end quote
                    p++;
                    break;
                }
                // 支持 \" 以及 \n 等
                if (*p == L'\\' && p[1]) {
                    buf[bi++] = *p;
                    p++;
                    if (bi + 1 < MAX_LINE) buf[bi++] = *p;
                    p++;
                    continue;
                }
                buf[bi++] = *p++;
            }
            buf[bi] = 0;
            // 消耗到下一个逗号
            while (*p && *p != L',') p++;
        }
        else {
            while (*p && *p != L',' && bi + 1 < MAX_LINE) {
                buf[bi++] = *p++;
            }
            buf[bi] = 0;
        }

        trim_w(buf);
        unescape_inplace(buf);

        if (cnt < max_items) {
            lstrcpynW(items[cnt], buf, MAX_LINE);
            cnt++;
        }

        while (*p == L',' || *p == L' ' || *p == L'\t') p++;
    }
    return cnt;
}

static void cfg_add_run(CFG* c, const wchar_t* cmd) {
    if (!cmd || !*cmd) return;
    if (c->RunCount >= MAX_RUN) return;
    lstrcpynW(c->RunProgram[c->RunCount], cmd, MAX_LINE);
    c->RunCount++;
}

static void cfg_add_lnk(CFG* c, const wchar_t* spec) {
    if (!spec || !*spec) return;
    if (c->LnkCount >= MAX_LNK) return;
    lstrcpynW(c->LnkSpec[c->LnkCount], spec, MAX_LINE);
    c->LnkCount++;
}

static void cfg_add_map(CFG* c, const wchar_t* spec) {
    if (!spec || !*spec) return;
    if (c->MapCount >= MAX_MAP) return;

    const wchar_t* colon = wcschr(spec, L':');
    if (!colon) return;

    wchar_t left[128] = { 0 };
    wchar_t right[MAX_LINE] = { 0 };

    size_t ln = (size_t)(colon - spec);
    if (ln >= _countof(left)) ln = _countof(left) - 1;
    wcsncpy_s(left, _countof(left), spec, ln);
    lstrcpynW(right, colon + 1, MAX_LINE);

    trim_w(left);
    trim_w(right);
    if (!*left || !*right) return;

    lstrcpynW(c->MapKey[c->MapCount], left, _countof(c->MapKey[c->MapCount]));
    lstrcpynW(c->MapCmd[c->MapCount], right, _countof(c->MapCmd[c->MapCount]));
    c->MapCount++;
}

static void cfg_parse_utf8_block(CFG* c, const uint8_t* data, size_t len) {
    if (!data || len == 0) return;

    int wlen = MultiByteToWideChar(CP_UTF8, 0, (LPCCH)data, (int)len, NULL, 0);
    if (wlen <= 0) return;

    wchar_t* w = (wchar_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (wlen + 2) * sizeof(wchar_t));
    if (!w) return;

    MultiByteToWideChar(CP_UTF8, 0, (LPCCH)data, (int)len, w, wlen);
    w[wlen] = 0;

    wchar_t* ctx = NULL;
    for (wchar_t* line = wcstok_s(w, L"\n", &ctx); line; line = wcstok_s(NULL, L"\n", &ctx)) {
        wchar_t buf[MAX_LINE];
        lstrcpynW(buf, line, MAX_LINE);
        trim_w(buf);
        if (!*buf) continue;
        if (buf[0] == L';' || buf[0] == L'#') continue;

        wchar_t* eq = wcschr(buf, L'=');
        if (!eq) continue;
        *eq = 0;

        wchar_t key[256];
        wchar_t val[MAX_LINE];

        lstrcpynW(key, buf, 256);
        lstrcpynW(val, eq + 1, MAX_LINE);
        trim_w(key);
        trim_w(val);

        // list 类键：RunProgram / lnk / Platform（支持 CSV 多项）
        if (keyeq(key, L"RunProgram")) {
            wchar_t items[64][MAX_LINE];
            int n = csv_split_items(val, items, 64);
            if (n == 0) {
                // 也允许 RunProgram=setup.exe 这种
                wchar_t v2[MAX_LINE];
                lstrcpynW(v2, val, MAX_LINE);
                unquote_and_unescape(v2);
                cfg_add_run(c, v2);
            }
            else {
                for (int i = 0; i < n; i++) cfg_add_run(c, items[i]);
            }
            continue;
        }
        if (keyeq(key, L"lnk")) {
            wchar_t items[64][MAX_LINE];
            int n = csv_split_items(val, items, 64);
            if (n == 0) {
                wchar_t v2[MAX_LINE];
                lstrcpynW(v2, val, MAX_LINE);
                unquote_and_unescape(v2);
                if (v2[0]) cfg_add_lnk(c, v2);
            }
            else {
                for (int i = 0; i < n; i++) {
                    if (items[i][0]) cfg_add_lnk(c, items[i]); // 空项忽略（例子里的 ""）
                }
            }
            continue;
        }
        if (keyeq(key, L"Platform") || keyeq(key, L"PlatformMap")) {
            wchar_t items[64][MAX_LINE];
            int n = csv_split_items(val, items, 64);
            if (n == 0) {
                wchar_t v2[MAX_LINE];
                lstrcpynW(v2, val, MAX_LINE);
                unquote_and_unescape(v2);
                cfg_add_map(c, v2);
            }
            else {
                for (int i = 0; i < n; i++) cfg_add_map(c, items[i]);
            }
            continue;
        }

        // 普通键：取一个值
        unquote_and_unescape(val);

        if (keyeq(key, L"Title")) {
            lstrcpynW(c->Title, val, _countof(c->Title));
        }
        else if (keyeq(key, L"BeginPrompt")) {
            lstrcpynW(c->BeginPrompt, val, _countof(c->BeginPrompt));
        }
        else if (keyeq(key, L"Directory")) {
            lstrcpynW(c->Directory, val, _countof(c->Directory));
        }
        else if (keyeq(key, L"ExecuteFile")) {
            lstrcpynW(c->ExecuteFile, val, _countof(c->ExecuteFile));
        }
        else if (keyeq(key, L"ExecuteParameters")) {
            lstrcpynW(c->ExecuteParameters, val, _countof(c->ExecuteParameters));
        }
        else if (keyeq(key, L"Forward")) {
            c->Forward = (int)wcstol(val, NULL, 10);
        }
        else if (keyeq(key, L"TimeOut")) {
            c->TimeOut = (int)wcstol(val, NULL, 10);
        }
        else if (keyeq(key, L"Path")) {
            lstrcpynW(c->Path, val, _countof(c->Path));
        }
        else if (keyeq(key, L"PathName")) {
            lstrcpynW(c->PathName, val, _countof(c->PathName));
        }
        else if (keyeq(key, L"cover")) {
            c->Cover = (int)wcstol(val, NULL, 10);
        }
    }

    HeapFree(GetProcessHeap(), 0, w);

    // PathName 清洗（默认 WrapperTemp，且过滤非法字符）
    sanitize_dirname(c->PathName, L"WrapperTemp");
}

static void get_working_dir(wchar_t* out, size_t cap) {
    DWORD n = GetCurrentDirectoryW((DWORD)cap, out);
    if (!n || n >= cap) lstrcpynW(out, L".", (int)cap);
}

static void replace_token_ci(const wchar_t* in, const wchar_t* token, const wchar_t* repl, wchar_t* out, size_t cap) {
    size_t tlen = wcslen(token);
    size_t rlen = wcslen(repl);
    size_t oi = 0;

    for (size_t i = 0; in[i] && oi + 1 < cap;) {
        int match = 1;
        for (size_t k = 0; k < tlen; k++) {
            wchar_t a = in[i + k];
            wchar_t b = token[k];
            if (!a) { match = 0; break; }
            if (towupper(a) != towupper(b)) { match = 0; break; }
        }
        if (match) {
            for (size_t k = 0; k < rlen && oi + 1 < cap; k++) out[oi++] = repl[k];
            i += tlen;
        }
        else {
            out[oi++] = in[i++];
        }
    }
    out[oi] = 0;
}

static void expand_path_vars(const wchar_t* in, const wchar_t* located, const wchar_t* working, wchar_t* out, size_t cap) {
    wchar_t tmp1[2048];
    wchar_t tmp2[2048];

    replace_token_ci(in, L"%located%", located, tmp1, _countof(tmp1));
    replace_token_ci(tmp1, L"%working%", working, tmp2, _countof(tmp2));

    DWORD n = ExpandEnvironmentStringsW(tmp2, out, (DWORD)cap);
    if (!n || n >= cap) lstrcpynW(out, tmp2, (int)cap);
}

// ---------------- lnk：创建桌面快捷方式 ----------------
static int get_desktop_dir(wchar_t* out, size_t cap) {
    if (SHGetSpecialFolderPathW(NULL, out, CSIDL_DESKTOPDIRECTORY, FALSE)) {
        out[cap - 1] = 0;
        return 1;
    }
    return 0;
}

static void resolve_path_under_outdir(const wchar_t* outdir, const wchar_t* maybe_rel, wchar_t* out, size_t cap) {
    if (!maybe_rel || !*maybe_rel) { out[0] = 0; return; }
    if (!PathIsRelativeW(maybe_rel)) {
        lstrcpynW(out, maybe_rel, (int)cap);
        return;
    }
    swprintf_s(out, cap, L"%s\\%s", outdir, maybe_rel);
}

static int create_shortcut_desktop(const wchar_t* outdir, const wchar_t* src, const wchar_t* desc,
    const wchar_t* linkname, const wchar_t* iconfile) {
    wchar_t desktop[MAX_PATH];
    if (!get_desktop_dir(desktop, _countof(desktop))) return 0;

    wchar_t target[MAX_PATH];
    wchar_t icon[MAX_PATH];
    resolve_path_under_outdir(outdir, src, target, _countof(target));
    resolve_path_under_outdir(outdir, iconfile, icon, _countof(icon));

    wchar_t lnkfile[MAX_PATH];
    wchar_t namebuf[MAX_PATH];
    lstrcpynW(namebuf, linkname && *linkname ? linkname : L"Shortcut", _countof(namebuf));

    // 自动补 .lnk
    size_t n = wcslen(namebuf);
    if (n < 4 || lstrcmpiW(namebuf + n - 4, L".lnk") != 0) {
        if (n + 4 < _countof(namebuf)) wcscat_s(namebuf, _countof(namebuf), L".lnk");
    }

    swprintf_s(lnkfile, _countof(lnkfile), L"%s\\%s", desktop, namebuf);

    HRESULT hr = CoInitialize(NULL);

    IShellLinkW* psl = NULL;
    hr = CoCreateInstance(&CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, &IID_IShellLinkW, (void**)&psl);
    if (FAILED(hr) || !psl) { CoUninitialize(); return 0; }

    psl->lpVtbl->SetPath(psl, target);
    if (desc && *desc) psl->lpVtbl->SetDescription(psl, desc);
    if (iconfile && *iconfile) psl->lpVtbl->SetIconLocation(psl, icon, 0);

    IPersistFile* ppf = NULL;
    hr = psl->lpVtbl->QueryInterface(psl, &IID_IPersistFile, (void**)&ppf);
    if (SUCCEEDED(hr) && ppf) {
        ppf->lpVtbl->Save(ppf, lnkfile, TRUE);
        ppf->lpVtbl->Release(ppf);
    }
    psl->lpVtbl->Release(psl);
    CoUninitialize();
    return 1;
}

// lnk spec: "src,desc,name,icon"
static void parse_lnk_spec_4(const wchar_t* spec, wchar_t* f1, wchar_t* f2, wchar_t* f3, wchar_t* f4) {
    f1[0] = f2[0] = f3[0] = f4[0] = 0;
    if (!spec) return;

    // 简单按逗号切 4 段（不支持字段内再嵌逗号；如要字段内逗号请你换成别的分隔符）
    // 你给的例子本身是无逗号字段，所以够用
    const wchar_t* p = spec;
    wchar_t buf[MAX_LINE];
    lstrcpynW(buf, spec, MAX_LINE);

    wchar_t* a = buf;
    wchar_t* b = wcschr(a, L','); if (!b) return; *b++ = 0;
    wchar_t* c = wcschr(b, L','); if (!c) return; *c++ = 0;
    wchar_t* d = wcschr(c, L','); if (!d) return; *d++ = 0;

    trim_w(a); trim_w(b); trim_w(c); trim_w(d);
    lstrcpynW(f1, a, MAX_PATH);
    lstrcpynW(f2, b, 512);
    lstrcpynW(f3, c, MAX_PATH);
    lstrcpynW(f4, d, MAX_PATH);
}

// ---------------- 平台映射匹配 ----------------
static void normalize_key_no_space(const wchar_t* in, wchar_t* out, size_t cap) {
    size_t oi = 0;
    for (size_t i = 0; in[i] && oi + 1 < cap; i++) {
        wchar_t c = in[i];
        if (c == L' ' || c == L'\t' || c == L'\r' || c == L'\n') continue;
        out[oi++] = towupper(c);
    }
    out[oi] = 0;
}

static const wchar_t* find_platform_cmd(const CFG* cfg, const wchar_t* platform_label) {
    if (!cfg || cfg->MapCount <= 0) return NULL;
    wchar_t key1[256];
    normalize_key_no_space(platform_label, key1, _countof(key1));

    for (int i = 0; i < cfg->MapCount; i++) {
        wchar_t key2[256];
        normalize_key_no_space(cfg->MapKey[i], key2, _countof(key2));
        if (lstrcmpW(key1, key2) == 0) return cfg->MapCmd[i];
    }
    return NULL;
}

// ---------------- 主逻辑 ----------------
static int real_main(int argc, wchar_t** argv) {
    hide_own_console_if_any();

    if (argc >= 2 && lstrcmpW(argv[1], L"--cleanup") == 0) {
        return cleanup_main(argc, argv);
    }

    wchar_t exedir[MAX_PATH];
    exe_dir(exedir, MAX_PATH);

    wchar_t selfpath[MAX_PATH];
    exe_path(selfpath, MAX_PATH);

    SELF_OVERLAY ov;
    if (!open_self_overlay(selfpath, &ov)) die(L"open self fail");

    CFG cfg;
    cfg_defaults(&cfg);

    if (ov.cfg_len > 0) cfg_parse_utf8_block(&cfg, ov.base + ov.cfg_off, ov.cfg_len);

    // 必须有 payload（没有 markers / payload 就没法跑）
    if (ov.pay_len == 0) {
        close_self_overlay(&ov);
        die(L"no payload (missing markers or payload not appended)");
    }

    // Title 为空：不弹窗（即使 BeginPrompt 有）
    if (cfg.Title[0] && cfg.BeginPrompt[0]) {
        int r = MessageBoxW(NULL, cfg.BeginPrompt, cfg.Title, MB_OKCANCEL | MB_ICONINFORMATION);
        if (r != IDOK) { close_self_overlay(&ov); return 3; }
    }

    // 计算解压目录：Path + PathName
    wchar_t located[MAX_PATH];
    lstrcpynW(located, exedir, MAX_PATH);

    wchar_t working[MAX_PATH];
    get_working_dir(working, MAX_PATH);

    wchar_t basepath[MAX_PATH];
    expand_path_vars(cfg.Path, located, working, basepath, MAX_PATH);

    size_t bl = wcslen(basepath);
    while (bl && (basepath[bl - 1] == L'\\' || basepath[bl - 1] == L'/')) { basepath[bl - 1] = 0; bl--; }

    wchar_t outdir[MAX_PATH];
    swprintf_s(outdir, MAX_PATH, L"%s\\%s", basepath, cfg.PathName);

    mk_dir_tree(outdir);
    mk_mark(outdir);

    // 必须有 7z.exe（放在壳同目录）
    wchar_t zpath[MAX_PATH];
    wsprintfW(zpath, L"%s\\7z.exe", exedir);
    if (!fexist(zpath)) {
        rm_dir_best_effort(outdir);
        close_self_overlay(&ov);
        die(L"no 7z.exe");
    }

    // 当前 payload id
    uint32_t cur_sz = (uint32_t)((ov.pay_len > 0xFFFFFFFFu) ? 0xFFFFFFFFu : ov.pay_len);
    uint32_t cur_crc = crc32_calc(ov.base + ov.pay_off, ov.pay_len);

    // 判断是否能跳过解压：目录存在+标记+exok+payload id 一致
    int can_skip_extract = 0;
    if (dexist(outdir) && has_mark(outdir) && has_exok(outdir)) {
        uint32_t old_crc = 0, old_sz = 0;
        if (read_payload_idfile(outdir, &old_crc, &old_sz) && old_crc == cur_crc && old_sz == cur_sz) {
            can_skip_extract = 1;
        }
    }

    if (!can_skip_extract) {
        wchar_t paypth[MAX_PATH];
        swprintf_s(paypth, MAX_PATH, L"%s\\%s", outdir, PAYFILE);

        if (!write_payload_from_overlay(&ov, paypth)) {
            rm_dir_best_effort(outdir);
            close_self_overlay(&ov);
            die(L"write payload fail");
        }

        // cover：0 覆盖(-aoa)，非0 跳过(-aos)
        const wchar_t* ao = (cfg.Cover == 0) ? L"-aoa" : L"-aos";

        wchar_t cmd7z[32768];
        swprintf_s(cmd7z, 32768, L"\"%s\" x -y %s -o\"%s\" \"%s\"",
            zpath, ao, outdir, paypth);

        DWORD c7z = run_wait_ex(zpath, cmd7z, exedir, 1);
        if (c7z == (DWORD)-1 || c7z != 0) {
            rm_dir_best_effort(outdir);
            close_self_overlay(&ov);
            die(L"7z fail");
        }

        write_exok(outdir);
        write_payload_idfile(outdir, cur_crc, cur_sz);
    }

    close_self_overlay(&ov);

    // 先创建快捷方式（lnk）
    for (int i = 0; i < cfg.LnkCount; i++) {
        wchar_t f1[MAX_PATH], f2[512], f3[MAX_PATH], f4[MAX_PATH];
        parse_lnk_spec_4(cfg.LnkSpec[i], f1, f2, f3, f4);
        if (f1[0] && f3[0]) {
            create_shortcut_desktop(outdir, f1, f2, f3, f4[0] ? f4 : f1);
        }
    }

    // 获取当前平台标签，并尝试 Platform 映射
    wchar_t platform[128];
    get_platform_label(platform, _countof(platform));
    const wchar_t* mapped = find_platform_cmd(&cfg, platform);

    const wchar_t* raw = GetCommandLineW();
    const wchar_t* tail = tail1(raw);

    DWORD lastCode = 0;

    if (mapped && *mapped) {
        // 命中映射：直接运行映射的程序（相对 outdir），不跑 RunProgram
        wchar_t cmd[MAX_LINE];
        lstrcpynW(cmd, mapped, _countof(cmd));

        // Forward 参数：转发给“映射程序”这一个（等价于第 0 条）
        if (cfg.Forward >= 0 && cfg.Forward == 0 && tail && *tail) {
            wchar_t tmp[MAX_LINE];
            swprintf_s(tmp, _countof(tmp), L"%s %s", cmd, tail);
            lstrcpynW(cmd, tmp, _countof(cmd));
        }

        wchar_t* cmdline = _wcsdup(cmd);
        if (!cmdline) { rm_dir_best_effort(outdir); die(L"oom"); }
        lastCode = run_wait_ex(NULL, cmdline, outdir, 1);
        free(cmdline);
        if (lastCode == (DWORD)-1) lastCode = 1;
    }
    else if (cfg.ExecuteFile[0]) {
        // ExecuteFile 更适合系统命令/打开文档/msiexec 等
        // 如果是相对路径，按 outdir 解析
        wchar_t exefile[MAX_PATH];
        resolve_path_under_outdir(outdir, cfg.ExecuteFile, exefile, _countof(exefile));
        lastCode = run_shell_wait(exefile, cfg.ExecuteParameters, outdir);
        if (lastCode == (DWORD)-1) lastCode = 1;
    }
    else {
        // RunProgram：逗号分割得到多条，按顺序执行
        if (cfg.RunCount == 0) {
            // 默认 setup.exe（如果既没映射，也没 ExecuteFile，也没 RunProgram）
            cfg_add_run(&cfg, L"setup.exe");
        }

        // RunProgram 工作目录：outdir + Directory（默认 .\）
        wchar_t run_wdir[MAX_PATH];
        wchar_t dir_exp[MAX_PATH];
        expand_path_vars(cfg.Directory, outdir, working, dir_exp, MAX_PATH);
        trim_w(dir_exp);

        if (dir_exp[0] == 0 || lstrcmpiW(dir_exp, L".") == 0 || lstrcmpiW(dir_exp, L".\\") == 0 || lstrcmpiW(dir_exp, L"./") == 0) {
            lstrcpynW(run_wdir, outdir, MAX_PATH);
        }
        else {
            if (PathIsRelativeW(dir_exp)) swprintf_s(run_wdir, MAX_PATH, L"%s\\%s", outdir, dir_exp);
            else lstrcpynW(run_wdir, dir_exp, MAX_PATH);
        }
        mk_dir_tree(run_wdir);

        for (int i = 0; i < cfg.RunCount; i++) {
            wchar_t final[MAX_LINE];
            lstrcpynW(final, cfg.RunProgram[i], MAX_LINE);

            // Forward：把尾参拼到第 N 条
            if (cfg.Forward >= 0 && cfg.Forward == i && tail && *tail) {
                wchar_t tmp[MAX_LINE];
                swprintf_s(tmp, MAX_LINE, L"%s %s", final, tail);
                lstrcpynW(final, tmp, MAX_LINE);
            }

            wchar_t* cmdline = _wcsdup(final);
            if (!cmdline) { lastCode = 2; break; }

            DWORD rc = run_wait_ex(NULL, cmdline, run_wdir, 1);
            free(cmdline);

            if (rc == (DWORD)-1) { lastCode = 1; break; }
            lastCode = rc;
            if (rc != 0) break; // 非 0 直接中止
        }
    }

    // TimeOut：<0 不删；>=0 则延迟删除 outdir（永远不删包装 EXE）
    if (cfg.TimeOut >= 0) {
        ULONGLONG tok = ((ULONGLONG)GetCurrentProcessId() << 32) ^ GetTickCount64();
        wchar_t tokW[32];
        swprintf_s(tokW, 32, L"%I64X", tok);

        write_cleanup_token(outdir, tokW);
        DWORD delay_ms = (DWORD)cfg.TimeOut * 1000u;
        spawn_cleanup_self(selfpath, exedir, outdir, tokW, delay_ms);
    }

    return (int)lastCode;
}

// Console 子系统入口
int wmain(int argc, wchar_t** argv) {
    return real_main(argc, argv);
}

// Windows 子系统入口
int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrev, PWSTR lpCmdLine, int nShowCmd) {
    (void)hInst; (void)hPrev; (void)lpCmdLine; (void)nShowCmd;

    int argc = 0;
    wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    int rc = real_main(argc, argv);
    if (argv) LocalFree(argv);
    return rc;
}
