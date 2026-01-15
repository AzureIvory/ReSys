#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <shellapi.h>
#include <shlwapi.h>
#include <shlobj.h>
#include <winternl.h>
#include <objbase.h>
#include <shobjidl.h>
#include <strsafe.h>
#include <stdio.h>
#include <wchar.h>
#include <stdint.h>
#include <stdlib.h>
#include <wctype.h>
#include <stdarg.h>

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "User32.lib")

// ===================== logging =====================
// Log priority: exe_dir\\<exe>.log  ->  %TEMP%\\<exe>_<pid>.log
// (UTF-16LE with BOM)
static HANDLE gLog = INVALID_HANDLE_VALUE;
static wchar_t gLogPath[MAX_PATH] = L"";
static CRITICAL_SECTION gLogCs;
static int gLogInited = 0;
int silent = 0;
static void log_close(void);

static void build_log_path_try_exedir(wchar_t* out, size_t cap) {
    wchar_t self[MAX_PATH];
    self[0] = 0;
    GetModuleFileNameW(NULL, self, MAX_PATH);

    wchar_t dir[MAX_PATH];
    lstrcpynW(dir, self, _countof(dir));
    PathRemoveFileSpecW(dir);

    wchar_t base[MAX_PATH];
    lstrcpynW(base, PathFindFileNameW(self), _countof(base));
    PathRemoveExtensionW(base);

    swprintf_s(out, cap, L"%s\\%s.log", dir, base);
}

static void build_log_path_temp(wchar_t* out, size_t cap) {
    wchar_t self[MAX_PATH];
    self[0] = 0;
    GetModuleFileNameW(NULL, self, MAX_PATH);
    wchar_t base[MAX_PATH];
    lstrcpynW(base, PathFindFileNameW(self), _countof(base));
    PathRemoveExtensionW(base);

    wchar_t tmp[MAX_PATH];
    DWORD n = GetTempPathW(_countof(tmp), tmp);
    if (!n || n >= _countof(tmp)) lstrcpynW(tmp, L".", _countof(tmp));
    // temp path usually ends with \\; keep it.
    swprintf_s(out, cap, L"%s%s_%lu.log", tmp, base, (unsigned long)GetCurrentProcessId());
}

static void log_open(void) {
    if (gLogInited) return;
    InitializeCriticalSection(&gLogCs);
    gLogInited = 1;

    wchar_t path1[MAX_PATH];
    wchar_t path2[MAX_PATH];
    build_log_path_try_exedir(path1, _countof(path1));
    build_log_path_temp(path2, _countof(path2));

    HANDLE h = CreateFileW(path1,
                           FILE_APPEND_DATA | GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        h = CreateFileW(path2,
                        FILE_APPEND_DATA | GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE) lstrcpynW(gLogPath, path2, _countof(gLogPath));
    } else {
        lstrcpynW(gLogPath, path1, _countof(gLogPath));
    }

    gLog = h;
    if (gLog == INVALID_HANDLE_VALUE) return;

    LARGE_INTEGER sz;
    sz.QuadPart = 0;
    if (GetFileSizeEx(gLog, &sz) && sz.QuadPart == 0) {
        // UTF-16LE BOM
        const WORD bom = 0xFEFF;
        DWORD wr = 0;
        WriteFile(gLog, &bom, sizeof(bom), &wr, NULL);
    }
}

static void log_write_wstr(const wchar_t* s) {
    if (!s) return;
    if (gLog == INVALID_HANDLE_VALUE) return;
    DWORD wr = 0;
    size_t bytes = wcslen(s) * sizeof(wchar_t);
    if (bytes > 0xFFFFFFFFu) bytes = 0xFFFFFFFFu;
    WriteFile(gLog, s, (DWORD)bytes, &wr, NULL);
}

static void log_v(const wchar_t* fmt, va_list ap) {
    if (!fmt) return;
    log_open();
    if (gLog == INVALID_HANDLE_VALUE) return;

    EnterCriticalSection(&gLogCs);

    SYSTEMTIME st;
    GetLocalTime(&st);

    wchar_t head[256];
    swprintf_s(head, _countof(head),
               L"%04u-%02u-%02u %02u:%02u:%02u.%03u [pid=%lu tid=%lu] ",
               (unsigned)st.wYear, (unsigned)st.wMonth, (unsigned)st.wDay,
               (unsigned)st.wHour, (unsigned)st.wMinute, (unsigned)st.wSecond, (unsigned)st.wMilliseconds,
               (unsigned long)GetCurrentProcessId(), (unsigned long)GetCurrentThreadId());
    log_write_wstr(head);

    wchar_t buf[4096];
    buf[0] = 0;
    StringCchVPrintfW(buf, _countof(buf), fmt, ap);
    log_write_wstr(buf);
    log_write_wstr(L"\r\n");

    // Helpful when running under debugger.
    OutputDebugStringW(head);
    OutputDebugStringW(buf);
    OutputDebugStringW(L"\r\n");

    LeaveCriticalSection(&gLogCs);
}

static void logw(const wchar_t* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    log_v(fmt, ap);
    va_end(ap);
}

static void log_last_errorW(const wchar_t* where, DWORD err) {
    wchar_t msg[1024];
    msg[0] = 0;
    FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   NULL, err,
                   MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                   msg, (DWORD)_countof(msg), NULL);
    // strip CRLF
    for (size_t i = 0; msg[i]; i++) {
        if (msg[i] == L'\r' || msg[i] == L'\n') { msg[i] = 0; break; }
    }
    logw(L"ERROR at %s: GetLastError=%lu (%s)", where ? where : L"(null)", (unsigned long)err, msg);
}

static void log_winerr(const wchar_t* where) {
    DWORD err = GetLastError();
    log_last_errorW(where, err);
}

static void log_close(void) {
    if (gLog != INVALID_HANDLE_VALUE) {
        CloseHandle(gLog);
        gLog = INVALID_HANDLE_VALUE;
    }
    if (gLogInited) {
        DeleteCriticalSection(&gLogCs);
        gLogInited = 0;
    }
}

// ---------- crash handling (best-effort) ----------
// Logs exception code/address + a simple stack backtrace (addresses).
typedef USHORT (WINAPI *RtlCaptureStackBackTrace_t)(ULONG, ULONG, PVOID*, PULONG);
static void log_stack_backtrace(void) {
    HMODULE hk = GetModuleHandleW(L"kernel32.dll");
    if (!hk) return;
    RtlCaptureStackBackTrace_t p = (RtlCaptureStackBackTrace_t)GetProcAddress(hk, "RtlCaptureStackBackTrace");
    if (!p) return;

    PVOID frames[48];
    USHORT n = p(0, (ULONG)_countof(frames), frames, NULL);
    for (USHORT i = 0; i < n; i++) {
        logw(L"  bt[%02u] %p", (unsigned)i, frames[i]);
    }
}

static void log_exception(EXCEPTION_POINTERS* ep) {
    if (!ep || !ep->ExceptionRecord) return;
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    PVOID addr = ep->ExceptionRecord->ExceptionAddress;
    logw(L"*** CRASH: exception=0x%08lX addr=%p flags=0x%08lX", (unsigned long)code, addr, (unsigned long)ep->ExceptionRecord->ExceptionFlags);
    log_stack_backtrace();
}

static LONG WINAPI wrapper_unhandled_filter(EXCEPTION_POINTERS* ep) {
    log_exception(ep);
    logw(L"Log file: %s", gLogPath[0] ? gLogPath : L"(not created)");
    log_close();
    return EXCEPTION_EXECUTE_HANDLER;
}

static void install_crash_handlers(void) {
    SetUnhandledExceptionFilter(wrapper_unhandled_filter);
}

// -------- LZMA SDK (7z decode) --------
#include "7z/7z.h"
#include "7z/7zAlloc.h"
#include "7z/7zCrc.h"
#include "7z/7zTypes.h"

// -------- marker files (通用化) --------
#define MKRFILE    L".wrapper_marker"
#define IDFILE     L".payload_id"
#define EXOKFILE   L".extracted_ok"
#define CLEANFILE  L".cleanup_token"

// -------- config markers --------
static const char* CFG_BEGIN = ";!@Install@!UTF-8!";
static const char* CFG_END   = ";!@InstallEnd@!";

#define MAX_RUN   64
#define MAX_LNK   64
#define MAX_MAP   64
#define MAX_LINE  4096

static void die(const wchar_t* msg) {
    DWORD err = GetLastError();
    log_last_errorW(msg ? msg : L"(die)", err);
    logw(L"FATAL: %s", msg ? msg : L"(null)");
    if (gLogPath[0]) logw(L"Log file: %s", gLogPath);
    fwprintf(stderr, L"%s (Error Code: %lu)\n", msg ? msg : L"(null)", (unsigned long)err);
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
    logw(L"mk_dir_tree: %s", p ? p : L"(null)");
    int rc = SHCreateDirectoryExW(NULL, p, NULL);
    if (rc == ERROR_SUCCESS || rc == ERROR_ALREADY_EXISTS) return;
    SetLastError((DWORD)rc);
    die(L"mk_dir_tree fail");
}

static void mk_mark(const wchar_t* dir) {
    wchar_t path[MAX_PATH];
    StringCchPrintfW(path, MAX_PATH, L"%s\\%s", dir, MKRFILE);
    logw(L"mk_mark: %s", path);
    HANDLE h = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) die(L"mk_mark fail");
    DWORD w = 0;
    WriteFile(h, "ok\n", 3, &w, NULL);
    CloseHandle(h);
}

static int has_mark(const wchar_t* dir) {
    wchar_t path[MAX_PATH];
    StringCchPrintfW(path, MAX_PATH, L"%s\\%s", dir, MKRFILE);
    return fexist(path);
}

static void rm_dir_best_effort(const wchar_t* dir) {
    if (!dir || !*dir) return;
    if (!has_mark(dir)) {
        logw(L"rm_dir_best_effort: skip (no marker) dir=%s", dir);
        return;
    }
    logw(L"rm_dir_best_effort: deleting dir=%s", dir);
    wchar_t from[MAX_PATH + 2];
    StringCchCopyW(from, MAX_PATH + 1, dir);
    int n = lstrlenW(from);
    from[n + 1] = L'\0';

    SHFILEOPSTRUCTW op = {0};
    op.wFunc  = FO_DELETE;
    op.pFrom  = from;
    op.fFlags = FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT;
    (void)SHFileOperationW(&op);
}

static void exe_dir(wchar_t* out, size_t cap) {
    if (!GetModuleFileNameW(NULL, out, (DWORD)cap)) die(L"exe_dir fail");
    out[cap - 1] = 0;
    PathRemoveFileSpecW(out);
    logw(L"exe_dir: %s", out);
}

static void exe_path(wchar_t* out, size_t cap) {
    if (!GetModuleFileNameW(NULL, out, (DWORD)cap)) die(L"exe_path fail");
    out[cap - 1] = 0;
    logw(L"exe_path: %s", out);
}

static void hide_own_console_if_any(void) {
    HWND h = GetConsoleWindow();
    if (!h) return;
    DWORD pids[2] = {0};
    DWORD n = GetConsoleProcessList(pids, 2);
    silent = (n <= 1);   // 双击启动通常 n==1；从 cmd 里跑通常 n==2
    logw(L"console: hwnd=%p processListCount=%lu", (void*)h, (unsigned long)n);
    if (n == 1) {
        ShowWindow(h, SW_HIDE);
        logw(L"console: hidden");
    }
}

// -------- CRC32 --------
static uint32_t crc32_calc(const void* data, size_t len) {
    static uint32_t table[256];
    static int inited = 0;
    if (!inited) {
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t c = i;
            for (int k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            table[i] = c;
        }
        inited = 1;
    }
    uint32_t c = 0xFFFFFFFFu;
    const uint8_t* p = (const uint8_t*)data;
    for (size_t i = 0; i < len; i++) c = table[(c ^ p[i]) & 0xFFu] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

// -------- small text files --------
static void write_textA(const wchar_t* path, const char* s) {
    HANDLE h = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD wr = 0;
    (void)WriteFile(h, s, (DWORD)lstrlenA(s), &wr, NULL);
    CloseHandle(h);
}

static int read_textA(const wchar_t* path, char* out, DWORD cap) {
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    DWORD rd = 0;
    if (!ReadFile(h, out, cap - 1, &rd, NULL)) { CloseHandle(h); return 0; }
    out[rd] = 0;
    CloseHandle(h);
    return 1;
}

static void path_join(wchar_t* out, size_t cap, const wchar_t* dir, const wchar_t* name) {
    StringCchPrintfW(out, cap, L"%s\\%s", dir, name);
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
    *sz  = (uint32_t)s;
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

// -------- run process --------
static DWORD run_wait_ex(const wchar_t* app, wchar_t* cmd, const wchar_t* wdir, int silent) {
    logw(L"run_wait_ex: app=%s | cmd=%s | wdir=%s | silent=%d",
         app ? app : L"(null)", cmd ? cmd : L"(null)", wdir ? wdir : L"(null)", silent);
    STARTUPINFOW si = {0};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {0};

    HANDLE hNullIn = NULL, hNullOut = NULL, hNullErr = NULL;
    SECURITY_ATTRIBUTES sa = {0};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    DWORD flags = silent ? CREATE_NO_WINDOW : 0;
    BOOL inherit = FALSE;

    if (silent) {
        hNullIn  = CreateFileW(L"NUL", GENERIC_READ,  FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        hNullOut = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        hNullErr = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

        if (hNullIn && hNullIn != INVALID_HANDLE_VALUE &&
            hNullOut && hNullOut != INVALID_HANDLE_VALUE &&
            hNullErr && hNullErr != INVALID_HANDLE_VALUE) {
            si.dwFlags |= STARTF_USESTDHANDLES;
            si.hStdInput  = hNullIn;
            si.hStdOutput = hNullOut;
            si.hStdError  = hNullErr;
            inherit = TRUE;
        } else {
            logw(L"run_wait_ex: silent stdio redirect failed (inherit will be FALSE)");
            log_winerr(L"CreateFileW(NUL)");
        }
    } else {
        si.dwFlags |= STARTF_USESTDHANDLES;
        si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);
        si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
        si.hStdError  = GetStdHandle(STD_ERROR_HANDLE);
        inherit = TRUE;
    }

    if (!CreateProcessW(app, cmd, NULL, NULL, inherit, flags, NULL, wdir, &si, &pi)) {
        log_winerr(L"CreateProcessW");
        if (hNullIn  && hNullIn  != INVALID_HANDLE_VALUE) CloseHandle(hNullIn);
        if (hNullOut && hNullOut != INVALID_HANDLE_VALUE) CloseHandle(hNullOut);
        if (hNullErr && hNullErr != INVALID_HANDLE_VALUE) CloseHandle(hNullErr);
        return (DWORD)-1;
    }

    logw(L"run_wait_ex: started pid=%lu", (unsigned long)pi.dwProcessId);

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    logw(L"run_wait_ex: exit code=%lu", (unsigned long)code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    if (hNullIn  && hNullIn  != INVALID_HANDLE_VALUE) CloseHandle(hNullIn);
    if (hNullOut && hNullOut != INVALID_HANDLE_VALUE) CloseHandle(hNullOut);
    if (hNullErr && hNullErr != INVALID_HANDLE_VALUE) CloseHandle(hNullErr);

    return code;
}

// -------- cmdline tail (Forward) --------
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

// -------- cleanup child --------
static void write_cleanup_token(const wchar_t* dir, const wchar_t* token) {
    wchar_t p[MAX_PATH];
    path_join(p, MAX_PATH, dir, CLEANFILE);
    char buf[64] = {0};
    size_t n = wcslen(token);
    if (n >= sizeof(buf)) n = sizeof(buf) - 1;
    for (size_t i = 0; i < n; i++) buf[i] = (char)token[i];
    buf[n] = 0;
    write_textA(p, buf);
}

static int read_cleanup_token(const wchar_t* dir, wchar_t* out, size_t cap) {
    wchar_t p[MAX_PATH];
    path_join(p, MAX_PATH, dir, CLEANFILE);
    char buf[64];
    if (!read_textA(p, buf, (DWORD)sizeof(buf))) return 0;
    for (int i = 0; buf[i]; i++) if (buf[i] == '\r' || buf[i] == '\n') { buf[i] = 0; break; }
    size_t n = strlen(buf);
    if (n + 1 > cap) return 0;
    for (size_t i = 0; i < n; i++) out[i] = (wchar_t)(unsigned char)buf[i];
    out[n] = 0;
    return 1;
}

static void spawn_cleanup_self(const wchar_t* exepath, const wchar_t* exedir,
                               const wchar_t* outdir, const wchar_t* token,
                               DWORD delay_ms) {
    wchar_t cmd[4096];
    StringCchPrintfW(cmd, 4096, L"\"%s\" --cleanup \"%s\" \"%s\" %u",
                     exepath, outdir, token, (unsigned)delay_ms);

    logw(L"spawn_cleanup_self: %s", cmd);

    STARTUPINFOW si = {0};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {0};
    DWORD flags = CREATE_NO_WINDOW | DETACHED_PROCESS;

    wchar_t* cmdline = _wcsdup(cmd);
    if (!cmdline) return;

    if (CreateProcessW(exepath, cmdline, NULL, NULL, FALSE, flags, NULL, exedir, &si, &pi)) {
        logw(L"cleanup child started pid=%lu", (unsigned long)pi.dwProcessId);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    } else {
        log_winerr(L"CreateProcessW(cleanup)");
    }
    free(cmdline);
}

static int cleanup_main(int argc, wchar_t** argv) {
    if (argc < 5) {
        logw(L"cleanup_main: argc too small=%d", argc);
        return 0;
    }
    const wchar_t* dir   = argv[2];
    const wchar_t* token = argv[3];
    DWORD delay = (DWORD)wcstoul(argv[4], NULL, 10);

    logw(L"cleanup_main: dir=%s token=%s delay_ms=%lu", dir ? dir : L"(null)", token ? token : L"(null)", (unsigned long)delay);
    Sleep(delay);

    wchar_t cur[64];
    if (!read_cleanup_token(dir, cur, 64)) {
        logw(L"cleanup_main: missing token file");
        return 0;
    }
    if (lstrcmpW(cur, token) != 0) {
        logw(L"cleanup_main: token mismatch cur=%s", cur);
        return 0;
    }

    rm_dir_best_effort(dir);
    return 0;
}

// -------- overlay parse --------
static size_t find_bytes(const uint8_t* hay, size_t haylen, const char* needle, size_t nlen) {
    if (!hay || !needle || nlen == 0 || haylen < nlen) return (size_t)-1;
    const uint8_t first = (uint8_t)needle[0];
    for (size_t i = 0; i + nlen <= haylen; i++) {
        if (hay[i] != first) continue;
        if (memcmp(hay + i, needle, nlen) == 0) return i;
    }
    return (size_t)-1;
}

//反方向找
static size_t rfind_bytes(const uint8_t* hay, size_t haylen, const char* needle, size_t nlen) {
    if (!hay || !needle || nlen == 0 || haylen < nlen) return (size_t)-1;
    const uint8_t first = (uint8_t)needle[0];
    size_t i = haylen - nlen;
    for (;;) {
        if (hay[i] == first && memcmp(hay + i, needle, nlen) == 0) return i;
        if (i == 0) break;
        i--;
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

    logw(L"open_self_overlay: %s", selfpath ? selfpath : L"(null)");

    HANDLE hf = CreateFileW(selfpath, GENERIC_READ,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            NULL, OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hf == INVALID_HANDLE_VALUE) {
        log_winerr(L"CreateFileW(self)");
        return 0;
    }

    LARGE_INTEGER li;
    if (!GetFileSizeEx(hf, &li) || li.QuadPart <= 0) {
        DWORD e = GetLastError();
        CloseHandle(hf);
        SetLastError(e);
        return 0;
    }

    logw(L"self size: %I64d bytes", li.QuadPart);

    HANDLE hm = CreateFileMappingW(hf, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hm) {
        DWORD e = GetLastError();
        CloseHandle(hf);
        SetLastError(e);
        return 0;
    }

    void* view = MapViewOfFile(hm, FILE_MAP_READ, 0, 0, 0);
    if (!view) {
        DWORD e = GetLastError();
        CloseHandle(hm);
        CloseHandle(hf);
        SetLastError(e);
        return 0;
    }

    logw(L"mapped self image ok");

    ov->base  = (const uint8_t*)view;
    ov->size  = (size_t)li.QuadPart;
    ov->hFile = hf;
    ov->hMap  = hm;

    ov->cfg_off = ov->cfg_len = ov->pay_off = ov->pay_len = 0;

    // 从文件尾部反向查找最后一段 config（避免命中 exe 内部常量字符串）
    size_t epos = rfind_bytes(ov->base, ov->size, CFG_END, strlen(CFG_END));
    if (epos == (size_t)-1) {
        logw(L"CFG_END not found (will treat as no config/payload)");
        return 1;
    }

    size_t bpos = rfind_bytes(ov->base, epos, CFG_BEGIN, strlen(CFG_BEGIN));
    if (bpos == (size_t)-1) {
        logw(L"CFG_BEGIN not found (will treat as no config/payload)");
        return 1;
    }

    size_t after_begin = bpos;
    while (after_begin < ov->size && ov->base[after_begin] != '\n') after_begin++;
    if (after_begin < ov->size && ov->base[after_begin] == '\n') after_begin++;

    if (after_begin > epos) return 1;

    ov->cfg_off = after_begin;
    ov->cfg_len = (epos > after_begin) ? (epos - after_begin) : 0;

    size_t pay = epos + strlen(CFG_END);
    while (pay < ov->size) {
        uint8_t c = ov->base[pay];
        if (c == '\r' || c == '\n' || c == ' ' || c == '\t') { pay++; continue; }
        break;
    }
    ov->pay_off = pay;
    ov->pay_len = (pay <= ov->size) ? (ov->size - pay) : 0;

    logw(L"overlay parsed: cfg_off=%Iu cfg_len=%Iu pay_off=%Iu pay_len=%Iu", (size_t)ov->cfg_off, (size_t)ov->cfg_len, (size_t)ov->pay_off, (size_t)ov->pay_len);

    return 1;
}


static void close_self_overlay(SELF_OVERLAY* ov) {
    if (ov->base) UnmapViewOfFile(ov->base);
    if (ov->hMap) CloseHandle(ov->hMap);
    if (ov->hFile && ov->hFile != INVALID_HANDLE_VALUE) CloseHandle(ov->hFile);
    ZeroMemory(ov, sizeof(*ov));
}

// -------- platform label --------
typedef LONG (WINAPI *RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);

static int get_os_version(DWORD *major, DWORD *minor, DWORD *build) {
    HMODULE h = GetModuleHandleW(L"ntdll.dll");
    if (!h) h = LoadLibraryW(L"ntdll.dll");
    if (!h) return 0;

    RtlGetVersionPtr p = (RtlGetVersionPtr)GetProcAddress(h, "RtlGetVersion");
    if (!p) return 0;

    RTL_OSVERSIONINFOW v = {0};
    v.dwOSVersionInfoSize = sizeof(v);
    if (p(&v) != 0) return 0;

    *major = v.dwMajorVersion;
    *minor = v.dwMinorVersion;
    *build = v.dwBuildNumber;
    return 1;
}

static const wchar_t* win_nameW(DWORD major, DWORD minor, DWORD build) {
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
    DWORD major=0, minor=0, build=0;
    if (!get_os_version(&major, &minor, &build)) {
        StringCchPrintfW(out, cap, L"Windows %s", arch_nameW());
        return;
    }
    StringCchPrintfW(out, cap, L"%s %s", win_nameW(major, minor, build), arch_nameW());
}

// -------- config --------
typedef struct {
    wchar_t Title[256];
    wchar_t BeginPrompt[2048];

    wchar_t Directory[MAX_PATH];          // 默认 ".\\"
    wchar_t ExecuteFile[1024];            // ✅ 这里必须存在
    wchar_t ExecuteParameters[2048];

    int Forward;
    int TimeOut;                          // 秒，<0 不删
    wchar_t Path[MAX_PATH];
    wchar_t PathName[256];

    int Cover;

    wchar_t RunProgram[MAX_RUN][MAX_LINE];
    int RunCount;

    wchar_t LnkSpec[MAX_LNK][MAX_LINE];
    int LnkCount;

    // Platform: "Windows7 32:win732"（只指向目录）
    wchar_t MapKey[MAX_MAP][128];
    wchar_t MapDir[MAX_MAP][MAX_LINE];
    int MapCount;
} CFG;

static void cfg_defaults(CFG* c) {
    ZeroMemory(c, sizeof(*c));
    c->Forward = 0;
    c->TimeOut = 0;
    c->Cover   = 0;
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
    while (n && (s[n-1] == L' ' || s[n-1] == L'\t' || s[n-1] == L'\r' || s[n-1] == L'\n')) {
        s[n-1] = 0; n--;
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
    if (n >= 2 && v[0] == L'"' && v[n-1] == L'"') {
        v[n-1] = 0;
        memmove(v, v+1, (n-1) * sizeof(wchar_t));
    }
    unescape_inplace(v);
}

static int is_invalid_name_ch(wchar_t c) {
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
    while (oi && (out[oi-1] == L'.' || out[oi-1] == L' ')) out[--oi] = 0;
    if (out[0] == 0) lstrcpynW(s, fallback, 256);
    else lstrcpynW(s, out, 256);
}

// CSV 分割：支持 "a","b"
static int csv_split_items(const wchar_t* in, wchar_t items[][MAX_LINE], int max_items) {
    int cnt = 0;
    const wchar_t* p = in;
    while (p && *p) {
        while (*p == L' ' || *p == L'\t' || *p == L'\r' || *p == L'\n' || *p == L',') p++;
        if (!*p) break;

        wchar_t buf[MAX_LINE] = {0};
        size_t bi = 0;

        if (*p == L'"') {
            p++;
            while (*p && bi + 1 < MAX_LINE) {
                if (*p == L'"') { p++; break; }
                if (*p == L'\\' && p[1]) {
                    buf[bi++] = *p++;
                    if (bi + 1 < MAX_LINE) buf[bi++] = *p++;
                    continue;
                }
                buf[bi++] = *p++;
            }
            buf[bi] = 0;
            while (*p && *p != L',') p++;
        } else {
            while (*p && *p != L',' && bi + 1 < MAX_LINE) buf[bi++] = *p++;
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

// Platform spec: "Windows7 32:win732"
static void cfg_add_map_dir(CFG* c, const wchar_t* spec) {
    if (!spec || !*spec) return;
    if (c->MapCount >= MAX_MAP) return;

    const wchar_t* colon = wcschr(spec, L':');
    if (!colon) return;

    wchar_t left[128] = {0};
    wchar_t right[MAX_LINE] = {0};

    size_t ln = (size_t)(colon - spec);
    if (ln >= _countof(left)) ln = _countof(left) - 1;
    wcsncpy_s(left, _countof(left), spec, ln);
    lstrcpynW(right, colon + 1, MAX_LINE);

    trim_w(left);
    trim_w(right);
    if (!*left || !*right) return;

    lstrcpynW(c->MapKey[c->MapCount], left, _countof(c->MapKey[c->MapCount]));
    lstrcpynW(c->MapDir[c->MapCount], right, _countof(c->MapDir[c->MapCount]));
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

        if (keyeq(key, L"RunProgram")) {
            wchar_t (*items)[MAX_LINE] = (wchar_t (*)[MAX_LINE])HeapAlloc(
                GetProcessHeap(), HEAP_ZERO_MEMORY, 64 * sizeof(*items)
            );
            if (items) {
                int n = csv_split_items(val, items, 64);
                if (n == 0) {
                    wchar_t v2[MAX_LINE];
                    lstrcpynW(v2, val, MAX_LINE);
                    unquote_and_unescape(v2);
                    cfg_add_run(c, v2);
                } else {
                    for (int i = 0; i < n; i++) {
                        cfg_add_run(c, items[i]);
                    }
                }
                HeapFree(GetProcessHeap(), 0, items);
            }else{
                wchar_t v2[MAX_LINE]; 
                lstrcpynW(v2, val, MAX_LINE);
                unquote_and_unescape(v2);
                cfg_add_run(c, v2);
            }
            continue;
        }

        if (keyeq(key, L"lnk")) {
            wchar_t (*items)[MAX_LINE] = (wchar_t (*)[MAX_LINE])HeapAlloc(
                GetProcessHeap(), HEAP_ZERO_MEMORY, 64 * sizeof(*items)
            );
            if (items) {
                int n = csv_split_items(val, items, 64);
                if (n == 0) {
                    wchar_t v2[MAX_LINE];
                    lstrcpynW(v2, val, MAX_LINE);
                    unquote_and_unescape(v2);
                    cfg_add_run(c, v2);
                } else {
                    for (int i = 0; i < n; i++) {
                        cfg_add_run(c, items[i]);
                    }
                }
                HeapFree(GetProcessHeap(), 0, items);
            }else{
                wchar_t v2[MAX_LINE]; 
                lstrcpynW(v2, val, MAX_LINE);
                unquote_and_unescape(v2);
                cfg_add_run(c, v2);
            }
            continue;
        }

        if (keyeq(key, L"Platform")) {
            wchar_t (*items)[MAX_LINE] = (wchar_t (*)[MAX_LINE])HeapAlloc(
                GetProcessHeap(), HEAP_ZERO_MEMORY, 64 * sizeof(*items)
            );
            if (items) {
                int n = csv_split_items(val, items, 64);
                if (n == 0) {
                    wchar_t v2[MAX_LINE];
                    lstrcpynW(v2, val, MAX_LINE);
                    unquote_and_unescape(v2);
                    cfg_add_run(c, v2);
                } else {
                    for (int i = 0; i < n; i++) {
                        cfg_add_run(c, items[i]);
                    }
                }
                HeapFree(GetProcessHeap(), 0, items);
            }else{
                wchar_t v2[MAX_LINE]; 
                lstrcpynW(v2, val, MAX_LINE);
                unquote_and_unescape(v2);
                cfg_add_run(c, v2);
            }
            continue;
        }

        unquote_and_unescape(val);

        if (keyeq(key, L"Title")) lstrcpynW(c->Title, val, _countof(c->Title));
        else if (keyeq(key, L"BeginPrompt")) lstrcpynW(c->BeginPrompt, val, _countof(c->BeginPrompt));
        else if (keyeq(key, L"Directory")) lstrcpynW(c->Directory, val, _countof(c->Directory));
        else if (keyeq(key, L"ExecuteFile")) lstrcpynW(c->ExecuteFile, val, _countof(c->ExecuteFile));
        else if (keyeq(key, L"ExecuteParameters")) lstrcpynW(c->ExecuteParameters, val, _countof(c->ExecuteParameters));
        else if (keyeq(key, L"Forward")) c->Forward = (int)wcstol(val, NULL, 10);
        else if (keyeq(key, L"TimeOut")) c->TimeOut = (int)wcstol(val, NULL, 10);
        else if (keyeq(key, L"Path")) lstrcpynW(c->Path, val, _countof(c->Path));
        else if (keyeq(key, L"PathName")) lstrcpynW(c->PathName, val, _countof(c->PathName));
        else if (keyeq(key, L"cover")) c->Cover = (int)wcstol(val, NULL, 10);
    }

    HeapFree(GetProcessHeap(), 0, w);
    sanitize_dirname(c->PathName, L"WrapperTemp");
}

// ---------------- 路径变量展开 ----------------
static void get_working_dir(wchar_t* out, size_t cap) {
    DWORD n = GetCurrentDirectoryW((DWORD)cap, out);
    if (!n || n >= cap) lstrcpynW(out, L".", (int)cap);
}

static void replace_token_ci(const wchar_t* in, const wchar_t* token, const wchar_t* repl, wchar_t* out, size_t cap) {
    size_t tlen = wcslen(token), rlen = wcslen(repl);
    size_t oi = 0;
    for (size_t i = 0; in[i] && oi + 1 < cap;) {
        int match = 1;
        for (size_t k = 0; k < tlen; k++) {
            wchar_t a = in[i + k], b = token[k];
            if (!a) { match = 0; break; }
            if (towupper(a) != towupper(b)) { match = 0; break; }
        }
        if (match) {
            for (size_t k = 0; k < rlen && oi + 1 < cap; k++) out[oi++] = repl[k];
            i += tlen;
        } else {
            out[oi++] = in[i++];
        }
    }
    out[oi] = 0;
}

static void expand_path_vars(const wchar_t* in, const wchar_t* located, const wchar_t* working, wchar_t* out, size_t cap) {
    wchar_t tmp1[2048], tmp2[2048];
    replace_token_ci(in, L"%located%", located, tmp1, _countof(tmp1));
    replace_token_ci(tmp1, L"%working%", working, tmp2, _countof(tmp2));
    DWORD n = ExpandEnvironmentStringsW(tmp2, out, (DWORD)cap);
    if (!n || n >= cap) lstrcpynW(out, tmp2, (int)cap);
}

// ---------------- Platform dir 匹配（忽略空白/大小写） ----------------
static void normalize_key_no_space(const wchar_t* in, wchar_t* out, size_t cap) {
    size_t oi = 0;
    for (size_t i = 0; in[i] && oi + 1 < cap; i++) {
        wchar_t c = in[i];
        if (c == L' ' || c == L'\t' || c == L'\r' || c == L'\n') continue;
        out[oi++] = towupper(c);
    }
    out[oi] = 0;
}

static const wchar_t* find_platform_dir(const CFG* cfg, const wchar_t* platform_label) {
    if (!cfg || cfg->MapCount <= 0) return NULL;
    wchar_t key1[256]; normalize_key_no_space(platform_label, key1, _countof(key1));
    for (int i = 0; i < cfg->MapCount; i++) {
        wchar_t key2[256]; normalize_key_no_space(cfg->MapKey[i], key2, _countof(key2));
        if (lstrcmpW(key1, key2) == 0) return cfg->MapDir[i];
    }
    return NULL;
}

// ---------------- lnk：桌面快捷方式（src/ico 都按 outdir 相对） ----------------
static int get_desktop_dir(wchar_t* out, size_t cap) {
    if (SHGetSpecialFolderPathW(NULL, out, CSIDL_DESKTOPDIRECTORY, FALSE)) {
        out[cap - 1] = 0;
        return 1;
    }
    return 0;
}

static void resolve_path_under(const wchar_t* root, const wchar_t* maybe_rel, wchar_t* out, size_t cap) {
    if (!maybe_rel || !*maybe_rel) { out[0] = 0; return; }
    if (!PathIsRelativeW(maybe_rel)) { lstrcpynW(out, maybe_rel, (int)cap); return; }
    swprintf_s(out, cap, L"%s\\%s", root, maybe_rel);
}

static int create_shortcut_desktop(const wchar_t* outdir, const wchar_t* src, const wchar_t* desc,
                                   const wchar_t* linkname, const wchar_t* iconfile) {
    wchar_t desktop[MAX_PATH];
    if (!get_desktop_dir(desktop, _countof(desktop))) return 0;

    wchar_t target[MAX_PATH], icon[MAX_PATH];
    resolve_path_under(outdir, src, target, _countof(target));
    resolve_path_under(outdir, iconfile, icon, _countof(icon));

    wchar_t namebuf[MAX_PATH];
    lstrcpynW(namebuf, (linkname && *linkname) ? linkname : L"Shortcut", _countof(namebuf));
    size_t n = wcslen(namebuf);
    if (n < 4 || lstrcmpiW(namebuf + n - 4, L".lnk") != 0) {
        if (n + 4 < _countof(namebuf)) wcscat_s(namebuf, _countof(namebuf), L".lnk");
    }

    wchar_t lnkfile[MAX_PATH];
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

static void parse_lnk_spec_4(const wchar_t* spec, wchar_t* f1, wchar_t* f2, wchar_t* f3, wchar_t* f4) {
    f1[0] = f2[0] = f3[0] = f4[0] = 0;
    if (!spec) return;

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

// ---------------- LZMA SDK：内存 ILookInStream（直接从 EXE 尾部 payload 解压） ----------------
typedef struct {
    ILookInStream vt;
    const Byte* data;
    size_t size;
    size_t pos;
} CMemLookInStream;

static SRes MemLook(const ILookInStream *pp, const void **buf, size_t *size) {
    CMemLookInStream* p = (CMemLookInStream*)pp;
    size_t rem = (p->pos < p->size) ? (p->size - p->pos) : 0;
    size_t req = *size;
    if (req > rem) req = rem;
    *buf = (const void*)(p->data + p->pos);
    *size = req;
    return SZ_OK;
}

static SRes MemSkip(const ILookInStream *pp, size_t offset) {
    CMemLookInStream* p = (CMemLookInStream*)pp;
    if (offset > p->size - p->pos) p->pos = p->size;
    else p->pos += offset;
    return SZ_OK;
}

static SRes MemRead(const ILookInStream *pp, void *buf, size_t *size) {
    CMemLookInStream* p = (CMemLookInStream*)pp;
    size_t rem = (p->pos < p->size) ? (p->size - p->pos) : 0;
    size_t req = *size;
    if (req > rem) req = rem;
    if (req) memcpy(buf, p->data + p->pos, req);
    p->pos += req;
    *size = req;
    return SZ_OK;
}

static SRes MemSeek(const ILookInStream *pp, Int64 *pos, ESzSeek origin) {
    CMemLookInStream* p = (CMemLookInStream*)pp;
    Int64 base = 0;
    if (origin == SZ_SEEK_SET) base = 0;
    else if (origin == SZ_SEEK_CUR) base = (Int64)p->pos;
    else if (origin == SZ_SEEK_END) base = (Int64)p->size;
    else return SZ_ERROR_PARAM;

    Int64 np = base + *pos;
    if (np < 0) return SZ_ERROR_PARAM;
    if ((UInt64)np > (UInt64)p->size) return SZ_ERROR_PARAM;

    p->pos = (size_t)np;
    *pos = np;
    return SZ_OK;
}

static void MemStream_Init(CMemLookInStream* s, const Byte* data, size_t size) {
    s->vt.Look = MemLook;
    s->vt.Skip = MemSkip;
    s->vt.Read = MemRead;
    s->vt.Seek = MemSeek;
    s->data = data;
    s->size = size;
    s->pos = 0;
}

static void normalize_slashes(wchar_t* s) {
    for (; *s; s++) if (*s == L'/') *s = L'\\';
}

static int is_bad_extract_path(const wchar_t* rel) {
    if (!rel || !*rel) return 1;
    if (wcsstr(rel, L":")) return 1;          // 禁止盘符
    if (rel[0] == L'\\' || rel[0] == L'/') return 1; // 禁止绝对
    if (wcsstr(rel, L"..\\")) return 1;
    if (wcsstr(rel, L"../")) return 1;
    if (wcscmp(rel, L"..") == 0) return 1;
    return 0;
}

static void ensure_parent_dir(const wchar_t* filepath) {
    wchar_t tmp[MAX_PATH];
    lstrcpynW(tmp, filepath, MAX_PATH);
    PathRemoveFileSpecW(tmp);
    if (tmp[0]) mk_dir_tree(tmp);
}

// cover: 0=覆盖；非0=跳过
static int extract_7z_from_memory(const Byte* pay, size_t pay_len, const wchar_t* outdir, int cover) {
    logw(L"extract_7z_from_memory: pay_len=%Iu outdir=%s cover=%d", (size_t)pay_len, outdir ? outdir : L"(null)", cover);
    // 7z header CRC 表
    CrcGenerateTable();

    ISzAlloc allocImp     = { SzAlloc, SzFree };
    ISzAlloc allocTempImp = { SzAllocTemp, SzFreeTemp };

    CMemLookInStream mem;
    MemStream_Init(&mem, pay, pay_len);

    CSzArEx db;
    SzArEx_Init(&db);

    SRes res = SzArEx_Open(&db, &mem.vt, &allocImp, &allocTempImp);
    if (res != SZ_OK) {
        logw(L"SzArEx_Open failed: res=%d", (int)res);
        SzArEx_Free(&db, &allocImp);
        return 0;
    }

    logw(L"7z opened: NumFiles=%u", (unsigned)db.NumFiles);

    UInt32 blockIndex = 0xFFFFFFFF;
    Byte* outBuffer = NULL;
    size_t outBufferSize = 0;

    for (UInt32 i = 0; i < db.NumFiles; i++) {
        // 文件名 UTF-16
        size_t nameLen = SzArEx_GetFileNameUtf16(&db, i, NULL);
        if (nameLen == 0) continue;

        wchar_t* name = (wchar_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (nameLen + 1) * sizeof(wchar_t));
        if (!name) { res = SZ_ERROR_MEM; break; }

        SzArEx_GetFileNameUtf16(&db, i, (UInt16*)name);
        name[nameLen] = 0;

        // best-effort per-file trace (helpful for pinpointing crashes)
        if (i < 32 || (i % 50) == 0) {
            logw(L"extract item[%u]: %s (isDir=%d)", (unsigned)i, name, (int)db.IsDirs[i]);
        }

        normalize_slashes(name);
        if (is_bad_extract_path(name)) { HeapFree(GetProcessHeap(), 0, name); continue; }

        wchar_t full[MAX_PATH];
        swprintf_s(full, MAX_PATH, L"%s\\%s", outdir, name);

        if (SzArEx_IsDir(&db, i)) {
            mk_dir_tree(full);
            HeapFree(GetProcessHeap(), 0, name);
            continue;
        }

        // cover!=0 且目标已存在 => 跳过（不解码该文件）
        if (cover != 0 && fexist(full)) {
            if (i < 32 || (i % 50) == 0) logw(L"extract skip (exists & cover!=0): %s", full);
            HeapFree(GetProcessHeap(), 0, name);
            continue;
        }

        ensure_parent_dir(full);

        size_t offset = 0, outSizeProcessed = 0;
        res = SzArEx_Extract(&db, &mem.vt, i,
                            &blockIndex, &outBuffer, &outBufferSize,
                            &offset, &outSizeProcessed,
                            &allocImp, &allocTempImp);
        if (res != SZ_OK) {
            logw(L"SzArEx_Extract failed: i=%u res=%d", (unsigned)i, (int)res);
            HeapFree(GetProcessHeap(), 0, name);
            break;
        }

        HANDLE h = CreateFileW(full, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h == INVALID_HANDLE_VALUE) {
            log_winerr(L"CreateFileW(extracted file)");
            logw(L"CreateFileW failed for: %s", full);
            HeapFree(GetProcessHeap(), 0, name);
            res = SZ_ERROR_FAIL;
            break;
        }

        DWORD wr = 0;
        if (outSizeProcessed > 0) {
            if (!WriteFile(h, outBuffer + offset, (DWORD)outSizeProcessed, &wr, NULL) || wr != (DWORD)outSizeProcessed) {
                log_winerr(L"WriteFile(extracted file)");
                logw(L"WriteFile failed for: %s", full);
                CloseHandle(h);
                HeapFree(GetProcessHeap(), 0, name);
                res = SZ_ERROR_FAIL;
                break;
            }
        }
        CloseHandle(h);
        HeapFree(GetProcessHeap(), 0, name);
    }

    if (outBuffer) allocImp.Free(&allocImp, outBuffer);
    SzArEx_Free(&db, &allocImp);

    return (res == SZ_OK);
}

// ---------------- 主逻辑 ----------------
static int real_main(int argc, wchar_t** argv) {
    logw(L"==== wrapper start ====");
    logw(L"cmdline: %s", GetCommandLineW());
    logw(L"argc=%d", argc);
    for (int i = 0; i < argc && i < 32; i++) {
        logw(L"argv[%d]=%s", i, argv[i] ? argv[i] : L"(null)");
    }

    hide_own_console_if_any();

    if (argc >= 2 && lstrcmpW(argv[1], L"--cleanup") == 0) {
        logw(L"mode: cleanup");
        int rc = cleanup_main(argc, argv);
        logw(L"cleanup done rc=%d", rc);
        return rc;
    }

    wchar_t exedir[MAX_PATH];
    exe_dir(exedir, MAX_PATH);

    wchar_t selfpath[MAX_PATH];
    exe_path(selfpath, MAX_PATH);

    SELF_OVERLAY ov;
    if (!open_self_overlay(selfpath, &ov)) die(L"open self fail");

    static CFG cfg;                // 放到全局/静态区，不占用栈
    ZeroMemory(&cfg, sizeof(cfg)); // 每次启动清空一次
    cfg_defaults(&cfg);
    if (ov.cfg_len > 0) cfg_parse_utf8_block(&cfg, ov.base + ov.cfg_off, ov.cfg_len);

    logw(L"overlay info: cfg_len=%Iu pay_len=%Iu", (size_t)ov.cfg_len, (size_t)ov.pay_len);
    logw(L"cfg: Title=\"%s\"", cfg.Title[0] ? cfg.Title : L"(empty)");
    logw(L"cfg: Path=\"%s\" PathName=\"%s\"", cfg.Path, cfg.PathName);
    logw(L"cfg: Directory=\"%s\"", cfg.Directory);
    logw(L"cfg: ExecuteFile=\"%s\" ExecuteParameters=\"%s\"", cfg.ExecuteFile, cfg.ExecuteParameters);
    logw(L"cfg: Forward=%d TimeOut=%d Cover=%d RunCount=%d LnkCount=%d MapCount=%d",
         cfg.Forward, cfg.TimeOut, cfg.Cover, cfg.RunCount, cfg.LnkCount, cfg.MapCount);
    for (int i = 0; i < cfg.RunCount && i < 16; i++) logw(L"cfg.RunProgram[%d]=%s", i, cfg.RunProgram[i]);
    for (int i = 0; i < cfg.LnkCount && i < 16; i++) logw(L"cfg.LnkSpec[%d]=%s", i, cfg.LnkSpec[i]);
    for (int i = 0; i < cfg.MapCount && i < 16; i++) logw(L"cfg.PlatformMap[%d]: %s => %s", i, cfg.MapKey[i], cfg.MapDir[i]);

    if (ov.pay_len == 0) {
        close_self_overlay(&ov);
        die(L"no payload (missing markers or payload not appended)");
    }

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

    logw(L"path vars: located=%s", located);
    logw(L"path vars: working=%s", working);
    logw(L"path vars: basepath(expanded)=%s", basepath);

    size_t bl = wcslen(basepath);
    while (bl && (basepath[bl-1] == L'\\' || basepath[bl-1] == L'/')) { basepath[bl-1] = 0; bl--; }

    wchar_t outdir[MAX_PATH];
    swprintf_s(outdir, MAX_PATH, L"%s\\%s", basepath, cfg.PathName);

    logw(L"outdir=%s", outdir);

    mk_dir_tree(outdir);
    mk_mark(outdir);

    // payload id（来自内存）
    const Byte* pay = (const Byte*)(ov.base + ov.pay_off);
    size_t pay_len = ov.pay_len;
    uint32_t cur_sz  = (uint32_t)((pay_len > 0xFFFFFFFFu) ? 0xFFFFFFFFu : pay_len);
    uint32_t cur_crc = crc32_calc(pay, pay_len);
    logw(L"payload id: len=%Iu cur_sz=%u cur_crc=%08X", (size_t)pay_len, (unsigned)cur_sz, (unsigned)cur_crc);

    // 是否可跳过解压（payload 未变且已解压完成）
    int can_skip_extract = 0;
    if (dexist(outdir) && has_mark(outdir) && has_exok(outdir)) {
        uint32_t old_crc=0, old_sz=0;
        if (read_payload_idfile(outdir, &old_crc, &old_sz) && old_crc == cur_crc && old_sz == cur_sz) {
            can_skip_extract = 1;
        }
    }

    logw(L"can_skip_extract=%d (Cover=%d)", can_skip_extract, cfg.Cover);

    // cover: 0 覆盖；非0 跳过
    if (!can_skip_extract) {
        logw(L"extract start: outdir=%s", outdir);
        if (!extract_7z_from_memory(pay, pay_len, outdir, cfg.Cover)) {
            rm_dir_best_effort(outdir);
            close_self_overlay(&ov);
            die(L"extract fail");
        }
        logw(L"extract ok");
        write_exok(outdir);
        write_payload_idfile(outdir, cur_crc, cur_sz);
    } else {
        logw(L"extract skipped (already extracted and payload id matches)");
    }

    close_self_overlay(&ov);

    // 先创建快捷方式
    for (int i = 0; i < cfg.LnkCount; i++) {
        wchar_t f1[MAX_PATH], f2[512], f3[MAX_PATH], f4[MAX_PATH];
        parse_lnk_spec_4(cfg.LnkSpec[i], f1, f2, f3, f4);
        if (f1[0] && f3[0]) {
            create_shortcut_desktop(outdir, f1, f2, f3, f4[0] ? f4 : f1);
        }
    }

    // Platform => 选择运行根目录（只指向目录，不指向具体 exe）
    wchar_t platform[128];
    get_platform_label(platform, _countof(platform));
    const wchar_t* mappedDir = find_platform_dir(&cfg, platform);
    logw(L"platform_label=%s", platform);
    logw(L"mappedDir=%s", (mappedDir && *mappedDir) ? mappedDir : L"(null)");

    wchar_t runroot[MAX_PATH];
    lstrcpynW(runroot, outdir, MAX_PATH);
    if (mappedDir && *mappedDir) {
        wchar_t tmp[MAX_PATH];
        swprintf_s(tmp, MAX_PATH, L"%s\\%s", outdir, mappedDir);
        if (dexist(tmp)) lstrcpynW(runroot, tmp, MAX_PATH);
        // 如果目录不存在：自动回退 outdir
    }

    logw(L"runroot=%s", runroot);

    // 执行逻辑：ExecuteFile 优先，否则 RunProgram
    const wchar_t* raw  = GetCommandLineW();
    const wchar_t* tail = tail1(raw);

    logw(L"cmdline tail(forward)='%s'", tail ? tail : L"(null)");
    logw(L"forward tail='%s'", (tail && *tail) ? tail : L"(empty)");

    DWORD lastCode = 0;

    if (cfg.ExecuteFile[0]) {
        // ExecuteFile：如果是相对路径，按 runroot 解析
        wchar_t exefile[MAX_PATH];
        resolve_path_under(runroot, cfg.ExecuteFile, exefile, _countof(exefile));
        logw(L"resolved ExecuteFile=%s", exefile);
        // ShellExecute 更适合打开文档/msiexec；这里为了保持静默一致，用 CreateProcess 跑
        wchar_t cmdline[MAX_LINE];
        if (cfg.ExecuteParameters[0]) swprintf_s(cmdline, MAX_LINE, L"\"%s\" %s", exefile, cfg.ExecuteParameters);
        else swprintf_s(cmdline, MAX_LINE, L"\"%s\"", exefile);

        wchar_t* cl = _wcsdup(cmdline);
        if (!cl) die(L"oom");
        logw(L"ExecuteFile cmdline=%s", cl);
        lastCode = run_wait_ex(NULL, cl, runroot, 1);
        free(cl);
        if (lastCode == (DWORD)-1) lastCode = 1;
    } else {
        if (cfg.RunCount == 0) {
            cfg_add_run(&cfg, L"setup.exe");
            logw(L"RunCount==0, default to setup.exe");
        }

        // 运行目录：runroot + Directory
        wchar_t run_wdir[MAX_PATH];
        wchar_t dir_exp[MAX_PATH];
        expand_path_vars(cfg.Directory, runroot, working, dir_exp, MAX_PATH);
        trim_w(dir_exp);

        if (dir_exp[0] == 0 || lstrcmpiW(dir_exp, L".") == 0 || lstrcmpiW(dir_exp, L".\\") == 0 || lstrcmpiW(dir_exp, L"./") == 0) {
            lstrcpynW(run_wdir, runroot, MAX_PATH);
        } else {
            if (PathIsRelativeW(dir_exp)) swprintf_s(run_wdir, MAX_PATH, L"%s\\%s", runroot, dir_exp);
            else lstrcpynW(run_wdir, dir_exp, MAX_PATH);
        }
        mk_dir_tree(run_wdir);
        logw(L"run_wdir=%s", run_wdir);

        for (int i = 0; i < cfg.RunCount; i++) {
            wchar_t final[MAX_LINE];
            lstrcpynW(final, cfg.RunProgram[i], MAX_LINE);

            logw(L"RunProgram[%d] raw=%s", i, final);

            if (cfg.Forward >= 0 && cfg.Forward == i && tail && *tail) {
                wchar_t tmp[MAX_LINE];
                swprintf_s(tmp, MAX_LINE, L"%s %s", final, tail);
                lstrcpynW(final, tmp, MAX_LINE);
                logw(L"RunProgram[%d] forward args => %s", i, final);
            }

            logw(L"RunProgram[%d] final cmd=%s", i, final);

            /* 如果 RunProgram 是单纯文件名/相对路径（不带参数），先解析到 run_wdir 下的绝对路径 */
            if (!wcschr(final, L' ') && !wcschr(final, L'\t')) {
                wchar_t exepath[MAX_PATH];
                resolve_path_under(run_wdir, final, exepath, _countof(exepath));
                if (!fexist(exepath)) {
                    logw(L"FATAL: RunProgram[%d] not found: %s", i, exepath);
                }else{
                    swprintf_s(final, MAX_LINE, L"\"%s\"", exepath);
                }
            }
            wchar_t* cmdline = _wcsdup(final);
            if (!cmdline) { lastCode = 2; continue; }

            logw(L"RunProgram[%d] cmdline=%s", i, cmdline);

            wchar_t exepath[MAX_PATH];
            resolve_path_under(run_wdir, cfg.RunProgram[i], exepath, _countof(exepath)); // 你已有/自己实现：run_wdir + 文件名 => 绝对路径

            wchar_t full[MAX_LINE];
            if (cfg.Forward >= 0 && cfg.Forward == i && tail && *tail)
                swprintf_s(full, MAX_LINE, L"\"%s\" %s", exepath, tail);
            else
                swprintf_s(full, MAX_LINE, L"\"%s\"", exepath);

            free(cmdline);
            cmdline = _wcsdup(full);

            DWORD rc = run_wait_ex(exepath, cmdline, run_wdir, silent);
            free(cmdline);

            if (rc == (DWORD)-1) rc = 1;
            lastCode = rc;
        }
    }

    // TimeOut：<0 不删；>=0 延迟删除解压目录（永远不删包装 EXE）
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

static int entry_main(int argc, wchar_t** argv) {
    // ensure log is ready as early as possible
    log_open();
    install_crash_handlers();
    if (gLogPath[0]) logw(L"Log file: %s", gLogPath);
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);

    int rc = 0;
    __try {
        rc = real_main(argc, argv);
    } __except (wrapper_unhandled_filter(GetExceptionInformation())) {
        rc = 2;
    }

    logw(L"==== wrapper exit rc=%d ====", rc);
    log_close();
    return rc;
}

int wmain(int argc, wchar_t** argv) {
    return entry_main(argc, argv);
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrev, PWSTR lpCmdLine, int nShowCmd) {
    (void)hInst; (void)hPrev; (void)lpCmdLine; (void)nShowCmd;
    int argc = 0;
    wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    int rc = entry_main(argc, argv);
    if (argv) LocalFree(argv);
    return rc;
}
