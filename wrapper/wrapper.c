#define _CRT_SECURE_NO_WARNINGS
#define UNICODE
#define _UNICODE

#include <windows.h>
#include <shellapi.h>
#include <shlwapi.h>
#include <shlobj.h>
#include <objbase.h>
#include <shobjidl.h>
#include <stdio.h>
#include <wchar.h>
#include <stdint.h>
#include <stdlib.h>
#include <wctype.h>

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Ole32.lib")

// ---------------- LZMA SDK headers (来自 LZMA SDK 的 C\ 目录) ----------------
#include "7z/7z.h"
#include "7z/7zCrc.h"
#include "7z/7zTypes.h"
#include "7z/Alloc.h"
#include "7z/CpuArch.h"



// ---------------- wrapper files ----------------
#define MKRFILE    L".pa_wrapper_marker"
#define IDFILE     L".pa_payload_id"
#define EXOKFILE   L".pa_extracted_ok"
#define CLEANFILE  L".pa_cleanup_token"

#define MAX_RUN    64
#define MAX_LNK    32
#define MAX_LINE   4096

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

// 删除：失败就算了（不报错、不阻塞）
static void rm_dir_best_effort(const wchar_t* dir) {
    if (!has_mark(dir)) return;

    wchar_t from[MAX_PATH + 2];
    lstrcpynW(from, dir, MAX_PATH + 1);
    int n = lstrlenW(from);
    from[n + 1] = L'\0'; // 双 0 结尾

    SHFILEOPSTRUCTW op = {0};
    op.wFunc  = FO_DELETE;
    op.pFrom  = from;
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

// 只隐藏“自己创建出来的控制台窗口”，避免从 cmd 里启动时把用户的 cmd 隐藏掉
static void hide_own_console_if_any(void) {
    HWND h = GetConsoleWindow();
    if (!h) return;

    DWORD pids[2] = {0};
    DWORD n = GetConsoleProcessList(pids, 2);
    if (n == 1) ShowWindow(h, SW_HIDE);
}

// ---------------- CRC32（用于 payload id 缓存判断）----------------
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

// ---------------- 运行进程：不弹控制台 + 静默（stdout/stderr -> NUL） ----------------
static DWORD run_wait_ex(const wchar_t* app, wchar_t* cmd, const wchar_t* wdir, int silent) {
    STARTUPINFOW si = {0};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {0};

    HANDLE hNullIn = NULL, hNullOut = NULL, hNullErr = NULL;
    SECURITY_ATTRIBUTES sa = {0};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    DWORD flags = CREATE_NO_WINDOW;
    BOOL inherit = FALSE;

    if (silent) {
        hNullIn  = CreateFileW(L"NUL", GENERIC_READ,  FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        hNullOut = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        hNullErr = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

        if (hNullIn  && hNullIn  != INVALID_HANDLE_VALUE &&
            hNullOut && hNullOut != INVALID_HANDLE_VALUE &&
            hNullErr && hNullErr != INVALID_HANDLE_VALUE) {
            si.dwFlags |= STARTF_USESTDHANDLES;
            si.hStdInput  = hNullIn;
            si.hStdOutput = hNullOut;
            si.hStdError  = hNullErr;
            inherit = TRUE;
        } else {
            inherit = FALSE;
        }
    }

    if (!CreateProcessW(app, cmd, NULL, NULL, inherit, flags, NULL, wdir, &si, &pi)) {
        if (hNullIn  && hNullIn  != INVALID_HANDLE_VALUE) CloseHandle(hNullIn);
        if (hNullOut && hNullOut != INVALID_HANDLE_VALUE) CloseHandle(hNullOut);
        if (hNullErr && hNullErr != INVALID_HANDLE_VALUE) CloseHandle(hNullErr);
        return (DWORD)-1;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    if (hNullIn  && hNullIn  != INVALID_HANDLE_VALUE) CloseHandle(hNullIn);
    if (hNullOut && hNullOut != INVALID_HANDLE_VALUE) CloseHandle(hNullOut);
    if (hNullErr && hNullErr != INVALID_HANDLE_VALUE) CloseHandle(hNullErr);

    return code;
}

static DWORD run_shell_wait(const wchar_t* file, const wchar_t* params, const wchar_t* wdir) {
    SHELLEXECUTEINFOW sei = {0};
    sei.cbSize = sizeof(sei);
    sei.fMask  = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = L"open";
    sei.lpFile = file;
    sei.lpParameters = (params && *params) ? params : NULL;
    sei.lpDirectory  = (wdir && *wdir) ? wdir : NULL;
    sei.nShow = SW_SHOWNORMAL;

    if (!ShellExecuteExW(&sei)) {
        return (DWORD)-1;
    }
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
    } else {
        while (*cmd && *cmd != L' ' && *cmd != L'\t') cmd++;
    }
    return sk_ws(cmd);
}

// ---------------- cleanup token ----------------
static void write_cleanup_token(const wchar_t* dir, const wchar_t* token) {
    wchar_t p[MAX_PATH];
    path_join(p, MAX_PATH, dir, CLEANFILE);

    char buf[64] = {0};
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

    STARTUPINFOW si = {0};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {0};

    DWORD flags = CREATE_NO_WINDOW | DETACHED_PROCESS;

    wchar_t* cmdline = _wcsdup(cmd);
    if (!cmdline) return;

    if (CreateProcessW(exepath, cmdline, NULL, NULL, FALSE, flags, NULL, exedir, &si, &pi)) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    free(cmdline);
}

static void fullpath_norm(const wchar_t* in, wchar_t* out, size_t cap) {
    DWORD n = GetFullPathNameW(in, (DWORD)cap, out, NULL);
    if (!n || n >= cap) {
        lstrcpynW(out, in, (int)cap);
        out[cap - 1] = 0;
    }
    size_t L = wcslen(out);
    while (L > 3 && (out[L - 1] == L'\\' || out[L - 1] == L'/')) {
        out[L - 1] = 0; L--;
    }
}

static int path_is_prefix_dir_of_file(const wchar_t* dir, const wchar_t* file) {
    wchar_t d[MAX_PATH], f[MAX_PATH];
    fullpath_norm(dir, d, MAX_PATH);
    fullpath_norm(file, f, MAX_PATH);

    size_t dl = wcslen(d);
    if (dl == 0) return 0;

    wchar_t d2[MAX_PATH];
    lstrcpynW(d2, d, MAX_PATH);
    if (d2[dl - 1] != L'\\') {
        if (dl + 1 < MAX_PATH) {
            d2[dl] = L'\\';
            d2[dl + 1] = 0;
            dl++;
        }
    }

    for (size_t i = 0; i < dl; i++) {
        if (!f[i]) return 0;
        if (towupper(f[i]) != towupper(d2[i])) return 0;
    }
    return 1;
}

static int cleanup_main(int argc, wchar_t** argv) {
    if (argc < 5) return 0;

    const wchar_t* dir   = argv[2];
    const wchar_t* token = argv[3];
    DWORD delay = (DWORD)wcstoul(argv[4], NULL, 10);

    Sleep(delay);

    // 永远不删包装 EXE（如果包装 EXE 在 dir 里，直接不删）
    wchar_t selfpath[MAX_PATH];
    exe_path(selfpath, MAX_PATH);
    if (path_is_prefix_dir_of_file(dir, selfpath)) return 0;

    wchar_t cur[64];
    if (!read_cleanup_token(dir, cur, 64)) return 0;
    if (lstrcmpW(cur, token) != 0) return 0;

    rm_dir_best_effort(dir);
    return 0;
}

// ---------------- overlay 查找 config/payload ----------------
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
    const char* END   = ";!@InstallEnd@!";

    size_t bpos = find_bytes(ov->base, ov->size, BEGIN, strlen(BEGIN));
    if (bpos == (size_t)-1) return 1;

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

// ---------------- config 解析（保留你上一版：RunProgram 引号列表/lnk/cover/timeout 等） ----------------
typedef struct {
    wchar_t src[1024];
    wchar_t desc[512];
    wchar_t name[512];
    wchar_t icon[1024];
} LNK_SPEC;

typedef struct {
    wchar_t Title[256];
    wchar_t BeginPrompt[2048];

    wchar_t Directory[MAX_PATH];
    wchar_t ExecuteFile[1024];
    wchar_t ExecuteParameters[2048];

    int Forward;      // 默认 0
    int TimeOut;      // <0 不删；>=0 N 秒后删
    int Cover;        // 0 覆盖；非0 跳过
    wchar_t Path[MAX_PATH];
    wchar_t PathName[256]; // 默认 WrapperTemp（会 sanitize）

    wchar_t RunProgram[MAX_RUN][MAX_LINE];
    int RunCount;

    LNK_SPEC Lnk[MAX_LNK];
    int LnkCount;
} CFG;

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

static int keyeq(const wchar_t* a, const wchar_t* b) { return lstrcmpiW(a, b) == 0; }

static void unquote_unescape_basic(wchar_t* v) {
    trim_w(v);
    size_t n = wcslen(v);
    if (n >= 2 && v[0] == L'"' && v[n-1] == L'"') {
        v[n-1] = 0;
        memmove(v, v+1, (n-1) * sizeof(wchar_t));
    }
    wchar_t out[MAX_LINE];
    size_t oi = 0;
    for (size_t i = 0; v[i] && oi + 1 < MAX_LINE; i++) {
        if (v[i] == L'\\' && v[i+1]) {
            wchar_t n2 = v[i+1];
            if (n2 == L'"' || n2 == L'\\') { out[oi++] = n2; i++; continue; }
        }
        out[oi++] = v[i];
    }
    out[oi] = 0;
    lstrcpynW(v, out, MAX_LINE);
}

static void unescape_with_newlines(wchar_t* v) {
    trim_w(v);
    size_t n = wcslen(v);
    if (n >= 2 && v[0] == L'"' && v[n-1] == L'"') {
        v[n-1] = 0;
        memmove(v, v+1, (n-1) * sizeof(wchar_t));
    }
    wchar_t out[2048];
    size_t oi = 0;
    for (size_t i = 0; v[i] && oi + 1 < _countof(out); i++) {
        if (v[i] == L'\\' && v[i+1]) {
            wchar_t n2 = v[i+1];
            if (n2 == L'"' || n2 == L'\\') { out[oi++] = n2; i++; continue; }
            if (n2 == L'n') { out[oi++] = L'\n'; i++; continue; }
            if (n2 == L'r') { out[oi++] = L'\r'; i++; continue; }
            if (n2 == L't') { out[oi++] = L'\t'; i++; continue; }
        }
        out[oi++] = v[i];
    }
    out[oi] = 0;
    lstrcpynW(v, out, (int)_countof(out));
}

static int parse_quoted_list(const wchar_t* s, wchar_t items[][MAX_LINE], int max_items) {
    int count = 0;
    const wchar_t* p = s;
    while (*p && count < max_items) {
        while (*p == L' ' || *p == L'\t' || *p == L',') p++;
        if (!*p) break;

        wchar_t buf[MAX_LINE] = {0};
        size_t bi = 0;

        if (*p == L'"') {
            p++;
            while (*p && bi + 1 < MAX_LINE) {
                if (*p == L'\\' && p[1]) {
                    wchar_t n = p[1];
                    if (n == L'"' || n == L'\\') { buf[bi++] = n; p += 2; continue; }
                    if (n == L'n') { buf[bi++] = L'\n'; p += 2; continue; }
                    if (n == L'r') { buf[bi++] = L'\r'; p += 2; continue; }
                    if (n == L't') { buf[bi++] = L'\t'; p += 2; continue; }
                }
                if (*p == L'"') { p++; break; }
                buf[bi++] = *p++;
            }
            buf[bi] = 0;
            while (*p && *p != L',') {
                if (*p == L' ' || *p == L'\t') { p++; continue; }
                p++;
            }
            if (*p == L',') p++;
        } else {
            while (*p && *p != L',' && bi + 1 < MAX_LINE) buf[bi++] = *p++;
            if (*p == L',') p++;
            buf[bi] = 0;
        }

        trim_w(buf);
        if (buf[0]) {
            lstrcpynW(items[count], buf, MAX_LINE);
            count++;
        }
    }
    return count;
}

static void sanitize_name_inplace(wchar_t* s) {
    if (!s) return;

    wchar_t out[256];
    size_t oi = 0;
    for (size_t i = 0; s[i] && oi + 1 < _countof(out); i++) {
        wchar_t c = s[i];
        if (c < 32) continue;
        if (c == L'*' || c == L':' || c == L'/' || c == L'\\' || c == L'?' ||
            c == L'"' || c == L'<' || c == L'>' || c == L'|') {
            continue;
        }
        out[oi++] = c;
    }
    out[oi] = 0;
    while (oi && (out[oi-1] == L' ' || out[oi-1] == L'.')) { out[oi-1] = 0; oi--; }

    if (out[0] == 0) lstrcpyW(s, L"WrapperTemp");
    else lstrcpynW(s, out, 256);
}

static void cfg_defaults(CFG* c) {
    ZeroMemory(c, sizeof(*c));
    c->Forward = 0;
    c->TimeOut = 0;
    c->Cover   = 0;
    lstrcpyW(c->Directory, L".\\");
    lstrcpyW(c->Path, L"%temp%");
    lstrcpyW(c->PathName, L"WrapperTemp");
}

static void cfg_add_run(CFG* c, const wchar_t* cmd) {
    if (!cmd || !*cmd) return;
    if (c->RunCount >= MAX_RUN) return;
    lstrcpynW(c->RunProgram[c->RunCount], cmd, MAX_LINE);
    c->RunCount++;
}

static int split_4_fields(const wchar_t* s, wchar_t* f0, size_t c0, wchar_t* f1, size_t c1, wchar_t* f2, size_t c2, wchar_t* f3, size_t c3) {
    const wchar_t* p = s;
    wchar_t* outs[4] = { f0, f1, f2, f3 };
    size_t caps[4] = { c0, c1, c2, c3 };

    for (int i = 0; i < 4; i++) {
        outs[i][0] = 0;
        wchar_t buf[1024] = {0};
        size_t bi = 0;
        while (*p && *p != L',' && bi + 1 < _countof(buf)) buf[bi++] = *p++;
        buf[bi] = 0;
        if (*p == L',') p++;
        trim_w(buf);
        lstrcpynW(outs[i], buf, (int)caps[i]);
    }
    return 1;
}

static void cfg_add_lnk(CFG* c, const wchar_t* spec) {
    if (!spec || !*spec) return;
    if (c->LnkCount >= MAX_LNK) return;

    LNK_SPEC* x = &c->Lnk[c->LnkCount];
    ZeroMemory(x, sizeof(*x));

    wchar_t f0[1024], f1[512], f2[512], f3[1024];
    if (!split_4_fields(spec, f0, _countof(f0), f1, _countof(f1), f2, _countof(f2), f3, _countof(f3))) return;
    if (!f0[0] || !f2[0]) return;

    lstrcpynW(x->src,  f0, _countof(x->src));
    lstrcpynW(x->desc, f1, _countof(x->desc));
    lstrcpynW(x->name, f2, _countof(x->name));
    lstrcpynW(x->icon, f3, _countof(x->icon));
    c->LnkCount++;
}

static void get_working_dir(wchar_t* out, size_t cap) {
    DWORD n = GetCurrentDirectoryW((DWORD)cap, out);
    if (!n || n >= cap) lstrcpynW(out, L".", (int)cap);
}

static void replace_token_ci(const wchar_t* in, const wchar_t* token, const wchar_t* repl, wchar_t* out, size_t cap) {
    size_t tlen = wcslen(token);
    size_t rlen = wcslen(repl);
    size_t oi = 0;

    for (size_t i = 0; in[i] && oi + 1 < cap; ) {
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
        } else {
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
            wchar_t items[MAX_RUN][MAX_LINE];
            int n = parse_quoted_list(val, items, MAX_RUN);
            for (int i = 0; i < n; i++) cfg_add_run(c, items[i]);
        } else if (keyeq(key, L"lnk")) {
            wchar_t items[MAX_LNK][MAX_LINE];
            int n = parse_quoted_list(val, items, MAX_LNK);
            for (int i = 0; i < n; i++) cfg_add_lnk(c, items[i]);
        } else if (keyeq(key, L"Title")) {
            unquote_unescape_basic(val);
            lstrcpynW(c->Title, val, _countof(c->Title));
        } else if (keyeq(key, L"BeginPrompt")) {
            unescape_with_newlines(val);
            lstrcpynW(c->BeginPrompt, val, _countof(c->BeginPrompt));
        } else if (keyeq(key, L"Directory")) {
            unquote_unescape_basic(val);
            lstrcpynW(c->Directory, val, _countof(c->Directory));
        } else if (keyeq(key, L"ExecuteFile")) {
            unquote_unescape_basic(val);
            lstrcpynW(c->ExecuteFile, val, _countof(c->ExecuteFile));
        } else if (keyeq(key, L"ExecuteParameters")) {
            unquote_unescape_basic(val);
            lstrcpynW(c->ExecuteParameters, val, _countof(c->ExecuteParameters));
        } else if (keyeq(key, L"Forward")) {
            unquote_unescape_basic(val);
            c->Forward = (int)wcstol(val, NULL, 10);
        } else if (keyeq(key, L"TimeOut")) {
            unquote_unescape_basic(val);
            c->TimeOut = (int)wcstol(val, NULL, 10);
        } else if (keyeq(key, L"cover")) {
            unquote_unescape_basic(val);
            c->Cover = (int)wcstol(val, NULL, 10);
        } else if (keyeq(key, L"Path")) {
            unquote_unescape_basic(val);
            lstrcpynW(c->Path, val, _countof(c->Path));
        } else if (keyeq(key, L"PathName")) {
            unquote_unescape_basic(val);
            lstrcpynW(c->PathName, val, _countof(c->PathName));
        }
    }

    HeapFree(GetProcessHeap(), 0, w);
}

// ---------------- 桌面快捷方式（同你上一版） ----------------
static void sanitize_filename_inplace(wchar_t* s) {
    if (!s) return;
    wchar_t out[512];
    size_t oi = 0;
    for (size_t i = 0; s[i] && oi + 1 < _countof(out); i++) {
        wchar_t c = s[i];
        if (c < 32) continue;
        if (c == L'*' || c == L':' || c == L'/' || c == L'\\' || c == L'?' ||
            c == L'"' || c == L'<' || c == L'>' || c == L'|') continue;
        out[oi++] = c;
    }
    out[oi] = 0;
    while (oi && (out[oi-1] == L' ' || out[oi-1] == L'.')) { out[oi-1] = 0; oi--; }
    lstrcpynW(s, out, 512);
}

static void ensure_lnk_ext(wchar_t* name, size_t cap) {
    size_t n = wcslen(name);
    if (n >= 4) {
        const wchar_t* tail = name + (n - 4);
        if (lstrcmpiW(tail, L".lnk") == 0) return;
    }
    if (n + 4 < cap) wcscat_s(name, cap, L".lnk");
}

static void build_path_from_outdir(const wchar_t* outdir, const wchar_t* maybeRel, wchar_t* out, size_t cap) {
    if (!maybeRel || !*maybeRel) { out[0] = 0; return; }
    if (!PathIsRelativeW(maybeRel)) { lstrcpynW(out, maybeRel, (int)cap); return; }
    swprintf_s(out, cap, L"%s\\%s", outdir, maybeRel);
}

static int create_desktop_shortcut(const wchar_t* outdir, const LNK_SPEC* s) {
    if (!s || !s->src[0] || !s->name[0]) return 0;

    wchar_t desktop[MAX_PATH];
    if (SHGetFolderPathW(NULL, CSIDL_DESKTOPDIRECTORY, NULL, SHGFP_TYPE_CURRENT, desktop) != S_OK) return 0;

    wchar_t linkname[512];
    lstrcpynW(linkname, s->name, _countof(linkname));
    sanitize_filename_inplace(linkname);
    if (!linkname[0]) return 0;
    ensure_lnk_ext(linkname, _countof(linkname));

    wchar_t linkpath[MAX_PATH];
    swprintf_s(linkpath, MAX_PATH, L"%s\\%s", desktop, linkname);

    wchar_t target[1024];
    build_path_from_outdir(outdir, s->src, target, _countof(target));

    wchar_t icon[1024];
    build_path_from_outdir(outdir, s->icon, icon, _countof(icon));

    wchar_t wdir[1024];
    lstrcpynW(wdir, target, _countof(wdir));
    PathRemoveFileSpecW(wdir);

    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    int coinited = SUCCEEDED(hr);

    IShellLinkW* psl = NULL;
    hr = CoCreateInstance(&CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, &IID_IShellLinkW, (void**)&psl);
    if (FAILED(hr) || !psl) { if (coinited) CoUninitialize(); return 0; }

    psl->lpVtbl->SetPath(psl, target);
    if (wdir[0]) psl->lpVtbl->SetWorkingDirectory(psl, wdir);
    if (s->desc[0]) psl->lpVtbl->SetDescription(psl, s->desc);
    if (icon[0]) psl->lpVtbl->SetIconLocation(psl, icon, 0);

    IPersistFile* ppf = NULL;
    hr = psl->lpVtbl->QueryInterface(psl, &IID_IPersistFile, (void**)&ppf);
    if (SUCCEEDED(hr) && ppf) {
        hr = ppf->lpVtbl->Save(ppf, linkpath, TRUE);
        ppf->lpVtbl->Release(ppf);
    }
    psl->lpVtbl->Release(psl);
    if (coinited) CoUninitialize();
    return SUCCEEDED(hr) ? 1 : 0;
}

// ---------------- 关键：LZMA SDK 直接解压 7z（支持 LZMA/LZMA2） ----------------

// 内存输入流（随机访问）
typedef struct {
    ISeekInStream vt;
    const Byte* data;
    size_t size;
    size_t pos;
} CMemInStream;

static SRes MemInStream_Read(void* pp, void* buf, size_t* size) {
    CMemInStream* p = (CMemInStream*)pp;
    size_t req = *size;
    size_t left = (p->pos < p->size) ? (p->size - p->pos) : 0;
    if (req > left) req = left;
    if (req) memcpy(buf, p->data + p->pos, req);
    p->pos += req;
    *size = req;
    return SZ_OK;
}

static SRes MemInStream_Seek(void* pp, Int64* pos, ESzSeek origin) {
    CMemInStream* p = (CMemInStream*)pp;
    Int64 newPos;
    switch (origin) {
        case SZ_SEEK_SET: newPos = *pos; break;
        case SZ_SEEK_CUR: newPos = (Int64)p->pos + *pos; break;
        case SZ_SEEK_END: newPos = (Int64)p->size + *pos; break;
        default: return SZ_ERROR_PARAM;
    }
    if (newPos < 0) return SZ_ERROR_PARAM;
    if ((UInt64)newPos > (UInt64)p->size) return SZ_ERROR_PARAM;
    p->pos = (size_t)newPos;
    *pos = newPos;
    return SZ_OK;
}

static void MemInStream_CreateVTable(CMemInStream* p) {
    p->vt.Read = MemInStream_Read;
    p->vt.Seek = MemInStream_Seek;
}

static int is_safe_rel_path(wchar_t* s) {
    // 只允许相对路径，不允许盘符、UNC、绝对路径
    if (!s || !*s) return 0;
    if (s[0] == L'\\' || s[0] == L'/') return 0;
    if (wcslen(s) >= 2 && s[1] == L':') return 0;

    // 把 / 变成 \
    for (size_t i = 0; s[i]; i++) if (s[i] == L'/') s[i] = L'\\';

    // 逐段检查 ..（防目录穿越）
    const wchar_t* p = s;
    while (*p) {
        const wchar_t* seg = p;
        while (*p && *p != L'\\') p++;
        size_t seglen = (size_t)(p - seg);
        if (seglen == 2 && seg[0] == L'.' && seg[1] == L'.') return 0;
        if (*p == L'\\') p++;
    }
    return 1;
}

static void ensure_parent_dir(const wchar_t* fullpath) {
    wchar_t tmp[MAX_PATH * 4];
    lstrcpynW(tmp, fullpath, _countof(tmp));
    tmp[_countof(tmp) - 1] = 0;
    PathRemoveFileSpecW(tmp);
    if (tmp[0]) mk_dir_tree(tmp);
}

static int extract_7z_from_memory_lzmasdk(const Byte* data, size_t size, const wchar_t* outdir, int cover_nonzero_skip) {
    // 初始化 7z crc 表（SDK 要求）
    CrcGenerateTable();

    ISzAlloc allocImp = { SzAlloc, SzFree };
    ISzAlloc allocTempImp = { SzAlloc, SzFree };

    CMemInStream memStream;
    memStream.data = data;
    memStream.size = size;
    memStream.pos  = 0;
    MemInStream_CreateVTable(&memStream);

    CLookToRead2 lookStream;
    LookToRead2_CreateVTable(&lookStream, False);
    lookStream.realStream = &memStream.vt;
    LookToRead2_Init(&lookStream);

    CSzArEx db;
    SzArEx_Init(&db);

    SRes res = SzArEx_Open(&db, &lookStream.vt, &allocImp, &allocTempImp);
    if (res != SZ_OK) {
        SzArEx_Free(&db, &allocImp);
        return 0;
    }

    UInt32 blockIndex = 0xFFFFFFFF;
    Byte* outBuffer = NULL;
    size_t outBufferSize = 0;

    UInt32 numFiles = db.NumFiles;
    for (UInt32 i = 0; i < numFiles; i++) {
        int isDir = SzArEx_IsDir(&db, i);

        // 取 UTF-16 文件名
        size_t nameLen = SzArEx_GetFileNameUtf16(&db, i, NULL);
        if (nameLen == 0 || nameLen > 32768) { res = SZ_ERROR_FAIL; break; }

        UInt16* name16 = (UInt16*)allocImp.Alloc(&allocImp, nameLen * sizeof(UInt16));
        if (!name16) { res = SZ_ERROR_MEM; break; }
        SzArEx_GetFileNameUtf16(&db, i, name16);

        // Windows 下 wchar_t 就是 UTF-16
        wchar_t* rel = (wchar_t*)name16;
        trim_w(rel);
        if (!is_safe_rel_path(rel)) {
            allocImp.Free(&allocImp, name16);
            continue; // 不安全路径直接跳过
        }

        // 拼出目标路径
        size_t need = wcslen(outdir) + 1 + wcslen(rel) + 2;
        wchar_t* full = (wchar_t*)malloc(need * sizeof(wchar_t));
        if (!full) { allocImp.Free(&allocImp, name16); res = SZ_ERROR_MEM; break; }
        swprintf_s(full, need, L"%s\\%s", outdir, rel);

        // 再做一次“必须在 outdir 下面”的保护
        if (!path_is_prefix_dir_of_file(outdir, full)) {
            free(full);
            allocImp.Free(&allocImp, name16);
            continue;
        }

        if (isDir) {
            mk_dir_tree(full);
            free(full);
            allocImp.Free(&allocImp, name16);
            continue;
        }

        // cover!=0：目标已存在就跳过（等价 -aos）
        if (cover_nonzero_skip && fexist(full)) {
            free(full);
            allocImp.Free(&allocImp, name16);
            continue;
        }

        // 解包该文件到 outBuffer
        size_t offset = 0;
        size_t outSizeProcessed = 0;
        res = SzArEx_Extract(&db, &lookStream.vt, i,
                            &blockIndex, &outBuffer, &outBufferSize,
                            &offset, &outSizeProcessed,
                            &allocImp, &allocTempImp);
        if (res != SZ_OK) {
            free(full);
            allocImp.Free(&allocImp, name16);
            break;
        }

        ensure_parent_dir(full);

        // 覆盖写入（CREATE_ALWAYS）
        DWORD attr = GetFileAttributesW(full);
        if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_READONLY)) {
            SetFileAttributesW(full, attr & ~FILE_ATTRIBUTE_READONLY);
        }

        HANDLE h = CreateFileW(full, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h == INVALID_HANDLE_VALUE) {
            free(full);
            allocImp.Free(&allocImp, name16);
            res = SZ_ERROR_FAIL;
            break;
        }

        DWORD wr = 0;
        const Byte* p = outBuffer + offset;
        size_t left = outSizeProcessed;
        while (left) {
            DWORD chunk = (left > 1u<<20) ? (1u<<20) : (DWORD)left;
            if (!WriteFile(h, p, chunk, &wr, NULL) || wr != chunk) {
                CloseHandle(h);
                res = SZ_ERROR_FAIL;
                break;
            }
            p += chunk;
            left -= chunk;
        }
        CloseHandle(h);

        free(full);
        allocImp.Free(&allocImp, name16);

        if (res != SZ_OK) break;
    }

    if (outBuffer) allocImp.Free(&allocImp, outBuffer);
    SzArEx_Free(&db, &allocImp);

    return (res == SZ_OK);
}

// ---------------- 统一 main ----------------
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

    if (!cfg.PathName[0]) lstrcpyW(cfg.PathName, L"WrapperTemp");
    sanitize_name_inplace(cfg.PathName);

    if (cfg.Title[0] && cfg.BeginPrompt[0]) {
        int r = MessageBoxW(NULL, cfg.BeginPrompt, cfg.Title, MB_OKCANCEL | MB_ICONINFORMATION);
        if (r != IDOK) { close_self_overlay(&ov); return 3; }
    }

    if (ov.pay_len == 0) { close_self_overlay(&ov); die(L"no payload"); }

    wchar_t working[MAX_PATH];
    get_working_dir(working, MAX_PATH);

    wchar_t basepath[MAX_PATH];
    expand_path_vars(cfg.Path, exedir, working, basepath, MAX_PATH);

    size_t bl = wcslen(basepath);
    while (bl && (basepath[bl-1] == L'\\' || basepath[bl-1] == L'/')) { basepath[bl-1] = 0; bl--; }

    wchar_t outdir[MAX_PATH];
    swprintf_s(outdir, MAX_PATH, L"%s\\%s", basepath, cfg.PathName);

    mk_dir_tree(outdir);
    mk_mark(outdir);

    int outdir_contains_self = path_is_prefix_dir_of_file(outdir, selfpath);

    // payload id
    uint32_t cur_sz  = (uint32_t)((ov.pay_len > 0xFFFFFFFFu) ? 0xFFFFFFFFu : ov.pay_len);
    uint32_t cur_crc = crc32_calc(ov.base + ov.pay_off, ov.pay_len);

    int can_skip_extract = 0;
    if (dexist(outdir) && has_mark(outdir) && has_exok(outdir)) {
        uint32_t old_crc = 0, old_sz = 0;
        if (read_payload_idfile(outdir, &old_crc, &old_sz) && old_crc == cur_crc && old_sz == cur_sz) {
            can_skip_extract = 1;
        }
    }

    if (!can_skip_extract) {
        // cover: 0 覆盖；非0 跳过
        int ok = extract_7z_from_memory_lzmasdk((const Byte*)(ov.base + ov.pay_off), ov.pay_len, outdir, (cfg.Cover != 0));
        if (!ok) {
            rm_dir_best_effort(outdir);
            close_self_overlay(&ov);
            die(L"lzma sdk extract fail");
        }
        write_exok(outdir);
        write_payload_idfile(outdir, cur_crc, cur_sz);
    }

    close_self_overlay(&ov);

    // 创建桌面快捷方式
    for (int i = 0; i < cfg.LnkCount; i++) {
        (void)create_desktop_shortcut(outdir, &cfg.Lnk[i]);
    }

    // 执行：ExecuteFile 优先，否则 RunProgram 顺序执行
    const wchar_t* raw  = GetCommandLineW();
    const wchar_t* tail = tail1(raw);

    DWORD lastCode = 0;

    if (cfg.ExecuteFile[0]) {
        lastCode = run_shell_wait(cfg.ExecuteFile, cfg.ExecuteParameters, outdir);
        if (lastCode == (DWORD)-1) lastCode = 1;
    } else {
        if (cfg.RunCount == 0) cfg_add_run(&cfg, L"setup.exe");

        wchar_t dir_exp[MAX_PATH];
        expand_path_vars(cfg.Directory, outdir, working, dir_exp, MAX_PATH);

        wchar_t run_wdir[MAX_PATH];
        wchar_t dtrim[MAX_PATH];
        lstrcpynW(dtrim, dir_exp, MAX_PATH);
        trim_w(dtrim);

        if (dtrim[0] == 0 || lstrcmpiW(dtrim, L".") == 0 || lstrcmpiW(dtrim, L".\\") == 0 || lstrcmpiW(dtrim, L"./") == 0) {
            lstrcpynW(run_wdir, outdir, MAX_PATH);
        } else {
            if (PathIsRelativeW(dtrim)) swprintf_s(run_wdir, MAX_PATH, L"%s\\%s", outdir, dtrim);
            else lstrcpynW(run_wdir, dtrim, MAX_PATH);
        }
        mk_dir_tree(run_wdir);

        for (int i = 0; i < cfg.RunCount; i++) {
            wchar_t final[MAX_LINE];
            lstrcpynW(final, cfg.RunProgram[i], MAX_LINE);

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
            if (rc != 0) break;
        }
    }

    // TimeOut：<0 不删；>=0 N 秒后删；永不删除包装 EXE
    if (cfg.TimeOut >= 0 && !outdir_contains_self) {
        ULONGLONG tok = ((ULONGLONG)GetCurrentProcessId() << 32) ^ GetTickCount64();
        wchar_t tokW[32];
        swprintf_s(tokW, 32, L"%I64X", tok);

        write_cleanup_token(outdir, tokW);
        DWORD delay_ms = (DWORD)cfg.TimeOut * 1000u;
        spawn_cleanup_self(selfpath, exedir, outdir, tokW, delay_ms);
    }

    return (int)lastCode;
}

int wmain(int argc, wchar_t** argv) { return real_main(argc, argv); }

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrev, PWSTR lpCmdLine, int nShowCmd) {
    (void)hInst; (void)hPrev; (void)lpCmdLine; (void)nShowCmd;
    int argc = 0;
    wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    int rc = real_main(argc, argv);
    if (argv) LocalFree(argv);
    return rc;
}
