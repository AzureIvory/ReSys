#define UNICODE
#define _UNICODE
#include <windows.h>
#include <shellapi.h>   // SHFileOperationW
#include <shlwapi.h>    // PathRemoveFileSpecW
#include <stdio.h>
#include <wchar.h>
#include <stdint.h>
#include <stdlib.h>

#pragma comment(lib, "Shlwapi.lib")

#define MKRFILE    L".pa_wrapper_marker"
#define IDFILE     L".pa_payload_id"
#define EXOKFILE   L".pa_extracted_ok"
#define CLEANFILE  L".pa_cleanup_token"

#define RUNDIR     L"pa_runtime"
#define PAYFILE    L"payload.7z"

// 运行结束后延迟删除：默认 3 分钟（可改）
#define CLEANUP_DELAY_MS (3u * 60u * 1000u)

static void die(const wchar_t* msg) {
    // 只输出错误
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
    // n==1：通常是系统为本进程新建的控制台，隐藏它
    // n>1：说明共享了父控制台（例如从 cmd 启动），不要动
    if (n == 1) {
        ShowWindow(h, SW_HIDE);
    }
}

// ---------------- 资源 payload ----------------
static void payload_get(const void** dat, DWORD* sz) {
    HRSRC hrs = FindResourceW(NULL, MAKEINTRESOURCEW(101), RT_RCDATA);
    if (!hrs) die(L"res find fail");

    HGLOBAL hg = LoadResource(NULL, hrs);
    if (!hg) die(L"res load fail");

    DWORD s = SizeofResource(NULL, hrs);
    void* d = LockResource(hg);
    if (!d || s == 0) die(L"res lock fail");

    *dat = d;
    *sz = s;
}

// 写资源到文件（payload.7z）
static void res_out(const wchar_t* dst) {
    const void* dat = NULL;
    DWORD sz = 0;
    payload_get(&dat, &sz);

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

static void payload_id(uint32_t* out_crc, uint32_t* out_sz) {
    const void* dat = NULL;
    DWORD sz = 0;
    payload_get(&dat, &sz);
    *out_sz = (uint32_t)sz;
    *out_crc = crc32_calc(dat, (size_t)sz);
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

// ---------------- 运行进程：隐藏窗口 + 可静默（重定向到 NUL） ----------------
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
            // 即使重定向失败，也强制不弹窗口
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

// ---------------- 命令行拼接 ----------------
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

    if (tail && *tail) swprintf_s(buf, len, L"\"%s\" %s", paPath, tail);
    else               swprintf_s(buf, len, L"\"%s\"", paPath);
    return buf;
}

// ---------------- cleanup 子进程 ----------------
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

static int cleanup_main(int argc, wchar_t** argv) {
    // argv[2]=dir argv[3]=token argv[4]=delay_ms
    if (argc < 5) return 0;

    const wchar_t* dir   = argv[2];
    const wchar_t* token = argv[3];
    DWORD delay = (DWORD)wcstoul(argv[4], NULL, 10);

    Sleep(delay);

    // token 不一致：说明又跑了一次，别删（避免误删正在使用的目录）
    wchar_t cur[64];
    if (!read_cleanup_token(dir, cur, 64)) return 0;
    if (lstrcmpW(cur, token) != 0) return 0;

    rm_dir_best_effort(dir);
    return 0;
}

// ---------------- 统一 main ----------------
static int real_main(int argc, wchar_t** argv) {
    // 不弹控制台窗口（只隐藏“自己新建的控制台”）
    hide_own_console_if_any();

    if (argc >= 2 && lstrcmpW(argv[1], L"--cleanup") == 0) {
        return cleanup_main(argc, argv);
    }

    wchar_t exedir[MAX_PATH];
    exe_dir(exedir, MAX_PATH);

    wchar_t selfpath[MAX_PATH];
    exe_path(selfpath, MAX_PATH);

    wchar_t outdir[MAX_PATH];
    wsprintfW(outdir, L"%s\\%s", exedir, RUNDIR);

    wchar_t zpath[MAX_PATH];
    wsprintfW(zpath, L"%s\\7z.exe", exedir);
    if (!fexist(zpath)) die(L"no 7z.exe");

    mk_dir(outdir);
    mk_mark(outdir);

    // 当前内置 payload 的 id
    uint32_t cur_crc = 0, cur_sz = 0;
    payload_id(&cur_crc, &cur_sz);

    // 判断是否能完全跳过解压
    wchar_t papth[MAX_PATH];
    wsprintfW(papth, L"%s\\partassist.exe", outdir);

    int can_skip_extract = 0;
    if (dexist(outdir) && has_mark(outdir) && fexist(papth) && has_exok(outdir)) {
        uint32_t old_crc = 0, old_sz = 0;
        if (read_payload_idfile(outdir, &old_crc, &old_sz) &&
            old_crc == cur_crc && old_sz == cur_sz) {
            can_skip_extract = 1;
        }
    }

    if (!can_skip_extract) {
        // 需要解压才写 payload.7z
        wchar_t paypth[MAX_PATH];
        wsprintfW(paypth, L"%s\\%s", outdir, PAYFILE);
        res_out(paypth);

        // payload 没变：解压遇到同名跳过（-aos）
        // payload 变了：覆盖更新（-aoa）
        uint32_t old_crc = 0, old_sz = 0;
        int has_old = read_payload_idfile(outdir, &old_crc, &old_sz);
        const wchar_t* ao = (has_old && old_crc == cur_crc && old_sz == cur_sz) ? L"-aos" : L"-aoa";

        wchar_t cmd7z[32768];
        swprintf_s(cmd7z, 32768, L"\"%s\" x -y %s -o\"%s\" \"%s\"",
                   zpath, ao, outdir, paypth);

        // 7z：不弹窗 + 静默（不输出任何东西）
        DWORD c7z = run_wait_ex(zpath, cmd7z, exedir, 1);
        if (c7z == (DWORD)-1 || c7z != 0) {
            rm_dir_best_effort(outdir);
            die(L"7z fail");
        }

        write_exok(outdir);
        write_payload_idfile(outdir, cur_crc, cur_sz);
    }

    if (!fexist(papth)) {
        rm_dir_best_effort(outdir);
        die(L"no partassist.exe");
    }

    wchar_t* cmdpa = mk_cmd(papth);
    if (!cmdpa) {
        rm_dir_best_effort(outdir);
        die(L"mk_cmd fail");
    }

    // partassist：同样不弹窗 + 静默（避免它自己刷 stdout/stderr）
    DWORD cpa = run_wait_ex(papth, cmdpa, outdir, 1);
    HeapFree(GetProcessHeap(), 0, cmdpa);

    // 延迟删除：写 token + 启动 cleanup 子进程（不阻塞）
    ULONGLONG tok = ((ULONGLONG)GetCurrentProcessId() << 32) ^ GetTickCount64();
    wchar_t tokW[32];
    swprintf_s(tokW, 32, L"%I64X", tok);
    write_cleanup_token(outdir, tokW);
    spawn_cleanup_self(selfpath, exedir, outdir, tokW, CLEANUP_DELAY_MS);

    return (int)cpa;
}

// Console 子系统入口（如果你还用 /SUBSYSTEM:CONSOLE）
int wmain(int argc, wchar_t** argv) {
    return real_main(argc, argv);
}

// Windows 子系统入口（如果你用 /SUBSYSTEM:WINDOWS）
int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrev, PWSTR lpCmdLine, int nShowCmd) {
    (void)hInst; (void)hPrev; (void)lpCmdLine; (void)nShowCmd;

    int argc = 0;
    wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    int rc = real_main(argc, argv);
    if (argv) LocalFree(argv);
    return rc;
}
