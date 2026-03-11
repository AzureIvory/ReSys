//go:build ignore
// +build ignore
#define _CRT_SECURE_NO_WARNINGS
#include "wimbridge.h"

#include <stdlib.h>
#include <string.h>
#include <wchar.h>

typedef struct WIMStruct WIMStruct;

#define WIMLIB_GUID_LEN 16

typedef struct wimlib_wim_info {
    uint8_t  guid[WIMLIB_GUID_LEN];
    uint32_t image_count;
    uint32_t boot_index;
    uint32_t wim_version;
    uint32_t chunk_size;
    uint16_t part_number;
    uint16_t total_parts;
    int32_t  compression_type;
    uint64_t total_bytes;

    uint32_t has_integrity_table : 1;
    uint32_t opened_from_file    : 1;
    uint32_t is_readonly         : 1;
    uint32_t has_rpfix           : 1;
    uint32_t is_marked_readonly  : 1;
    uint32_t spanned             : 1;
    uint32_t write_in_progress   : 1;
    uint32_t metadata_only       : 1;
    uint32_t resource_only       : 1;
    uint32_t pipable             : 1;
    uint32_t reserved_flags      : 22;

    uint32_t reserved[9];
} wimlib_wim_info;

typedef struct wimlib_dir_entry_min {
    const wchar_t *filename;
    const wchar_t *dos_name;
    const wchar_t *full_path;
    size_t         depth;
    const char    *security_descriptor;
    size_t         security_descriptor_size;
    uint32_t       attributes;
} wimlib_dir_entry_min;

typedef int (*wimlib_iterate_dir_tree_callback_t)(const wimlib_dir_entry_min *dentry, void *user_ctx);

typedef enum wimlib_update_op {
    WIMLIB_UPDATE_OP_ADD    = 0,
    WIMLIB_UPDATE_OP_DELETE = 1,
    WIMLIB_UPDATE_OP_RENAME = 2,
} wimlib_update_op;

typedef struct wimlib_add_command {
    wchar_t *fs_source_path;
    wchar_t *wim_target_path;
    wchar_t *config_file;
    int      add_flags;
} wimlib_add_command;

typedef struct wimlib_delete_command {
    wchar_t *wim_path;
    int      delete_flags;
} wimlib_delete_command;

typedef struct wimlib_rename_command {
    wchar_t *wim_source_path;
    wchar_t *wim_target_path;
    int      rename_flags;
} wimlib_rename_command;

typedef struct wimlib_update_command {
    wimlib_update_op op;
    union {
        wimlib_add_command    add;
        wimlib_delete_command delete_;
        wimlib_rename_command rename;
    };
} wimlib_update_command;

/* -------- cdecl function typedefs from libwim -------- */

typedef int   (__cdecl *fn_global_init)(int init_flags);
typedef void  (__cdecl *fn_global_cleanup)(void);
typedef int   (__cdecl *fn_open_wim)(const wchar_t *wim_file, int open_flags, WIMStruct **wim_ret);
typedef void  (__cdecl *fn_free)(WIMStruct *wim);
typedef int   (__cdecl *fn_verify_wim)(WIMStruct *wim, int verify_flags);
typedef const wchar_t* (__cdecl *fn_get_error_string)(int code);
typedef int   (__cdecl *fn_get_wim_info)(WIMStruct *wim, wimlib_wim_info *info);
typedef const wchar_t* (__cdecl *fn_get_image_name)(const WIMStruct *wim, int image);
typedef const wchar_t* (__cdecl *fn_get_image_description)(const WIMStruct *wim, int image);
typedef int   (__cdecl *fn_get_xml_data)(WIMStruct *wim, void **buf_ret, size_t *bufsize_ret);
typedef int   (__cdecl *fn_extract_image)(WIMStruct *wim, int image, const wchar_t *target, int extract_flags);
typedef int   (__cdecl *fn_extract_pathlist)(WIMStruct *wim, int image, const wchar_t *target, const wchar_t *path_list_file, int extract_flags);
typedef int   (__cdecl *fn_iterate_dir_tree)(WIMStruct *wim, int image, const wchar_t *path, int flags, wimlib_iterate_dir_tree_callback_t cb, void *user_ctx);
typedef int   (__cdecl *fn_update_image)(WIMStruct *wim, int image, const wimlib_update_command *cmds, size_t num_cmds, int update_flags);
typedef int   (__cdecl *fn_overwrite)(WIMStruct *wim, int write_flags, unsigned num_threads);

typedef struct wimlib_api {
    HMODULE mod;
    fn_global_init           global_init;
    fn_global_cleanup        global_cleanup;
    fn_open_wim              open_wim;
    fn_free                  free_wim;
    fn_verify_wim            verify_wim;
    fn_get_error_string      get_error_string;
    fn_get_wim_info          get_wim_info;
    fn_get_image_name        get_image_name;
    fn_get_image_description get_image_description;
    fn_get_xml_data          get_xml_data;
    fn_extract_image         extract_image;
    fn_extract_pathlist      extract_pathlist;
    fn_iterate_dir_tree      iterate_dir_tree;
    fn_update_image          update_image;
    fn_overwrite             overwrite;
} wimlib_api;

typedef struct WB_Handle {
    WIMStruct *wim;
    wchar_t   *opened_path;
} WB_Handle;

static HINSTANCE g_hinst = NULL;
static wimlib_api g_api;
static int g_loaded = 0;

/* -------- helpers -------- */

static FARPROC get_sym(HMODULE mod, const char *name) {
    FARPROC p = GetProcAddress(mod, name);
    if (p) return p;

    {
        char buf[256];
        size_t n = strlen(name);
        if (n + 2 >= sizeof(buf)) return NULL;
        buf[0] = '_';
        memcpy(buf + 1, name, n + 1);
        p = GetProcAddress(mod, buf);
        if (p) return p;
    }
    return NULL;
}

static wchar_t *wb_wcsdup(const wchar_t *s) {
    size_t n;
    wchar_t *p;
    if (!s) return NULL;
    n = wcslen(s);
    p = (wchar_t *)malloc((n + 1) * sizeof(wchar_t));
    if (!p) return NULL;
    memcpy(p, s, (n + 1) * sizeof(wchar_t));
    return p;
}

static int wb_copy_wstr_to_buf(const wchar_t *src, wchar_t *buf, uint32_t buf_len) {
    size_t need;
    if (!buf || buf_len == 0) return WB_ERR_INVALID_ARG;
    if (!src) {
        buf[0] = 0;
        return WB_OK;
    }
    need = wcslen(src) + 1;
    if (need > (size_t)buf_len) return WB_ERR_BUFFER_TOO_SMALL;
    memcpy(buf, src, need * sizeof(wchar_t));
    return WB_OK;
}

static int wb_build_dll_path(const wchar_t *dll_dir, wchar_t *out_path, DWORD out_cch) {
    DWORD n;
    if (!out_path || out_cch < 32) return WB_ERR_INVALID_ARG;

    if (dll_dir && dll_dir[0]) {
        n = (DWORD)wcslen(dll_dir);
        if (n + 15 >= out_cch) return WB_ERR_BUFFER_TOO_SMALL;
        wcscpy(out_path, dll_dir);
        if (n > 0 && out_path[n - 1] != L'\\' && out_path[n - 1] != L'/') {
            wcscat(out_path, L"\\");
        }
        wcscat(out_path, L"libwim-15.dll");
        return WB_OK;
    }

    n = GetModuleFileNameW(g_hinst, out_path, out_cch);
    if (n == 0 || n >= out_cch) return WB_ERR_INTERNAL;

    {
        wchar_t *slash = wcsrchr(out_path, L'\\');
        if (!slash) slash = wcsrchr(out_path, L'/');
        if (!slash) return WB_ERR_INTERNAL;
        slash[1] = 0;
        if (wcslen(out_path) + 14 >= out_cch) return WB_ERR_BUFFER_TOO_SMALL;
        wcscat(out_path, L"libwim-15.dll");
    }
    return WB_OK;
}

static int wb_utf16le_to_utf8_alloc(const void *utf16_buf, uint32_t utf16_bytes, char **out_buf, uint32_t *out_len) {
    int chars;
    int written;
    char *dst;

    if (!out_buf || !out_len) return WB_ERR_INVALID_ARG;
    *out_buf = NULL;
    *out_len = 0;

    if (!utf16_buf || utf16_bytes == 0) {
        dst = (char *)malloc(1);
        if (!dst) return WB_ERR_NOMEM;
        dst[0] = '\0';
        *out_buf = dst;
        *out_len = 0;
        return WB_OK;
    }

    chars = (int)(utf16_bytes / 2);
    if (chars > 0) {
        const wchar_t *w = (const wchar_t *)utf16_buf;
        if (w[chars - 1] == 0) chars--;
    }

    written = WideCharToMultiByte(CP_UTF8, 0, (const wchar_t *)utf16_buf, chars, NULL, 0, NULL, NULL);
    if (written <= 0) return WB_ERR_INTERNAL;

    dst = (char *)malloc((size_t)written + 1);
    if (!dst) return WB_ERR_NOMEM;

    written = WideCharToMultiByte(CP_UTF8, 0, (const wchar_t *)utf16_buf, chars, dst, written, NULL, NULL);
    if (written <= 0) {
        free(dst);
        return WB_ERR_INTERNAL;
    }

    dst[written] = '\0';
    *out_buf = dst;
    *out_len = (uint32_t)written;
    return WB_OK;
}

static int wb_load_api(const wchar_t *dll_dir) {
    wchar_t dll_path[MAX_PATH * 2];

    if (g_loaded) return WB_OK;

    memset(&g_api, 0, sizeof(g_api));

    if (wb_build_dll_path(dll_dir, dll_path, (DWORD)(sizeof(dll_path) / sizeof(dll_path[0]))) != WB_OK) {
        return WB_ERR_LOAD_DLL;
    }

    g_api.mod = LoadLibraryW(dll_path);
    if (!g_api.mod) return WB_ERR_LOAD_DLL;

#define LOAD_SYM(field, type, name) \
    do { \
        FARPROC p = get_sym(g_api.mod, name); \
        if (!p) { \
            FreeLibrary(g_api.mod); \
            memset(&g_api, 0, sizeof(g_api)); \
            return WB_ERR_LOAD_SYMBOL; \
        } \
        g_api.field = (type)p; \
    } while (0)

    LOAD_SYM(global_init,           fn_global_init,           "wimlib_global_init");
    LOAD_SYM(global_cleanup,        fn_global_cleanup,        "wimlib_global_cleanup");
    LOAD_SYM(open_wim,              fn_open_wim,              "wimlib_open_wim");
    LOAD_SYM(free_wim,              fn_free,                  "wimlib_free");
    LOAD_SYM(verify_wim,            fn_verify_wim,            "wimlib_verify_wim");
    LOAD_SYM(get_error_string,      fn_get_error_string,      "wimlib_get_error_string");
    LOAD_SYM(get_wim_info,          fn_get_wim_info,          "wimlib_get_wim_info");
    LOAD_SYM(get_image_name,        fn_get_image_name,        "wimlib_get_image_name");
    LOAD_SYM(get_image_description, fn_get_image_description, "wimlib_get_image_description");
    LOAD_SYM(get_xml_data,          fn_get_xml_data,          "wimlib_get_xml_data");
    LOAD_SYM(extract_image,         fn_extract_image,         "wimlib_extract_image");
    LOAD_SYM(extract_pathlist,      fn_extract_pathlist,      "wimlib_extract_pathlist");
    LOAD_SYM(iterate_dir_tree,      fn_iterate_dir_tree,      "wimlib_iterate_dir_tree");
    LOAD_SYM(update_image,          fn_update_image,          "wimlib_update_image");
    LOAD_SYM(overwrite,             fn_overwrite,             "wimlib_overwrite");

#undef LOAD_SYM

    {
        int r = g_api.global_init(0);
        if (r != 0) {
            FreeLibrary(g_api.mod);
            memset(&g_api, 0, sizeof(g_api));
            return r;
        }
    }

    g_loaded = 1;
    return WB_OK;
}

static void wb_unload_api(void) {
    if (!g_loaded) return;
    g_api.global_cleanup();
    if (g_api.mod) FreeLibrary(g_api.mod);
    memset(&g_api, 0, sizeof(g_api));
    g_loaded = 0;
}

static int wb_fill_wim_info(WIMStruct *wim, WB_WimInfo *out_info) {
    wimlib_wim_info info;
    uint32_t flags = 0;
    int r;

    if (!g_loaded) return WB_ERR_NOT_LOADED;
    if (!wim || !out_info) return WB_ERR_INVALID_ARG;

    memset(&info, 0, sizeof(info));
    r = g_api.get_wim_info(wim, &info);
    if (r != 0) return r;

    memset(out_info, 0, sizeof(*out_info));
    memcpy(out_info->guid, info.guid, 16);
    out_info->image_count      = info.image_count;
    out_info->boot_index       = info.boot_index;
    out_info->wim_version      = info.wim_version;
    out_info->chunk_size       = info.chunk_size;
    out_info->part_number      = info.part_number;
    out_info->total_parts      = info.total_parts;
    out_info->compression_type = info.compression_type;
    out_info->total_bytes      = info.total_bytes;

    if (info.has_integrity_table) flags |= WB_WIMINFO_HAS_INTEGRITY_TABLE;
    if (info.opened_from_file)    flags |= WB_WIMINFO_OPENED_FROM_FILE;
    if (info.is_readonly)         flags |= WB_WIMINFO_IS_READONLY;
    if (info.has_rpfix)           flags |= WB_WIMINFO_HAS_RPFIX;
    if (info.is_marked_readonly)  flags |= WB_WIMINFO_IS_MARKED_READONLY;
    if (info.spanned)             flags |= WB_WIMINFO_SPANNED;
    if (info.write_in_progress)   flags |= WB_WIMINFO_WRITE_IN_PROGRESS;
    if (info.metadata_only)       flags |= WB_WIMINFO_METADATA_ONLY;
    if (info.resource_only)       flags |= WB_WIMINFO_RESOURCE_ONLY;
    if (info.pipable)             flags |= WB_WIMINFO_PIPABLE;

    out_info->flags = flags;
    return WB_OK;
}

typedef struct wb_dir_collect_item {
    wchar_t *full_path;
    uint32_t depth;
    uint32_t attributes;
} wb_dir_collect_item;

typedef struct wb_dir_collect {
    wb_dir_collect_item *items;
    uint32_t len;
    uint32_t cap;
    int oom;
} wb_dir_collect;

static int wb_dir_cb(const wimlib_dir_entry_min *d, void *ctx) {
    wb_dir_collect *c = (wb_dir_collect *)ctx;
    wb_dir_collect_item *p;

    if (!c || !d || !d->full_path) return 0;
    if (c->oom) return 1;

    if (c->len == c->cap) {
        uint32_t new_cap = (c->cap == 0) ? 256 : c->cap * 2;
        wb_dir_collect_item *new_items =
            (wb_dir_collect_item *)realloc(c->items, (size_t)new_cap * sizeof(wb_dir_collect_item));
        if (!new_items) {
            c->oom = 1;
            return 1;
        }
        c->items = new_items;
        c->cap = new_cap;
    }

    p = &c->items[c->len];
    p->full_path = wb_wcsdup(d->full_path);
    if (!p->full_path) {
        c->oom = 1;
        return 1;
    }

    p->depth = (uint32_t)d->depth;
    p->attributes = d->attributes;
    c->len++;
    return 0;
}

static void wb_free_collect(wb_dir_collect *c) {
    uint32_t i;
    if (!c) return;
    for (i = 0; i < c->len; i++) {
        free(c->items[i].full_path);
    }
    free(c->items);
    c->items = NULL;
    c->len = 0;
    c->cap = 0;
    c->oom = 0;
}

/* -------- exports -------- */

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        g_hinst = hinst;
        DisableThreadLibraryCalls(hinst);
    }
    return TRUE;
}

int __stdcall WimBridge_Load(const wchar_t *dll_dir) {
    return wb_load_api(dll_dir);
}

void __stdcall WimBridge_Unload(void) {
    wb_unload_api();
}

int __stdcall WimBridge_OpenWim(const wchar_t *wim_path, int open_flags, void **out_handle) {
    WB_Handle *h = NULL;
    WIMStruct *w = NULL;
    int r;

    if (!out_handle || !wim_path) return WB_ERR_INVALID_ARG;
    *out_handle = NULL;

    if (!g_loaded) return WB_ERR_NOT_LOADED;

    h = (WB_Handle *)calloc(1, sizeof(WB_Handle));
    if (!h) return WB_ERR_NOMEM;

    r = g_api.open_wim(wim_path, open_flags, &w);
    if (r != 0) {
        free(h);
        return r;
    }
    if (!w) {
        free(h);
        return WB_ERR_INTERNAL;
    }

    h->wim = w;
    h->opened_path = wb_wcsdup(wim_path);
    *out_handle = h;
    return WB_OK;
}

void __stdcall WimBridge_CloseWim(void *handle) {
    WB_Handle *h = (WB_Handle *)handle;
    if (!h) return;
    if (g_loaded && h->wim) g_api.free_wim(h->wim);
    free(h->opened_path);
    free(h);
}

int __stdcall WimBridge_VerifyWim(void *handle) {
    WB_Handle *h = (WB_Handle *)handle;
    if (!g_loaded) return WB_ERR_NOT_LOADED;
    if (!h || !h->wim) return WB_ERR_INVALID_ARG;
    return g_api.verify_wim(h->wim, 0);
}

int __stdcall WimBridge_GetWimInfo(void *handle, WB_WimInfo *out_info) {
    WB_Handle *h = (WB_Handle *)handle;
    if (!h || !h->wim || !out_info) return WB_ERR_INVALID_ARG;
    return wb_fill_wim_info(h->wim, out_info);
}

int __stdcall WimBridge_GetImageName(void *handle, int image, wchar_t *buf, uint32_t buf_len) {
    WB_Handle *h = (WB_Handle *)handle;
    const wchar_t *s;
    if (!g_loaded) return WB_ERR_NOT_LOADED;
    if (!h || !h->wim) return WB_ERR_INVALID_ARG;
    s = g_api.get_image_name(h->wim, image);
    return wb_copy_wstr_to_buf(s, buf, buf_len);
}

int __stdcall WimBridge_GetImageDescription(void *handle, int image, wchar_t *buf, uint32_t buf_len) {
    WB_Handle *h = (WB_Handle *)handle;
    const wchar_t *s;
    if (!g_loaded) return WB_ERR_NOT_LOADED;
    if (!h || !h->wim) return WB_ERR_INVALID_ARG;
    s = g_api.get_image_description(h->wim, image);
    return wb_copy_wstr_to_buf(s, buf, buf_len);
}

int __stdcall WimBridge_GetXMLUtf8(void *handle, char **out_buf, uint32_t *out_len) {
    WB_Handle *h = (WB_Handle *)handle;
    void *xml_buf = NULL;
    size_t xml_size = 0;
    int r;

    if (!out_buf || !out_len) return WB_ERR_INVALID_ARG;
    *out_buf = NULL;
    *out_len = 0;

    if (!g_loaded) return WB_ERR_NOT_LOADED;
    if (!h || !h->wim) return WB_ERR_INVALID_ARG;

    r = g_api.get_xml_data(h->wim, &xml_buf, &xml_size);
    if (r != 0) return r;

    r = wb_utf16le_to_utf8_alloc(xml_buf, (uint32_t)xml_size, out_buf, out_len);
    free(xml_buf);
    return r;
}

void __stdcall WimBridge_FreeBuffer(void *p) {
    free(p);
}

int __stdcall WimBridge_Apply(void *handle, int image, const wchar_t *target_dir, int extract_flags) {
    WB_Handle *h = (WB_Handle *)handle;
    if (!g_loaded) return WB_ERR_NOT_LOADED;
    if (!h || !h->wim || !target_dir) return WB_ERR_INVALID_ARG;
    return g_api.extract_image(h->wim, image, target_dir, extract_flags);
}

int __stdcall WimBridge_ExtractPathList(void *handle, int image, const wchar_t *target_dir, const wchar_t *path_list_file, int extract_flags) {
    WB_Handle *h = (WB_Handle *)handle;
    if (!g_loaded) return WB_ERR_NOT_LOADED;
    if (!h || !h->wim || !target_dir || !path_list_file) return WB_ERR_INVALID_ARG;
    return g_api.extract_pathlist(h->wim, image, target_dir, path_list_file, extract_flags);
}

int __stdcall WimBridge_ListPaths(void *handle, int image, const wchar_t *path, int iterate_flags, WB_DirEntry **out_items, uint32_t *out_count) {
    WB_Handle *h = (WB_Handle *)handle;
    wb_dir_collect c;
    WB_DirEntry *out = NULL;
    uint32_t i;
    int r;

    if (!out_items || !out_count) return WB_ERR_INVALID_ARG;
    *out_items = NULL;
    *out_count = 0;

    if (!g_loaded) return WB_ERR_NOT_LOADED;
    if (!h || !h->wim || !path) return WB_ERR_INVALID_ARG;

    memset(&c, 0, sizeof(c));
    r = g_api.iterate_dir_tree(h->wim, image, path, iterate_flags, wb_dir_cb, &c);
    if (r != 0 || c.oom) {
        wb_free_collect(&c);
        return c.oom ? WB_ERR_NOMEM : r;
    }

    if (c.len == 0) {
        return WB_OK;
    }

    out = (WB_DirEntry *)calloc(c.len, sizeof(WB_DirEntry));
    if (!out) {
        wb_free_collect(&c);
        return WB_ERR_NOMEM;
    }

    for (i = 0; i < c.len; i++) {
        out[i].full_path = c.items[i].full_path;
        out[i].depth = c.items[i].depth;
        out[i].attributes = c.items[i].attributes;
        c.items[i].full_path = NULL;
    }

    wb_free_collect(&c);

    *out_items = out;
    *out_count = i;
    return WB_OK;
}

void __stdcall WimBridge_FreeDirEntries(WB_DirEntry *items, uint32_t count) {
    uint32_t i;
    if (!items) return;
    for (i = 0; i < count; i++) {
        free(items[i].full_path);
    }
    free(items);
}

int __stdcall WimBridge_UpdateAdd(void *handle, int image, const wchar_t *fs_src, const wchar_t *wim_dst, int add_flags) {
    WB_Handle *h = (WB_Handle *)handle;
    wimlib_update_command cmd;

    if (!g_loaded) return WB_ERR_NOT_LOADED;
    if (!h || !h->wim || !fs_src || !wim_dst) return WB_ERR_INVALID_ARG;

    memset(&cmd, 0, sizeof(cmd));
    cmd.op = WIMLIB_UPDATE_OP_ADD;
    cmd.add.fs_source_path = (wchar_t *)fs_src;
    cmd.add.wim_target_path = (wchar_t *)wim_dst;
    cmd.add.config_file = NULL;
    cmd.add.add_flags = add_flags;

    return g_api.update_image(h->wim, image, &cmd, 1, 0);
}

int __stdcall WimBridge_UpdateDelete(void *handle, int image, const wchar_t *wim_path, int delete_flags) {
    WB_Handle *h = (WB_Handle *)handle;
    wimlib_update_command cmd;

    if (!g_loaded) return WB_ERR_NOT_LOADED;
    if (!h || !h->wim || !wim_path) return WB_ERR_INVALID_ARG;

    memset(&cmd, 0, sizeof(cmd));
    cmd.op = WIMLIB_UPDATE_OP_DELETE;
    cmd.delete_.wim_path = (wchar_t *)wim_path;
    cmd.delete_.delete_flags = delete_flags;

    return g_api.update_image(h->wim, image, &cmd, 1, 0);
}

int __stdcall WimBridge_UpdateRename(void *handle, int image, const wchar_t *src, const wchar_t *dst, int rename_flags) {
    WB_Handle *h = (WB_Handle *)handle;
    wimlib_update_command cmd;

    if (!g_loaded) return WB_ERR_NOT_LOADED;
    if (!h || !h->wim || !src || !dst) return WB_ERR_INVALID_ARG;

    memset(&cmd, 0, sizeof(cmd));
    cmd.op = WIMLIB_UPDATE_OP_RENAME;
    cmd.rename.wim_source_path = (wchar_t *)src;
    cmd.rename.wim_target_path = (wchar_t *)dst;
    cmd.rename.rename_flags = rename_flags;

    return g_api.update_image(h->wim, image, &cmd, 1, 0);
}

int __stdcall WimBridge_Overwrite(void *handle, int write_flags, uint32_t threads) {
    WB_Handle *h = (WB_Handle *)handle;
    if (!g_loaded) return WB_ERR_NOT_LOADED;
    if (!h || !h->wim) return WB_ERR_INVALID_ARG;
    return g_api.overwrite(h->wim, write_flags, (unsigned)threads);
}

int __stdcall WimBridge_GetLastErrorStringW(int code, wchar_t *buf, uint32_t buf_len) {
    const wchar_t *s = NULL;

    if (!buf || buf_len == 0) return WB_ERR_INVALID_ARG;

    if (code < 0) {
        switch (code) {
        case WB_ERR_INVALID_ARG:      s = L"invalid argument"; break;
        case WB_ERR_NOT_LOADED:       s = L"bridge not loaded"; break;
        case WB_ERR_LOAD_DLL:         s = L"failed to load libwim-15.dll"; break;
        case WB_ERR_LOAD_SYMBOL:      s = L"failed to load required symbol from libwim-15.dll"; break;
        case WB_ERR_NOMEM:            s = L"out of memory"; break;
        case WB_ERR_BUFFER_TOO_SMALL: s = L"buffer too small"; break;
        case WB_ERR_INTERNAL:         s = L"internal bridge error"; break;
        default:                      s = L"unknown bridge error"; break;
        }
        return wb_copy_wstr_to_buf(s, buf, buf_len);
    }

    if (!g_loaded) {
        s = L"libwim is not loaded";
        return wb_copy_wstr_to_buf(s, buf, buf_len);
    }

    s = g_api.get_error_string(code);
    return wb_copy_wstr_to_buf(s ? s : L"unknown libwim error", buf, buf_len);
}