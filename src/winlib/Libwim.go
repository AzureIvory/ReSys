//go:build windows && cgo

// Package wimlib provides a small, efficient cgo wrapper around libwim-15.dll.
//
// It loads DLL from: <exe_dir>\tools\libwim-15.dll
//
// Covered APIs (matching your needs):
//   - wimlib_global_init / wimlib_global_cleanup
//   - wimlib_open_wim / wimlib_free
//   - wimlib_verify_wim
//   - wimlib_get_error_string
//   - wimlib_get_wim_info
//   - wimlib_get_image_name / wimlib_get_image_description
//   - wimlib_get_xml_data            (info --xml)
//   - wimlib_extract_image           (apply)
//   - wimlib_iterate_dir_tree        (dir)   -> wrapped as ListPaths()
//   - wimlib_update_image            (update)-> wrapped as UpdateAdd/Delete/Rename
//   - wimlib_overwrite               (commit changes)
//
// Notes:
// - wimlib's Windows DLL uses cdecl calling convention (per wimlib.h).
// - To keep cgo rules safe, ALL strings passed to C are allocated in C memory.

package wimlib

/*
#cgo CFLAGS: -DUNICODE -D_UNICODE
#include <windows.h>
#include <stdint.h>
#include <stdlib.h>
#include <wchar.h>

// Opaque WIM handle type (matches wimlib.h's "WIMStruct").
typedef struct WIMStruct WIMStruct;

// ---- Minimal structs we need ----

// A safe "prefix" of struct wimlib_wim_info with the same fields we want.
// We call wimlib_get_wim_info() into the real struct shape in C.
#define WIMLIB_GUID_LEN 16

// The real wimlib_wim_info contains bitfields. We define it exactly as in wimlib.h
// (v1.14.5 header), but we only expose a flattened result to Go.
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

	// bitfields
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

// Flattened info we return to Go (no bitfields).
typedef struct wim_info_flat {
	uint8_t  guid[WIMLIB_GUID_LEN];
	uint32_t image_count;
	uint32_t boot_index;
	uint32_t wim_version;
	uint32_t chunk_size;
	uint16_t part_number;
	uint16_t total_parts;
	int32_t  compression_type;
	uint64_t total_bytes;
	uint32_t flags; // packed booleans
} wim_info_flat;

// Bits in wim_info_flat.flags
#define WIMINFO_HAS_INTEGRITY_TABLE (1u<<0)
#define WIMINFO_OPENED_FROM_FILE    (1u<<1)
#define WIMINFO_IS_READONLY         (1u<<2)
#define WIMINFO_HAS_RPFIX           (1u<<3)
#define WIMINFO_IS_MARKED_READONLY  (1u<<4)
#define WIMINFO_SPANNED             (1u<<5)
#define WIMINFO_WRITE_IN_PROGRESS   (1u<<6)
#define WIMINFO_METADATA_ONLY       (1u<<7)
#define WIMINFO_RESOURCE_ONLY       (1u<<8)
#define WIMINFO_PIPABLE             (1u<<9)

// A minimal prefix of struct wimlib_dir_entry sufficient for "dir" listing.
// We only read full_path / depth / attributes.
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

// ---- update command structs (from wimlib.h) ----
typedef enum wimlib_update_op {
	WIMLIB_UPDATE_OP_ADD    = 0,
	WIMLIB_UPDATE_OP_DELETE = 1,
	WIMLIB_UPDATE_OP_RENAME = 2,
} wimlib_update_op;

typedef struct wimlib_add_command {
	wchar_t *fs_source_path;
	wchar_t *wim_target_path; // use "\" for root
	wchar_t *config_file;     // optional
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

// ---- Function pointer typedefs (cdecl) ----
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

// ---- API table ----
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

// Small helper: GetProcAddress with optional leading underscore fallback.
static FARPROC get_sym(HMODULE mod, const char *name) {
	FARPROC p = GetProcAddress(mod, name);
	if (p) return p;

	// Some toolchains may export cdecl as "_name" (32-bit). Try underscore fallback.
	char buf[256];
	buf[0] = '_';
	strncpy(buf+1, name, sizeof(buf)-2);
	buf[sizeof(buf)-1] = 0;
	return GetProcAddress(mod, buf);
}

static int wimlib_load(wimlib_api *api, const wchar_t *dll_path) {
	api->mod = LoadLibraryW(dll_path);
	if (!api->mod) return -1;

	#define LOAD_SYM(field, type, symname) \
		do { \
			FARPROC p = get_sym(api->mod, symname); \
			if (!p) return -2; \
			api->field = (type)p; \
		} while(0)

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
	return 0;
}

static void wimlib_unload(wimlib_api *api) {
	if (api->mod) {
		FreeLibrary(api->mod);
		api->mod = NULL;
	}
}

// ---- Simple C wrappers ----

static int api_global_init(wimlib_api *api, int flags) { return api->global_init(flags); }
static void api_global_cleanup(wimlib_api *api) { api->global_cleanup(); }
static int api_open_wim(wimlib_api *api, const wchar_t *path, int open_flags, WIMStruct **out) {
	return api->open_wim(path, open_flags, out);
}
static void api_free_wim(wimlib_api *api, WIMStruct *w) { api->free_wim(w); }
static int api_verify_wim(wimlib_api *api, WIMStruct *w) { return api->verify_wim(w, 0); }
static const wchar_t* api_errstr(wimlib_api *api, int code) { return api->get_error_string(code); }

static int api_get_wim_info_flat(wimlib_api *api, WIMStruct *w, wim_info_flat *out) {
	wimlib_wim_info info;
	int r = api->get_wim_info(w, &info);
	if (r != 0) return r;

	memset(out, 0, sizeof(*out));
	memcpy(out->guid, info.guid, WIMLIB_GUID_LEN);
	out->image_count      = info.image_count;
	out->boot_index       = info.boot_index;
	out->wim_version      = info.wim_version;
	out->chunk_size       = info.chunk_size;
	out->part_number      = info.part_number;
	out->total_parts      = info.total_parts;
	out->compression_type = info.compression_type;
	out->total_bytes      = info.total_bytes;

	uint32_t f = 0;
	if (info.has_integrity_table) f |= WIMINFO_HAS_INTEGRITY_TABLE;
	if (info.opened_from_file)    f |= WIMINFO_OPENED_FROM_FILE;
	if (info.is_readonly)         f |= WIMINFO_IS_READONLY;
	if (info.has_rpfix)           f |= WIMINFO_HAS_RPFIX;
	if (info.is_marked_readonly)  f |= WIMINFO_IS_MARKED_READONLY;
	if (info.spanned)             f |= WIMINFO_SPANNED;
	if (info.write_in_progress)   f |= WIMINFO_WRITE_IN_PROGRESS;
	if (info.metadata_only)       f |= WIMINFO_METADATA_ONLY;
	if (info.resource_only)       f |= WIMINFO_RESOURCE_ONLY;
	if (info.pipable)             f |= WIMINFO_PIPABLE;
	out->flags = f;

	return 0;
}

static const wchar_t* api_image_name(wimlib_api *api, const WIMStruct *w, int idx) {
	return api->get_image_name(w, idx);
}
static const wchar_t* api_image_desc(wimlib_api *api, const WIMStruct *w, int idx) {
	return api->get_image_description(w, idx);
}

static int api_get_xml(wimlib_api *api, WIMStruct *w, void **buf, size_t *n) {
	return api->get_xml_data(w, buf, n);
}
static void api_free_buf(void *p) { free(p); }

static int api_extract_image(wimlib_api *api, WIMStruct *w, int image, const wchar_t *target, int flags) {
	return api->extract_image(w, image, target, flags);
}
static int api_extract_pathlist(wimlib_api *api, WIMStruct *w, int image, const wchar_t *target, const wchar_t *listfile, int flags) {
	return api->extract_pathlist(w, image, target, listfile, flags);
}

typedef struct dir_item {
	wchar_t *full_path;  // heap-allocated copy
	size_t   depth;
	uint32_t attributes;
} dir_item;

typedef struct dir_items {
	dir_item *items;
	size_t    len;
	size_t    cap;
} dir_items;

static int dir_cb(const wimlib_dir_entry_min *d, void *ctx) {
	dir_items *out = (dir_items*)ctx;
	if (!d || !d->full_path) return 0;

	if (out->len == out->cap) {
		size_t ncap = (out->cap == 0) ? 256 : (out->cap * 2);
		dir_item *p = (dir_item*)realloc(out->items, ncap * sizeof(dir_item));
		if (!p) return 1;
		out->items = p;
		out->cap = ncap;
	}

	size_t wlen = wcslen(d->full_path);
	wchar_t *cpy = (wchar_t*)malloc((wlen + 1) * sizeof(wchar_t));
	if (!cpy) return 1;
	memcpy(cpy, d->full_path, (wlen + 1) * sizeof(wchar_t));

	out->items[out->len].full_path = cpy;
	out->items[out->len].depth = d->depth;
	out->items[out->len].attributes = d->attributes;
	out->len++;
	return 0;
}

static int api_list_paths(wimlib_api *api, WIMStruct *w, int image, const wchar_t *path, int flags, dir_item **items, size_t *n) {
	dir_items out;
	memset(&out, 0, sizeof(out));

	int r = api->iterate_dir_tree(w, image, path, flags, dir_cb, &out);
	if (r != 0) {
		// free partial
		for (size_t i=0; i<out.len; i++) free(out.items[i].full_path);
		free(out.items);
		return r;
	}
	*items = out.items;
	*n = out.len;
	return 0;
}

static void api_free_list(dir_item *items, size_t n) {
	if (!items) return;
	for (size_t i=0; i<n; i++) free(items[i].full_path);
	free(items);
}

// update helpers: single-command wrappers (simple and matches wimlib-imagex update use cases)
static int api_update_add(wimlib_api *api, WIMStruct *w, int image,
	const wchar_t *fs_src, const wchar_t *wim_dst, const wchar_t *config, int add_flags)
{
	wimlib_update_command cmd;
	memset(&cmd, 0, sizeof(cmd));
	cmd.op = WIMLIB_UPDATE_OP_ADD;
	cmd.add.fs_source_path = (wchar_t*)fs_src;
	cmd.add.wim_target_path = (wchar_t*)wim_dst;
	cmd.add.config_file = (wchar_t*)config;
	cmd.add.add_flags = add_flags;
	return api->update_image(w, image, &cmd, 1, 0);
}

static int api_update_delete(wimlib_api *api, WIMStruct *w, int image,
	const wchar_t *wim_path, int delete_flags)
{
	wimlib_update_command cmd;
	memset(&cmd, 0, sizeof(cmd));
	cmd.op = WIMLIB_UPDATE_OP_DELETE;
	cmd.delete_.wim_path = (wchar_t*)wim_path;
	cmd.delete_.delete_flags = delete_flags;
	return api->update_image(w, image, &cmd, 1, 0);
}

static int api_update_rename(wimlib_api *api, WIMStruct *w, int image,
	const wchar_t *src, const wchar_t *dst, int rename_flags)
{
	wimlib_update_command cmd;
	memset(&cmd, 0, sizeof(cmd));
	cmd.op = WIMLIB_UPDATE_OP_RENAME;
	cmd.rename.wim_source_path = (wchar_t*)src;
	cmd.rename.wim_target_path = (wchar_t*)dst;
	cmd.rename.rename_flags = rename_flags;
	return api->update_image(w, image, &cmd, 1, 0);
}

static int api_overwrite(wimlib_api *api, WIMStruct *w, int write_flags, unsigned threads) {
	return api->overwrite(w, write_flags, threads);
}
*/
import "C"

import (
	"ReSys/src/log"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

// Common constants (from wimlib.h)
const (
	// Image selectors
	NoImage   = 0
	AllImages = -1 // WIMLIB_ALL_IMAGES

	// Open flags
	OpenFlagCheckIntegrity = 0x00000001
	OpenFlagWriteAccess    = 0x00000004

	// Extract flags
	ExtractFlagNoACLs = 0x00000040 // --no-acls

	// Iterate flags
	IterateRecursive = 0x00000001
	IterateChildren  = 0x00000002
)

type Lib struct {
	api *C.wimlib_api
}

type WIM struct {
	lib      *Lib
	h        *C.WIMStruct
	wimPathW *C.wchar_t // keep the C-allocated wim path alive until Free()
}

type WimInfo struct {
	GUID            [16]byte
	ImageCount      uint32
	BootIndex       uint32
	WimVersion      uint32
	ChunkSize       uint32
	PartNumber      uint16
	TotalParts      uint16
	CompressionType int32
	TotalBytes      uint64

	HasIntegrityTable bool
	OpenedFromFile    bool
	IsReadonly        bool
	HasRpfix          bool
	IsMarkedReadonly  bool
	Spanned           bool
	WriteInProgress   bool
	MetadataOnly      bool
	ResourceOnly      bool
	Pipable           bool
}

type DirEntry struct {
	FullPath   string
	Depth      uint64
	Attributes uint32
}

// Load loads libwim-15.dll from "<exe_dir>\\tools\\libwim-15.dll" and calls wimlib_global_init(0).
func LibwimLoad() (*Lib, error) {
	exe, err := os.Executable()
	if err != nil {
		log.LogWrite(-2, "[LibwimLoad]获取可执行路径失败: err=%v", err)
		return nil, err
	}
	dll := filepath.Join(filepath.Dir(exe), "tools", "libwim-15.dll")

	p, freeP, err := allocWString(dll)
	if err != nil {
		log.LogWrite(-2, "[LibwimLoad]分配DLL路径失败: path=%s err=%v", dll, err)
		return nil, err
	}
	defer freeP()

	api := (*C.wimlib_api)(C.calloc(1, C.size_t(unsafe.Sizeof(C.wimlib_api{}))))
	if api == nil {
		err := errors.New("calloc wimlib_api failed")
		log.LogWrite(-2, "[LibwimLoad]分配api结构失败: %v", err)
		return nil, err
	}

	if r := C.wimlib_load(api, p); r != 0 {
		C.free(unsafe.Pointer(api))
		err := errors.New("load libwim-15.dll failed (missing file or missing symbols)")
		log.LogWrite(-2, "[LibwimLoad]加载libwim失败: path=%s", dll)
		return nil, err
	}

	// global_init is idempotent; we still call it explicitly.
	if code := int(C.api_global_init(api, 0)); code != 0 {
		C.wimlib_unload(api)
		C.free(unsafe.Pointer(api))
		err := errors.New("wimlib_global_init failed: " + errStringFrom(api, code))
		log.LogWrite(-2, "[LibwimLoad]初始化wimlib失败: err=%v", err)
		return nil, err
	}

	return &Lib{api: api}, nil
}

func (l *Lib) Close() {
	if l == nil || l.api == nil {
		return
	}
	C.api_global_cleanup(l.api)
	C.wimlib_unload(l.api)
	C.free(unsafe.Pointer(l.api))
	l.api = nil
}

// OpenWim opens a WIM/ESD file and returns a handle.
// For update operations, pass openFlags including OpenFlagWriteAccess.
func (l *Lib) OpenWim(path string, openFlags int) (*WIM, error) {
	if l == nil || l.api == nil {
		return nil, errors.New("wimlib not loaded")
	}

	// IMPORTANT: allocate the path in C memory in case wimlib keeps it internally.
	p, freeP, err := allocWString(path)
	if err != nil {
		return nil, err
	}

	var out *C.WIMStruct
	code := int(C.api_open_wim(l.api, p, C.int(openFlags), &out))
	if code != 0 {
		freeP()
		return nil, errors.New(errStringFrom(l.api, code))
	}
	if out == nil {
		freeP()
		return nil, errors.New("wimlib_open_wim returned NULL handle")
	}

	return &WIM{lib: l, h: out, wimPathW: p}, nil
}

func (w *WIM) Free() {
	if w == nil || w.h == nil {
		return
	}
	C.api_free_wim(w.lib.api, w.h)
	w.h = nil
	if w.wimPathW != nil {
		C.free(unsafe.Pointer(w.wimPathW))
		w.wimPathW = nil
	}
}

// Verify verifies WIM metadata + stream integrity (like "verify").
// verify_flags are reserved in current API; we call with 0.
func (w *WIM) Verify() error {
	if w == nil || w.h == nil {
		return errors.New("nil WIM")
	}
	code := int(C.api_verify_wim(w.lib.api, w.h))
	if code != 0 {
		return errors.New(errStringFrom(w.lib.api, code))
	}
	return nil
}

// GetWimInfo corresponds to "info" (basic header info).
func (w *WIM) GetWimInfo() (WimInfo, error) {
	var out WimInfo
	if w == nil || w.h == nil {
		return out, errors.New("nil WIM")
	}
	var cinfo C.wim_info_flat
	code := int(C.api_get_wim_info_flat(w.lib.api, w.h, &cinfo))
	if code != 0 {
		return out, errors.New(errStringFrom(w.lib.api, code))
	}

	copy(out.GUID[:], (*[16]byte)(unsafe.Pointer(&cinfo.guid[0]))[:])
	out.ImageCount = uint32(cinfo.image_count)
	out.BootIndex = uint32(cinfo.boot_index)
	out.WimVersion = uint32(cinfo.wim_version)
	out.ChunkSize = uint32(cinfo.chunk_size)
	out.PartNumber = uint16(cinfo.part_number)
	out.TotalParts = uint16(cinfo.total_parts)
	out.CompressionType = int32(cinfo.compression_type)
	out.TotalBytes = uint64(cinfo.total_bytes)

	flags := uint32(cinfo.flags)
	out.HasIntegrityTable = flags&C.WIMINFO_HAS_INTEGRITY_TABLE != 0
	out.OpenedFromFile = flags&C.WIMINFO_OPENED_FROM_FILE != 0
	out.IsReadonly = flags&C.WIMINFO_IS_READONLY != 0
	out.HasRpfix = flags&C.WIMINFO_HAS_RPFIX != 0
	out.IsMarkedReadonly = flags&C.WIMINFO_IS_MARKED_READONLY != 0
	out.Spanned = flags&C.WIMINFO_SPANNED != 0
	out.WriteInProgress = flags&C.WIMINFO_WRITE_IN_PROGRESS != 0
	out.MetadataOnly = flags&C.WIMINFO_METADATA_ONLY != 0
	out.ResourceOnly = flags&C.WIMINFO_RESOURCE_ONLY != 0
	out.Pipable = flags&C.WIMINFO_PIPABLE != 0

	return out, nil
}

func (w *WIM) GetImageName(index int) string {
	if w == nil || w.h == nil {
		return ""
	}
	p := C.api_image_name(w.lib.api, (*C.WIMStruct)(unsafe.Pointer(w.h)), C.int(index))
	return wcharPtrToString(p)
}

func (w *WIM) GetImageDescription(index int) string {
	if w == nil || w.h == nil {
		return ""
	}
	p := C.api_image_desc(w.lib.api, (*C.WIMStruct)(unsafe.Pointer(w.h)), C.int(index))
	return wcharPtrToString(p)
}

// GetXML returns UTF-8 XML string (info --xml).
// wimlib_get_xml_data() returns raw UTF-16LE bytes + size in bytes.
func (w *WIM) GetXML() (string, error) {
	if w == nil || w.h == nil {
		return "", errors.New("nil WIM")
	}
	var buf unsafe.Pointer
	var n C.size_t
	code := int(C.api_get_xml(w.lib.api, w.h, (*unsafe.Pointer)(unsafe.Pointer(&buf)), &n))
	if code != 0 {
		return "", errors.New(errStringFrom(w.lib.api, code))
	}
	defer C.api_free_buf(buf)

	u16n := int(n) / 2
	if u16n <= 0 {
		return "", nil
	}
	u16 := unsafe.Slice((*uint16)(buf), u16n)
	if len(u16) > 0 && u16[len(u16)-1] == 0 {
		u16 = u16[:len(u16)-1]
	}
	return string(utf16.Decode(u16)), nil
}

// Apply == wimlib-imagex apply (extract whole image to target directory).
func (w *WIM) Apply(image int, targetDir string, extractFlags int) error {
	if w == nil || w.h == nil {
		return errors.New("nil WIM")
	}
	t, freeT, err := allocWString(targetDir)
	if err != nil {
		return err
	}
	defer freeT()

	code := int(C.api_extract_image(w.lib.api, w.h, C.int(image), t, C.int(extractFlags)))
	if code != 0 {
		return errors.New(errStringFrom(w.lib.api, code))
	}
	return nil
}

// ExtractByPathList == wimlib-imagex extract using a path list file.
// This is the simplest/most cgo-safe way to emulate "extract <paths...> --dest-dir X --no-acls":
//   - put one path per line into a UTF-8/UTF-16 text file (wimlib supports both)
//   - call this with targetDir = --dest-dir, extractFlags include ExtractFlagNoACLs if needed.
func (w *WIM) ExtractByPathList(image int, targetDir, pathListFile string, extractFlags int) error {
	if w == nil || w.h == nil {
		return errors.New("nil WIM")
	}
	t, freeT, err := allocWString(targetDir)
	if err != nil {
		return err
	}
	defer freeT()

	lf, freeLF, err := allocWString(pathListFile)
	if err != nil {
		return err
	}
	defer freeLF()

	code := int(C.api_extract_pathlist(w.lib.api, w.h, C.int(image), t, lf, C.int(extractFlags)))
	if code != 0 {
		return errors.New(errStringFrom(w.lib.api, code))
	}
	return nil
}

// ListPaths provides a "dir" style listing by collecting full paths via wimlib_iterate_dir_tree().
// For large images this can allocate a lot; it's still the cleanest “API-only” approach without Go callbacks.
func (w *WIM) ListPaths(image int, wimPath string, iterateFlags int) ([]DirEntry, error) {
	if w == nil || w.h == nil {
		return nil, errors.New("nil WIM")
	}

	p, freeP, err := allocWString(wimPath)
	if err != nil {
		log.LogWrite(-2, "[ListPaths]分配路径失败: wimPath=%s err=%v", wimPath, err)
		return nil, err
	}
	defer freeP()

	var items *C.dir_item
	var n C.size_t
	code := int(C.api_list_paths(w.lib.api, w.h, C.int(image), p, C.int(iterateFlags), &items, &n))
	if code != 0 {
		return nil, errors.New(errStringFrom(w.lib.api, code))
	}
	defer C.api_free_list(items, n)

	out := make([]DirEntry, 0, int(n))
	s := unsafe.Slice(items, int(n))
	for i := range s {
		out = append(out, DirEntry{
			FullPath:   wcharPtrToString(s[i].full_path),
			Depth:      uint64(s[i].depth),
			Attributes: uint32(s[i].attributes),
		})
	}
	return out, nil
}

// UpdateAdd/Delete/Rename are single-command helpers that map well to wimlib-imagex update.
// After updates, you MUST call Overwrite() to persist changes to disk.
func (w *WIM) UpdateAdd(image int, fsSource, wimTarget string, addFlags int) error {
	if w == nil || w.h == nil {
		return errors.New("nil WIM")
	}
	src, freeS, err := allocWString(fsSource)
	if err != nil {
		return err
	}
	defer freeS()

	dst, freeD, err := allocWString(wimTarget)
	if err != nil {
		return err
	}
	defer freeD()

	// config_file omitted (NULL)
	code := int(C.api_update_add(w.lib.api, w.h, C.int(image), src, dst, nil, C.int(addFlags)))
	if code != 0 {
		return errors.New(errStringFrom(w.lib.api, code))
	}
	return nil
}

func (w *WIM) UpdateDelete(image int, wimPath string, deleteFlags int) error {
	if w == nil || w.h == nil {
		return errors.New("nil WIM")
	}
	p, freeP, err := allocWString(wimPath)
	if err != nil {
		return err
	}
	defer freeP()

	code := int(C.api_update_delete(w.lib.api, w.h, C.int(image), p, C.int(deleteFlags)))
	if code != 0 {
		return errors.New(errStringFrom(w.lib.api, code))
	}
	return nil
}

func (w *WIM) UpdateRename(image int, srcPath, dstPath string, renameFlags int) error {
	if w == nil || w.h == nil {
		return errors.New("nil WIM")
	}
	s, freeS, err := allocWString(srcPath)
	if err != nil {
		return err
	}
	defer freeS()

	d, freeD, err := allocWString(dstPath)
	if err != nil {
		return err
	}
	defer freeD()

	code := int(C.api_update_rename(w.lib.api, w.h, C.int(image), s, d, C.int(renameFlags)))
	if code != 0 {
		return errors.New(errStringFrom(w.lib.api, code))
	}
	return nil
}

// Overwrite persists changes to the backing WIM file (like committing "update").
// threads: 0 lets wimlib choose.
func (w *WIM) Overwrite(writeFlags int, threads uint) error {
	if w == nil || w.h == nil {
		return errors.New("nil WIM")
	}
	code := int(C.api_overwrite(w.lib.api, w.h, C.int(writeFlags), C.uint(threads)))
	if code != 0 {
		return errors.New(errStringFrom(w.lib.api, code))
	}
	return nil
}

// ---- internal helpers ----

func errStringFrom(api *C.wimlib_api, code int) string {
	if api == nil {
		return "wimlib error: " + itoa(code)
	}
	p := C.api_errstr(api, C.int(code))
	s := wcharPtrToString(p)
	if s == "" {
		return "wimlib error code: " + itoa(code)
	}
	return s
}

func wcharPtrToString(p *C.wchar_t) string {
	if p == nil {
		return ""
	}
	return utf16zPtrToString((*uint16)(unsafe.Pointer(p)))
}

func allocWString(s string) (*C.wchar_t, func(), error) {
	u16, err := syscall.UTF16FromString(s)
	if err != nil {
		return nil, nil, err
	}
	n := len(u16) * 2
	mem := C.malloc(C.size_t(n))
	if mem == nil {
		return nil, nil, errors.New("malloc failed")
	}
	dst := unsafe.Slice((*uint16)(mem), len(u16))
	copy(dst, u16)
	return (*C.wchar_t)(mem), func() { C.free(mem) }, nil
}

func itoa(i int) string {
	// tiny helper; avoid fmt for efficiency
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [32]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + (i % 10))
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

func wimtest() {
	lib, _ := LibwimLoad()
	defer lib.Close()

	w, _ := lib.OpenWim("install.wim", 0)
	defer w.Free()

	_ = w.Verify()

	info, _ := w.GetWimInfo()
	_ = info.ImageCount

	xml, _ := w.GetXML() // info --xml
	_ = xml

	_ = w.Apply(1, "D:\\apply", 0) // apply

	paths, _ := w.ListPaths(1, "\\", IterateRecursive) // dir
	_ = paths

	// update: open with write access + commit overwrite
	w2, _ := lib.OpenWim("custom.wim", OpenFlagWriteAccess)
	defer w2.Free()
	_ = w2.UpdateAdd(1, "C:\\add\\file.txt", "\\Windows\\Temp\\file.txt", 0)
	_ = w2.Overwrite(0, 0)

	// extract with --dest-dir and --no-acls via pathlist
	_ = w.ExtractByPathList(1, "D:\\dest", "paths.txt", ExtractFlagNoACLs)
}

// UTF-16 NUL 结尾指针 -> Go string
func utf16zPtrToString(p *uint16) string {
	if p == nil {
		return ""
	}
	// 扫描到 0 结束
	n := 0
	for *(*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(p)) + uintptr(n)*2)) != 0 {
		n++
		// 上限，防止野指针无限扫
		if n > 1<<20 {
			break
		}
	}
	return syscall.UTF16ToString(unsafe.Slice(p, n))
}
