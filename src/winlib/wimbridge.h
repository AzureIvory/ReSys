#ifndef WIMBRIDGE_H
#define WIMBRIDGE_H

#include <windows.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WB_OK                     0
#define WB_ERR_INVALID_ARG       -1
#define WB_ERR_NOT_LOADED        -2
#define WB_ERR_LOAD_DLL          -3
#define WB_ERR_LOAD_SYMBOL       -4
#define WB_ERR_NOMEM             -5
#define WB_ERR_BUFFER_TOO_SMALL  -6
#define WB_ERR_INTERNAL          -7

#define WB_WIMINFO_HAS_INTEGRITY_TABLE (1u << 0)
#define WB_WIMINFO_OPENED_FROM_FILE    (1u << 1)
#define WB_WIMINFO_IS_READONLY         (1u << 2)
#define WB_WIMINFO_HAS_RPFIX           (1u << 3)
#define WB_WIMINFO_IS_MARKED_READONLY  (1u << 4)
#define WB_WIMINFO_SPANNED             (1u << 5)
#define WB_WIMINFO_WRITE_IN_PROGRESS   (1u << 6)
#define WB_WIMINFO_METADATA_ONLY       (1u << 7)
#define WB_WIMINFO_RESOURCE_ONLY       (1u << 8)
#define WB_WIMINFO_PIPABLE             (1u << 9)

typedef struct WB_WimInfo {
    uint8_t  guid[16];
    uint32_t image_count;
    uint32_t boot_index;
    uint32_t wim_version;
    uint32_t chunk_size;
    uint16_t part_number;
    uint16_t total_parts;
    int32_t  compression_type;
    uint64_t total_bytes;
    uint32_t flags;
} WB_WimInfo;

typedef struct WB_DirEntry {
    wchar_t *full_path;
    uint32_t depth;
    uint32_t attributes;
} WB_DirEntry;

__declspec(dllexport) int  __stdcall WimBridge_Load(const wchar_t *dll_dir);
__declspec(dllexport) void __stdcall WimBridge_Unload(void);

__declspec(dllexport) int  __stdcall WimBridge_OpenWim(
    const wchar_t *wim_path,
    int open_flags,
    void **out_handle);

__declspec(dllexport) void __stdcall WimBridge_CloseWim(void *handle);

__declspec(dllexport) int  __stdcall WimBridge_VerifyWim(void *handle);

__declspec(dllexport) int  __stdcall WimBridge_GetWimInfo(
    void *handle,
    WB_WimInfo *out_info);

__declspec(dllexport) int  __stdcall WimBridge_GetImageName(
    void *handle,
    int image,
    wchar_t *buf,
    uint32_t buf_len);

__declspec(dllexport) int  __stdcall WimBridge_GetImageDescription(
    void *handle,
    int image,
    wchar_t *buf,
    uint32_t buf_len);

__declspec(dllexport) int  __stdcall WimBridge_GetXMLUtf8(
    void *handle,
    char **out_buf,
    uint32_t *out_len);

__declspec(dllexport) void __stdcall WimBridge_FreeBuffer(void *p);

__declspec(dllexport) int  __stdcall WimBridge_Apply(
    void *handle,
    int image,
    const wchar_t *target_dir,
    int extract_flags);

__declspec(dllexport) int  __stdcall WimBridge_ExtractPathList(
    void *handle,
    int image,
    const wchar_t *target_dir,
    const wchar_t *path_list_file,
    int extract_flags);

__declspec(dllexport) int  __stdcall WimBridge_ListPaths(
    void *handle,
    int image,
    const wchar_t *path,
    int iterate_flags,
    WB_DirEntry **out_items,
    uint32_t *out_count);

__declspec(dllexport) void __stdcall WimBridge_FreeDirEntries(
    WB_DirEntry *items,
    uint32_t count);

__declspec(dllexport) int  __stdcall WimBridge_UpdateAdd(
    void *handle,
    int image,
    const wchar_t *fs_src,
    const wchar_t *wim_dst,
    int add_flags);

__declspec(dllexport) int  __stdcall WimBridge_UpdateDelete(
    void *handle,
    int image,
    const wchar_t *wim_path,
    int delete_flags);

__declspec(dllexport) int  __stdcall WimBridge_UpdateRename(
    void *handle,
    int image,
    const wchar_t *src,
    const wchar_t *dst,
    int rename_flags);

__declspec(dllexport) int  __stdcall WimBridge_Overwrite(
    void *handle,
    int write_flags,
    uint32_t threads);

__declspec(dllexport) int  __stdcall WimBridge_GetLastErrorStringW(
    int code,
    wchar_t *buf,
    uint32_t buf_len);

#ifdef __cplusplus
}
#endif

#endif