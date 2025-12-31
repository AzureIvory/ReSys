// vds_ops.h
#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

// Format a volume by drive letter, e.g. L"E:".
// fs: L"NTFS" or L"FAT32" (case-insensitive).
__declspec(dllexport) HRESULT __stdcall FormatW(
    LPCWSTR letter,
    LPCWSTR fs,
    LPCWSTR label,
    BOOL quick
);

// Delete a volume (becomes unallocated space), by drive letter e.g. L"E:".
__declspec(dllexport) HRESULT __stdcall DeleteVolumeW(
    LPCWSTR volLetter
);

// Extend (merge) a volume into adjacent unallocated space at the end.
// sizeMB <= 0 => use all adjacent unallocated space.
__declspec(dllexport) HRESULT __stdcall MergeVolumeW(
    LPCWSTR volLetter,
    int sizeMB
);

// Split a volume by shrinking it and creating a new volume in the freed tail space.
// sizeMB: new partition size in MB.
// desiredLetter: e.g. L"E" or L"E:"; empty => auto pick.
// outNewLetter: receives L"X:" (needs at least 3 wchar slots, including NUL).
__declspec(dllexport) HRESULT __stdcall SplitVolumeW(
    LPCWSTR volLetter,
    int sizeMB,
    LPCWSTR fs,
    LPCWSTR label,
    LPCWSTR desiredLetter,
    LPWSTR outNewLetter,
    int outCch
);

#ifdef __cplusplus
}
#endif
