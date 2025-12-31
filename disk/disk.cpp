#include <windows.h>
#include <vds.h>
#include <string>
#include <algorithm>
#include <initguid.h>
#include <objbase.h>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "uuid.lib")

#define SAFE_RELEASE(p) do { if ((p) != nullptr) { (p)->Release(); (p) = nullptr; } } while (0)

static std::wstring ToUpperCopy(std::wstring s) {
    for (auto& ch : s) if (ch >= L'a' && ch <= L'z') ch = ch - L'a' + L'A';
    return s;
}

static std::wstring NormalizeLetterPath(LPCWSTR in) {
    // accept "E", "E:", "E:\"
    if (!in || !*in) return L"";
    wchar_t c = in[0];
    if (c >= L'a' && c <= L'z') c = c - L'a' + L'A';
    std::wstring out;
    out.push_back(c);
    out.append(L":\\");
    return out;
}

static wchar_t NormalizeSingleLetter(LPCWSTR in) {
    if (!in || !*in) return 0;
    wchar_t c = in[0];
    if (c >= L'a' && c <= L'z') c = c - L'a' + L'A';
    if (c < L'A' || c > L'Z') return 0;
    return c;
}

struct ComScope {
    bool needUninit = false;
    HRESULT Init() {
        HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        if (hr == RPC_E_CHANGED_MODE) {
            needUninit = false; // already STA; don't uninit
        } else if (SUCCEEDED(hr)) {
            needUninit = true;
        } else {
            return hr;
        }

        // If already initialized, may return RPC_E_TOO_LATE; ignore.
        CoInitializeSecurity(
            nullptr, -1, nullptr, nullptr,
            RPC_C_AUTHN_LEVEL_CONNECT,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            nullptr, EOAC_NONE, nullptr
        );
        return S_OK;
    }
    ~ComScope() { if (needUninit) CoUninitialize(); }
};

static HRESULT LoadVdsService(IVdsService** ppService) {
    if (!ppService) return E_INVALIDARG;
    *ppService = nullptr;

    IVdsServiceLoader* loader = nullptr;
    CLSID clsidVdsLoader;
    HRESULT hr = CLSIDFromString(L"{9C38ED61-D565-4728-AEEE-C80952F0ECDE}", &clsidVdsLoader);
    if (FAILED(hr)) return hr;
    hr = CoCreateInstance(clsidVdsLoader, nullptr, CLSCTX_LOCAL_SERVER,
                      IID_IVdsServiceLoader, (void**)&loader);
    if (FAILED(hr)) return hr;

    IVdsService* svc = nullptr;
    hr = loader->LoadService(nullptr, &svc);
    SAFE_RELEASE(loader);
    if (FAILED(hr)) return hr;

    hr = svc->WaitForServiceReady();
    if (FAILED(hr)) { SAFE_RELEASE(svc); return hr; }

    svc->Refresh();
    *ppService = svc;
    return S_OK;
}

static void FreeAccessPaths(LPWSTR* paths, LONG nPaths) {
    if (!paths) return;
    for (LONG i = 0; i < nPaths; i++) CoTaskMemFree(paths[i]);
    CoTaskMemFree(paths);
}

static HRESULT WaitAsync(IVdsAsync* async, VDS_ASYNC_OUTPUT* outOpt /*nullable*/) {
    if (!async) return E_INVALIDARG;

    HRESULT hrResult = E_FAIL;
    VDS_ASYNC_OUTPUT outLocal = {};
    HRESULT hr = async->Wait(&hrResult, outOpt ? outOpt : &outLocal); // signature in vds.h :contentReference[oaicite:1]{index=1}
    SAFE_RELEASE(async);

    // If CreateVolume returned an object, caller must release it (docs say Wait adds ref).
    if (!outOpt && outLocal.type == VDS_ASYNCOUT_CREATEVOLUME && outLocal.cv.pVolumeUnk) {
        outLocal.cv.pVolumeUnk->Release();
        outLocal.cv.pVolumeUnk = nullptr;
    }

    return FAILED(hr) ? hr : hrResult;
}

static HRESULT FindVolumeByLetter(IVdsService* svc, const std::wstring& letterPath, IVdsVolume** outVol) {
    if (!svc || !outVol) return E_INVALIDARG;
    *outVol = nullptr;

    const std::wstring want = ToUpperCopy(letterPath);

    IEnumVdsObject* enumProv = nullptr;
    HRESULT hr = svc->QueryProviders(VDS_QUERY_SOFTWARE_PROVIDERS, &enumProv);
    if (FAILED(hr)) return hr;

    IUnknown* unkProv = nullptr;
    ULONG fetched = 0;

    while (enumProv->Next(1, &unkProv, &fetched) == S_OK) {
        IVdsProvider* provider = nullptr;
        hr = unkProv->QueryInterface(IID_IVdsProvider, (void**)&provider);
        SAFE_RELEASE(unkProv);
        if (FAILED(hr)) continue;

        IVdsSwProvider* sw = nullptr;
        hr = provider->QueryInterface(IID_IVdsSwProvider, (void**)&sw);
        SAFE_RELEASE(provider);
        if (FAILED(hr)) continue;

        IEnumVdsObject* enumPack = nullptr;
        hr = sw->QueryPacks(&enumPack);
        SAFE_RELEASE(sw);
        if (FAILED(hr)) continue;

        IUnknown* unkPack = nullptr;
        ULONG fetched2 = 0;

        while (enumPack->Next(1, &unkPack, &fetched2) == S_OK) {
            IVdsPack* pack = nullptr;
            hr = unkPack->QueryInterface(IID_IVdsPack, (void**)&pack);
            SAFE_RELEASE(unkPack);
            if (FAILED(hr)) continue;

            IEnumVdsObject* enumVol = nullptr;
            hr = pack->QueryVolumes(&enumVol);
            SAFE_RELEASE(pack);
            if (FAILED(hr)) continue;

            IUnknown* unkVol = nullptr;
            ULONG fetched3 = 0;

            while (enumVol->Next(1, &unkVol, &fetched3) == S_OK) {
                IVdsVolume* vol = nullptr;
                hr = unkVol->QueryInterface(IID_IVdsVolume, (void**)&vol);
                SAFE_RELEASE(unkVol);
                if (FAILED(hr)) continue;

                IVdsVolumeMF* mf = nullptr;
                hr = vol->QueryInterface(IID_IVdsVolumeMF, (void**)&mf);
                if (SUCCEEDED(hr) && mf) {
                    LPWSTR* paths = nullptr;
                    LONG nPaths = 0;
                    hr = mf->QueryAccessPaths(&paths, &nPaths);
                    SAFE_RELEASE(mf);

                    if (SUCCEEDED(hr) && nPaths > 0 && paths && paths[0]) {
                        std::wstring p0 = ToUpperCopy(std::wstring(paths[0]));
                        if (p0.size() == 2 && p0[1] == L':') p0.push_back(L'\\');

                        if (p0 == want) {
                            FreeAccessPaths(paths, nPaths);
                            SAFE_RELEASE(enumVol);
                            SAFE_RELEASE(enumPack);
                            SAFE_RELEASE(enumProv);
                            *outVol = vol;
                            return S_OK;
                        }
                    }
                    FreeAccessPaths(paths, nPaths);
                }

                SAFE_RELEASE(vol);
            }

            SAFE_RELEASE(enumVol);
        }

        SAFE_RELEASE(enumPack);
    }

    SAFE_RELEASE(enumProv);
    return HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
}

static HRESULT GetFileSystemNameUpper(IVdsVolume* vol, std::wstring* outFsUpper) {
    if (!vol || !outFsUpper) return E_INVALIDARG;
    outFsUpper->clear();

    IVdsVolumeMF2* mf2 = nullptr;
    HRESULT hr = vol->QueryInterface(IID_IVdsVolumeMF2, (void**)&mf2);
    if (FAILED(hr)) return hr;

    LPWSTR fsName = nullptr;
    hr = mf2->GetFileSystemTypeName(&fsName);
    SAFE_RELEASE(mf2);
    if (FAILED(hr)) return hr;

    *outFsUpper = ToUpperCopy(std::wstring(fsName ? fsName : L""));
    CoTaskMemFree(fsName);
    return S_OK;
}

static bool IsExtendShrinkSupportedFs(const std::wstring& fsUpper) {
    return (fsUpper == L"NTFS" || fsUpper == L"RAW");
}

static HRESULT GetSingleDiskEndOffset(IVdsVolume* vol, GUID* outDiskId, ULONGLONG* outEndOffset) {
    if (!vol || !outDiskId || !outEndOffset) return E_INVALIDARG;
    *outDiskId = GUID_NULL;
    *outEndOffset = 0;

    IEnumVdsObject* enumPlex = nullptr;
    HRESULT hr = vol->QueryPlexes(&enumPlex);
    if (FAILED(hr)) return hr;

    IUnknown* unkPlex = nullptr;
    ULONG fetched = 0;
    hr = enumPlex->Next(1, &unkPlex, &fetched);
    SAFE_RELEASE(enumPlex);
    if (hr != S_OK) return HRESULT_FROM_WIN32(ERROR_NOT_FOUND);

    IVdsVolumePlex* plex = nullptr;
    hr = unkPlex->QueryInterface(IID_IVdsVolumePlex, (void**)&plex);
    SAFE_RELEASE(unkPlex);
    if (FAILED(hr)) return hr;

    VDS_DISK_EXTENT* ext = nullptr;
    LONG nExt = 0;
    hr = plex->QueryExtents(&ext, &nExt);
    SAFE_RELEASE(plex);
    if (FAILED(hr)) return hr;

    GUID disk = GUID_NULL;
    ULONGLONG endMax = 0;
    for (LONG i = 0; i < nExt; i++) {
        if (disk == GUID_NULL) disk = ext[i].diskId;
        if (memcmp(&disk, &ext[i].diskId, sizeof(GUID)) != 0) {
            CoTaskMemFree(ext);
            return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
        }
        ULONGLONG end = ext[i].ullOffset + ext[i].ullSize;
        if (end > endMax) endMax = end;
    }
    CoTaskMemFree(ext);

    *outDiskId = disk;
    *outEndOffset = endMax;
    return S_OK;
}

static void FreeDiskPropStrings(VDS_DISK_PROP& prop) {
    CoTaskMemFree(prop.pwszDiskAddress);
    CoTaskMemFree(prop.pwszName);
    CoTaskMemFree(prop.pwszFriendlyName);
    CoTaskMemFree(prop.pwszAdaptorName);
    CoTaskMemFree(prop.pwszDevicePath);
    prop.pwszDiskAddress = prop.pwszName = prop.pwszFriendlyName = prop.pwszAdaptorName = prop.pwszDevicePath = nullptr;
}

static HRESULT FindDiskById(IVdsPack* pack, const GUID& diskId, IVdsDisk** outDisk) {
    if (!pack || !outDisk) return E_INVALIDARG;
    *outDisk = nullptr;

    IEnumVdsObject* enumDisk = nullptr;
    HRESULT hr = pack->QueryDisks(&enumDisk);
    if (FAILED(hr)) return hr;

    IUnknown* unkDisk = nullptr;
    ULONG fetched = 0;

    while (enumDisk->Next(1, &unkDisk, &fetched) == S_OK) {
        IVdsDisk* disk = nullptr;
        hr = unkDisk->QueryInterface(IID_IVdsDisk, (void**)&disk);
        SAFE_RELEASE(unkDisk);
        if (FAILED(hr)) continue;

        VDS_DISK_PROP prop = {};
        hr = disk->GetProperties(&prop);
        if (SUCCEEDED(hr) && memcmp(&prop.id, &diskId, sizeof(GUID)) == 0) {
            FreeDiskPropStrings(prop);
            SAFE_RELEASE(enumDisk);
            *outDisk = disk;
            return S_OK;
        }
        FreeDiskPropStrings(prop);
        SAFE_RELEASE(disk);
    }

    SAFE_RELEASE(enumDisk);
    return HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
}

static HRESULT GetFreeExtentAtOffset(IVdsDisk* disk, ULONGLONG offset, ULONGLONG* outFreeSize) {
    if (!disk || !outFreeSize) return E_INVALIDARG;
    *outFreeSize = 0;

    VDS_DISK_EXTENT* ext = nullptr;
    LONG nExt = 0;
    HRESULT hr = disk->QueryExtents(&ext, &nExt);
    if (FAILED(hr)) return hr;

    for (LONG i = 0; i < nExt; i++) {
        if (ext[i].type == VDS_DET_FREE && ext[i].ullOffset == offset) {
            *outFreeSize = ext[i].ullSize;
            break;
        }
    }
    CoTaskMemFree(ext);
    return (*outFreeSize > 0) ? S_OK : HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
}

static HRESULT CreateSimpleVolumeOnDisk(IVdsPack* pack, const GUID& diskId, ULONGLONG bytes, IVdsVolume** outNewVol) {
    if (!pack || !outNewVol) return E_INVALIDARG;
    *outNewVol = nullptr;

    VDS_INPUT_DISK in = {};
    in.diskId = diskId;
    in.ullSize = bytes;
    in.plexId = GUID_NULL;

    IVdsAsync* async = nullptr;
    HRESULT hr = pack->CreateVolume(VDS_VT_SIMPLE, &in, 1, 0, &async);
    if (FAILED(hr)) return hr;

    VDS_ASYNC_OUTPUT out = {};
    hr = WaitAsync(async, &out);
    if (FAILED(hr)) {
        if (out.type == VDS_ASYNCOUT_CREATEVOLUME && out.cv.pVolumeUnk) out.cv.pVolumeUnk->Release();
        return hr;
    }

    if (out.type != VDS_ASYNCOUT_CREATEVOLUME || !out.cv.pVolumeUnk) return E_FAIL;

    IVdsVolume* newVol = nullptr;
    hr = out.cv.pVolumeUnk->QueryInterface(IID_IVdsVolume, (void**)&newVol);
    out.cv.pVolumeUnk->Release();
    out.cv.pVolumeUnk = nullptr;

    if (FAILED(hr)) return hr;
    *outNewVol = newVol;
    return S_OK;
}

static bool IsDriveLetterFree(wchar_t letterUpper) {
    DWORD mask = GetLogicalDrives();
    int bit = (int)(letterUpper - L'A');
    if (bit < 0 || bit > 25) return false;
    return ((mask & (1u << bit)) == 0);
}

static wchar_t PickFreeDriveLetter() {
    DWORD mask = GetLogicalDrives();
    for (wchar_t c = L'D'; c <= L'Z'; c++) {
        int bit = (int)(c - L'A');
        if ((mask & (1u << bit)) == 0) return c;
    }
    return 0;
}

static HRESULT AssignDriveLetter(IVdsVolume* vol, wchar_t letterUpper) {
    if (!vol) return E_INVALIDARG;
    IVdsVolumeMF* mf = nullptr;
    HRESULT hr = vol->QueryInterface(IID_IVdsVolumeMF, (void**)&mf);
    if (FAILED(hr)) return hr;

    std::wstring path;
    path.push_back(letterUpper);
    path.append(L":\\");
    hr = mf->AddAccessPath(const_cast<LPWSTR>(path.c_str()));
    SAFE_RELEASE(mf);
    return hr;
}

// ---------------- Exports ----------------

extern "C" __declspec(dllexport)
HRESULT __stdcall FormatW(LPCWSTR letter, LPCWSTR fs, LPCWSTR label, BOOL quick) {
    ComScope com;
    HRESULT hr = com.Init();
    if (FAILED(hr)) return hr;

    IVdsService* svc = nullptr;
    hr = LoadVdsService(&svc);
    if (FAILED(hr)) return hr;

    IVdsVolume* vol = nullptr;
    hr = FindVolumeByLetter(svc, NormalizeLetterPath(letter), &vol);
    SAFE_RELEASE(svc);
    if (FAILED(hr)) return hr;

    std::wstring fsUp = ToUpperCopy(fs ? std::wstring(fs) : L"");
    if (fsUp != L"NTFS" && fsUp != L"FAT32") { SAFE_RELEASE(vol); return E_INVALIDARG; }

    IVdsVolumeMF2* mf2 = nullptr;
    hr = vol->QueryInterface(IID_IVdsVolumeMF2, (void**)&mf2);
    if (FAILED(hr)) { SAFE_RELEASE(vol); return hr; }

    IVdsAsync* async = nullptr;
    hr = mf2->FormatEx(
        const_cast<LPWSTR>(fsUp.c_str()),
        0,
        0,
        const_cast<LPWSTR>(label),
        TRUE,
        quick,
        FALSE,
        &async
    );
    SAFE_RELEASE(mf2);
    SAFE_RELEASE(vol);
    if (FAILED(hr)) return hr;

    return WaitAsync(async, nullptr);
}

extern "C" __declspec(dllexport)
HRESULT __stdcall DeleteVolumeW(LPCWSTR volLetter) {
    ComScope com;
    HRESULT hr = com.Init();
    if (FAILED(hr)) return hr;

    IVdsService* svc = nullptr;
    hr = LoadVdsService(&svc);
    if (FAILED(hr)) return hr;

    IVdsVolume* vol = nullptr;
    hr = FindVolumeByLetter(svc, NormalizeLetterPath(volLetter), &vol);
    SAFE_RELEASE(svc);
    if (FAILED(hr)) return hr;

    hr = vol->Delete(TRUE);
    SAFE_RELEASE(vol);
    return hr;
}

extern "C" __declspec(dllexport)
HRESULT __stdcall MergeVolumeW(LPCWSTR volLetter, int sizeMB) {
    ComScope com;
    HRESULT hr = com.Init();
    if (FAILED(hr)) return hr;

    IVdsService* svc = nullptr;
    hr = LoadVdsService(&svc);
    if (FAILED(hr)) return hr;

    IVdsVolume* vol = nullptr;
    hr = FindVolumeByLetter(svc, NormalizeLetterPath(volLetter), &vol);
    SAFE_RELEASE(svc);
    if (FAILED(hr)) return hr;

    std::wstring curFs;
    if (SUCCEEDED(GetFileSystemNameUpper(vol, &curFs)) && !IsExtendShrinkSupportedFs(curFs)) {
        SAFE_RELEASE(vol);
        return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
    }

    IVdsPack* pack = nullptr;
    hr = vol->GetPack(&pack);
    if (FAILED(hr)) { SAFE_RELEASE(vol); return hr; }

    GUID diskId;
    ULONGLONG endOffset = 0;
    hr = GetSingleDiskEndOffset(vol, &diskId, &endOffset);
    if (FAILED(hr)) { SAFE_RELEASE(pack); SAFE_RELEASE(vol); return hr; }

    IVdsDisk* disk = nullptr;
    hr = FindDiskById(pack, diskId, &disk);
    if (FAILED(hr)) { SAFE_RELEASE(pack); SAFE_RELEASE(vol); return hr; }

    ULONGLONG freeBytes = 0;
    hr = GetFreeExtentAtOffset(disk, endOffset, &freeBytes);
    SAFE_RELEASE(disk);
    if (FAILED(hr)) { SAFE_RELEASE(pack); SAFE_RELEASE(vol); return hr; }

    ULONGLONG want = 0;
    if (sizeMB <= 0) want = freeBytes;
    else {
        want = (ULONGLONG)sizeMB * 1024ULL * 1024ULL;
        if (want > freeBytes) want = freeBytes;
    }
    if (want == 0) { SAFE_RELEASE(pack); SAFE_RELEASE(vol); return HRESULT_FROM_WIN32(ERROR_DISK_FULL); }

    VDS_INPUT_DISK in = {};
    in.diskId = diskId;
    in.ullSize = want;
    in.plexId = GUID_NULL;

    IVdsAsync* async = nullptr;
    hr = vol->Extend(&in, 1, &async);
    SAFE_RELEASE(pack);
    SAFE_RELEASE(vol);
    if (FAILED(hr)) return hr;

    return WaitAsync(async, nullptr);
}

extern "C" __declspec(dllexport)
HRESULT __stdcall SplitVolumeW(
    LPCWSTR volLetter, int sizeMB,
    LPCWSTR fs, LPCWSTR label,
    LPCWSTR desiredLetter,
    LPWSTR outNewLetter, int outCch
) {
    if (!outNewLetter || outCch < 3) return E_INVALIDARG;
    outNewLetter[0] = 0;
    if (sizeMB <= 0) return E_INVALIDARG;

    std::wstring fsUp = ToUpperCopy(fs ? std::wstring(fs) : L"");
    if (fsUp != L"NTFS" && fsUp != L"FAT32") return E_INVALIDARG;

    ComScope com;
    HRESULT hr = com.Init();
    if (FAILED(hr)) return hr;

    IVdsService* svc = nullptr;
    hr = LoadVdsService(&svc);
    if (FAILED(hr)) return hr;

    IVdsVolume* vol = nullptr;
    hr = FindVolumeByLetter(svc, NormalizeLetterPath(volLetter), &vol);
    SAFE_RELEASE(svc);
    if (FAILED(hr)) return hr;

    std::wstring curFs;
    if (SUCCEEDED(GetFileSystemNameUpper(vol, &curFs)) && !IsExtendShrinkSupportedFs(curFs)) {
        SAFE_RELEASE(vol);
        return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
    }

    IVdsPack* pack = nullptr;
    hr = vol->GetPack(&pack);
    if (FAILED(hr)) { SAFE_RELEASE(vol); return hr; }

    GUID diskId;
    ULONGLONG endOffset = 0;
    hr = GetSingleDiskEndOffset(vol, &diskId, &endOffset);
    if (FAILED(hr)) { SAFE_RELEASE(pack); SAFE_RELEASE(vol); return hr; }

    IVdsDisk* disk = nullptr;
    hr = FindDiskById(pack, diskId, &disk);
    if (FAILED(hr)) { SAFE_RELEASE(pack); SAFE_RELEASE(vol); return hr; }

    ULONGLONG bytesReq = (ULONGLONG)sizeMB * 1024ULL * 1024ULL;

    IVdsAsync* shrinkAsync = nullptr;
    hr = vol->Shrink(bytesReq, &shrinkAsync);
    if (FAILED(hr)) { SAFE_RELEASE(disk); SAFE_RELEASE(pack); SAFE_RELEASE(vol); return hr; }

    hr = WaitAsync(shrinkAsync, nullptr);
    if (FAILED(hr)) { SAFE_RELEASE(disk); SAFE_RELEASE(pack); SAFE_RELEASE(vol); return hr; }

    // recompute new end and free extent
    ULONGLONG newEnd = 0;
    GUID diskId2;
    hr = GetSingleDiskEndOffset(vol, &diskId2, &newEnd);
    if (FAILED(hr) || memcmp(&diskId, &diskId2, sizeof(GUID)) != 0) {
        SAFE_RELEASE(disk); SAFE_RELEASE(pack); SAFE_RELEASE(vol);
        return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
    }

    ULONGLONG freeBytes = 0;
    hr = GetFreeExtentAtOffset(disk, newEnd, &freeBytes);
    if (FAILED(hr) || freeBytes < bytesReq) {
        SAFE_RELEASE(disk); SAFE_RELEASE(pack); SAFE_RELEASE(vol);
        return HRESULT_FROM_WIN32(ERROR_DISK_FULL);
    }

    IVdsVolume* newVol = nullptr;
    hr = CreateSimpleVolumeOnDisk(pack, diskId, bytesReq, &newVol);
    if (FAILED(hr)) { SAFE_RELEASE(disk); SAFE_RELEASE(pack); SAFE_RELEASE(vol); return hr; }

    // format new vol
    IVdsVolumeMF2* mf2 = nullptr;
    hr = newVol->QueryInterface(IID_IVdsVolumeMF2, (void**)&mf2);
    if (FAILED(hr)) { SAFE_RELEASE(newVol); SAFE_RELEASE(disk); SAFE_RELEASE(pack); SAFE_RELEASE(vol); return hr; }

    IVdsAsync* fmtAsync = nullptr;
    hr = mf2->FormatEx(
        const_cast<LPWSTR>(fsUp.c_str()),
        0, 0,
        const_cast<LPWSTR>(label),
        TRUE, TRUE, FALSE,
        &fmtAsync
    );
    SAFE_RELEASE(mf2);
    if (FAILED(hr)) { SAFE_RELEASE(newVol); SAFE_RELEASE(disk); SAFE_RELEASE(pack); SAFE_RELEASE(vol); return hr; }

    hr = WaitAsync(fmtAsync, nullptr);
    if (FAILED(hr)) { SAFE_RELEASE(newVol); SAFE_RELEASE(disk); SAFE_RELEASE(pack); SAFE_RELEASE(vol); return hr; }

    // assign letter
    wchar_t want = NormalizeSingleLetter(desiredLetter);
    wchar_t target = 0;

    if (want) {
        if (!IsDriveLetterFree(want)) {
            SAFE_RELEASE(newVol); SAFE_RELEASE(disk); SAFE_RELEASE(pack); SAFE_RELEASE(vol);
            return HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS);
        }
        target = want;
    } else {
        target = PickFreeDriveLetter();
        if (!target) {
            SAFE_RELEASE(newVol); SAFE_RELEASE(disk); SAFE_RELEASE(pack); SAFE_RELEASE(vol);
            return HRESULT_FROM_WIN32(ERROR_NO_MORE_FILES);
        }
    }

    hr = AssignDriveLetter(newVol, target);
    if (FAILED(hr)) { SAFE_RELEASE(newVol); SAFE_RELEASE(disk); SAFE_RELEASE(pack); SAFE_RELEASE(vol); return hr; }

    outNewLetter[0] = target;
    outNewLetter[1] = L':';
    outNewLetter[2] = 0;

    SAFE_RELEASE(newVol);
    SAFE_RELEASE(disk);
    SAFE_RELEASE(pack);
    SAFE_RELEASE(vol);
    return S_OK;
}

BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) { return TRUE; }
