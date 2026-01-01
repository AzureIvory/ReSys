#include <windows.h>
#include <vds.h>
#include <string>
#include <algorithm>
#include <objbase.h>
#include <cstdio>

#pragma comment(lib, "ole32.lib")

#define SAFE_RELEASE(p) do { if ((p) != nullptr) { (p)->Release(); (p) = nullptr; } } while (0)

static std::wstring ToUpperCopy(std::wstring s) {
    for (auto& ch : s) if (ch >= L'a' && ch <= L'z') ch = ch - L'a' + L'A';
    return s;
}
static std::wstring ToLowerCopy(std::wstring s) {
    for (auto& ch : s) if (ch >= L'A' && ch <= L'Z') ch = ch - L'A' + L'a';
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

static void PrintHr(HRESULT hr, const wchar_t* where) {
    wchar_t* msg = nullptr;
    DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    DWORD lang = MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT);
    DWORD n = FormatMessageW(flags, nullptr, (DWORD)hr, lang, (LPWSTR)&msg, 0, nullptr);
    if (n && msg) {
        while (n && (msg[n - 1] == L'\r' || msg[n - 1] == L'\n')) msg[--n] = 0;
        std::fwprintf(stderr, L"[!] %s failed: hr=0x%08X (%s)\n", where, (unsigned)hr, msg);
        LocalFree(msg);
    } else {
        std::fwprintf(stderr, L"[!] %s failed: hr=0x%08X\n", where, (unsigned)hr);
    }

    if (hr == (HRESULT)0x80040154) {
        std::fwprintf(stderr,
            L"    Tip: 0x80040154 = Class not registered. In x64 WinPE, run the x64 build.\n");
    }
}

struct ComScope {
    bool needUninit = false;

    HRESULT Init() {
        HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        if (hr == RPC_E_CHANGED_MODE) {
            needUninit = false;
        } else if (SUCCEEDED(hr)) {
            needUninit = true;
        } else {
            return hr;
        }

        HRESULT hrSec = CoInitializeSecurity(
            nullptr, -1, nullptr, nullptr,
            RPC_C_AUTHN_LEVEL_CONNECT,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            nullptr, EOAC_NONE, nullptr
        );
        if (FAILED(hrSec) && hrSec != RPC_E_TOO_LATE) return hrSec;

        return S_OK;
    }

    ~ComScope() { if (needUninit) CoUninitialize(); }
};

static HRESULT LoadVdsService(IVdsService** ppService) {
    if (!ppService) return E_INVALIDARG;
    *ppService = nullptr;

    IVdsServiceLoader* loader = nullptr;

    // CLSID_VdsLoader = {9C38ED61-D565-4728-AEEE-C80952F0ECDE}
    CLSID clsidVdsLoader;
    HRESULT hr = CLSIDFromString(L"{9C38ED61-D565-4728-AEEE-C80952F0ECDE}", &clsidVdsLoader);
    if (FAILED(hr)) return hr;

    hr = CoCreateInstance(clsidVdsLoader, nullptr, CLSCTX_LOCAL_SERVER,
                          __uuidof(IVdsServiceLoader), (void**)&loader);
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
    HRESULT hr = async->Wait(&hrResult, outOpt ? outOpt : &outLocal);
    SAFE_RELEASE(async);

    if (!outOpt && outLocal.type == VDS_ASYNCOUT_CREATEVOLUME && outLocal.cv.pVolumeUnk) {
        outLocal.cv.pVolumeUnk->Release();
        outLocal.cv.pVolumeUnk = nullptr;
    }
    return FAILED(hr) ? hr : hrResult;
}

static HRESULT WaitAsyncWithProgress(IVdsAsync* async, const wchar_t* stage, VDS_ASYNC_OUTPUT* outOpt /*nullable*/)
{
    if (!async) return E_INVALIDARG;

    const HRESULT VDS_E_OPERATION_PENDING_HR = (HRESULT)0x80042409; // VDS_E_OPERATION_PENDING
    HRESULT hrResult = VDS_E_OPERATION_PENDING_HR;
    ULONG pct = 0;

    for (;;) {
        HRESULT hr = async->QueryStatus(&hrResult, &pct);
        if (FAILED(hr)) {
            SAFE_RELEASE(async);
            return hr;
        }
        std::wprintf(L"\r[..] %s: %lu%%", stage ? stage : L"working", pct);
        if (hrResult != VDS_E_OPERATION_PENDING_HR) break;
        Sleep(500);
    }
    std::wprintf(L"\n");

    VDS_ASYNC_OUTPUT outLocal = {};
    HRESULT hrWait = async->Wait(&hrResult, outOpt ? outOpt : &outLocal);
    SAFE_RELEASE(async);

    if (!outOpt && outLocal.type == VDS_ASYNCOUT_CREATEVOLUME && outLocal.cv.pVolumeUnk) {
        outLocal.cv.pVolumeUnk->Release();
        outLocal.cv.pVolumeUnk = nullptr;
    }

    return FAILED(hrWait) ? hrWait : hrResult;
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
        hr = unkProv->QueryInterface(__uuidof(IVdsProvider), (void**)&provider);
        SAFE_RELEASE(unkProv);
        if (FAILED(hr)) continue;

        IVdsSwProvider* sw = nullptr;
        hr = provider->QueryInterface(__uuidof(IVdsSwProvider), (void**)&sw);
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
            hr = unkPack->QueryInterface(__uuidof(IVdsPack), (void**)&pack);
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
                hr = unkVol->QueryInterface(__uuidof(IVdsVolume), (void**)&vol);
                SAFE_RELEASE(unkVol);
                if (FAILED(hr)) continue;

                IVdsVolumeMF* mf = nullptr;
                hr = vol->QueryInterface(__uuidof(IVdsVolumeMF), (void**)&mf);
                if (SUCCEEDED(hr) && mf) {
                    LPWSTR* paths = nullptr;
                    LONG nPaths = 0;
                    hr = mf->QueryAccessPaths(&paths, &nPaths);
                    SAFE_RELEASE(mf);

                    if (SUCCEEDED(hr) && nPaths > 0 && paths) {
                        bool hit = false;
                        for (LONG i = 0; i < nPaths; i++) {
                            if (!paths[i]) continue;
                            std::wstring p = ToUpperCopy(std::wstring(paths[i]));
                            if (p.size() == 2 && p[1] == L':') p.push_back(L'\\'); // "E:" -> "E:\"
                            if (p == want) { hit = true; break; }
                        }
                        FreeAccessPaths(paths, nPaths);

                        if (hit) {
                            SAFE_RELEASE(enumVol);
                            SAFE_RELEASE(enumPack);
                            SAFE_RELEASE(enumProv);
                            *outVol = vol;
                            return S_OK;
                        }
                    } else {
                        FreeAccessPaths(paths, nPaths);
                    }
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
    HRESULT hr = vol->QueryInterface(__uuidof(IVdsVolumeMF2), (void**)&mf2);
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
    hr = unkPlex->QueryInterface(__uuidof(IVdsVolumePlex), (void**)&plex);
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
        hr = unkDisk->QueryInterface(__uuidof(IVdsDisk), (void**)&disk);
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
    hr = WaitAsyncWithProgress(async, L"createVolume(VDS)", &out);
    if (FAILED(hr)) {
        if (out.type == VDS_ASYNCOUT_CREATEVOLUME && out.cv.pVolumeUnk) out.cv.pVolumeUnk->Release();
        return hr;
    }

    if (out.type != VDS_ASYNCOUT_CREATEVOLUME || !out.cv.pVolumeUnk) return E_FAIL;

    IVdsVolume* newVol = nullptr;
    hr = out.cv.pVolumeUnk->QueryInterface(__uuidof(IVdsVolume), (void**)&newVol);
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
    HRESULT hr = vol->QueryInterface(__uuidof(IVdsVolumeMF), (void**)&mf);
    if (FAILED(hr)) return hr;

    std::wstring path;
    path.push_back(letterUpper);
    path.append(L":\\");
    hr = mf->AddAccessPath(const_cast<LPWSTR>(path.c_str()));
    SAFE_RELEASE(mf);
    return hr;
}

// ---------------- shrink helpers ----------------

static HRESULT ShrinkViaVdsRelaxed(IVdsVolume* vol, ULONGLONG desiredBytes)
{
    if (!vol) return E_INVALIDARG;

    IVdsVolumeShrink* vs = nullptr;
    HRESULT hr = vol->QueryInterface(__uuidof(IVdsVolumeShrink), (void**)&vs);
    if (FAILED(hr)) return hr;

    // 先估算最多能回收多少，避免无意义的长时间尝试
    ULONGLONG maxReclaim = 0;
    HRESULT hrQ = vs->QueryMaxReclaimableBytes(&maxReclaim);
    if (SUCCEEDED(hrQ)) {
        if (maxReclaim == 0) { SAFE_RELEASE(vs); return HRESULT_FROM_WIN32(ERROR_DISK_FULL); }
        if (desiredBytes > maxReclaim) desiredBytes = maxReclaim;
    }

    IVdsAsync* async = nullptr;
    // 关键：min=0 => 不强制必须达到 desired（更像磁盘管理 / diskpart）
    hr = vs->Shrink(desiredBytes, 0 /*min*/, &async);
    SAFE_RELEASE(vs);
    if (FAILED(hr)) return hr;

    return WaitAsyncWithProgress(async, L"shrink(VDS)", nullptr);
}

static HRESULT ShrinkViaDiskpart_Stdin(wchar_t driveLetterUpper, int desiredMB, std::wstring* outLogPath /*nullable*/)
{
    wchar_t cwd[MAX_PATH] = L"";
    GetCurrentDirectoryW(MAX_PATH, cwd);

    wchar_t scriptPath[MAX_PATH] = L"";
    swprintf(scriptPath, MAX_PATH, L"%s\\dp_shrink.txt", cwd);

    wchar_t logPath[MAX_PATH] = L"";
    swprintf(logPath, MAX_PATH, L"%s\\dp_shrink.log", cwd);

    if (outLogPath) *outLogPath = logPath;

    // 写脚本（ASCII + CRLF 最稳）
    {
        HANDLE hScript = CreateFileW(scriptPath, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                     FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hScript == INVALID_HANDLE_VALUE) return HRESULT_FROM_WIN32(GetLastError());

        char buf[256] = {0};
        int n = sprintf_s(buf, sizeof(buf),
            "select volume %c\r\n"
            "shrink desired=%d minimum=0\r\n"
            "exit\r\n",
            (char)driveLetterUpper, desiredMB);

        DWORD written = 0;
        BOOL ok = WriteFile(hScript, buf, (DWORD)n, &written, nullptr);
        CloseHandle(hScript);
        if (!ok) return HRESULT_FROM_WIN32(GetLastError());
    }

    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = nullptr;
    sa.bInheritHandle = TRUE;

    HANDLE hIn = CreateFileW(scriptPath, GENERIC_READ, FILE_SHARE_READ, &sa, OPEN_EXISTING,
                             FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hIn == INVALID_HANDLE_VALUE) return HRESULT_FROM_WIN32(GetLastError());

    HANDLE hLog = CreateFileW(logPath, GENERIC_WRITE, FILE_SHARE_READ, &sa, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hLog == INVALID_HANDLE_VALUE) { CloseHandle(hIn); return HRESULT_FROM_WIN32(GetLastError()); }

    // 启动 diskpart.exe（无参数），stdin 重定向为脚本
    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput  = hIn;
    si.hStdOutput = hLog;
    si.hStdError  = hLog;

    PROCESS_INFORMATION pi = {};
    wchar_t cmdLine[] = L"diskpart.exe";

    BOOL ok = CreateProcessW(nullptr, cmdLine, nullptr, nullptr, TRUE,
                             CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);

    CloseHandle(hIn);
    CloseHandle(hLog);

    if (!ok) return HRESULT_FROM_WIN32(GetLastError());

    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return (exitCode == 0) ? S_OK : HRESULT_FROM_WIN32(ERROR_GEN_FAILURE);
}

// ---------------- Commands ----------------

static HRESULT CmdFormat(LPCWSTR letter, LPCWSTR fs, LPCWSTR label, BOOL quick) {
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

    std::wstring lbl = label ? std::wstring(label) : L"";

    IVdsVolumeMF2* mf2 = nullptr;
    hr = vol->QueryInterface(__uuidof(IVdsVolumeMF2), (void**)&mf2);
    if (FAILED(hr)) { SAFE_RELEASE(vol); return hr; }

    IVdsAsync* async = nullptr;
    hr = mf2->FormatEx(
        const_cast<LPWSTR>(fsUp.c_str()),
        0, 0,
        const_cast<LPWSTR>(lbl.c_str()),
        TRUE,
        quick,
        FALSE,
        &async
    );
    SAFE_RELEASE(mf2);
    SAFE_RELEASE(vol);
    if (FAILED(hr)) return hr;

    return WaitAsyncWithProgress(async, L"format(VDS)", nullptr);
}

static HRESULT CmdDelete(LPCWSTR volLetter) {
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

static HRESULT CmdMerge(LPCWSTR volLetter, int sizeMB) {
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

    return WaitAsyncWithProgress(async, L"extend(VDS)", nullptr);
}

static HRESULT CmdSplit(
    LPCWSTR volLetter, int sizeMB,
    LPCWSTR fs, LPCWSTR label,
    LPCWSTR desiredLetter,
    std::wstring* outNewLetter
) {
    if (!outNewLetter) return E_INVALIDARG;
    outNewLetter->clear();
    if (sizeMB <= 0) return E_INVALIDARG;

    std::wstring fsUp = ToUpperCopy(fs ? std::wstring(fs) : L"");
    if (fsUp != L"NTFS" && fsUp != L"FAT32") return E_INVALIDARG;

    std::wstring lbl = label ? std::wstring(label) : L"";

    ComScope com;
    HRESULT hr = com.Init();
    if (FAILED(hr)) return hr;

    // 第一次加载 VDS，拿 oldEnd
    IVdsService* svc = nullptr;
    hr = LoadVdsService(&svc);
    if (FAILED(hr)) return hr;

    IVdsVolume* vol = nullptr;
    hr = FindVolumeByLetter(svc, NormalizeLetterPath(volLetter), &vol);
    if (FAILED(hr)) { SAFE_RELEASE(svc); return hr; }

    std::wstring curFs;
    if (SUCCEEDED(GetFileSystemNameUpper(vol, &curFs)) && !IsExtendShrinkSupportedFs(curFs)) {
        SAFE_RELEASE(vol); SAFE_RELEASE(svc);
        return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
    }

    GUID diskIdOld = GUID_NULL;
    ULONGLONG oldEnd = 0;
    hr = GetSingleDiskEndOffset(vol, &diskIdOld, &oldEnd);
    if (FAILED(hr)) { SAFE_RELEASE(vol); SAFE_RELEASE(svc); return hr; }

    ULONGLONG reqBytes = (ULONGLONG)sizeMB * 1024ULL * 1024ULL;

    // 1) 先 VDS shrink（min=0）
    HRESULT hrShrink = ShrinkViaVdsRelaxed(vol, reqBytes);

    // 2) VDS 失败 => diskpart
    if (FAILED(hrShrink)) {
        PrintHr(hrShrink, L"shrink(VDS)");
        std::fwprintf(stderr, L"[!] VDS shrink failed, fallback to diskpart...\n");

        wchar_t letterUp = NormalizeSingleLetter(volLetter);
        if (!letterUp) { SAFE_RELEASE(vol); SAFE_RELEASE(svc); return E_INVALIDARG; }

        std::wstring logPath;
        std::wprintf(L"[..] shrink(diskpart) running...\n");
        HRESULT hrDp = ShrinkViaDiskpart_Stdin(letterUp, sizeMB, &logPath);
        if (FAILED(hrDp)) {
            PrintHr(hrDp, L"shrink(diskpart)");
            std::fwprintf(stderr, L"[!] diskpart log: %s\n", logPath.c_str());
            SAFE_RELEASE(vol); SAFE_RELEASE(svc);
            return hrDp;
        }
        std::wprintf(L"[OK] diskpart shrink finished. log: %s\n", logPath.c_str());
    }

    // shrink 完后：释放旧对象，重新加载 VDS，确保拿到新布局（尤其 diskpart 做的 shrink）
    SAFE_RELEASE(vol);
    SAFE_RELEASE(svc);

    hr = LoadVdsService(&svc);
    if (FAILED(hr)) return hr;

    hr = FindVolumeByLetter(svc, NormalizeLetterPath(volLetter), &vol);
    if (FAILED(hr)) { SAFE_RELEASE(svc); return hr; }

    GUID diskIdNew = GUID_NULL;
    ULONGLONG newEnd = 0;
    hr = GetSingleDiskEndOffset(vol, &diskIdNew, &newEnd);
    if (FAILED(hr)) { SAFE_RELEASE(vol); SAFE_RELEASE(svc); return hr; }

    if (memcmp(&diskIdOld, &diskIdNew, sizeof(GUID)) != 0 || newEnd >= oldEnd) {
        SAFE_RELEASE(vol); SAFE_RELEASE(svc);
        return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
    }

    ULONGLONG reclaimed = oldEnd - newEnd;
    if (reclaimed == 0) {
        SAFE_RELEASE(vol); SAFE_RELEASE(svc);
        return HRESULT_FROM_WIN32(ERROR_DISK_FULL);
    }
    if (reclaimed < reqBytes) {
        std::wprintf(L"[!] requested=%llu bytes, reclaimed=%llu bytes. Will create smaller volume.\n",
                     reqBytes, reclaimed);
        reqBytes = reclaimed;
    }

    // 继续用你原来的 VDS 创建 + 格式化 + 分配盘符
    IVdsPack* pack = nullptr;
    hr = vol->GetPack(&pack);
    if (FAILED(hr)) { SAFE_RELEASE(vol); SAFE_RELEASE(svc); return hr; }

    IVdsDisk* disk = nullptr;
    hr = FindDiskById(pack, diskIdNew, &disk);
    if (FAILED(hr)) { SAFE_RELEASE(pack); SAFE_RELEASE(vol); SAFE_RELEASE(svc); return hr; }

    ULONGLONG freeBytes = 0;
    hr = GetFreeExtentAtOffset(disk, newEnd, &freeBytes);
    if (FAILED(hr) || freeBytes < reqBytes) {
        SAFE_RELEASE(disk); SAFE_RELEASE(pack); SAFE_RELEASE(vol); SAFE_RELEASE(svc);
        return HRESULT_FROM_WIN32(ERROR_DISK_FULL);
    }

    IVdsVolume* newVol = nullptr;
    hr = CreateSimpleVolumeOnDisk(pack, diskIdNew, reqBytes, &newVol);
    if (FAILED(hr)) { SAFE_RELEASE(disk); SAFE_RELEASE(pack); SAFE_RELEASE(vol); SAFE_RELEASE(svc); return hr; }

    // format 新卷（quick=true）
    IVdsVolumeMF2* mf2 = nullptr;
    hr = newVol->QueryInterface(__uuidof(IVdsVolumeMF2), (void**)&mf2);
    if (FAILED(hr)) { SAFE_RELEASE(newVol); SAFE_RELEASE(disk); SAFE_RELEASE(pack); SAFE_RELEASE(vol); SAFE_RELEASE(svc); return hr; }

    IVdsAsync* fmtAsync = nullptr;
    hr = mf2->FormatEx(
        const_cast<LPWSTR>(fsUp.c_str()),
        0, 0,
        const_cast<LPWSTR>(lbl.c_str()),
        TRUE, TRUE, FALSE,
        &fmtAsync
    );
    SAFE_RELEASE(mf2);
    if (FAILED(hr)) { SAFE_RELEASE(newVol); SAFE_RELEASE(disk); SAFE_RELEASE(pack); SAFE_RELEASE(vol); SAFE_RELEASE(svc); return hr; }

    hr = WaitAsyncWithProgress(fmtAsync, L"formatNew(VDS)", nullptr);
    if (FAILED(hr)) { SAFE_RELEASE(newVol); SAFE_RELEASE(disk); SAFE_RELEASE(pack); SAFE_RELEASE(vol); SAFE_RELEASE(svc); return hr; }

    // assign letter
    wchar_t want = NormalizeSingleLetter(desiredLetter);
    wchar_t target = 0;

    if (want) {
        if (!IsDriveLetterFree(want)) {
            SAFE_RELEASE(newVol); SAFE_RELEASE(disk); SAFE_RELEASE(pack); SAFE_RELEASE(vol); SAFE_RELEASE(svc);
            return HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS);
        }
        target = want;
    } else {
        target = PickFreeDriveLetter();
        if (!target) {
            SAFE_RELEASE(newVol); SAFE_RELEASE(disk); SAFE_RELEASE(pack); SAFE_RELEASE(vol); SAFE_RELEASE(svc);
            return HRESULT_FROM_WIN32(ERROR_NO_MORE_FILES);
        }
    }

    hr = AssignDriveLetter(newVol, target);
    if (FAILED(hr)) { SAFE_RELEASE(newVol); SAFE_RELEASE(disk); SAFE_RELEASE(pack); SAFE_RELEASE(vol); SAFE_RELEASE(svc); return hr; }

    *outNewLetter = std::wstring(1, target) + L":";

    SAFE_RELEASE(newVol);
    SAFE_RELEASE(disk);
    SAFE_RELEASE(pack);
    SAFE_RELEASE(vol);
    SAFE_RELEASE(svc);
    return S_OK;
}

static void PrintUsage() {
    std::wprintf(
        L"DiskTool.exe commands:\n"
        L"  format <DriveLetter> <NTFS|FAT32> <Label> [quick(0/1)]\n"
        L"  delete <DriveLetter>\n"
        L"  merge  <DriveLetter> <SizeMB(0=all free)>\n"
        L"  split  <DriveLetter> <SizeMB> <NTFS|FAT32> <Label> [NewDriveLetter]\n"
        L"\nExamples:\n"
        L"  DiskTool.exe format E NTFS DATA 1\n"
        L"  DiskTool.exe merge  E 10240\n"
        L"  DiskTool.exe split  E 5120 NTFS NEWVOL F\n"
    );
}

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) { PrintUsage(); return 2; }

    std::wstring cmd = ToLowerCopy(argv[1]);
    HRESULT hr = E_INVALIDARG;

    if (cmd == L"format") {
        if (argc < 5) { PrintUsage(); return 2; }
        BOOL quick = TRUE;
        if (argc >= 6) quick = (wcstol(argv[5], nullptr, 10) != 0);
        hr = CmdFormat(argv[2], argv[3], argv[4], quick);
        if (FAILED(hr)) { PrintHr(hr, L"format"); return 1; }
        std::wprintf(L"[OK] format done.\n");
        return 0;
    }
    else if (cmd == L"delete") {
        if (argc < 3) { PrintUsage(); return 2; }
        hr = CmdDelete(argv[2]);
        if (FAILED(hr)) { PrintHr(hr, L"delete"); return 1; }
        std::wprintf(L"[OK] delete done.\n");
        return 0;
    }
    else if (cmd == L"merge") {
        if (argc < 4) { PrintUsage(); return 2; }
        int sizeMB = (int)wcstol(argv[3], nullptr, 10);
        hr = CmdMerge(argv[2], sizeMB);
        if (FAILED(hr)) { PrintHr(hr, L"merge"); return 1; }
        std::wprintf(L"[OK] merge done.\n");
        return 0;
    }
    else if (cmd == L"split") {
        if (argc < 6) { PrintUsage(); return 2; }
        int sizeMB = (int)wcstol(argv[3], nullptr, 10);
        LPCWSTR desired = (argc >= 7) ? argv[6] : nullptr;
        std::wstring newLetter;
        hr = CmdSplit(argv[2], sizeMB, argv[4], argv[5], desired, &newLetter);
        if (FAILED(hr)) { PrintHr(hr, L"split"); return 1; }
        std::wprintf(L"[OK] split done, new volume letter: %s\n", newLetter.c_str());
        return 0;
    }

    PrintUsage();
    return 2;
}
