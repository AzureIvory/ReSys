package dism

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

type Handle = windows.Handle

const (
	WIM_GENERIC_READ  = 0x80000000
	WIM_GENERIC_WRITE = 0x40000000
	WIM_GENERIC_MOUNT = 0x20000000

	WIM_CREATE_NEW      = 1
	WIM_CREATE_ALWAYS   = 2
	WIM_OPEN_EXISTING   = 3
	WIM_OPEN_ALWAYS     = 4
	WIM_COMPRESS_NONE   = 0
	WIM_COMPRESS_XPRESS = 1
	WIM_COMPRESS_LZX    = 2
	WIM_COMPRESS_LZMS   = 3

	INVALID_CALLBACK_VALUE = 0xFFFFFFFF
)

// 消息（WIM_MSG = 0x9476，PROGRESS=+2）
const (
	WIM_MSG_PROGRESS = 0x00009478
	WIM_MSG_PROCESS  = 0x00009479
	WIM_MSG_SCANNING = 0x0000947A
	WIM_MSG_COMPRESS = 0x0000947E
	WIM_MSG_ERROR    = 0x0000947F

	WIM_MSG_SUCCESS     = 0x00000000
	WIM_MSG_ABORT_IMAGE = 0xFFFFFFFF
)

// ---- DLL 封装 ----

type callbackCtx struct {
	progress uint32 // 0..100
	// 可扩展：cancel uint32 等
}

type API struct {
	dll *windows.LazyDLL

	pCreateFile                *windows.LazyProc
	pCloseHandle               *windows.LazyProc
	pSetTemporaryPath          *windows.LazyProc
	pLoadImage                 *windows.LazyProc
	pGetImageCount             *windows.LazyProc
	pApplyImage                *windows.LazyProc
	pCaptureImage              *windows.LazyProc
	pGetImageInformation       *windows.LazyProc
	pSetImageInformation       *windows.LazyProc
	pRegisterMessageCallback   *windows.LazyProc
	pUnregisterMessageCallback *windows.LazyProc

	// 可选（有些环境/版本不一定可用）
	pMountImage   *windows.LazyProc
	pUnmountImage *windows.LazyProc

	// kernel32!LocalFree（释放 WIMGetImageInformation 返回的 buffer）
	kernel32   *windows.LazyDLL
	pLocalFree *windows.LazyProc

	cb  uintptr
	ctx *callbackCtx
}

// NewWimg 加载/绑定 wimgapi.dll，返回可调用的 API 封装（支持自定义 DLL 路径）。
func NewWimg(dllPath string) (*API, error) {
	var dll *windows.LazyDLL

	// 1) 优先：程序目录同级 wimgapi.dll
	if dllPath == "" {
		if exe, err := os.Executable(); err == nil {
			local := filepath.Join(filepath.Dir(exe), "wimgapi.dll")
			if _, err2 := os.Stat(local); err2 == nil {
				dllPath = local
			}
		}
	}

	// 2) 指定路径 or 系统版本
	if dllPath != "" {
		dll = windows.NewLazyDLL(dllPath)
	} else {
		// 系统 DLL：WOW64 下会自动走 SysWOW64 的 32 位版本（这正是我们需要的）
		dll = windows.NewLazySystemDLL("wimgapi.dll")
	}

	api := &API{
		dll:      dll,
		kernel32: windows.NewLazySystemDLL("kernel32.dll"),
		ctx:      &callbackCtx{},
	}

	// 先 Load 一下，确保路径/搜索能成功
	if err := api.dll.Load(); err != nil {
		return nil, fmt.Errorf("load wimgapi.dll failed: %w", err)
	}

	// 绑定必需函数
	api.pCreateFile = api.dll.NewProc("WIMCreateFile")
	api.pCloseHandle = api.dll.NewProc("WIMCloseHandle")
	api.pSetTemporaryPath = api.dll.NewProc("WIMSetTemporaryPath")
	api.pLoadImage = api.dll.NewProc("WIMLoadImage")
	api.pGetImageCount = api.dll.NewProc("WIMGetImageCount")
	api.pApplyImage = api.dll.NewProc("WIMApplyImage")
	api.pCaptureImage = api.dll.NewProc("WIMCaptureImage")
	api.pGetImageInformation = api.dll.NewProc("WIMGetImageInformation")
	api.pSetImageInformation = api.dll.NewProc("WIMSetImageInformation")
	api.pRegisterMessageCallback = api.dll.NewProc("WIMRegisterMessageCallback")
	api.pUnregisterMessageCallback = api.dll.NewProc("WIMUnregisterMessageCallback")

	// 校验必需函数是否存在
	required := []*windows.LazyProc{
		api.pCreateFile, api.pCloseHandle, api.pSetTemporaryPath, api.pLoadImage,
		api.pGetImageCount, api.pApplyImage, api.pCaptureImage, api.pGetImageInformation,
		api.pSetImageInformation, api.pRegisterMessageCallback, api.pUnregisterMessageCallback,
	}
	for _, p := range required {
		if err := p.Find(); err != nil {
			return nil, fmt.Errorf("missing proc %v: %w", p.Name, err)
		}
	}

	// 可选函数
	api.pMountImage = api.dll.NewProc("WIMMountImage")
	_ = api.pMountImage.Find() // 忽略错误：不支持就当不可用
	api.pUnmountImage = api.dll.NewProc("WIMUnmountImage")
	_ = api.pUnmountImage.Find()

	// LocalFree
	api.pLocalFree = api.kernel32.NewProc("LocalFree")
	if err := api.pLocalFree.Find(); err != nil {
		return nil, fmt.Errorf("find kernel32!LocalFree failed: %w", err)
	}

	// 回调函数指针
	api.cb = syscall.NewCallback(api.messageCallback)

	return api, nil
}

// lastErr 返回当前线程的 Windows LastError（用于 DLL 调用失败时取错因）。
func lastErr() error {
	// x/sys/windows 会把 GetLastError 映射成 syscall.Errno
	return windows.GetLastError()
}

// messageCallback WIMGAPI 消息回调：采集进度，遇到错误尝试中止镜像操作。
//
// DWORD CALLBACK msgproc(DWORD msgId, WPARAM wParam, LPARAM lParam, PVOID userData)
func (a *API) messageCallback(msgID, wParam, lParam, userData uintptr) uintptr {
	switch uint32(msgID) {
	case WIM_MSG_PROGRESS:
		p := uint32(wParam)
		if p > 100 {
			p = 100
		}
		atomic.StoreUint32(&a.ctx.progress, p)
	case WIM_MSG_ERROR:
		// 注意：真正“可控取消”通常建议在 WIM_MSG_PROCESS 返回 ABORT
		// 这里保持简单：遇到 error 消息就尝试 abort
		return WIM_MSG_ABORT_IMAGE
	}
	return WIM_MSG_SUCCESS
}

// Progress 返回最近一次回调上报的进度百分比（0..100）。
func (a *API) Progress() uint8 {
	return uint8(atomic.LoadUint32(&a.ctx.progress))
}

// ---- API 封装 ----

// CreateFile 打开/创建 WIM 文件并返回句柄与创建方式（creation），失败返回系统错误。
func (a *API) CreateFile(path string, access, disposition, flagsAndAttrs, compression uint32) (Handle, uint32, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, 0, err
	}
	var creation uint32

	r1, _, _ := a.pCreateFile.Call(
		uintptr(unsafe.Pointer(p)),
		uintptr(access),
		uintptr(disposition),
		uintptr(flagsAndAttrs),
		uintptr(compression),
		uintptr(unsafe.Pointer(&creation)),
	)
	h := Handle(r1)
	if h == 0 {
		return 0, creation, lastErr()
	}
	return h, creation, nil
}

// CloseHandle 关闭 WIM/WIMGAPI 相关句柄。
func (a *API) CloseHandle(h Handle) error {
	r1, _, _ := a.pCloseHandle.Call(uintptr(h))
	if r1 == 0 {
		return lastErr()
	}
	return nil
}

// SetTemporaryPath 设置 WIM 操作的临时目录（通常指向系统 Temp）。
func (a *API) SetTemporaryPath(hWim Handle, tempDir string) error {
	p, err := windows.UTF16PtrFromString(tempDir)
	if err != nil {
		return err
	}
	r1, _, _ := a.pSetTemporaryPath.Call(uintptr(hWim), uintptr(unsafe.Pointer(p)))
	if r1 == 0 {
		return lastErr()
	}
	return nil
}

// LoadImage 通过索引加载镜像，返回 image 句柄（用完需 CloseHandle）。
func (a *API) LoadImage(hWim Handle, index uint32) (Handle, error) {
	r1, _, _ := a.pLoadImage.Call(uintptr(hWim), uintptr(index))
	hImg := Handle(r1)
	if hImg == 0 {
		return 0, lastErr()
	}
	return hImg, nil
}

// GetImageCount 返回 WIM 内镜像数量（无需额外错误返回）。
func (a *API) GetImageCount(hWim Handle) uint32 {
	r1, _, _ := a.pGetImageCount.Call(uintptr(hWim))
	return uint32(r1)
}

// RegisterCallback 注册消息回调并重置进度；返回 callback id（失败则为 INVALID）。
func (a *API) RegisterCallback(hWim Handle) (uint32, error) {
	atomic.StoreUint32(&a.ctx.progress, 0)

	r1, _, _ := a.pRegisterMessageCallback.Call(
		uintptr(hWim),
		a.cb,
		uintptr(unsafe.Pointer(a.ctx)),
	)
	id := uint32(r1)
	if id == INVALID_CALLBACK_VALUE {
		return id, lastErr()
	}
	return id, nil
}

// UnregisterCallback 解除消息回调注册（建议在不再需要时调用）。
func (a *API) UnregisterCallback(hWim Handle) {
	// 文档：不再需要时调用 WIMUnregisterMessageCallback :contentReference[oaicite:3]{index=3}
	_, _, _ = a.pUnregisterMessageCallback.Call(uintptr(hWim), a.cb)
}

// ApplyImage 将已加载的镜像应用到目标目录（解包/展开）。
func (a *API) ApplyImage(hImg Handle, targetDir string, flags uint32) error {
	p, err := windows.UTF16PtrFromString(targetDir)
	if err != nil {
		return err
	}
	r1, _, _ := a.pApplyImage.Call(uintptr(hImg), uintptr(unsafe.Pointer(p)), uintptr(flags))
	if r1 == 0 {
		return lastErr()
	}
	return nil
}

// CaptureImage 从源目录捕获生成镜像，返回 image 句柄（用完需 CloseHandle）。
func (a *API) CaptureImage(hWim Handle, sourceDir string, flags uint32) (Handle, error) {
	p, err := windows.UTF16PtrFromString(sourceDir)
	if err != nil {
		return 0, err
	}
	r1, _, _ := a.pCaptureImage.Call(uintptr(hWim), uintptr(unsafe.Pointer(p)), uintptr(flags))
	hImg := Handle(r1)
	if hImg == 0 {
		return 0, lastErr()
	}
	return hImg, nil
}

// GetImageInformation 读取镜像 XML 信息（内部负责 LocalFree 释放返回缓冲区）。
func (a *API) GetImageInformation(h Handle) (string, error) {
	var pv unsafe.Pointer
	var cb uint32

	r1, _, _ := a.pGetImageInformation.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(&pv)),
		uintptr(unsafe.Pointer(&cb)),
	)
	if r1 == 0 {
		return "", lastErr()
	}

	// 文档要求：用 LocalFree 释放 pv 指向的内存 :contentReference[oaicite:4]{index=4}
	defer func() {
		if pv != nil {
			_, _, _ = a.pLocalFree.Call(uintptr(pv))
		}
	}()

	if pv == nil || cb == 0 {
		return "", nil
	}

	u16len := int(cb / 2)
	u16s := unsafe.Slice((*uint16)(pv), u16len)

	// 去掉末尾 0
	n := u16len
	for n > 0 && u16s[n-1] == 0 {
		n--
	}
	runes := utf16.Decode(u16s[:n])
	return string(runes), nil
}

// SetImageInformation 写入镜像 XML 信息（xml 不能为空）。
func (a *API) SetImageInformation(hImg Handle, xml string) error {
	u16 := utf16.Encode([]rune(xml))
	if len(u16) == 0 {
		return errors.New("xml is empty")
	}
	cb := uint32(len(u16) * 2)

	r1, _, _ := a.pSetImageInformation.Call(
		uintptr(hImg),
		uintptr(unsafe.Pointer(&u16[0])),
		uintptr(cb),
	)
	if r1 == 0 {
		return lastErr()
	}
	return nil
}

// MountImage 挂载 WIM 镜像到目录（可选能力；tempDir=nil 表示只读挂载）。
func (a *API) MountImage(mountDir, wimFile string, index uint32, tempDir *string) error {
	// Mount/Unmount：可选（可能需要管理员权限/相关组件）
	// pszTempPath 为 NULL 时只读挂载；非 NULL 时可编辑 :contentReference[oaicite:5]{index=5}
	if err := a.pMountImage.Find(); err != nil {
		return fmt.Errorf("WIMMountImage not available: %w", err)
	}
	mp, _ := windows.UTF16PtrFromString(mountDir)
	wp, _ := windows.UTF16PtrFromString(wimFile)

	var tp *uint16
	if tempDir != nil {
		tp, _ = windows.UTF16PtrFromString(*tempDir)
	}

	r1, _, _ := a.pMountImage.Call(
		uintptr(unsafe.Pointer(mp)),
		uintptr(unsafe.Pointer(wp)),
		uintptr(index),
		uintptr(unsafe.Pointer(tp)),
	)
	if r1 == 0 {
		return lastErr()
	}
	return nil
}

// UnmountImage 卸载挂载点；commit=true 时提交改动，否则丢弃。
func (a *API) UnmountImage(mountDir, wimFile string, index uint32, commit bool) error {
	if err := a.pUnmountImage.Find(); err != nil {
		return fmt.Errorf("WIMUnmountImage not available: %w", err)
	}
	mp, _ := windows.UTF16PtrFromString(mountDir)
	wp, _ := windows.UTF16PtrFromString(wimFile)

	var bCommit uintptr
	if commit {
		bCommit = 1
	}

	r1, _, _ := a.pUnmountImage.Call(
		uintptr(unsafe.Pointer(mp)),
		uintptr(unsafe.Pointer(wp)),
		uintptr(index),
		bCommit,
	)
	if r1 == 0 {
		return lastErr()
	}
	return nil
}

// ---- 一个“高层示例”：Apply with progress poll ----

type ProgressWimg struct {
	Percent uint8
	Status  string
}

// ApplyWithProgress 应用指定索引镜像到目录，并通过轮询将进度推送到 channel（避免回调内阻塞）。
func ApplyWithProgress(api *API, wimPath string, index uint32, targetDir string, progressCh chan<- ProgressWimg) error {
	tempDir := os.TempDir()

	hWim, _, err := api.CreateFile(wimPath, WIM_GENERIC_READ, WIM_OPEN_EXISTING, 0, WIM_COMPRESS_NONE)
	if err != nil {
		return err
	}
	defer api.CloseHandle(hWim)

	_ = api.SetTemporaryPath(hWim, tempDir)

	_, _ = api.RegisterCallback(hWim)
	defer api.UnregisterCallback(hWim)

	// 进度轮询（避免在回调里做阻塞操作）
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		tk := time.NewTicker(120 * time.Millisecond)
		defer tk.Stop()
		var last uint8 = 255
		for {
			select {
			case <-stop:
				return
			case <-tk.C:
				p := api.Progress()
				if p != last && progressCh != nil {
					last = p
					progressCh <- ProgressWimg{Percent: p, Status: fmt.Sprintf("Applying... %d%%", p)}
				}
			}
		}
	}()

	hImg, err := api.LoadImage(hWim, index)
	if err != nil {
		return err
	}
	defer api.CloseHandle(hImg)

	if err := api.ApplyImage(hImg, targetDir, 0); err != nil {
		return err
	}

	if progressCh != nil {
		progressCh <- ProgressWimg{Percent: 100, Status: "Done"}
	}
	return nil
}
