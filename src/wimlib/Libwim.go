package wimlib

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

const (
	NoImage   = 0
	AllImages = -1

	OpenFlagCheckIntegrity = 0x00000001
	OpenFlagWriteAccess    = 0x00000004

	ExtractFlagNoACLs = 0x00000040

	IterateRecursive = 0x00000001
	IterateChildren  = 0x00000002

	wbOK                = 0
	wbErrInvalidArg     = -1
	wbErrNotLoaded      = -2
	wbErrLoadDLL        = -3
	wbErrLoadSymbol     = -4
	wbErrNoMem          = -5
	wbErrBufferTooSmall = -6
	wbErrInternal       = -7

	wbFlagHasIntegrityTable = 1 << 0
	wbFlagOpenedFromFile    = 1 << 1
	wbFlagIsReadonly        = 1 << 2
	wbFlagHasRpfix          = 1 << 3
	wbFlagIsMarkedReadonly  = 1 << 4
	wbFlagSpanned           = 1 << 5
	wbFlagWriteInProgress   = 1 << 6
	wbFlagMetadataOnly      = 1 << 7
	wbFlagResourceOnly      = 1 << 8
	wbFlagPipable           = 1 << 9
)

type wbWimInfo struct {
	GUID            [16]byte
	ImageCount      uint32
	BootIndex       uint32
	WimVersion      uint32
	ChunkSize       uint32
	PartNumber      uint16
	TotalParts      uint16
	CompressionType int32
	TotalBytes      uint64
	Flags           uint32
}

type wbDirEntry struct {
	FullPath   uintptr
	Depth      uint32
	Attributes uint32
}

type Lib struct {
	dllDir string
	dll    *syscall.LazyDLL

	procLoad            *syscall.LazyProc
	procUnload          *syscall.LazyProc
	procOpenWim         *syscall.LazyProc
	procCloseWim        *syscall.LazyProc
	procVerifyWim       *syscall.LazyProc
	procGetWimInfo      *syscall.LazyProc
	procGetImageName    *syscall.LazyProc
	procGetImageDesc    *syscall.LazyProc
	procGetXMLUtf8      *syscall.LazyProc
	procFreeBuffer      *syscall.LazyProc
	procApply           *syscall.LazyProc
	procExtractPathList *syscall.LazyProc
	procListPaths       *syscall.LazyProc
	procFreeDirEntries  *syscall.LazyProc
	procUpdateAdd       *syscall.LazyProc
	procUpdateDelete    *syscall.LazyProc
	procUpdateRename    *syscall.LazyProc
	procOverwrite       *syscall.LazyProc
	procGetLastErrorW   *syscall.LazyProc
}

type WIM struct {
	lib    *Lib
	handle uintptr
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
	Depth      uint32
	Attributes uint32
}

func LibwimLoad() (*Lib, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	toolsDir := filepath.Join(filepath.Dir(exe), "tools")
	bridgePath := filepath.Join(toolsDir, "wimbridge.dll")

	dll := syscall.NewLazyDLL(bridgePath)

	lib := &Lib{
		dllDir: toolsDir,
		dll:    dll,

		procLoad:            dll.NewProc("WimBridge_Load"),
		procUnload:          dll.NewProc("WimBridge_Unload"),
		procOpenWim:         dll.NewProc("WimBridge_OpenWim"),
		procCloseWim:        dll.NewProc("WimBridge_CloseWim"),
		procVerifyWim:       dll.NewProc("WimBridge_VerifyWim"),
		procGetWimInfo:      dll.NewProc("WimBridge_GetWimInfo"),
		procGetImageName:    dll.NewProc("WimBridge_GetImageName"),
		procGetImageDesc:    dll.NewProc("WimBridge_GetImageDescription"),
		procGetXMLUtf8:      dll.NewProc("WimBridge_GetXMLUtf8"),
		procFreeBuffer:      dll.NewProc("WimBridge_FreeBuffer"),
		procApply:           dll.NewProc("WimBridge_Apply"),
		procExtractPathList: dll.NewProc("WimBridge_ExtractPathList"),
		procListPaths:       dll.NewProc("WimBridge_ListPaths"),
		procFreeDirEntries:  dll.NewProc("WimBridge_FreeDirEntries"),
		procUpdateAdd:       dll.NewProc("WimBridge_UpdateAdd"),
		procUpdateDelete:    dll.NewProc("WimBridge_UpdateDelete"),
		procUpdateRename:    dll.NewProc("WimBridge_UpdateRename"),
		procOverwrite:       dll.NewProc("WimBridge_Overwrite"),
		procGetLastErrorW:   dll.NewProc("WimBridge_GetLastErrorStringW"),
	}

	if err := lib.dlLoad(); err != nil {
		return nil, err
	}
	return lib, nil
}

func (l *Lib) dlLoad() error {
	dirPtr, err := syscall.UTF16PtrFromString(l.dllDir)
	if err != nil {
		return err
	}
	r1, _, callErr := l.procLoad.Call(uintptr(unsafe.Pointer(dirPtr)))
	if int32(r1) != 0 {
		return l.errorFromCode(int32(r1), callErr)
	}
	return nil
}

func (l *Lib) Close() {
	if l == nil || l.procUnload == nil {
		return
	}
	l.procUnload.Call()
}

func (l *Lib) OpenWim(path string, openFlags int) (*WIM, error) {
	if l == nil {
		return nil, errors.New("nil lib")
	}
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}

	var handle uintptr
	r1, _, callErr := l.procOpenWim.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(openFlags),
		uintptr(unsafe.Pointer(&handle)),
	)
	if int32(r1) != 0 {
		return nil, l.errorFromCode(int32(r1), callErr)
	}
	if handle == 0 {
		return nil, errors.New("open wim returned null handle")
	}
	return &WIM{lib: l, handle: handle}, nil
}

func (w *WIM) Free() {
	if w == nil || w.handle == 0 || w.lib == nil {
		return
	}
	w.lib.procCloseWim.Call(w.handle)
	w.handle = 0
}

func (w *WIM) Verify() error {
	if w == nil || w.handle == 0 {
		return errors.New("nil WIM")
	}
	r1, _, callErr := w.lib.procVerifyWim.Call(w.handle)
	if int32(r1) != 0 {
		return w.lib.errorFromCode(int32(r1), callErr)
	}
	return nil
}

func (w *WIM) GetWimInfo() (WimInfo, error) {
	var out WimInfo
	if w == nil || w.handle == 0 {
		return out, errors.New("nil WIM")
	}

	var raw wbWimInfo
	r1, _, callErr := w.lib.procGetWimInfo.Call(
		w.handle,
		uintptr(unsafe.Pointer(&raw)),
	)
	if int32(r1) != 0 {
		return out, w.lib.errorFromCode(int32(r1), callErr)
	}

	out.GUID = raw.GUID
	out.ImageCount = raw.ImageCount
	out.BootIndex = raw.BootIndex
	out.WimVersion = raw.WimVersion
	out.ChunkSize = raw.ChunkSize
	out.PartNumber = raw.PartNumber
	out.TotalParts = raw.TotalParts
	out.CompressionType = raw.CompressionType
	out.TotalBytes = raw.TotalBytes

	out.HasIntegrityTable = raw.Flags&wbFlagHasIntegrityTable != 0
	out.OpenedFromFile = raw.Flags&wbFlagOpenedFromFile != 0
	out.IsReadonly = raw.Flags&wbFlagIsReadonly != 0
	out.HasRpfix = raw.Flags&wbFlagHasRpfix != 0
	out.IsMarkedReadonly = raw.Flags&wbFlagIsMarkedReadonly != 0
	out.Spanned = raw.Flags&wbFlagSpanned != 0
	out.WriteInProgress = raw.Flags&wbFlagWriteInProgress != 0
	out.MetadataOnly = raw.Flags&wbFlagMetadataOnly != 0
	out.ResourceOnly = raw.Flags&wbFlagResourceOnly != 0
	out.Pipable = raw.Flags&wbFlagPipable != 0

	return out, nil
}

func (w *WIM) GetImageName(index int) string {
	s, _ := w.getWideString(w.lib.procGetImageName, index)
	return s
}

func (w *WIM) GetImageDescription(index int) string {
	s, _ := w.getWideString(w.lib.procGetImageDesc, index)
	return s
}

func (w *WIM) getWideString(proc *syscall.LazyProc, index int) (string, error) {
	if w == nil || w.handle == 0 {
		return "", errors.New("nil WIM")
	}

	const initial = 256
	bufLen := uint32(initial)

	for i := 0; i < 8; i++ {
		buf := make([]uint16, bufLen)
		r1, _, callErr := proc.Call(
			w.handle,
			uintptr(index),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(bufLen),
		)
		rc := int32(r1)
		if rc == 0 {
			return syscall.UTF16ToString(buf), nil
		}
		if rc == wbErrBufferTooSmall {
			bufLen *= 2
			continue
		}
		return "", w.lib.errorFromCode(rc, callErr)
	}

	return "", errors.New("string too long")
}

func (w *WIM) GetXML() (string, error) {
	if w == nil || w.handle == 0 {
		return "", errors.New("nil WIM")
	}

	var p uintptr
	var n uint32

	r1, _, callErr := w.lib.procGetXMLUtf8.Call(
		w.handle,
		uintptr(unsafe.Pointer(&p)),
		uintptr(unsafe.Pointer(&n)),
	)
	if int32(r1) != 0 {
		return "", w.lib.errorFromCode(int32(r1), callErr)
	}
	if p == 0 || n == 0 {
		if p != 0 {
			w.lib.procFreeBuffer.Call(p)
		}
		return "", nil
	}
	defer w.lib.procFreeBuffer.Call(p)

	b := unsafe.Slice((*byte)(unsafe.Pointer(p)), int(n))
	return string(b), nil
}

func (w *WIM) Apply(image int, targetDir string, extractFlags int) error {
	if w == nil || w.handle == 0 {
		return errors.New("nil WIM")
	}
	targetPtr, err := syscall.UTF16PtrFromString(targetDir)
	if err != nil {
		return err
	}
	r1, _, callErr := w.lib.procApply.Call(
		w.handle,
		uintptr(image),
		uintptr(unsafe.Pointer(targetPtr)),
		uintptr(extractFlags),
	)
	if int32(r1) != 0 {
		return w.lib.errorFromCode(int32(r1), callErr)
	}
	return nil
}

func (w *WIM) ExtractByPathList(image int, targetDir, pathListFile string, extractFlags int) error {
	if w == nil || w.handle == 0 {
		return errors.New("nil WIM")
	}
	targetPtr, err := syscall.UTF16PtrFromString(targetDir)
	if err != nil {
		return err
	}
	listPtr, err := syscall.UTF16PtrFromString(pathListFile)
	if err != nil {
		return err
	}

	r1, _, callErr := w.lib.procExtractPathList.Call(
		w.handle,
		uintptr(image),
		uintptr(unsafe.Pointer(targetPtr)),
		uintptr(unsafe.Pointer(listPtr)),
		uintptr(extractFlags),
	)
	if int32(r1) != 0 {
		return w.lib.errorFromCode(int32(r1), callErr)
	}
	return nil
}

func (w *WIM) ListPaths(image int, wimPath string, iterateFlags int) ([]DirEntry, error) {
	if w == nil || w.handle == 0 {
		return nil, errors.New("nil WIM")
	}
	pathPtr, err := syscall.UTF16PtrFromString(wimPath)
	if err != nil {
		return nil, err
	}

	var items uintptr
	var count uint32

	r1, _, callErr := w.lib.procListPaths.Call(
		w.handle,
		uintptr(image),
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(iterateFlags),
		uintptr(unsafe.Pointer(&items)),
		uintptr(unsafe.Pointer(&count)),
	)
	if int32(r1) != 0 {
		return nil, w.lib.errorFromCode(int32(r1), callErr)
	}
	if items == 0 || count == 0 {
		return nil, nil
	}
	defer w.lib.procFreeDirEntries.Call(items, uintptr(count))

	raw := unsafe.Slice((*wbDirEntry)(unsafe.Pointer(items)), int(count))
	out := make([]DirEntry, 0, len(raw))
	for _, it := range raw {
		out = append(out, DirEntry{
			FullPath:   utf16PtrToString((*uint16)(unsafe.Pointer(it.FullPath))),
			Depth:      it.Depth,
			Attributes: it.Attributes,
		})
	}
	return out, nil
}

func (w *WIM) UpdateAdd(image int, fsSource, wimTarget string, addFlags int) error {
	if w == nil || w.handle == 0 {
		return errors.New("nil WIM")
	}
	srcPtr, err := syscall.UTF16PtrFromString(fsSource)
	if err != nil {
		return err
	}
	dstPtr, err := syscall.UTF16PtrFromString(wimTarget)
	if err != nil {
		return err
	}

	r1, _, callErr := w.lib.procUpdateAdd.Call(
		w.handle,
		uintptr(image),
		uintptr(unsafe.Pointer(srcPtr)),
		uintptr(unsafe.Pointer(dstPtr)),
		uintptr(addFlags),
	)
	if int32(r1) != 0 {
		return w.lib.errorFromCode(int32(r1), callErr)
	}
	return nil
}

func (w *WIM) UpdateDelete(image int, wimPath string, deleteFlags int) error {
	if w == nil || w.handle == 0 {
		return errors.New("nil WIM")
	}
	pathPtr, err := syscall.UTF16PtrFromString(wimPath)
	if err != nil {
		return err
	}
	r1, _, callErr := w.lib.procUpdateDelete.Call(
		w.handle,
		uintptr(image),
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(deleteFlags),
	)
	if int32(r1) != 0 {
		return w.lib.errorFromCode(int32(r1), callErr)
	}
	return nil
}

func (w *WIM) UpdateRename(image int, srcPath, dstPath string, renameFlags int) error {
	if w == nil || w.handle == 0 {
		return errors.New("nil WIM")
	}
	srcPtr, err := syscall.UTF16PtrFromString(srcPath)
	if err != nil {
		return err
	}
	dstPtr, err := syscall.UTF16PtrFromString(dstPath)
	if err != nil {
		return err
	}
	r1, _, callErr := w.lib.procUpdateRename.Call(
		w.handle,
		uintptr(image),
		uintptr(unsafe.Pointer(srcPtr)),
		uintptr(unsafe.Pointer(dstPtr)),
		uintptr(renameFlags),
	)
	if int32(r1) != 0 {
		return w.lib.errorFromCode(int32(r1), callErr)
	}
	return nil
}

func (w *WIM) Overwrite(writeFlags int, threads uint32) error {
	if w == nil || w.handle == 0 {
		return errors.New("nil WIM")
	}
	r1, _, callErr := w.lib.procOverwrite.Call(
		w.handle,
		uintptr(writeFlags),
		uintptr(threads),
	)
	if int32(r1) != 0 {
		return w.lib.errorFromCode(int32(r1), callErr)
	}
	return nil
}

func (l *Lib) errorFromCode(code int32, callErr error) error {
	if code == 0 {
		return nil
	}

	const bufLen = 1024
	buf := make([]uint16, bufLen)

	r1, _, _ := l.procGetLastErrorW.Call(
		uintptr(int(code)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(bufLen),
	)
	if int32(r1) == 0 {
		msg := syscall.UTF16ToString(buf)
		if msg != "" {
			return errors.New(msg)
		}
	}

	if callErr != nil && callErr != syscall.Errno(0) {
		return callErr
	}
	return errors.New("wimbridge error")
}

func utf16PtrToString(p *uint16) string {
	if p == nil {
		return ""
	}
	n := 0
	for {
		v := *(*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(p)) + uintptr(n)*2))
		if v == 0 {
			break
		}
		n++
		if n > 1<<20 {
			break
		}
	}
	return syscall.UTF16ToString(unsafe.Slice(p, n))
}
