//go:build windows

package ui

import (
	"fmt"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	fileDialogOle32 = windows.NewLazySystemDLL("ole32.dll")
	fileDialogShell = windows.NewLazySystemDLL("shell32.dll")

	procFDCoInitializeEx              = fileDialogOle32.NewProc("CoInitializeEx")
	procFDCoUninitialize              = fileDialogOle32.NewProc("CoUninitialize")
	procFDCoCreateInstance            = fileDialogOle32.NewProc("CoCreateInstance")
	procFDCoTaskMemFree               = fileDialogOle32.NewProc("CoTaskMemFree")
	procFDShCreateItemFromParsingName = fileDialogShell.NewProc("SHCreateItemFromParsingName")
)

const (
	fdCOINITApartmentThreaded = 0x2
	fdCLSCTXInprocServer      = 0x1

	fdFOSNoChangeDir     = 0x8
	fdFOSForceFilesystem = 0x40
	fdFOSPathMustExist   = 0x800
	fdFOSFileMustExist   = 0x1000

	fdSIGDNFileSysPath = 0x80058000

	fdHResultCanceled    = 0x800704C7
	fdHResultChangedMode = 0x80010106
)

var (
	fdCLSIDFileOpenDialog = fileDialogGUID{0xDC1C5A9C, 0xE88A, 0x4DDE, [8]byte{0xA5, 0xA1, 0x60, 0xF8, 0x2A, 0x20, 0xAE, 0xF7}}
	fdIIDIFileOpenDialog  = fileDialogGUID{0xD57C7288, 0xD4AD, 0x4768, [8]byte{0xBE, 0x02, 0x9D, 0x96, 0x95, 0x32, 0xD9, 0x60}}
	fdIIDIShellItem       = fileDialogGUID{0x43826D1E, 0xE718, 0x42EE, [8]byte{0xBC, 0x55, 0xA1, 0xE2, 0x61, 0xC3, 0x7B, 0xFE}}
)

type fileDialogFilter struct {
	Name string
	Spec string
}

type fileDialogGUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

type fileDialogFilterSpec struct {
	Name *uint16
	Spec *uint16
}

type fileOpenDialog struct {
	lpVtbl *fileOpenDialogVtbl
}

type fileOpenDialogVtbl struct {
	QueryInterface      uintptr
	AddRef              uintptr
	Release             uintptr
	Show                uintptr
	SetFileTypes        uintptr
	SetFileTypeIndex    uintptr
	GetFileTypeIndex    uintptr
	Advise              uintptr
	Unadvise            uintptr
	SetOptions          uintptr
	GetOptions          uintptr
	SetDefaultFolder    uintptr
	SetFolder           uintptr
	GetFolder           uintptr
	GetCurrentSelection uintptr
	SetFileName         uintptr
	GetFileName         uintptr
	SetTitle            uintptr
	SetOkButtonLabel    uintptr
	SetFileNameLabel    uintptr
	GetResult           uintptr
	AddPlace            uintptr
	SetDefaultExtension uintptr
	Close               uintptr
	SetClientGuid       uintptr
	ClearClientData     uintptr
	SetFilter           uintptr
	GetResults          uintptr
	GetSelectedItems    uintptr
}

type shellItem struct {
	lpVtbl *shellItemVtbl
}

type shellItemVtbl struct {
	QueryInterface uintptr
	AddRef         uintptr
	Release        uintptr
	BindToHandler  uintptr
	GetParent      uintptr
	GetDisplayName uintptr
	GetAttributes  uintptr
	Compare        uintptr
}

func openImageFileDialog(initial string) (string, error) {
	return openFileDialog("选择安装镜像", []fileDialogFilter{
		{Name: "安装镜像 (*.iso;*.wim;*.esd)", Spec: "*.iso;*.wim;*.esd"},
		{Name: "所有文件 (*.*)", Spec: "*.*"},
	}, initial)
}

func openPEFileDialog(initial string) (string, error) {
	return openFileDialog("选择 PE WIM", []fileDialogFilter{
		{Name: "PE WIM (*.wim)", Spec: "*.wim"},
		{Name: "所有文件 (*.*)", Spec: "*.*"},
	}, initial)
}

func openFileDialog(title string, filters []fileDialogFilter, initial string) (string, error) {
	if ui.app == nil {
		return "", fmt.Errorf("ui is not initialized")
	}

	if ui.app.IsUIThread() {
		return openFileDialogNative(title, filters, initial)
	}

	type dialogResult struct {
		path string
		err  error
	}
	ch := make(chan dialogResult, 1)
	if err := ui.app.Post(func() {
		path, openErr := openFileDialogNative(title, filters, initial)
		ch <- dialogResult{path: path, err: openErr}
	}); err != nil {
		return "", err
	}
	result := <-ch
	return result.path, result.err
}

func openFileDialogNative(title string, filters []fileDialogFilter, initial string) (string, error) {
	needUninit, err := fileDialogCoInitialize()
	if err != nil {
		return "", err
	}
	if needUninit {
		defer procFDCoUninitialize.Call()
	}

	dialog, err := fileDialogCreate()
	if err != nil {
		return "", err
	}
	defer dialog.release()

	if err := dialog.setFileTypes(filters); err != nil {
		return "", err
	}
	if err := dialog.setOptions(fdFOSForceFilesystem | fdFOSPathMustExist | fdFOSFileMustExist | fdFOSNoChangeDir); err != nil {
		return "", err
	}
	if err := dialog.setTitle(title); err != nil {
		return "", err
	}

	initial = strings.TrimSpace(initial)
	if initial != "" {
		initialDir := initial
		if ext := strings.TrimSpace(filepath.Ext(initial)); ext != "" {
			initialDir = filepath.Dir(initial)
			_ = dialog.setFileName(filepath.Base(initial))
		}
		_ = dialog.setFolder(initialDir)
	}

	hr, _, _ := syscall.SyscallN(dialog.lpVtbl.Show, uintptr(unsafe.Pointer(dialog)), uintptr(ui.app.Handle()))
	switch uint32(hr) {
	case 0:
	case fdHResultCanceled:
		return "", nil
	default:
		if fileDialogFailed(hr) {
			return "", fmt.Errorf("IFileOpenDialog.Show failed: 0x%08X", uint32(hr))
		}
	}

	item, err := dialog.getResult()
	if err != nil {
		return "", err
	}
	defer item.release()

	path, err := item.fileSystemPath()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(path), nil
}

func fileDialogCoInitialize() (bool, error) {
	hr, _, _ := procFDCoInitializeEx.Call(0, fdCOINITApartmentThreaded)
	switch uint32(hr) {
	case 0, 1:
		return true, nil
	case fdHResultChangedMode:
		return false, nil
	default:
		if fileDialogFailed(hr) {
			return false, fmt.Errorf("CoInitializeEx failed: 0x%08X", uint32(hr))
		}
		return false, nil
	}
}

func fileDialogCreate() (*fileOpenDialog, error) {
	var dialog *fileOpenDialog
	hr, _, _ := procFDCoCreateInstance.Call(
		uintptr(unsafe.Pointer(&fdCLSIDFileOpenDialog)),
		0,
		fdCLSCTXInprocServer,
		uintptr(unsafe.Pointer(&fdIIDIFileOpenDialog)),
		uintptr(unsafe.Pointer(&dialog)),
	)
	if fileDialogFailed(hr) || dialog == nil {
		return nil, fmt.Errorf("CoCreateInstance(IFileOpenDialog) failed: 0x%08X", uint32(hr))
	}
	return dialog, nil
}

func (d *fileOpenDialog) release() {
	if d == nil || d.lpVtbl == nil || d.lpVtbl.Release == 0 {
		return
	}
	syscall.SyscallN(d.lpVtbl.Release, uintptr(unsafe.Pointer(d)))
}

func (d *fileOpenDialog) setFileTypes(filters []fileDialogFilter) error {
	if d == nil {
		return fmt.Errorf("IFileOpenDialog is nil")
	}
	if len(filters) == 0 {
		return nil
	}

	specs := make([]fileDialogFilterSpec, 0, len(filters))
	for _, filter := range filters {
		namePtr, err := windows.UTF16PtrFromString(filter.Name)
		if err != nil {
			return err
		}
		specPtr, err := windows.UTF16PtrFromString(filter.Spec)
		if err != nil {
			return err
		}
		specs = append(specs, fileDialogFilterSpec{Name: namePtr, Spec: specPtr})
	}

	hr, _, _ := syscall.SyscallN(
		d.lpVtbl.SetFileTypes,
		uintptr(unsafe.Pointer(d)),
		uintptr(len(specs)),
		uintptr(unsafe.Pointer(&specs[0])),
	)
	if fileDialogFailed(hr) {
		return fmt.Errorf("IFileOpenDialog.SetFileTypes failed: 0x%08X", uint32(hr))
	}

	hr, _, _ = syscall.SyscallN(d.lpVtbl.SetFileTypeIndex, uintptr(unsafe.Pointer(d)), 1)
	if fileDialogFailed(hr) {
		return fmt.Errorf("IFileOpenDialog.SetFileTypeIndex failed: 0x%08X", uint32(hr))
	}
	return nil
}

func (d *fileOpenDialog) setOptions(flags uint32) error {
	if d == nil {
		return fmt.Errorf("IFileOpenDialog is nil")
	}

	var current uint32
	hr, _, _ := syscall.SyscallN(
		d.lpVtbl.GetOptions,
		uintptr(unsafe.Pointer(d)),
		uintptr(unsafe.Pointer(&current)),
	)
	if fileDialogFailed(hr) {
		return fmt.Errorf("IFileOpenDialog.GetOptions failed: 0x%08X", uint32(hr))
	}

	hr, _, _ = syscall.SyscallN(
		d.lpVtbl.SetOptions,
		uintptr(unsafe.Pointer(d)),
		uintptr(current|flags),
	)
	if fileDialogFailed(hr) {
		return fmt.Errorf("IFileOpenDialog.SetOptions failed: 0x%08X", uint32(hr))
	}
	return nil
}

func (d *fileOpenDialog) setTitle(title string) error {
	if d == nil || strings.TrimSpace(title) == "" {
		return nil
	}
	titlePtr, err := windows.UTF16PtrFromString(title)
	if err != nil {
		return err
	}
	hr, _, _ := syscall.SyscallN(
		d.lpVtbl.SetTitle,
		uintptr(unsafe.Pointer(d)),
		uintptr(unsafe.Pointer(titlePtr)),
	)
	if fileDialogFailed(hr) {
		return fmt.Errorf("IFileOpenDialog.SetTitle failed: 0x%08X", uint32(hr))
	}
	return nil
}

func (d *fileOpenDialog) setFileName(name string) error {
	if d == nil || strings.TrimSpace(name) == "" {
		return nil
	}
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	hr, _, _ := syscall.SyscallN(
		d.lpVtbl.SetFileName,
		uintptr(unsafe.Pointer(d)),
		uintptr(unsafe.Pointer(namePtr)),
	)
	if fileDialogFailed(hr) {
		return fmt.Errorf("IFileOpenDialog.SetFileName failed: 0x%08X", uint32(hr))
	}
	return nil
}

func (d *fileOpenDialog) setFolder(path string) error {
	if d == nil {
		return fmt.Errorf("IFileOpenDialog is nil")
	}
	path = strings.TrimSpace(path)
	if path == "" || path == "." {
		return nil
	}

	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}

	var folder *shellItem
	hr, _, _ := procFDShCreateItemFromParsingName.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		0,
		uintptr(unsafe.Pointer(&fdIIDIShellItem)),
		uintptr(unsafe.Pointer(&folder)),
	)
	if fileDialogFailed(hr) || folder == nil {
		return fmt.Errorf("SHCreateItemFromParsingName failed: 0x%08X", uint32(hr))
	}
	defer folder.release()

	hr, _, _ = syscall.SyscallN(
		d.lpVtbl.SetFolder,
		uintptr(unsafe.Pointer(d)),
		uintptr(unsafe.Pointer(folder)),
	)
	if fileDialogFailed(hr) {
		return fmt.Errorf("IFileOpenDialog.SetFolder failed: 0x%08X", uint32(hr))
	}
	return nil
}

func (d *fileOpenDialog) getResult() (*shellItem, error) {
	if d == nil {
		return nil, fmt.Errorf("IFileOpenDialog is nil")
	}
	var item *shellItem
	hr, _, _ := syscall.SyscallN(
		d.lpVtbl.GetResult,
		uintptr(unsafe.Pointer(d)),
		uintptr(unsafe.Pointer(&item)),
	)
	if fileDialogFailed(hr) || item == nil {
		return nil, fmt.Errorf("IFileOpenDialog.GetResult failed: 0x%08X", uint32(hr))
	}
	return item, nil
}

func (s *shellItem) release() {
	if s == nil || s.lpVtbl == nil || s.lpVtbl.Release == 0 {
		return
	}
	syscall.SyscallN(s.lpVtbl.Release, uintptr(unsafe.Pointer(s)))
}

func (s *shellItem) fileSystemPath() (string, error) {
	if s == nil {
		return "", fmt.Errorf("IShellItem is nil")
	}

	var rawPath *uint16
	hr, _, _ := syscall.SyscallN(
		s.lpVtbl.GetDisplayName,
		uintptr(unsafe.Pointer(s)),
		fdSIGDNFileSysPath,
		uintptr(unsafe.Pointer(&rawPath)),
	)
	if fileDialogFailed(hr) {
		return "", fmt.Errorf("IShellItem.GetDisplayName failed: 0x%08X", uint32(hr))
	}
	if rawPath == nil {
		return "", nil
	}
	defer procFDCoTaskMemFree.Call(uintptr(unsafe.Pointer(rawPath)))
	return windows.UTF16PtrToString(rawPath), nil
}

func fileDialogFailed(hr uintptr) bool {
	return int32(uint32(hr)) < 0
}
