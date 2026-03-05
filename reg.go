package main

import (
	"fmt"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)
// 注册表
const (
	// Registry value types
	REG_EXPAND_SZ = 2
	REG_DWORD     = 4

	// Access rights (REGSAM)
	KEY_QUERY_VALUE    = 0x0001
	KEY_SET_VALUE      = 0x0002
	KEY_CREATE_SUB_KEY = 0x0004
	KEY_ENUMERATE      = 0x0008
	KEY_NOTIFY         = 0x0010

	KEY_WOW64_64KEY = 0x0100
	KEY_WOW64_32KEY = 0x0200

	KEY_WRITE = 0x20006
)

type RegView uint32

const (
	RegViewDefault RegView = 0
	RegView32      RegView = KEY_WOW64_32KEY
	RegView64      RegView = KEY_WOW64_64KEY
)

var (
	procRegCreateKeyExW = modAdvapi32.NewProc("RegCreateKeyExW")
	procRegSetValueExW  = modAdvapi32.NewProc("RegSetValueExW")
)

// 解析 HKLM\... 这种完整路径
func parseFullKeyPath(full string) (root syscall.Handle, subPath string, err error) {
	s := strings.ReplaceAll(full, "/", `\`)
	s = strings.TrimSpace(s)
	parts := strings.SplitN(s, `\`, 2)
	if len(parts) < 2 {
		return 0, "", fmt.Errorf("invalid key path: %q", full)
	}

	switch strings.ToUpper(parts[0]) {
	case "HKLM", "HKEY_LOCAL_MACHINE":
		root = syscall.Handle(windows.HKEY_LOCAL_MACHINE)
	case "HKCU", "HKEY_CURRENT_USER":
		root = syscall.Handle(windows.HKEY_CURRENT_USER)
	case "HKCR", "HKEY_CLASSES_ROOT":
		root = syscall.Handle(windows.HKEY_CLASSES_ROOT)
	case "HKU", "HKEY_USERS":
		root = syscall.Handle(windows.HKEY_USERS)
	case "HKCC", "HKEY_CURRENT_CONFIG":
		root = syscall.Handle(windows.HKEY_CURRENT_CONFIG)
	default:
		return 0, "", fmt.Errorf("unsupported root key: %q", parts[0])
	}

	subPath = parts[1]
	return root, subPath, nil
}

// RegCreateKeyPath: 等价于 reg.exe add <key> /f（确保 key 存在）
func RegCreateKeyPath(fullKeyPath string, view RegView) error {
	root, sub, err := parseFullKeyPath(fullKeyPath)
	if err != nil {
		return err
	}
	h, err := regCreateOrOpenKey(root, sub, view)
	if err != nil {
		return err
	}
	RegCloseKey(h)
	return nil
}

func regCreateOrOpenKey(root syscall.Handle, subPath string, view RegView) (syscall.Handle, error) {
	subPtr, err := syscall.UTF16PtrFromString(subPath)
	if err != nil {
		return 0, err
	}

	var h syscall.Handle
	var disp uint32

	// samDesired：写入 + 创建子键 + 查询（够用）
	sam := uint32(KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_CREATE_SUB_KEY | uint32(view))

	r0, _, e1 := procRegCreateKeyExW.Call(
		uintptr(root),
		uintptr(unsafe.Pointer(subPtr)),
		0,
		0,
		0, // REG_OPTION_NON_VOLATILE
		uintptr(sam),
		0,
		uintptr(unsafe.Pointer(&h)),
		uintptr(unsafe.Pointer(&disp)),
	)
	if r0 != 0 {
		if e1 != nil && e1 != syscall.Errno(0) {
			return 0, fmt.Errorf("RegCreateKeyExW(%s) failed: %v (code=%d)", subPath, e1, r0)
		}
		return 0, fmt.Errorf("RegCreateKeyExW(%s) failed: code=%d", subPath, r0)
	}
	return h, nil
}

func RegSetDword(fullKeyPath, valueName string, data uint32, view RegView) error {
	root, sub, err := parseFullKeyPath(fullKeyPath)
	if err != nil {
		return err
	}
	h, err := regCreateOrOpenKey(root, sub, view) // 和 reg.exe add 一样：不存在就创建
	if err != nil {
		return err
	}
	defer RegCloseKey(h)

	return regSetValueDword(h, valueName, data)
}

func regSetValueDword(h syscall.Handle, name string, data uint32) error {
	var namePtr *uint16
	var err error
	if name != "" {
		namePtr, err = syscall.UTF16PtrFromString(name)
		if err != nil {
			return err
		}
	}

	r0, _, e1 := procRegSetValueExW.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(namePtr)), // name=="" 时传 nil 表示默认值
		0,
		uintptr(REG_DWORD),
		uintptr(unsafe.Pointer(&data)),
		uintptr(4),
	)
	if r0 != 0 {
		if e1 != nil && e1 != syscall.Errno(0) {
			return fmt.Errorf("RegSetValueExW(DWORD,%s) failed: %v (code=%d)", name, e1, r0)
		}
		return fmt.Errorf("RegSetValueExW(DWORD,%s) failed: code=%d", name, r0)
	}
	return nil
}
func RegSetStringPath(fullKeyPath, valueName, data string, view RegView) error {
	return regSetStringTyped(fullKeyPath, valueName, data, REG_SZ, view)
}

func RegSetExpandStringPath(fullKeyPath, valueName, data string, view RegView) error {
	return regSetStringTyped(fullKeyPath, valueName, data, REG_EXPAND_SZ, view)
}

func regSetStringTyped(fullKeyPath, valueName, data string, typ uint32, view RegView) error {
	root, sub, err := parseFullKeyPath(fullKeyPath)
	if err != nil {
		return err
	}
	h, err := regCreateOrOpenKey(root, sub, view)
	if err != nil {
		return err
	}
	defer RegCloseKey(h)

	return regSetValueString(h, valueName, data, typ)
}

func regSetValueString(h syscall.Handle, name, data string, typ uint32) error {
	var namePtr *uint16
	var err error
	if name != "" {
		namePtr, err = syscall.UTF16PtrFromString(name)
		if err != nil {
			return err
		}
	}

	// UTF-16 + 结尾 \0（REG_SZ/REG_EXPAND_SZ 推荐带 NUL）
	u16, err := syscall.UTF16FromString(data)
	if err != nil {
		return err
	}
	cb := uint32(len(u16) * 2)

	r0, _, e1 := procRegSetValueExW.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(namePtr)),
		0,
		uintptr(typ),
		uintptr(unsafe.Pointer(&u16[0])),
		uintptr(cb),
	)
	if r0 != 0 {
		if e1 != nil && e1 != syscall.Errno(0) {
			return fmt.Errorf("RegSetValueExW(STR,%s) failed: %v (code=%d)", name, e1, r0)
		}
		return fmt.Errorf("RegSetValueExW(STR,%s) failed: code=%d", name, r0)
	}
	return nil
}
func RegUnloadHiveRetry(subKey string, tries int, delay time.Duration) error {
	if tries <= 0 {
		tries = 1
	}
	if delay <= 0 {
		delay = 500 * time.Millisecond
	}

	var lastErr error
	for i := 0; i < tries; i++ {
		if err := RegUnloadHive(subKey); err == nil {
			return nil
		} else {
			lastErr = err
			time.Sleep(delay)
		}
	}
	return lastErr
}

// 加载离线注册表 hive
// subKey：挂载点名称，如"OFFLINE_SYSTEM"
// file:注册表 hive 文件的 完整路径
// 需要有 SeBackupPrivilege / SeRestorePrivilege 之类的权限
func RegLoadHive(subKey, file string) error {
	subKeyPtr, err := syscall.UTF16PtrFromString(subKey)
	if err != nil {
		return err
	}
	filePtr, err := syscall.UTF16PtrFromString(file)
	if err != nil {
		return err
	}
	r0, _, e1 := procRegLoadKeyW.Call(
		uintptr(HKEY_LOCAL_MACHINE),
		uintptr(unsafe.Pointer(subKeyPtr)),
		uintptr(unsafe.Pointer(filePtr)),
	)
	if r0 != 0 {
		if e1 != nil && e1 != syscall.Errno(0) {
			return fmt.Errorf("RegLoadKeyW(%s) failed: %v (code=%d)", subKey, e1, r0)
		}
		return fmt.Errorf("RegLoadKeyW(%s) failed: code=%d", subKey, r0)
	}
	return nil
}

// 卸载之前通过 RegLoadKeyW 加载的 hive
// subKey：挂载点名称，如"OFFLINE_SYSTEM"
func RegUnloadHive(subKey string) error {
	subKeyPtr, err := syscall.UTF16PtrFromString(subKey)
	if err != nil {
		return err
	}
	r0, _, e1 := procRegUnLoadKeyW.Call(
		uintptr(HKEY_LOCAL_MACHINE),
		uintptr(unsafe.Pointer(subKeyPtr)),
	)
	if r0 != 0 {
		if e1 != nil && e1 != syscall.Errno(0) {
			return fmt.Errorf("RegUnLoadKeyW(%s) failed: %v (code=%d)", subKey, e1, r0)
		}
		return fmt.Errorf("RegUnLoadKeyW(%s) failed: code=%d", subKey, r0)
	}
	return nil
}

// 打开某个注册表子键，获得一个 可读句柄
// root:根键,如syscall.Handle(HKEY_LOCAL_MACHINE)
// path:子路径,如"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
func RegOpenKey(root syscall.Handle, path string) (syscall.Handle, error) {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var h syscall.Handle
	r0, _, e1 := procRegOpenKeyExW.Call(
		uintptr(root),
		uintptr(unsafe.Pointer(pathPtr)),
		0,
		uintptr(KEY_READ),
		uintptr(unsafe.Pointer(&h)),
	)
	if r0 != 0 {
		if e1 != nil && e1 != syscall.Errno(0) {
			return 0, fmt.Errorf("RegOpenKeyExW(%s) failed: %v (code=%d)", path, e1, r0)
		}
		return 0, fmt.Errorf("RegOpenKeyExW(%s) failed: code=%d", path, r0)
	}
	return h, nil
}

func RegCloseKey(h syscall.Handle) {
	if h == 0 {
		return
	}
	_, _, _ = procRegCloseKey.Call(uintptr(h))
}

// 从指定键下读取一个 字符串类型的值
// h:已经打开的注册表键句柄。
// name:值名称
func RegGetString(h syscall.Handle, name string) (string, error) {
	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return "", err
	}

	var typ uint32
	var dataLen uint32

	r0, _, e1 := procRegQueryValueExW.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(namePtr)),
		0,
		uintptr(unsafe.Pointer(&typ)),
		0,
		uintptr(unsafe.Pointer(&dataLen)),
	)
	if r0 != 0 {
		if e1 != nil && e1 != syscall.Errno(0) {
			return "", fmt.Errorf("RegQueryValueExW(%s,len) failed: %v (code=%d)", name, e1, r0)
		}
		return "", fmt.Errorf("RegQueryValueExW(%s,len) failed: code=%d", name, r0)
	}
	if dataLen < 2 {
		return "", nil
	}

	buf := make([]uint16, dataLen/2)
	r0, _, e1 = procRegQueryValueExW.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(namePtr)),
		0,
		uintptr(unsafe.Pointer(&typ)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&dataLen)),
	)
	if r0 != 0 {
		if e1 != nil && e1 != syscall.Errno(0) {
			return "", fmt.Errorf("RegQueryValueExW(%s,data) failed: %v (code=%d)", name, e1, r0)
		}
		return "", fmt.Errorf("RegQueryValueExW(%s,data) failed: code=%d", name, r0)
	}

	n := 0
	for ; n < len(buf) && buf[n] != 0; n++ {
	}
	return syscall.UTF16ToString(buf[:n]), nil
}

//示例
func Examplereg() error {
	sub := "OFFLINE_SYSTEM"
	hiveFile := `D:\Windows\System32\config\SYSTEM`

	if err := RegLoadHive(sub, hiveFile); err != nil {
		return err
	}
	defer _ = RegUnloadHiveRetry(sub, 4, 500*time.Millisecond)

	key := `HKLM\` + sub + `\ControlSet001\Services\MySvc`
	if err := RegCreateKeyPath(key, RegViewDefault); err != nil {
		return err
	}

	if err := RegSetDwordPath(key, "Start", 2, RegViewDefault); err != nil {
		return err
	}
	if err := RegSetStringPath(key, "ImagePath", `%SystemRoot%\System32\mysvc.exe`, RegViewDefault); err != nil {
		return err
	}
	if err := RegSetExpandStringPath(key, "Description", `%SystemRoot%\System32\mysvc.exe`, RegViewDefault); err != nil {
		return err
	}
	return nil
}