package registry

import (
	"ReSys/src/log"
	"fmt"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	REG_SZ        = 1
	REG_EXPAND_SZ = 2
	REG_DWORD     = 4

	KEY_QUERY_VALUE    = 0x0001
	KEY_SET_VALUE      = 0x0002
	KEY_CREATE_SUB_KEY = 0x0004
	KEY_ENUMERATE      = 0x0008
	KEY_NOTIFY         = 0x0010

	KEY_WOW64_64KEY = 0x0100
	KEY_WOW64_32KEY = 0x0200

	KEY_READ  = 0x20019
	KEY_WRITE = 0x20006

	HKEY_LOCAL_MACHINE = syscall.Handle(0x80000002)
)

type RegView uint32

const (
	RegViewDefault RegView = 0
	RegView32      RegView = KEY_WOW64_32KEY
	RegView64      RegView = KEY_WOW64_64KEY
)

var (
	modAdvapi32          = syscall.NewLazyDLL("advapi32.dll")
	procRegCreateKeyExW  = modAdvapi32.NewProc("RegCreateKeyExW")
	procRegSetValueExW   = modAdvapi32.NewProc("RegSetValueExW")
	procRegCloseKey      = modAdvapi32.NewProc("RegCloseKey")
	procRegOpenKeyExW    = modAdvapi32.NewProc("RegOpenKeyExW")
	procRegQueryValueExW = modAdvapi32.NewProc("RegQueryValueExW")
	procRegLoadKeyW      = modAdvapi32.NewProc("RegLoadKeyW")
	procRegUnLoadKeyW    = modAdvapi32.NewProc("RegUnLoadKeyW")
)

// parseFullKey 解析完整注册表路径（如 HKLM\Software\...），拆分为根键与子路径。
func parseFullKey(full string) (root syscall.Handle, subPath string, err error) {
	s := strings.ReplaceAll(full, "/", `\`)
	s = strings.TrimSpace(s)
	parts := strings.SplitN(s, `\`, 2)
	if len(parts) < 2 {
		err = fmt.Errorf("invalid key path: %q", full)
		log.LogWrite(-2, "[parseFullKey]解析注册表路径失败: %v", err)
		return 0, "", err
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
		err = fmt.Errorf("unsupported root key: %q", parts[0])
		log.LogWrite(-2, "[parseFullKey]不支持的根键: %v", err)
		return 0, "", err
	}

	subPath = parts[1]
	return root, subPath, nil
}

// RegCreateKey 确保指定 key 存在（等价 reg.exe add <key> /f 只创建路径不写值）。
func RegCreateKey(fullKeyPath string, view RegView) error {
	root, sub, err := parseFullKey(fullKeyPath)
	if err != nil {
		log.LogWrite(-2, "[RegCreateKey]解析路径失败: key=%s err=%v", fullKeyPath, err)
		return err
	}
	h, err := regCreateOrOpenKey(root, sub, view)
	if err != nil {
		return err
	}
	RegCloseKey(h)
	return nil
}

// regCreateOrOpenKey 创建或打开子键并返回句柄（可附带 32/64 视图）。
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

// RegSetDword 在指定 key 下写入 DWORD 值（key 不存在则自动创建）。
func RegSetDword(fullKeyPath, valueName string, data uint32, view RegView) error {
	root, sub, err := parseFullKey(fullKeyPath)
	if err != nil {
		log.LogWrite(-2, "[RegSetDword]解析路径失败: key=%s err=%v", fullKeyPath, err)
		return err
	}
	h, err := regCreateOrOpenKey(root, sub, view) // 和 reg.exe add 一样：不存在就创建
	if err != nil {
		return err
	}
	defer RegCloseKey(h)

	return regSetValueDword(h, valueName, data)
}

// regSetValueDword 向已打开的键句柄写入 DWORD（name=="" 表示默认值）。
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

// RegSetString 写入 REG_SZ 字符串值（自动创建 key）。
func RegSetString(fullKeyPath, valueName, data string, view RegView) error {
	return regSetStringTyped(fullKeyPath, valueName, data, REG_SZ, view)
}

// RegSetExpandString 写入 REG_EXPAND_SZ 字符串值（支持环境变量展开，自动创建 key）。
func RegSetExpandString(fullKeyPath, valueName, data string, view RegView) error {
	return regSetStringTyped(fullKeyPath, valueName, data, REG_EXPAND_SZ, view)
}

// regSetStringTyped 写入指定类型的字符串值（REG_SZ / REG_EXPAND_SZ）。
func regSetStringTyped(fullKeyPath, valueName, data string, typ uint32, view RegView) error {
	root, sub, err := parseFullKey(fullKeyPath)
	if err != nil {
		log.LogWrite(-2, "[RegSetDword]解析路径失败: key=%s err=%v", fullKeyPath, err)
		return err
	}
	h, err := regCreateOrOpenKey(root, sub, view)
	if err != nil {
		return err
	}
	defer RegCloseKey(h)

	return regSetValueString(h, valueName, data, typ)
}

// regSetValueString 向已打开的键句柄写入字符串（UTF-16，包含结尾 NUL）。
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

// RegUnloadHiveRetry 卸载 hive（带重试与间隔），常用于句柄尚未完全释放的场景。
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

// RegLoadHive 加载离线注册表 hive 到 HKLM\<subKey>（需 SeBackupPrivilege/SeRestorePrivilege 等权限）。
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

// RegUnloadHive 卸载通过 RegLoadKeyW 挂载的 hive（从 HKLM\<subKey> 解挂）。
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

// RegOpenKey 以只读权限打开指定子键并返回句柄（使用完需 RegCloseKey）。
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

// RegCloseKey 关闭注册表键句柄（允许传入 0，视为 no-op）。
func RegCloseKey(h syscall.Handle) {
	if h == 0 {
		return
	}
	_, _, _ = procRegCloseKey.Call(uintptr(h))
}

// RegGetString 读取指定值为字符串（调用方需确保值类型为字符串相关）。
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

// Examplereg 演示：加载离线 SYSTEM hive，并写入一个服务项（最后自动卸载）。
func Examplereg() error {
	sub := "OFFLINE_SYSTEM"
	hiveFile := `D:\Windows\System32\config\SYSTEM`

	if err := RegLoadHive(sub, hiveFile); err != nil {
		return err
	}
	defer RegUnloadHiveRetry(sub, 4, 500*time.Millisecond)

	key := `HKLM\` + sub + `\ControlSet001\Services\MySvc`
	if err := RegCreateKey(key, RegViewDefault); err != nil {
		return err
	}

	if err := RegSetDword(key, "Start", 2, RegViewDefault); err != nil {
		return err
	}
	if err := RegSetString(key, "ImagePath", `%SystemRoot%\System32\mysvc.exe`, RegViewDefault); err != nil {
		return err
	}
	if err := RegSetExpandString(key, "Description", `%SystemRoot%\System32\mysvc.exe`, RegViewDefault); err != nil {
		return err
	}
	return nil
}
