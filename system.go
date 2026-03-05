//go:build windows

package main

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// -------------------- Boot Mode (UEFI / Legacy) --------------------

type BootMode int

const (
	BootModeUEFI BootMode = iota
	BootModeLegacy
)

func (m BootMode) String() string {
	switch m {
	case BootModeUEFI:
		return "UEFI"
	case BootModeLegacy:
		return "Legacy"
	default:
		return "Unknown"
	}
}

// DetectBootMode 使用 GetFirmwareEnvironmentVariableW 读“空变量”判断启动模式：
// - Legacy BIOS：返回 ERROR_INVALID_FUNCTION (1) => Legacy
// - UEFI：返回其他错误（如 ERROR_NOACCESS / ERROR_ENVVAR_NOT_FOUND 等）=> UEFI
func DetectBootMode() (BootMode, error) {
	k32 := windows.NewLazySystemDLL("kernel32.dll")
	proc := k32.NewProc("GetFirmwareEnvironmentVariableW")
	if err := k32.Load(); err != nil {
		return BootModeLegacy, err
	}
	if err := proc.Find(); err != nil {
		return BootModeLegacy, err
	}

	// lpName = ""（空字符串）
	// lpGuid = "{00000000-0000-0000-0000-000000000000}"（虚拟 GUID）
	name := windows.StringToUTF16Ptr("")
	guid := windows.StringToUTF16Ptr("{00000000-0000-0000-0000-000000000000}")
	var buf [1]byte

	r1, _, e1 := proc.Call(
		uintptr(unsafe.Pointer(name)),
		uintptr(unsafe.Pointer(guid)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)

	if r1 == 0 {
		// LazyProc.Call 返回的 e1 通常就是 GetLastError()
		if errno, ok := e1.(syscall.Errno); ok {
			if errno == windows.ERROR_INVALID_FUNCTION {
				return BootModeLegacy, nil
			}
			// 其他错误基本都视为 UEFI（如 ERROR_NOACCESS / ERROR_ENVVAR_NOT_FOUND）
			return BootModeUEFI, nil
		}
		// 拿不到 errno：保守当作 UEFI
		return BootModeUEFI, nil
	}

	// 成功（很少见，因为我们读的是“空变量”），也说明 UEFI
	return BootModeUEFI, nil
}

// -------------------- Secure Boot --------------------

// SecureBootEnabled 通过注册表读取 Secure Boot 状态：
// HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State\UEFISecureBootEnabled (DWORD)
// - 1 => true
// - 0 / 不存在（Win7常见）=> false
func SecureBootEnabled() (bool, error) {
	const keyPath = `SYSTEM\CurrentControlSet\Control\SecureBoot\State`
	const valueName = "UEFISecureBootEnabled"

	k, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.QUERY_VALUE)
	if err != nil {
		// Win7 或不支持 Secure Boot 的平台通常没有这个 key：当作 false，不报错
		if errors.Is(err, registry.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	defer k.Close()

	v, _, err := k.GetIntegerValue(valueName)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return v != 0, nil
}

// -------------------- WinPE Detect --------------------

// IsWinPE 多特征启发式判断
func IsWinPE() bool {
	// 特征1/2：典型 PE 文件
	if fileExists(`X:\Windows\System32\drivers\fbwf.sys`) {
		return true
	}
	if fileExists(`X:\Windows\System32\winpeshl.ini`) {
		return true
	}

	// 特征3：系统盘是 X:
	if sd := os.Getenv("SystemDrive"); strings.EqualFold(sd, "X:") {
		return true
	}

	// 特征4：X:\MININT
	if dirExists(`X:\MININT`) {
		return true
	}

	// 特征5：MiniNT 注册表键
	if registryKeyExistsHKLM(`SYSTEM\CurrentControlSet\Control\MiniNT`) {
		return true
	}

	// 额外常见特征：SystemStartOptions 包含 MININT（一些 PE 会有）
	if systemStartOptionsHasMinint() {
		return true
	}

	// 额外常见特征：HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinPE（有的 PE 会写）
	if registryKeyExistsHKLMAnyView(`SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinPE`) {
		return true
	}

	// 特征6：系统盘下也查一遍（兼容非 X: 的 PE/映射情况）
	if sd := os.Getenv("SystemDrive"); sd != "" {
		if fileExists(filepath.Join(sd+`\`, `Windows\System32\drivers\fbwf.sys`)) ||
			fileExists(filepath.Join(sd+`\`, `Windows\System32\winpeshl.ini`)) {
			return true
		}
	}

	return false
}

func systemStartOptionsHasMinint() bool {
	const keyPath = `SYSTEM\CurrentControlSet\Control`
	const valueName = "SystemStartOptions"

	k, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()

	s, _, err := k.GetStringValue(valueName)
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToUpper(s), "MININT")
}

// -------------------- TPM Detect --------------------

// TPMEnabledAndVersion：
// 1) 优先 WMI（最靠谱，能拿到 IsEnabled_InitialValue / SpecVersion）
// 2) WMI 不可用（WinPE/裁剪系统）时，退回注册表设备枚举：
//   - ACPI\MSFT0101 => 2.0
//   - Root\SecurityDevices\0000 => 1.2
//
// 注意：注册表兜底更偏“设备存在/版本推断”，无法 100% 等价于“固件启用状态”。
func TPMEnabledAndVersion() (bool, string, error) {
	// 1) WMI
	if enabled, ver, ok, err := tpmViaWMI(); ok {
		return enabled, ver, err // err 通常为 nil；保留以便你记录诊断
	}

	// 2) Registry fallback
	ver, present := tpmVersionViaRegistry()
	if present {
		// 兜底：能枚举到 TPM 设备，一般意味着系统能看到它；这里用 enabled=true 更贴近“可用”
		return true, ver, nil
	}
	return false, "", nil
}

func tpmVersionViaRegistry() (version string, present bool) {
	// TPM 2.0 常见枚举
	if registryKeyExistsHKLM(`SYSTEM\CurrentControlSet\Enum\ACPI\MSFT0101`) {
		return "2.0", true
	}
	// TPM 1.2 常见枚举
	if registryKeyExistsHKLM(`SYSTEM\CurrentControlSet\Enum\Root\SecurityDevices\0000`) {
		return "1.2", true
	}
	return "", false
}

// tpmViaWMI：用wmi检测 TPM 的启用状态和版本，理论上更准确（能区分固件启用状态和设备存在）
// PE系统通常没有，此处占位保留
func tpmViaWMI() (enabled bool, version string, ok bool, err error) {
	return false, "", false, nil
}

// -------------------- Network --------------------

// CheckNetwork：尝试连几个 DNS 的 tcp/53，有一个通就算在线
func CheckNetwork_DNS() bool {
	addrs := []string{
		"223.5.5.5:53",
		"119.29.29.29:53",
		"8.8.8.8:53",
		"1.1.1.1:53",
	}

	for _, a := range addrs {
		c, err := net.DialTimeout("tcp", a, 2*time.Second)
		if err == nil {
			_ = c.Close()
			return true
		}
	}
	return false
}

func registryKeyExistsHKLM(path string) bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.READ)
	if err != nil {
		return false
	}
	_ = k.Close()
	return true
}

// registryKeyExistsHKLMAnyView：
// 32 位进程在 64 位系统上访问 HKLM\SOFTWARE 时会被重定向到 Wow6432Node，
// 这个函数会优先尝试 64-bit view（WOW64_64KEY），再尝试默认 view。
func registryKeyExistsHKLMAnyView(path string) bool {
	access := uint32(registry.READ)

	// 只有 SOFTWARE 类路径才会被 Wow64 重定向；我们简单按前缀判断
	isSoftware := strings.HasPrefix(strings.ToUpper(path), "SOFTWARE\\")
	if isSoftware && isWOW64() {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, access|registry.WOW64_64KEY)
		if err == nil {
			_ = k.Close()
			return true
		}
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, access)
	if err == nil {
		_ = k.Close()
		return true
	}
	return false
}
