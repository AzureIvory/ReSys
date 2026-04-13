package windows

import (
	"ReSys/src/file"
	"ReSys/src/log"
	"ReSys/src/registry"
	"ReSys/src/tools"
	"ReSys/src/utils"
	"debug/pe"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	reg "golang.org/x/sys/windows/registry"
)

var (
	version                    = syscall.NewLazyDLL("version.dll")
	Shell32                    = syscall.NewLazyDLL("shell32.dll")
	procGetFileVersionInfoSize = version.NewProc("GetFileVersionInfoSizeW")
	procGetFileVersionInfo     = version.NewProc("GetFileVersionInfoW")
	procVerQueryValue          = version.NewProc("VerQueryValueW")
	procSHEmptyRecycleBinW     = Shell32.NewProc("SHEmptyRecycleBinW")
)

// 清空回收站标志
const (
	SHERB_NOCONFIRMATION = 0x00000001 // 不弹确认框
	SHERB_NOPROGRESSUI   = 0x00000002 // 不显示进度框
	SHERB_NOSOUND        = 0x00000004 // 不播放清空音效
)

const (
	HKEY_LOCAL_MACHINE = syscall.Handle(0x80000002)
	KEY_READ           = 0x20019 // 标准 KEY_READ
)

// Windows 版本信息结构体
type VS_FIXEDFILEINFO struct {
	DwSignature        uint32
	DwStrucVersion     uint32
	DwFileVersionMS    uint32 // 高16位是Major，低16位是Minor
	DwFileVersionLS    uint32 // 高16位是Build，低16位是Revision
	DwProductVersionMS uint32
	DwProductVersionLS uint32
	DwFileFlagsMask    uint32
	DwFileFlags        uint32
	DwFileOS           uint32
	DwFileType         uint32
	DwFileSubtype      uint32
	DwFileDateMS       uint32
	DwFileDateLS       uint32
}

// 检测指定盘符上的离线 Windows 版本和架构。
// drive：可以是 "D", "D:", "D:\"
// 返回如: "Windows 7 x64" / "Windows 10 x86" / "Windows 11 x64"
func DetectWin(drive string) (string, error) {
	root, err := utils.NormalizeDrive(drive, 0)
	if err != nil {
		return "", err
	}

	winDir := filepath.Join(root, "Windows")
	if !utils.DirExists(winDir) {
		return "", fmt.Errorf("no Windows directory on %s", root)
	}

	pfDir := filepath.Join(root, "Program Files")
	_ = utils.DirExists(pfDir)
	pfxDir := filepath.Join(root, "Program Files (x86)")
	syswowDir := filepath.Join(winDir, "SysWOW64")

	hasPFx86 := utils.DirExists(pfxDir)
	hasSysWOW := utils.DirExists(syswowDir)

	softwareHive := filepath.Join(winDir, "System32", "config", "SOFTWARE")
	if _, err := os.Stat(softwareHive); err != nil {
		return "", fmt.Errorf("SOFTWARE hive not found: %w", err)
	}
	systemHive := filepath.Join(winDir, "System32", "config", "SYSTEM")
	hasSystemHive := false
	if _, err := os.Stat(systemHive); err == nil {
		hasSystemHive = true
	}

	if err := registry.RegLoadHive("Offline_SOFTWARE", softwareHive); err != nil {
		return "", fmt.Errorf("load SOFTWARE hive: %w", err)
	}
	defer registry.RegUnloadHive("Offline_SOFTWARE")

	systemLoaded := false
	if hasSystemHive {
		if err := registry.RegLoadHive("Offline_SYSTEM", systemHive); err == nil {
			systemLoaded = true
			defer registry.RegUnloadHive("Offline_SYSTEM")
		}
	}

	// HKLM\Offline_SOFTWARE\Microsoft\Windows NT\CurrentVersion
	keyPath := `Offline_SOFTWARE\Microsoft\Windows NT\CurrentVersion`
	h, err := registry.RegOpenKey(registry.HKEY_LOCAL_MACHINE, keyPath)
	if err != nil {
		return "", fmt.Errorf("open offline CurrentVersion: %w", err)
	}
	defer registry.RegCloseKey(h)

	productName, _ := registry.RegGetString(h, "ProductName")
	currentVersion, _ := registry.RegGetString(h, "CurrentVersion")

	osName := "Unknown"

	switch currentVersion {
	case "6.1":
		osName = "Windows 7"
	case "6.2":
		osName = "Windows 8"
	case "6.3":
		osName = "Windows 8.1"
	case "10.0":
		upperPN := strings.ToUpper(productName)
		switch {
		case strings.Contains(upperPN, "WINDOWS 11"):
			osName = "Windows 11"
		case strings.Contains(upperPN, "WINDOWS 10"):
			osName = "Windows 10"
		default:
			// 用build号区分 10 / 11
			buildStr, _ := registry.RegGetString(h, "CurrentBuildNumber")
			if b, err := strconv.Atoi(buildStr); err == nil && b >= 22000 {
				osName = "Windows 11"
			} else if productName != "" {
				osName = productName
			} else {
				osName = "Windows 10"
			}
		}
	default:
		if productName != "" {
			osName = productName
		}
	}

	arch := DetectArch(root, hasPFx86, hasSysWOW, systemLoaded)

	return fmt.Sprintf("%s %s", osName, arch), nil
}

// 推测指定盘符的系统架构（32/64）
func DetectArch(root string, hasPFx86, hasSysWOW, systemLoaded bool) string {
	if hasPFx86 || hasSysWOW {
		return "x64"
	}

	// SYSTEM hive 里的环境变量
	if systemLoaded {
		keyPath := `Offline_SYSTEM\ControlSet001\Control\Session Manager\Environment`
		if h, err := registry.RegOpenKey(HKEY_LOCAL_MACHINE, keyPath); err == nil {
			defer registry.RegCloseKey(h)
			if s, err := registry.RegGetString(h, "PROCESSOR_ARCHITECTURE"); err == nil && s != "" {
				up := strings.ToUpper(s)
				if strings.Contains(up, "64") || up == "AMD64" || up == "ARM64" {
					return "x64"
				}
				return "x86"
			}
		}
	}

	// 只有Program Files就32位
	if utils.DirExists(filepath.Join(root, "Program Files")) {
		return "x86"
	}
	return "x86"
}

// 判断当前系统是否为 Windows XP（5.1/5.2）。
func IsWinXP() bool {
	h, err := registry.RegOpenKey(registry.HKEY_LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`)
	if err != nil {
		return false
	}
	defer registry.RegCloseKey(h)

	currentVersion, err := registry.RegGetString(h, "CurrentVersion")
	if err != nil {
		return false
	}
	return currentVersion == "5.1" || currentVersion == "5.2"
}

// 注册表的方式返回当前系统版本号与架构文本。
func GetCurrentWinVersion() (int, string, error) {
	h, err := registry.RegOpenKey(HKEY_LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`)
	if err != nil {
		return 0, "", err
	}
	defer registry.RegCloseKey(h)

	currentVersion, err := registry.RegGetString(h, "CurrentVersion")
	if err != nil {
		return 0, "", err
	}
	productName, _ := registry.RegGetString(h, "ProductName")
	buildStr, _ := registry.RegGetString(h, "CurrentBuildNumber")

	// 将 "6.1", "10.0" 这种字符串解析成数字
	var major, minor uint16
	fmt.Sscanf(currentVersion, "%d.%d", &major, &minor)

	// 解析 Build 号
	var build int
	if buildStr != "" {
		build, _ = strconv.Atoi(buildStr)
	}

	version := ParseToVers(major, minor, uint16(build), productName)

	if version == 0 {
		return 0, "", fmt.Errorf("unsupported Windows version: %s (Build: %d)", currentVersion, build)
	}

	arch := "32"
	if SystemArch() == "64" {
		arch = "64"
	}
	return version, arch, nil
}

func GetPEArch(filePath string) (string, error) {
	f, err := pe.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	switch f.Machine {
	case 0x8664: // pe.IMAGE_FILE_MACHINE_AMD64
		return "64", nil
	case 0x014c: // pe.IMAGE_FILE_MACHINE_I386
		return "32", nil
	case 0xaa64: // pe.IMAGE_FILE_MACHINE_ARM64
		return "ARM64", nil
	default:
		return "unknown", nil
	}
}

// 将win内核版本号转换为系统代号。
// version: 5=XP, 6=Vista, 7=Win7, 8=Win8, 9=Win8.1, 10=Win10, 11=Win11, 0=未知
// productName 允许为空（ntdll 模式下没有此信息）。
func ParseToVers(major, minor, build uint16, productName string) int {
	if major == 5 && (minor == 1 || minor == 2) {
		return 5
	}
	if major == 6 && minor == 0 {
		return 6
	}
	if major == 6 && minor == 1 {
		return 7
	}
	if major == 6 && minor == 2 {
		return 8
	}
	if major == 6 && minor == 3 {
		return 9
	}
	if major == 10 && minor == 0 {
		// 判断 Win11 逻辑
		if productName != "" {
			upperPN := strings.ToUpper(productName)
			if strings.Contains(upperPN, "WINDOWS 11") {
				return 11
			}
			// 如果明确写了 Windows 10，但 Build 依然异常高（早期 Win11 预览版），依然按 Build 判断更稳
		}

		// 只要 Build 大于等于 22000，就是 Windows 11
		if build >= 22000 {
			return 11
		}

		return 10
	}

	return 0 // 不支持或未知的版本
}

// 返回当前系统架构（32/64）
func SystemArch() string {
	arch := strings.ToLower(os.Getenv("PROCESSOR_ARCHITECTURE"))
	wow := strings.ToLower(os.Getenv("PROCESSOR_ARCHITEW6432"))
	if strings.Contains(arch, "64") || strings.Contains(wow, "64") || runtime.GOARCH == "amd64" {
		return "64"
	}
	return "32"
}

// GetImgVers 提取并识别 WIM/ESD 镜像中特定索引的系统版本。
// 返回:
//
//	version: 5=XP, 7=Win7, 10=Win10, 11=Win11 等
//	arch: "64" 或 "32"
func GetImgVers(imagePath string, index uint32) (int, string, error) {
	major, minor, build, err := GetNtdllVer(imagePath, index)
	if err != nil {
		return 0, "", fmt.Errorf("无法从 WIM/ESD 提取版本信息: %w", err)
	}
	version := ParseToVers(major, minor, build, "")
	if version == 0 {
		return 0, "", fmt.Errorf("识别到未知的内核版本: %d.%d.%d", major, minor, build)
	}
	tempNtdll := filepath.Join(os.TempDir(), "ntdll.dll")
	arch, err := GetPEArch(tempNtdll)
	if err != nil {
		// 如果 PE 解析失败，则回退到当前系统架构作为兜底
		arch = "64"
		if SystemArch() == "32" {
			arch = "32"
		}
	}

	return version, arch, nil
}

// 使用 wimlib 提取 ntdll.dll 并获取完整版本号
// 返回值: major(主版本), minor(次版本), build(编译号), error
func GetNtdllVer(imageFile string, index uint32) (uint16, uint16, uint16, error) {
	tempDir := os.TempDir()
	internalPath := "/Windows/System32/ntdll.dll"

	args := []string{
		"extract",
		imageFile,
		strconv.Itoa(int(index)),
		internalPath,
		fmt.Sprintf("--dest-dir=%s", tempDir),
		"--no-acls",
	}
	_, err := tools.RunCmd("wimlib-imagex.exe", nil, nil, "", args...)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("wimlib 提取 ntdll.dll 失败: %w", err)
	}

	extractedNtdll := filepath.Join(tempDir, "ntdll.dll")

	defer func() {
		if _, err := os.Stat(extractedNtdll); err == nil {
			os.Remove(extractedNtdll)
		}
	}()

	// 获取完整的三段版本号
	major, minor, build, err := getFileVersion(extractedNtdll)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("读取 ntdll.dll 版本失败: %w", err)
	}

	return major, minor, build, nil
}

// 返回PE文件的Major(主版本), Minor(次版本), Build(编译号)
func getFileVersion(filePath string) (uint16, uint16, uint16, error) {
	pathPtr, err := syscall.UTF16PtrFromString(filePath)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("路径转换失败: %w", err)
	}

	var handle uint32
	size, _, err := procGetFileVersionInfoSize.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(unsafe.Pointer(&handle)),
	)
	if size == 0 {
		return 0, 0, 0, fmt.Errorf("无法获取版本信息大小: %v", err)
	}

	info := make([]byte, size)
	ret, _, err := procGetFileVersionInfo.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		0,
		uintptr(size),
		uintptr(unsafe.Pointer(&info[0])),
	)
	if ret == 0 {
		return 0, 0, 0, fmt.Errorf("获取版本信息失败: %v", err)
	}

	subBlock, _ := syscall.UTF16PtrFromString(`\`)
	var blockPtr unsafe.Pointer
	var blockLen uint32

	ret, _, err = procVerQueryValue.Call(
		uintptr(unsafe.Pointer(&info[0])),
		uintptr(unsafe.Pointer(subBlock)),
		uintptr(unsafe.Pointer(&blockPtr)),
		uintptr(unsafe.Pointer(&blockLen)),
	)
	if ret == 0 || blockLen == 0 {
		return 0, 0, 0, fmt.Errorf("查询固定文件信息失败: %v", err)
	}

	fixedInfo := (*VS_FIXEDFILEINFO)(blockPtr)
	if fixedInfo.DwSignature != 0xfeef04bd {
		return 0, 0, 0, fmt.Errorf("无效的版本信息签名")
	}
	major := uint16(fixedInfo.DwFileVersionMS >> 16)
	minor := uint16(fixedInfo.DwFileVersionMS & 0xFFFF)
	build := uint16(fixedInfo.DwFileVersionLS >> 16) // 顺手把 Build 拿出来，区分 Win10/11 极度需要

	return major, minor, build, nil
}

// IsWinPE 多特征启发式判断
func IsWinPE() bool {
	// 特征1/2：典型 PE 文件
	if utils.FileExists(`X:\Windows\System32\drivers\fbwf.sys`) {
		return true
	}
	if utils.FileExists(`X:\Windows\System32\winpeshl.ini`) {
		return true
	}

	// 特征3：系统盘是 X:
	if sd := os.Getenv("SystemDrive"); strings.EqualFold(sd, "X:") {
		return true
	}

	// 特征4：X:\MININT
	if utils.DirExists(`X:\MININT`) {
		return true
	}

	// 特征5：MiniNT 注册表键
	if regKeyInHKLM(`SYSTEM\CurrentControlSet\Control\MiniNT`) {
		return true
	}

	// 额外常见特征：SystemStartOptions 包含 MININT（一些 PE 会有）
	if isMinint() {
		return true
	}

	// 额外常见特征：HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinPE（有的 PE 会写）
	if regKeyInHKLMAnyView(`SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinPE`) {
		return true
	}

	// 特征6：系统盘下也查一遍（兼容非 X: 的 PE/映射情况）
	if sd := os.Getenv("SystemDrive"); sd != "" {
		if utils.FileExists(filepath.Join(sd+`\`, `Windows\System32\drivers\fbwf.sys`)) ||
			utils.FileExists(filepath.Join(sd+`\`, `Windows\System32\winpeshl.ini`)) {
			return true
		}
	}

	return false
}

// 判断当前系统是不是带有 MININT 启动标记(PE)
func isMinint() bool {
	const keyPath = `SYSTEM\CurrentControlSet\Control`
	const valueName = "SystemStartOptions"

	k, err := reg.OpenKey(reg.LOCAL_MACHINE, keyPath, reg.QUERY_VALUE)
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

// 判断 HKLM 下某个注册表键是否存在
func regKeyInHKLM(path string) bool {
	k, err := reg.OpenKey(reg.LOCAL_MACHINE, path, reg.READ)
	if err != nil {
		return false
	}
	_ = k.Close()
	return true
}

// regKeyInHKLMAnyView：
// 32 位进程在 64 位系统上访问 HKLM\SOFTWARE 时会被重定向到 Wow6432Node，
// 这个函数会优先尝试 64-bit view（WOW64_64KEY），再尝试默认 view。
func regKeyInHKLMAnyView(path string) bool {
	access := uint32(reg.READ)

	// 只有 SOFTWARE 类路径才会被 Wow64 重定向
	isSoftware := strings.HasPrefix(strings.ToUpper(path), "SOFTWARE\\")
	if isSoftware && utils.IsWOW64() {
		k, err := reg.OpenKey(reg.LOCAL_MACHINE, path, access|reg.WOW64_64KEY)
		if err == nil {
			_ = k.Close()
			return true
		}
	}
	k, err := reg.OpenKey(reg.LOCAL_MACHINE, path, access)
	if err == nil {
		_ = k.Close()
		return true
	}
	return false
}

// GetTPM：
// 1) 优先 WMI（最靠谱，能拿到 IsEnabled_InitialValue / SpecVersion）
// 2) WMI 不可用（WinPE/裁剪系统）时，退回注册表设备枚举：
//   - ACPI\MSFT0101 => 2.0
//   - Root\SecurityDevices\0000 => 1.2
//
// 注意：注册表兜底更偏“设备存在/版本推断”，无法 100% 等价于“固件启用状态”。
func GetTPM() (bool, string, error) {
	// 1) WMI
	if enabled, ver, ok, err := tpmViaWMI(); ok {
		return enabled, ver, err // err 通常为 nil；保留以便你记录诊断
	}

	// 2) Registry fallback
	ver, present := tpmVersionReg()
	if present {
		// 兜底：能枚举到 TPM 设备，一般意味着系统能看到它；这里用 enabled=true 更贴近
		return true, ver, nil
	}
	return false, "", nil
}

func tpmVersionReg() (version string, present bool) {
	// TPM 2.0 常见枚举
	if regKeyInHKLM(`SYSTEM\CurrentControlSet\Enum\ACPI\MSFT0101`) {
		return "2.0", true
	}
	// TPM 1.2 常见枚举
	if regKeyInHKLM(`SYSTEM\CurrentControlSet\Enum\Root\SecurityDevices\0000`) {
		return "1.2", true
	}
	return "", false
}

// tpmViaWMI：用wmi检测 TPM 的启用状态和版本，理论上更准确（能区分固件启用状态和设备存在）
// PE系统通常没有，此处占位保留
func tpmViaWMI() (enabled bool, version string, ok bool, err error) {
	return false, "", false, nil
}

// 根据物理内存大小判断期望架构：
// - <4GB 使用 32 位
// - >=4GB 使用 64 位
// - 获取失败默认 64 位
// - win11 强制 64 位
func DesiredArch() string {
	version, _, _ := GetCurrentWinVersion()
	if version == 11 {
		return "64"
	}
	mem, err := tools.GetMemory()
	log.LogWrite(0, "[desiredArch]物理内存大小：%d GB, err=%v", mem, err)
	if err == nil {
		// 判断是否小于 4GB
		if mem < 4 {
			return "32"
		}
		return "64" // >= 4GB
	}

	// 获取失败默认 64 位
	return "64"
}

// 获取系统盘根路径（例如 C:\）。
func SystemDriveRoot() string {
	drive := strings.TrimSpace(os.Getenv("SystemDrive"))
	if drive == "" {
		windir := utils.WindowsDir()
		if windir != "" {
			drive = filepath.VolumeName(windir)
		}
	}
	drive = strings.TrimSpace(drive)
	if drive == "" {
		return ""
	}
	drive = strings.TrimRight(drive, `\`)
	if strings.HasSuffix(drive, ":") {
		return drive + `\`
	}
	if len(drive) == 1 {
		return strings.ToUpper(drive) + `:\`
	}
	if vol := filepath.VolumeName(drive); vol != "" {
		return vol + `\`
	}
	return ""
}

// CompactOS 支持对win10+系统进行压缩，支持正在运行的系统，速度较慢，不建议使用
func CompactOS(always bool) error {
	if always {
		t, err := tools.RunCmd("compact", nil, nil, "", "/compactos:always")
		fmt.Println(t)
		return err
	} else {
		t, err := tools.RunCmd("compact", nil, nil, "", "/compactos:never")
		fmt.Println(t)
		return err
	}

}

// 清理指定分区垃圾文件
func ClearPartition() {
	userProfile := os.Getenv("USERPROFILE")
	temp := os.Getenv("TEMP")
	winDir := os.Getenv("WINDIR")
	allUsers := os.Getenv("ALLUSERSPROFILE")
	systemRoot := os.Getenv("SystemRoot")
	//清理 Internet 缓存目录
	file.Remove(filepath.Join(userProfile, "AppData", "Local", "Microsoft", "Windows", "Temporary Internet Files"), true, true)
	file.Remove(filepath.Join(userProfile, "AppData", "Local", "Microsoft", "Windows", "INetCache"), true, true)
	file.Remove(filepath.Join(userProfile, "AppData", "Local", "Microsoft", "Windows", "INetCookies"), true, true)
	// 清理缩略图缓存
	file.Remove(filepath.Join(userProfile, "AppData", "Local", "Microsoft", "Windows", "Explorer", "thumbcache_*.db"), false, false)
	// 清理临时文件
	file.Remove(filepath.Join(temp), true, true)
	file.Remove(filepath.Join(winDir, "Temp"), true, true)
	file.Remove(filepath.Join(winDir, "*.tmp"), false, false)
	file.Remove(filepath.Join(winDir, "*.bak"), false, false)
	file.Remove(filepath.Join(winDir, "*.old"), false, false)
	file.Remove(filepath.Join(userProfile, "*.tmp"), false, false)
	file.Remove(filepath.Join(userProfile, "*.bak"), false, false)
	file.Remove(filepath.Join(userProfile, "Downloads", "*.tmp"), false, false)
	file.Remove(filepath.Join(userProfile, "Desktop", "*.tmp"), false, false)
	file.Remove(filepath.Join("C", "*.tmp"), false, false)
	file.Remove(filepath.Join("C", "*._mp"), false, false)
	file.Remove(filepath.Join(userProfile, "AppData", "Local", "Temp"), true, true)
	//清理历史记录
	file.Remove(filepath.Join(userProfile, "AppData", "Local", "Microsoft", "Windows", "History"), true, true)
	//清理系统错误报告
	file.Remove(filepath.Join(allUsers, "Microsoft", "Windows", "WER"), true, true)
	//清理Windows目录下的转储文件
	file.Remove(filepath.Join(winDir, "MEMORY.DMP"), false, false)
	file.Remove(filepath.Join(winDir, "Minidump", "*.dmp"), false, false)
	//清理系统错误内存转储文件
	file.Remove(filepath.Join(systemRoot, "MEMORY.DMP"), false, false)
	//清理调试转储文件
	file.Remove(filepath.Join(systemRoot, "Minidump"), true, true)
	//清理临时安装文件
	file.Remove(filepath.Join(winDir, "msdownld.tmp"), true, true)
	//清空回收站
	flags := uintptr(SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND)
	procSHEmptyRecycleBinW.Call(0, 0, flags)
	//清理浏览器缓存
	file.Remove(filepath.Join(userProfile, "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Cache"), true, true)
	file.Remove(filepath.Join(userProfile, "AppData", "Local", "Google", "Chrome", "User Data", "Default", "GPUCache"), true, true)
	file.Remove(filepath.Join(userProfile, "AppData", "Local", "Microsoft", "Edge", "User Data", "Default", "Cache"), true, true)
	file.Remove(filepath.Join(userProfile, "AppData", "Local", "Microsoft", "Edge", "User Data", "Default", "GPUCache"), true, true)
	file.Remove(filepath.Join(userProfile, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles", "*.default", "cache2"), true, true)
	file.Remove(filepath.Join(userProfile, "AppData", "Mozilla", "Local", "Firefox", "Profiles", "*.default-release", "cache2"), true, true)
	//清理更新下载缓存
	file.Remove(filepath.Join(winDir, "SoftwareDistribution", "Download"), true, true)
	//清理传递优化缓存
	file.Remove(filepath.Join(winDir, "ServiceProfiles", "NetworkService", "AppData", "Local", "Microsoft", "Windows", "DeliveryOptimization", "Cache"), true, true)
	//清理Windows更新日志
	file.Remove(filepath.Join(winDir, "WindowsUpdate.log"), false, false)
	//清理Windows.old文件夹
	file.Remove(filepath.Join("C", "Windows.old"), true, false)
	//清理Windows Installer缓存
	file.Remove(filepath.Join(winDir, "Installer", "$PatchCache$"), true, true)
	//清理系统更新卸载备份
	file.Remove(filepath.Join(winDir, "servicing", "LCU"), true, true)
	//清理系统日志文件
	file.Remove(filepath.Join(winDir, "Logs", "CBS"), true, true)
	file.Remove(filepath.Join(winDir, "Logs", "DISM"), true, true)
	file.Remove(filepath.Join(winDir, "System32", "LogFiles"), true, true)
	file.Remove(filepath.Join(winDir, "*.log"), false, false)
	file.Remove(filepath.Join(winDir, "inf", "*.log"), false, false)
	file.Remove(filepath.Join("C", "inetpub", "logs"), true, true)
	//清理软件缓存
	file.Remove(filepath.Join(userProfile, "AppData", "Roaming", "kingsoft", "wps", "cache"), true, true)
	file.Remove(filepath.Join(userProfile, "AppData", "Local", "Kingsoft", "WPS Office", "cache"), true, true)
	file.Remove(filepath.Join(userProfile, "AppData", "Roaming", "Kingsoft", "office6", "cache"), true, true)
	file.Remove(filepath.Join(userProfile, "AppData", "Roaming", "Tencent", "QQ", "Temp"), true, true)
	file.Remove(filepath.Join(userProfile, "AppData", "Local", "Tencent", "QQ", "Cache"), true, true)
	file.Remove(filepath.Join(userProfile, "AppData", "Roaming", "Tencent", "WeChat", "Cache"), true, true)
	file.Remove(filepath.Join(userProfile, "AppData", "Roaming", "Tencent", "WeChat", "Temp"), true, true)
	file.Remove(filepath.Join(userProfile, "AppData", "Roaming", "Thunder Network", "Thunder", "Profiles", "*", "Cache", "*"), true, false)
	file.Remove(filepath.Join(userProfile, "AppData", "Roaming", "Adobe", "Common", "Media Cache Files"), true, true)
	file.Remove(filepath.Join(userProfile, "AppData", "Local", "Adobe", "Common", "Media Cache Files"), true, true)
	file.Remove(filepath.Join(userProfile, "AppData", "Local", "Microsoft", "Office", "16.0", "OfficeFileCache"), true, true)
	file.Remove(filepath.Join(userProfile, "AppData", "Local", "Microsoft", "Office", "15.0", "OfficeFileCache"), true, true)
	file.Remove(filepath.Join(userProfile, "AppData", "Local", "Microsoft", "VisualStudio", "*", "ComponentModelCache", "*"), true, false)
	file.Remove(filepath.Join("C", "DrvPath"), true, true)
	//清理字体缓存
	file.Remove(filepath.Join(winDir, "ServiceProfiles", "LocalService", "AppData", "Local", "FontCache"), true, true)
	file.Remove(filepath.Join(winDir, "System32", "FNTCACHE.DAT"), false, false)
	//清理Media Player缓存
	file.Remove(filepath.Join(userProfile, "AppData", "Local", "Microsoft", "Media Player"), true, true)
	//清理Windows搜索历史
	file.Remove(filepath.Join(userProfile, "AppData", "Local", "Microsoft", "Windows", "ConnectedSearch", "History"), true, true)
	//清理Game Bar缓存
	file.Remove(filepath.Join(userProfile, "AppData", "Local", "Microsoft", "GameDVR"), true, true)
	//清理OneDrive缓存
	file.Remove(filepath.Join(userProfile, "AppData", "Local", "Microsoft", "OneDrive", "logs"), true, true)
	//清理Windows缓存文件
	file.Remove(filepath.Join(winDir, "cache"), true, true)
	//清理日志
	file.Remove(filepath.Join(systemRoot, "Logs"), true, true)
}
