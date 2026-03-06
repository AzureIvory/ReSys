package windows

import (
	"ReSys/src/registry"
	"ReSys/src/tools"
	"ReSys/src/utils"
	"debug/pe"
	"fmt"
	"runtime"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)
var(
	version                 = syscall.NewLazyDLL("version.dll")
	procGetFileVersionInfoSize = version.NewProc("GetFileVersionInfoSizeW")
	procGetFileVersionInfo     = version.NewProc("GetFileVersionInfoW")
	procVerQueryValue          = version.NewProc("VerQueryValueW")
)
const(
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

	arch := detectArch(root, hasPFx86, hasSysWOW, systemLoaded)

	return fmt.Sprintf("%s %s", osName, arch), nil
}

// 推测指定盘符的系统架构（32/64）
func detectArch(root string, hasPFx86, hasSysWOW, systemLoaded bool) string {
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
	var blockPtr uintptr
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

	fixedInfo := (*VS_FIXEDFILEINFO)(unsafe.Pointer(blockPtr))
	if fixedInfo.DwSignature != 0xfeef04bd {
		return 0, 0, 0, fmt.Errorf("无效的版本信息签名")
	}
	major := uint16(fixedInfo.DwFileVersionMS >> 16)
	minor := uint16(fixedInfo.DwFileVersionMS & 0xFFFF)
	build := uint16(fixedInfo.DwFileVersionLS >> 16) // 顺手把 Build 拿出来，区分 Win10/11 极度需要

	return major, minor, build, nil
}