package boot

import (
	"ReSys/src/disk"
	"ReSys/src/tools"
	"ReSys/src/utils"
	winver "ReSys/src/windows"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	syswin "golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// 根据分区取磁盘的分区格式（MBR/GPT/RAW）

var (
	Kernel32            = syscall.NewLazyDLL("kernel32.dll")
	procGetFirmwareType = Kernel32.NewProc("GetFirmwareType")
)

const (
	fwTypeUnknown = 0
	fwTypeBios    = 1
	fwTypeUefi    = 2
	fwTypeMax     = 3
)

// 获取当前系统引导 GUID
func GetBootGUID() (string, error) {
	windir := utils.WindowsDir()
	if windir == "" {
		return "", fmt.Errorf("WINDIR/SystemRoot is empty")
	}
	bcdeditPath := utils.GetSystemExe("bcdedit.exe")

	out, err := tools.RunCmd(bcdeditPath, nil, nil, "", "/enum")
	if err != nil && (errors.Is(err, os.ErrNotExist) || errors.Is(err, exec.ErrNotFound)) {
		if exe, e := os.Executable(); e == nil {
			fallback := filepath.Join(filepath.Dir(exe), "tools", "bcdedit.exe")
			out2, err2 := tools.RunCmd(fallback, nil, nil, "", "/enum")
			// 用 fallback 的结果覆盖
			out, err = out2, err2
			bcdeditPath = fallback
		}
	}
	// 这里如果 err != nil，也可能 out 里有内容（你 runCmd 会把输出带回来）
	// 但 bcdedit 通常需要管理员权限/环境正常，否则解析也没意义：直接返回错误更安全。
	if err != nil {
		return "", fmt.Errorf("bcdedit failed (%s): %w", bcdeditPath, err)
	}

	systemDrive := os.Getenv("SystemDrive")
	if systemDrive == "" {
		systemDrive = "C:"
	}
	systemDrive = strings.TrimRight(systemDrive, `\`)

	id, perr := parseBootIdentifier(out, systemDrive)
	if perr != nil {
		return "", perr
	}
	return id, nil
}

// 解析`bcdedit /enum`的输出，找到与当前系统盘匹配的引导项，并返回其 Identifier。
func parseBootIdentifier(out, systemDrive string) (string, error) {
	type entry struct {
		title    string
		id       string
		device   string
		osdevice string
	}

	isDashLine := func(s string) bool {
		s = strings.TrimSpace(s)
		if s == "" {
			return false
		}
		for _, r := range s {
			if r != '-' && r != '—' && r != '─' {
				return false
			}
		}
		return true
	}

	isBootLoaderTitle := func(title string) bool {
		t := strings.ToLower(title)
		// English / Chinese common headings
		return strings.Contains(t, "windows boot loader") ||
			strings.Contains(t, "boot loader") ||
			strings.Contains(title, "Windows 启动加载器") ||
			strings.Contains(title, "启动加载器")
	}

	matchesSystemDrive := func(v string) bool {
		if v == "" {
			return false
		}
		vl := strings.ToLower(v)
		sd := strings.ToLower(systemDrive)
		// 常见形式：partition=C: / partition=C:\ / ...C:
		return strings.Contains(vl, "partition="+sd) ||
			strings.Contains(vl, sd+`\`) ||
			strings.Contains(vl, sd)
	}

	flush := func(e entry) (hit bool, best bool, id string) {
		if e.id == "" {
			return false, false, ""
		}
		if matchesSystemDrive(e.device) || matchesSystemDrive(e.osdevice) {
			if isBootLoaderTitle(e.title) {
				return true, true, e.id // best hit
			}
			return true, false, e.id // hit but not best
		}
		return false, false, ""
	}

	var (
		cur         entry
		bestAnyHit  string // fallback if only non-boot-loader hits
		gotAnyEntry bool
	)

	lines := strings.Split(out, "\n")
	for _, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		trim := strings.TrimSpace(line)

		// block separator
		if trim == "" {
			if gotAnyEntry {
				hit, best, id := flush(cur)
				if best {
					return id, nil
				}
				if hit && bestAnyHit == "" {
					bestAnyHit = id
				}
			}
			cur = entry{}
			gotAnyEntry = false
			continue
		}
		if isDashLine(trim) {
			continue
		}

		// Try detect title line (usually appears before key/value lines)
		// Example: "Windows Boot Loader" / "Windows 启动加载器"
		// We treat a non key-value line as title when current entry hasn't started.
		if !gotAnyEntry {
			low := strings.ToLower(trim)
			if !(strings.HasPrefix(low, "identifier") || strings.HasPrefix(trim, "标识符") ||
				strings.HasPrefix(low, "device") || strings.HasPrefix(trim, "设备") ||
				strings.HasPrefix(low, "osdevice")) {
				// likely a section title
				cur.title = trim
				// still not mark gotAnyEntry yet (no properties)
			}
		}

		fields := strings.Fields(trim)
		if len(fields) < 2 {
			continue
		}
		key := fields[0]
		val := strings.Join(fields[1:], " ")
		gotAnyEntry = true

		kl := strings.ToLower(key)

		// identifier / 标识符
		if kl == "identifier" || key == "标识符" || strings.Contains(trim, "identifier") || strings.Contains(trim, "标识符") {
			// bcdedit identifier is usually last token
			cur.id = fields[len(fields)-1]
			continue
		}

		// osdevice
		if kl == "osdevice" || strings.Contains(kl, "osdevice") {
			cur.osdevice = val
			continue
		}

		// device / 设备
		if kl == "device" || key == "设备" || strings.Contains(trim, " device") || strings.Contains(trim, "设备") {
			cur.device = val
			continue
		}
	}

	// flush last block
	if gotAnyEntry {
		hit, best, id := flush(cur)
		if best {
			return id, nil
		}
		if hit && bestAnyHit == "" {
			bestAnyHit = id
		}
	}

	if bestAnyHit != "" {
		return bestAnyHit, nil
	}
	return "", fmt.Errorf("could not find current boot identifier for SystemDrive=%s", systemDrive)
}

// getFwTypeEx 使用 GetFirmwareEnvironmentVariableW 读“空变量”判断启动模式：
// - Legacy BIOS：返回 ERROR_INVALID_FUNCTION (1) => Legacy
// - UEFI：返回其他错误（如 ERROR_NOACCESS / ERROR_ENVVAR_NOT_FOUND 等）=> UEFI
// 1=bios, 2=uefi
func getFwTypeEx() (uint32, error) {
	k32 := syswin.NewLazySystemDLL("kernel32.dll")
	proc := k32.NewProc("GetFirmwareEnvironmentVariableW")
	if err := k32.Load(); err != nil {
		return fwTypeBios, err
	}
	if err := proc.Find(); err != nil {
		return fwTypeBios, err
	}

	// lpName = ""（空字符串）
	// lpGuid = "{00000000-0000-0000-0000-000000000000}"（虚拟 GUID）
	name := syswin.StringToUTF16Ptr("")
	guid := syswin.StringToUTF16Ptr("{00000000-0000-0000-0000-000000000000}")
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
			if errno == syswin.ERROR_INVALID_FUNCTION {
				return fwTypeBios, nil
			}
			// 其他错误基本都视为 UEFI（如 ERROR_NOACCESS / ERROR_ENVVAR_NOT_FOUND）
			return fwTypeUefi, nil
		}
		// 拿不到 errno：保守当作 UEFI
		return fwTypeUefi, nil
	}

	// 成功（很少见，因为我们读的是空变量），也说明 UEFI
	return fwTypeUefi, nil
}

// 获取固件类型（UEFI/BIOS）
// win8以上使用
// 1=bios, 2=uefi, 0=unknown
func getFwTypePlus() (uint32, error) {
	var t uint32
	r, _, err := procGetFirmwareType.Call(uintptr(unsafe.Pointer(&t)))
	if r == 0 {
		if err != nil && err != syscall.Errno(0) {
			return fwTypeUnknown, fmt.Errorf("GetFwType failed: %w", err)
		}
		return fwTypeUnknown, fmt.Errorf("GetFwType failed")
	}
	return t, nil
}

// GetFwType 获取固件类型（UEFI/BIOS）
func GetFwType() (uint32, error) {
	version, _, verErr := winver.GetCurrentWinVersion()
	if verErr != nil {
		t, err := getFwTypeEx()
		if err == nil {
			return t, nil
		}
		return fwTypeUnknown, fmt.Errorf("detect Windows version failed: %w; GetFwTypeEx failed: %v", verErr, err)
	}

	if version < 8 {
		return getFwTypeEx()
	}

	t, err := getFwTypePlus()
	if err == nil && t != fwTypeUnknown {
		return t, nil
	}

	fallback, fallbackErr := getFwTypeEx()
	if fallbackErr == nil {
		return fallback, nil
	}

	if err != nil {
		return fwTypeUnknown, fmt.Errorf("GetFwType failed: %v; GetFwTypeEx failed: %w", err, fallbackErr)
	}
	return fwTypeUnknown, fmt.Errorf("GetFwType returned unknown; GetFwTypeEx failed: %w", fallbackErr)
}

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

// 找 ESP分区
// 适用于已经挂载了而且分配了盘符的情况
// todo：还需要兼容多磁盘多系统多ESP的情况
// todo：，在多个ESP时优先考虑同盘的，如果同盘没有才考虑其他盘，其他盘也没就创建ESP分区吧
func FindESP(osRoot string) (string, error) {
	roots, err := disk.ListDrive()
	if err != nil {
		return "", fmt.Errorf("ListDrive: %w", err)
	}

	var (
		bestWithEFI     string
		bestWithEFISize uint64 = ^uint64(0)

		bestAny     string
		bestAnySize uint64 = ^uint64(0)
	)

	for _, r := range roots {
		dt := disk.GetDriveType(r)
		if dt != 3 && dt != 4 {
			continue
		}
		root, _ := utils.NormalizeDrive(r, 0)
		if root == "" {
			continue
		}
		// 跳过osRoot
		if strings.EqualFold(root, osRoot) {
			continue
		}

		fs, size, err := disk.GetVolumeInfo(root)
		if err != nil {
			continue
		}
		if fs != "FAT32" {
			continue
		}

		// >4GB
		if size > 4*1024*1024*1024 {
			continue
		}

		hasEFI := false
		if st, err := os.Stat(root + "EFI"); err == nil && st.IsDir() {
			hasEFI = true
		}

		if hasEFI {
			if size < bestWithEFISize {
				bestWithEFISize = size
				bestWithEFI = root
			}
		} else {
			if size < bestAnySize {
				bestAnySize = size
				bestAny = root
			}
		}
	}

	if bestWithEFI != "" {
		fmt.Println("[FindESP] use FAT32 + EFI:", bestWithEFI)
		return bestWithEFI, nil
	}
	if bestAny != "" {
		fmt.Println("[FindESP] use smallest FAT32:", bestAny)
		return bestAny, nil
	}
	return "", fmt.Errorf("no ESP-like FAT32 volume found")
}

// FixBoot自动判断并修复引导。
// osVol:系统分区
// sysVol: ESP分区，可空；找不到ESP时会使用系统分区
// locale: 语言（"zh-cn"/"en-us" 等），空则默认 "zh-cn"。
func FixBoot(osVol, sysVol, locale string) error {
	if locale == "" {
		locale = "zh-cn"
	}

	osRoot, err := FindOS(osVol)
	if err != nil {
		return fmt.Errorf("FindOS failed: %w", err)
	}
	winDir := osRoot + "Windows"

	if st, err := os.Stat(winDir); err != nil || !st.IsDir() {
		fmt.Println("[FixBoot] warning: Windows dir not found:", winDir, err)
	} else {
		fmt.Println("[FixBoot] OS volume:", osRoot)
	}

	fw, err := GetFwType()
	if err != nil {
		fmt.Println("[FixBoot] GetFirmwareType failed, treat as BIOS:", err)
		fw = fwTypeBios
	} else {
		if fw == fwTypeUefi {
			fmt.Println("[FixBoot] Firmware: UEFI")
		} else if fw == fwTypeBios {
			fmt.Println("[FixBoot] Firmware: BIOS")
		} else {
			fmt.Println("[FixBoot] Firmware: unknown:", fw)
		}
	}

	// 检测OS卷所在磁盘的分区格式
	diskStyle, diskNum, err := disk.GetDiskInfo(osRoot)
	if err != nil {
		fmt.Println("[FixBoot] GetDiskInfo failed, will fallback:", err)
	} else {
		fmt.Printf("[FixBoot] Disk %d style: %s\n", diskNum, diskStyle)
	}

	mode := "BIOS"
	switch diskStyle {
	case "MBR":
		mode = "BIOS"
	case "GPT":
		if fw == fwTypeUefi {
			mode = "UEFI"
		} else {
			mode = "BIOS"
		}
	default:
		if fw == fwTypeUefi {
			mode = "UEFI"
		} else {
			mode = "BIOS"
		}
	}

	fmt.Println("[FixBoot] final mode:", mode)

	if mode == "UEFI" {
		return FixUEFI(osRoot, sysVol, locale)
	}
	return FixBIOS(osRoot, sysVol, locale)
}

// UEFI引导修复
// todo 当EFI不存在时不应该直接用系统分区
// todo 当固件是GPT但是没有esp分区而且安装的是win8以上系统（需要efi引导的系统）时在磁盘新建一个esp，win7之前的系统时就转为mbr格式用bios引导
func FixUEFI(osRoot, sysHint, locale string) error {
	winDir := osRoot + "Windows"

	var sysRoot string
	if sysHint != "" {
		r, _ := utils.NormalizeDrive(sysHint, 0)
		if r != "" {
			if fs, _, err := disk.GetVolumeInfo(r); err == nil && fs == "FAT32" {
				sysRoot = r
				fmt.Println("[FixUEFI] use sysVol hint:", sysRoot)
			} else {
				fmt.Println("[FixUEFI] sysVol hint not FAT32, ignore:", r)
			}
		}
	}

	if sysRoot == "" {
		if r, err := FindESP(osRoot); err == nil {
			sysRoot = r
		} else {
			fmt.Println("[FixUEFI] FindESP failed:", err)
		}
	}

	// 找不到ESP就用系统卷
	if sysRoot == "" {
		sysRoot = osRoot
		fmt.Println("[FixUEFI] WARN: no ESP found, fallback to OS volume:", sysRoot)
	}

	args := []string{
		winDir,
		"/l", locale,
		"/s", sysRoot,
		"/f", "UEFI",
	}
	bcdpath := utils.GetSystemExe("bcdboot.exe")

	out, err := tools.RunCmd(bcdpath, nil, nil, "", args...)
	if err != nil {
		fmt.Println("[FixUEFI] bcdboot failed")
		fmt.Println(out)
		return err
	}
	fmt.Println("[FixUEFI] bcdboot ok")
	fmt.Println(out)
	return nil
}

// BIOS/MBR引导修复
func FixBIOS(osRoot, sysHint, locale string) error {
	winDir := osRoot + "Windows"
	sysRoot, _ := utils.NormalizeDrive(sysHint, 0)
	if sysRoot == "" {
		sysRoot = osRoot
	}

	// 修复MBR/PBR
	if out, err := tools.RunCmd("bootrec.exe", nil, nil, "", "/fixmbr"); err != nil {
		fmt.Println("[FixBIOS] bootrec /fixmbr failed (may be ok):", err)
		fmt.Println(out)
	} else {
		fmt.Println("[FixBIOS] bootrec /fixmbr ok")
		fmt.Println(out)
	}
	if out, err := tools.RunCmd("bootrec.exe", nil, nil, "", "/fixboot"); err != nil {
		fmt.Println("[FixBIOS] bootrec /fixboot failed, try bootsect:", err)
		fmt.Println(out)
		if out2, err2 := tools.RunCmd("bootsect.exe", nil, nil, "", "/nt60", sysRoot, "/mbr"); err2 != nil {
			fmt.Println("[FixBIOS] bootsect failed:", err2)
			fmt.Println(out2)
		} else {
			fmt.Println("[FixBIOS] bootsect ok")
		}
	} else {
		fmt.Println("[FixBIOS] bootrec /fixboot ok")
		fmt.Println(out)
	}

	//bcdboot
	args := []string{
		winDir,
		"/l", locale,
		"/s", sysRoot,
		"/f", "BIOS",
	}
	bcdpath := utils.GetSystemExe("bcdboot.exe")

	out, err := tools.RunCmd(bcdpath, nil, nil, "", args...)
	if err != nil {
		fmt.Println("[FixBIOS] bcdboot failed")
		fmt.Println(out)
		return err
	}
	fmt.Println("[FixBIOS] bcdboot ok")
	fmt.Println(out)
	return nil
}

// 找系统分区
func FindOS(hint string) (string, error) {
	if hint != "" {
		root, _ := utils.NormalizeDrive(hint, 0)
		if root != "" {
			if st, err := os.Stat(root + "Windows"); err == nil && st.IsDir() {
				fmt.Println("[FindOS] use hint:", root)
				return root, nil
			}
			fmt.Println("[FindOS] hint has no Windows dir:", root)
		}
	}

	roots, err := disk.ListDrive()
	if err != nil {
		return "", fmt.Errorf("ListDrive: %w", err)
	}

	var cand string
	for _, r := range roots {
		dt := disk.GetDriveType(r)
		// 跳过CD和网络盘
		if dt != 3 && dt != 4 {
			continue
		}
		root, _ := utils.NormalizeDrive(r, 0)
		if st, err := os.Stat(root + "Windows"); err == nil && st.IsDir() {
			cand = root
			fmt.Println("[FindOS] found OS volume:", cand)
			break
		}
	}

	if cand == "" {
		return "", fmt.Errorf("no volume with \\Windows found")
	}
	return cand, nil
}
