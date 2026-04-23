package boot

import (
	"ReSys/src/disk"
	"ReSys/src/log"
	"ReSys/src/tools"
	"ReSys/src/utils"
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

// Kernel32 句柄和固件类型 API。
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

const (
	espSizeMB                   = 200
	espSizeBytes         uint64 = espSizeMB * 1024 * 1024
	espShrinkSafetyBytes        = 64 * 1024 * 1024
	espProbeWindowBytes         = 32 * 1024 * 1024
)

// 获取当前系统引导 GUID。
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
			out, err = out2, err2
			bcdeditPath = fallback
		}
	}
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

func parseBootIdentifier(out, systemDrive string) (string, error) {
	type entry struct {
		title    string
		id       string
		device   string
		osdevice string
	}

	const (
		zhIdentifier       = "\u6807\u8bc6\u7b26"
		zhDevice           = "\u8bbe\u5907"
		zhWindowsBootLabel = "Windows \u542f\u52a8\u52a0\u8f7d\u5668"
		zhBootLoaderLabel  = "\u542f\u52a8\u52a0\u8f7d\u5668"
	)

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
		return strings.Contains(t, "windows boot loader") ||
			strings.Contains(t, "boot loader") ||
			strings.Contains(title, zhWindowsBootLabel) ||
			strings.Contains(title, zhBootLoaderLabel)
	}

	matchesSystemDrive := func(v string) bool {
		if v == "" {
			return false
		}
		vl := strings.ToLower(v)
		sd := strings.ToLower(systemDrive)
		return strings.Contains(vl, "partition="+sd) ||
			strings.Contains(vl, sd+`\`) ||
			strings.Contains(vl, sd)
	}

	flush := func(e entry) (bool, bool, string) {
		if e.id == "" {
			return false, false, ""
		}
		if matchesSystemDrive(e.device) || matchesSystemDrive(e.osdevice) {
			if isBootLoaderTitle(e.title) {
				return true, true, e.id
			}
			return true, false, e.id
		}
		return false, false, ""
	}

	var (
		cur         entry
		bestAnyHit  string
		gotAnyEntry bool
	)

	lines := strings.Split(out, "\n")
	for _, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		trim := strings.TrimSpace(line)
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

		if !gotAnyEntry {
			low := strings.ToLower(trim)
			if !(strings.HasPrefix(low, "identifier") || strings.HasPrefix(trim, zhIdentifier) ||
				strings.HasPrefix(low, "device") || strings.HasPrefix(trim, zhDevice) ||
				strings.HasPrefix(low, "osdevice")) {
				cur.title = trim
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

		if kl == "identifier" || key == zhIdentifier || strings.Contains(trim, "identifier") || strings.Contains(trim, zhIdentifier) {
			cur.id = fields[len(fields)-1]
			continue
		}
		if kl == "osdevice" || strings.Contains(kl, "osdevice") {
			cur.osdevice = val
			continue
		}
		if kl == "device" || key == zhDevice || strings.Contains(trim, " device") || strings.Contains(trim, zhDevice) {
			cur.device = val
			continue
		}
	}

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

func getFwTypeEx() (uint32, error) {
	k32 := syswin.NewLazySystemDLL("kernel32.dll")
	proc := k32.NewProc("GetFirmwareEnvironmentVariableW")
	if err := k32.Load(); err != nil {
		return fwTypeBios, err
	}
	if err := proc.Find(); err != nil {
		return fwTypeBios, err
	}

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
		if errno, ok := e1.(syscall.Errno); ok {
			if errno == syswin.ERROR_INVALID_FUNCTION {
				return fwTypeBios, nil
			}
			return fwTypeUefi, nil
		}
		return fwTypeUefi, nil
	}
	return fwTypeUefi, nil
}

func getFwTypePlus() (uint32, error) {
	return getFwTypeEx()
}

func GetFwType() (uint32, error) {
	if err := Kernel32.Load(); err == nil {
		if err := procGetFirmwareType.Find(); err == nil {
			var fwType uint32
			r, _, callErr := procGetFirmwareType.Call(uintptr(unsafe.Pointer(&fwType)))
			if r != 0 {
				if fwType == 0 || fwType >= fwTypeMax {
					return fwTypeUnknown, nil
				}
				return fwType, nil
			}
			if errno, ok := callErr.(syscall.Errno); ok && errno == 0 {
				// fallback below
			}
		}
	}
	return getFwTypePlus()
}

func SecureBootEnabled() (bool, error) {
	const keyPath = `SYSTEM\CurrentControlSet\Control\SecureBoot\State`
	const valueName = `UEFISecureBootEnabled`

	k, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.QUERY_VALUE)
	if err != nil {
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

func FindESP(osRoot string) (string, func(), error) {
	root, _ := utils.NormalizeDrive(osRoot, 0)
	if root == "" {
		return "", nil, fmt.Errorf("empty os root")
	}
	osRoot = root

	style, diskNum, err := disk.GetDiskInfo(osRoot)
	if err != nil {
		return "", nil, fmt.Errorf("GetDiskInfo: %w", err)
	}
	if !strings.EqualFold(style, "GPT") {
		return "", nil, fmt.Errorf("target disk %d is %s, ESP requires GPT", diskNum, style)
	}
	targetDisk := int(diskNum)

	if root, cleanup, found, err := disk.FindESPOnDisk(targetDisk); err != nil {
		return "", nil, fmt.Errorf("find target-disk ESP: %w", err)
	} else if found {
		fmt.Println("[FindESP] use same-disk EFI:", root)
		log.LogWrite(0, "[FindESP] found ESP on target disk %d, use it\n", targetDisk)
		return root, cleanup, nil
	}

	disks, err := disk.ListPhysicalDisks()
	if err != nil {
		return "", nil, fmt.Errorf("ListPhysicalDisks: %w", err)
	}
	log.LogWrite(0, "[FindESP] target disk %d, enumerate disks to find fallback ESP\n  err: %v", targetDisk, err)
	volumes, err := disk.ListVolumes()
	if err != nil {
		return "", nil, fmt.Errorf("ListVolumes: %w", err)
	}
	for _, d := range disks {
		if d.DiskNumber == targetDisk {
			continue
		}
		if disk.ShouldSkipFallbackDisk(d.DiskNumber, volumes) {
			fmt.Printf("[FindESP] skip fallback disk %d\n", d.DiskNumber)
			log.LogWrite(0, "[FindESP] skip fallback disk %d\n", d.DiskNumber)
			continue
		}
		if root, cleanup, found, err := disk.FindESPOnDisk(d.DiskNumber); err != nil {
			fmt.Printf("[FindESP] enumerate disk %d failed: %v\n", d.DiskNumber, err)
			log.LogWrite(0, "[FindESP] enumerate disk %d failed: %v\n", d.DiskNumber, err)
			continue
		} else if found {
			fmt.Println("[FindESP] use fallback EFI:", root)
			log.LogWrite(0, "[FindESP] found fallback ESP on disk %d, use it\n", d.DiskNumber)
			return root, cleanup, nil
		}
	}

	log.LogWrite(0, "[FindESP] no EFI found, create new ESP on disk %d\n", targetDisk)
	return CreateESP(osRoot)
}

// CreateESP 在目标 GPT 磁盘上创建一个 200MB 的 ESP 分区。
func CreateESP(osRoot string) (string, func(), error) {
	root, _ := utils.NormalizeDrive(osRoot, 0)
	if root == "" {
		return "", nil, fmt.Errorf("empty os root")
	}
	osRoot = root

	style, diskNum, err := disk.GetDiskInfo(osRoot)
	if err != nil {
		return "", nil, fmt.Errorf("GetDiskInfo: %w", err)
	}
	if !strings.EqualFold(style, "GPT") {
		return "", nil, fmt.Errorf("target disk %d is %s, cannot create ESP", diskNum, style)
	}
	targetDisk := int(diskNum)

	extents, err := disk.GetDiskFreeExtents(targetDisk)
	if err != nil {
		return "", nil, fmt.Errorf("GetDiskFreeExtents: %w", err)
	}
	if extent, ok := disk.PickESPFreeExtent(extents, espSizeBytes); ok {
		fmt.Printf("[CreateESP] use existing free extent on disk %d offset=%d size=%d\n", targetDisk, extent.OffsetBytes, extent.SizeBytes)
		return disk.CreateESPFromExtent(extent, espSizeMB, "SYSTEM")
	}

	shrinkRoot, err := disk.PickESPShrinkVolume(osRoot, targetDisk, espSizeBytes+espShrinkSafetyBytes)
	if err != nil {
		return "", nil, err
	}
	fmt.Printf("[CreateESP] shrink %s to create ESP on disk %d\n", shrinkRoot, targetDisk)
	if out, err := disk.ShrinkVolume(shrinkRoot, espSizeMB); err != nil {
		return "", nil, fmt.Errorf("ShrinkVolume %s failed: %w\n输出:\n%s", shrinkRoot, err, out)
	}

	extent, err := disk.FindESPFreeExtentAfterShrink(shrinkRoot, targetDisk, espSizeBytes, espProbeWindowBytes)
	if err != nil {
		return "", nil, err
	}
	return disk.CreateESPFromExtent(extent, espSizeMB, "SYSTEM")
}

// locale: 引导文件语言，例如 "zh-cn" 或 "en-us"，为空时默认 "zh-cn"。
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

	// 检测目标系统所在磁盘的分区格式。
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

// FixUEFI 修复 UEFI 引导。
func FixUEFI(osRoot, sysHint, locale string) error {
	winDir := osRoot + "Windows"

	var (
		sysRoot string
		cleanup func()
	)
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
		r, mountedCleanup, err := FindESP(osRoot)
		if err != nil {
			return fmt.Errorf("FindESP failed: %w", err)
		}
		sysRoot = r
		cleanup = mountedCleanup
	}
	if cleanup != nil {
		defer cleanup()
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
	log.LogWrite(0, "[FixUEFI] running: %s %s\n out: %s  err: %v", bcdpath, strings.Join(args, " "), out, err)
	return nil
}

// FixBIOS 修复 BIOS/MBR 引导。
func FixBIOS(osRoot, sysHint, locale string) error {
	winDir := osRoot + "Windows"
	sysRoot, _ := utils.NormalizeDrive(sysHint, 0)
	if sysRoot == "" {
		sysRoot = osRoot
	}

	// 修复 MBR/PBR。
	if out, err := tools.RunCmd("bootrec.exe", nil, nil, "", "/fixmbr"); err != nil {
		fmt.Println("[FixBIOS] bootrec /fixmbr failed (may be ok):", err)
		fmt.Println(out)
		log.LogWrite(0, "[FixBIOS] bootrec /fixmbr failed (may be ok): %v\nout: %s", err, out)
	} else {
		fmt.Println("[FixBIOS] bootrec /fixmbr ok")
		fmt.Println(out)
		log.LogWrite(0, "[FixBIOS] bootrec /fixmbr ok\nout: %s", out)
	}
	if out, err := tools.RunCmd("bootrec.exe", nil, nil, "", "/fixboot"); err != nil {
		fmt.Println("[FixBIOS] bootrec /fixboot failed, try bootsect:", err)
		fmt.Println(out)
		log.LogWrite(0, "[FixBIOS] bootrec /fixboot failed: %v\nout: %s", err, out)
		if out2, err2 := tools.RunCmd("bootsect.exe", nil, nil, "", "/nt60", sysRoot, "/mbr"); err2 != nil {
			fmt.Println("[FixBIOS] bootsect failed:", err2)
			fmt.Println(out2)
			log.LogWrite(0, "[FixBIOS] bootsect failed: %v\nout: %s", err2, out2)
		} else {
			fmt.Println("[FixBIOS] bootsect ok")
			log.LogWrite(0, "[FixBIOS] bootsect ok\nout: %s", out)
		}
	} else {
		fmt.Println("[FixBIOS] bootrec /fixboot ok")
		fmt.Println(out)
		log.LogWrite(0, "[FixBIOS] bootrec /fixboot ok\nout: %s", out)
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
	log.LogWrite(0, "[FixBIOS] running: %s %s\n out: %s  err: %v", bcdpath, strings.Join(args, " "), out, err)
	return nil
}

// 查找系统分区。
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
