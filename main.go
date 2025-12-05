package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/kdomanski/iso9660/util"
	"golang.org/x/text/encoding/simplifiedchinese"
)

// UI 可以在初始化时赋值，用于显示进度条。
// phase: 阶段（例："Creating files", "Extracting", "Applying metadata", "DISM" 等）
// percent: 0~100（如果没解析到就传 -1）
// raw: 原始行
var ImageProgress func(phase string, percent float64, raw string)

var (
	modShell32                  = syscall.NewLazyDLL("shell32.dll")
	procShellExecuteW           = modShell32.NewProc("ShellExecuteW")
	modKernel32                 = syscall.NewLazyDLL("kernel32.dll")
	procGetLogicalDriveStringsW = modKernel32.NewProc("GetLogicalDriveStringsW")
	procGetDriveTypeW           = modKernel32.NewProc("GetDriveTypeW")
	procCopyFileW               = modKernel32.NewProc("CopyFileW")
	//关机相关
	modUser32              = syscall.NewLazyDLL("user32.dll")
	modAdvapi32            = syscall.NewLazyDLL("advapi32.dll")
	procExitWindowsEx      = modUser32.NewProc("ExitWindowsEx")
	procOpenProcessToken   = modAdvapi32.NewProc("OpenProcessToken")
	procLookupPrivilegeVal = modAdvapi32.NewProc("LookupPrivilegeValueW")
	procAdjustTokenPriv    = modAdvapi32.NewProc("AdjustTokenPrivileges")
)

const (
	driveUnknown = 0
	driveNoRoot  = 1
	driveRemov   = 2
	driveFixed   = 3
	driveRemote  = 4
	driveCdrom   = 5
	driveRamdisk = 6
	//磁盘相关
	ioctlVolumeGetVolumeDiskExtents = 0x00560000 // IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS
	ioctlDiskGetDriveLayoutEx       = 0x00070050 // IOCTL_DISK_GET_DRIVE_LAYOUT_EX
	partitionStyleMBR               = 0          // PARTITION_STYLE_MBR
	partitionStyleGPT               = 1          // PARTITION_STYLE_GPT
	partitionStyleRAW               = 2          // PARTITION_STYLE_RAW
)

const (
	swHide = 0
)

// 调用ShellExecuteW执行指定动作（如 "mount" / "open"）。
func shellExecuteVerb(path string, verb string) error {
	pPath, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	pVerb, err := syscall.UTF16PtrFromString(verb)
	if err != nil {
		return err
	}

	r, _, callErr := procShellExecuteW.Call(
		0,
		uintptr(unsafe.Pointer(pVerb)),
		uintptr(unsafe.Pointer(pPath)),
		0,
		0,
		uintptr(swHide),
	)
	// 返回值 <= 32 代表失败
	if r <= 32 {
		if callErr != nil && callErr != syscall.Errno(0) {
			return fmt.Errorf("ShellExecuteW failed: ret=%d err=%w", r, callErr)
		}
		return fmt.Errorf("ShellExecuteW failed: ret=%d", r)
	}
	return nil
}

// 返回当前系统所有逻辑盘根路径，如 "C:\", "D:\" 等。
func ListDrive() ([]string, error) {
	// 256个WCHAR足够容纳26个盘符字符串
	buf := make([]uint16, 256)

	r, _, err := procGetLogicalDriveStringsW.Call(
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&buf[0])),
	)
	if r == 0 {
		return nil, err
	}

	var drives []string
	n := int(r)
	i := 0
	for i < n {
		// 盘符字符串以\0分隔，最后再多一个\0结束
		j := i
		for j < n && buf[j] != 0 {
			j++
		}
		if j == i {
			// 连续两个\0，结束
			break
		}
		drive := syscall.UTF16ToString(buf[i:j])
		drives = append(drives, drive)
		i = j + 1
	}

	return drives, nil
}

// 判断盘符类型。
func GetDriveType(root string) uint32 {
	pRoot, err := syscall.UTF16PtrFromString(root)
	if err != nil {
		return driveUnknown
	}
	r, _, _ := procGetDriveTypeW.Call(uintptr(unsafe.Pointer(pRoot)))
	return uint32(r)
}

// 列出当前系统中的所有光驱盘符。
func ListCD() ([]string, error) {
	roots, err := ListDrive()
	if err != nil {
		return nil, err
	}
	var cds []string
	for _, r := range roots {
		if GetDriveType(r) == driveCdrom {
			cds = append(cds, r)
		}
	}
	return cds, nil
}

// 使用ShellExecute挂载ISO，返回新挂载出来的光驱盘符
func MountISO(isoPath string, wait time.Duration) (string, error) {
	if _, err := os.Stat(isoPath); err != nil {
		return "", fmt.Errorf("iso not found: %w", err)
	}

	// 先记录现有CD盘符
	before, err := ListCD()
	if err != nil {
		return "", fmt.Errorf("list cdrom before mount: %w", err)
	}
	beforeSet := make(map[string]struct{}, len(before))
	for _, d := range before {
		beforeSet[d] = struct{}{}
	}

	// 先使用"mount"，不行再用"open"
	if err := shellExecuteVerb(isoPath, "mount"); err != nil {
		// 某些PE/组件不支持mount verb就退回到open
		if err2 := shellExecuteVerb(isoPath, "open"); err2 != nil {
			return "", fmt.Errorf("mount/open iso failed: %v / %v", err, err2)
		}
	}

	// 轮询寻找新的CD盘符
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		time.Sleep(500 * time.Millisecond)

		now, err := ListCD()
		if err != nil {
			continue
		}
		for _, d := range now {
			if _, ok := beforeSet[d]; !ok {
				// 找到新出现的CD盘符，认为是挂载的ISO
				return d, nil
			}
		}
	}

	return "", errors.New("timeout: iso mounted but no new cdrom drive detected")
}

// 将ISO的内容解包到指定目录（第三方库）。
func UnpackISO(isoPath, dstDir string) error {
	if err := os.MkdirAll(dstDir, 0755); err != nil {
		return fmt.Errorf("create dst dir: %w", err)
	}

	f, err := os.Open(isoPath)
	if err != nil {
		return fmt.Errorf("open iso: %w", err)
	}
	defer f.Close()

	if err := util.ExtractImageToDirectory(f, dstDir); err != nil {
		return fmt.Errorf("extract iso: %w", err)
	}
	return nil
}

// 执行外部命令，返回stdout+stderr文本。
// onLine：不为 nil 时，每输出一行（或一条 \r 结尾的进度）就回调一次。
// 这个是同步函数
func runCmd(bin string, onLine func(string), args ...string) (string, error) {
	cmd := exec.Command(bin, args...)
	exe, err := os.Executable()
	if err == nil {
		cmd.Dir = filepath.Dir(exe)
	}

	var buf bytes.Buffer

	// 自定义writer：一方面把原始输出塞进buf，另一方面拆分成行给onLine。
	type lineWriter struct {
		all    *bytes.Buffer
		onLine func(string)
		part   []byte // 当前未结束的一行（以\n或\r为界）
	}

	lw := &lineWriter{
		all:    &buf,
		onLine: onLine,
		part:   make([]byte, 0, 256),
	}

	// 实现 io.Writer
	// 注意：wimlib / DISM 进度通常用 '\r' 覆盖同一行，这里把 '\r' 也当作一次行结束处理。
	writeLine := func(l string) {
		if lw.onLine != nil {
			lw.onLine(l)
		} else {
			fmt.Println(l)
		}
	}

	lwWrite := func(p []byte) {
		// 先全部记录下来，便于最终返回完整输出
		lw.all.Write(p)

		for _, b := range p {
			if b == '\n' || b == '\r' {
				if len(lw.part) > 0 {
					line := string(lw.part)
					writeLine(line)
					lw.part = lw.part[:0]
				}
			} else {
				lw.part = append(lw.part, b)
			}
		}
	}

	// 包装成真正的io.Writer
	cmd.Stdout = writerFunc(func(p []byte) (int, error) {
		lwWrite(p)
		return len(p), nil
	})
	cmd.Stderr = cmd.Stdout

	// 同步执行命令
	err = cmd.Run()

	// 处理最后一行（没有 \n/\r 结尾）
	if len(lw.part) > 0 {
		writeLine(string(lw.part))
		lw.part = lw.part[:0]
	}

	raw := buf.Bytes()

	decoded, decErr := simplifiedchinese.GBK.NewDecoder().Bytes(raw)
	out := string(raw)
	if decErr == nil {
		out = string(decoded)
	} else {
		fmt.Println("[runCmdGBK] gbk decode failed, fallback raw:", decErr)
	}

	if err != nil {
		return out, fmt.Errorf("%s %v failed: %w\n%s", bin, args, err, out)
	}
	return out, nil
}

// 把匿名函数适配成 io.Writer
type writerFunc func(p []byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// 规范化盘符根路径：接受 "C", "C:", "C:\"，统一变成 "C:\"
func normRoot(vol string) string {
	v := strings.TrimSpace(vol)
	if v == "" {
		return ""
	}
	// 转成大写盘符，方便 log
	v = strings.ToUpper(v)
	if len(v) == 1 && v[0] >= 'A' && v[0] <= 'Z' {
		return v + ":\\"
	}
	if len(v) == 2 && v[1] == ':' {
		return v + "\\"
	}
	if !strings.HasSuffix(v, `\`) && !strings.HasSuffix(v, `/`) {
		v += `\`
	}
	v = strings.ReplaceAll(v, `/`, `\`)
	return v
}

// 固件类型检测BIOS/UEFI
var (
	procGetFirmwareType = modKernel32.NewProc("GetFirmwareType")
)

const (
	fwTypeUnknown = 0
	fwTypeBios    = 1
	fwTypeUefi    = 2
	fwTypeMax     = 3
)

func GetFwType() (uint32, error) {
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

// 从一行输出中提取百分比（形如 "(100%)" / "50.3%"），失败返回 -1
func extractPercent(line string) float64 {
	// 找第一个 '%' 左边的数字
	idx := strings.Index(line, "%")
	if idx == -1 {
		return -1
	}

	// 向左回溯，找到连续的数字和小数点
	i := idx - 1
	for i >= 0 && ((line[i] >= '0' && line[i] <= '9') || line[i] == '.') {
		i--
	}
	if i == idx-1 {
		return -1
	}
	numStr := strings.TrimSpace(line[i+1 : idx])
	v, err := strconv.ParseFloat(numStr, 64)
	if err != nil {
		return -1
	}
	if v < 0 {
		v = 0
	}
	if v > 100 {
		v = 100
	}
	return v
}

// ApplyImage 会优先使用DISM，失败后wimlib-imagex
// imagePath:WIM 或 ESD 路径
// index:镜像索引（1 开始）
// targetVol:目标卷，如 "C:"、"C:\"
func ApplyImage(imagePath string, index int, targetVol string) error {
	if _, err := os.Stat(imagePath); err != nil {
		return fmt.Errorf("image not found: %w", err)
	}
	if index <= 0 {
		return fmt.Errorf("invalid image index: %d", index)
	}

	targetRoot := normRoot(targetVol)
	if targetRoot == "" {
		return fmt.Errorf("invalid target volume: %q", targetVol)
	}

	// DISM回调
	dismArgs := []string{
		"/Apply-Image",
		"/ImageFile:" + imagePath,
		fmt.Sprintf("/Index:%d", index),
		"/ApplyDir:" + targetRoot,
	}

	dismOnLine := func(line string) {
		if ImageProgress == nil {
			return
		}
		// 尝试从 DISM 输出中解析百分比（大部分是 "xx.x%"）
		pct := extractPercent(line)
		if pct >= 0 {
			ImageProgress("DISM", pct, line)
		}
	}

	if out, err := runCmd("dism.exe", dismOnLine, dismArgs...); err == nil {
		fmt.Println("[ApplyImage] DISM ok")
		fmt.Println(out)
		// DISM 结束，报 100%
		if ImageProgress != nil {
			ImageProgress("DISM", 100, "DISM apply finished")
		}
		return nil
	} else {
		fmt.Println("[ApplyImage] DISM failed, will try wimlib-imagex")
		fmt.Println(out)
	}

	// wimlib回调
	wimArgs := []string{
		"apply",
		imagePath,
		fmt.Sprintf("%d", index),
		targetRoot,
	}
	exePath, _ := os.Executable()
	exePath = filepath.Join(filepath.Dir(exePath), "wimlib-imagex.exe")

	wimOnLine := func(line string) {
		if ImageProgress == nil {
			return
		}

		phase := ""
		lower := strings.ToLower(line)

		switch {
		case strings.HasPrefix(lower, "creating files"):
			phase = "Creating files"
		case strings.HasPrefix(lower, "extracting file data"):
			phase = "Extracting"
		case strings.HasPrefix(lower, "applying metadata"):
			phase = "Applying metadata"
		default:
			// 其他行我们就当普通日志，不一定有进度
		}

		pct := extractPercent(line)
		if pct >= 0 || phase != "" {
			ImageProgress(phase, pct, line)
		}
	}

	if out, err := runCmd(exePath, wimOnLine, wimArgs...); err == nil {
		fmt.Println("[ApplyImage] wimlib-imagex ok")
		fmt.Println(out)
		if ImageProgress != nil {
			ImageProgress("wimlib", 100, "wimlib apply finished")
		}
		return nil
	} else {
		fmt.Println("[ApplyImage] wimlib-imagex failed")
		fmt.Println(out)
		return err
	}
}

// ApplyWimImage 安装 WIM 镜像到指定卷。
// wimPath:wim路径
// index:要安装的索引
// targetVol:目标卷，如"C:"、"C:\"
func ApplyWimImage(wimPath string, index int, targetVol string) error {
	if !strings.EqualFold(strings.TrimSpace(
		wimPath[len(wimPath)-4:]), ".wim") && !strings.HasSuffix(strings.ToLower(wimPath), ".wim") {
		// 简单校验一下后缀，不强制
	}
	return ApplyImage(wimPath, index, targetVol)
}

// 安装ESD镜像到指定卷。
func ApplyEsdImage(esdPath string, index int, targetVol string) error {
	return ApplyImage(esdPath, index, targetVol)
}

var (
	procGetVolumeInformationW = modKernel32.NewProc("GetVolumeInformationW")
	procGetDiskFreeSpaceExW   = modKernel32.NewProc("GetDiskFreeSpaceExW")
)

// 获取卷的文件系统类型和总大小（字节）
func getVolumeInfo(root string) (fsType string, totalBytes uint64, err error) {
	root = normRoot(root)
	if root == "" {
		return "", 0, fmt.Errorf("empty root")
	}
	pRoot, e := syscall.UTF16PtrFromString(root)
	if e != nil {
		return "", 0, e
	}

	volName := make([]uint16, 256)
	fsName := make([]uint16, 256)
	var serial, maxCompLen, flags uint32

	r1, _, e1 := procGetVolumeInformationW.Call(
		uintptr(unsafe.Pointer(pRoot)),
		uintptr(unsafe.Pointer(&volName[0])),
		uintptr(len(volName)),
		uintptr(unsafe.Pointer(&serial)),
		uintptr(unsafe.Pointer(&maxCompLen)),
		uintptr(unsafe.Pointer(&flags)),
		uintptr(unsafe.Pointer(&fsName[0])),
		uintptr(len(fsName)),
	)
	if r1 == 0 {
		if e1 != nil && e1 != syscall.Errno(0) {
			return "", 0, fmt.Errorf("GetVolumeInformationW: %w", e1)
		}
		return "", 0, fmt.Errorf("GetVolumeInformationW failed")
	}
	fsType = strings.ToUpper(syscall.UTF16ToString(fsName))

	var freeBytes, total, freeTotal uint64
	r2, _, e2 := procGetDiskFreeSpaceExW.Call(
		uintptr(unsafe.Pointer(pRoot)),
		uintptr(unsafe.Pointer(&freeBytes)),
		uintptr(unsafe.Pointer(&total)),
		uintptr(unsafe.Pointer(&freeTotal)),
	)
	if r2 == 0 {
		if e2 != nil && e2 != syscall.Errno(0) {
			return fsType, 0, fmt.Errorf("GetDiskFreeSpaceExW: %w", e2)
		}
		return fsType, 0, fmt.Errorf("GetDiskFreeSpaceExW failed")
	}
	return fsType, total, nil
}

// 读取指定卷的剩余空间
func GetFreeSize(vol string) (freeBytes uint64, err error) {
	root := normRoot(vol)
	if root == "" {
		return 0, fmt.Errorf("empty volume")
	}

	pRoot, e := syscall.UTF16PtrFromString(root)
	if e != nil {
		return 0, e
	}

	var freeAvail, total, freeTotal uint64

	r, _, e2 := procGetDiskFreeSpaceExW.Call(
		uintptr(unsafe.Pointer(pRoot)),
		uintptr(unsafe.Pointer(&freeAvail)), // 当前用户可用空间
		uintptr(unsafe.Pointer(&total)),     // 卷总大小
		uintptr(unsafe.Pointer(&freeTotal)), // 卷总空闲（包括管理员保留）
	)
	if r == 0 {
		if e2 != nil && e2 != syscall.Errno(0) {
			return 0, fmt.Errorf("GetDiskFreeSpaceExW: %w", e2)
		}
		return 0, fmt.Errorf("GetDiskFreeSpaceExW failed")
	}
	return freeAvail, nil
}

// 找系统分区（有 \Windows 目录的卷）
func FindOS(hint string) (string, error) {
	// 先用参数的看看有没有
	if hint != "" {
		root := normRoot(hint)
		if root != "" {
			if st, err := os.Stat(root + "Windows"); err == nil && st.IsDir() {
				fmt.Println("[FindOS] use hint:", root)
				return root, nil
			}
			fmt.Println("[FindOS] hint has no Windows dir:", root)
		}
	}

	// 枚举所有卷
	roots, err := ListDrive()
	if err != nil {
		return "", fmt.Errorf("ListDrive: %w", err)
	}

	var cand string
	for _, r := range roots {
		dt := GetDriveType(r)
		// 跳过CD和网络盘
		if dt != driveFixed && dt != driveRemov {
			continue
		}
		root := normRoot(r)
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

// 找 ESP：只看FAT32,在有EFI目录的中选最小的
func FindESP(osRoot string) (string, error) {
	roots, err := ListDrive()
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
		dt := GetDriveType(r)
		if dt != driveFixed && dt != driveRemov {
			continue
		}
		root := normRoot(r)
		if root == "" {
			continue
		}
		// 跳过osRoot
		if strings.EqualFold(root, osRoot) {
			continue
		}

		fs, size, err := getVolumeInfo(root)
		if err != nil {
			continue
		}
		if fs != "FAT32" {
			continue
		}

		// 略过>4GB的大FAT32
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

	// 自动找系统
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

	// 获取固件类型（UEFI/BIOS）
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

	// 检测OS卷所在磁盘的分区格式（MBR/GPT）
	diskStyle, diskNum, err := GetDiskInfo(osRoot)
	if err != nil {
		fmt.Println("[FixBoot] GetDiskInfo failed, will fallback:", err)
	} else {
		fmt.Printf("[FixBoot] Disk %d style: %s\n", diskNum, diskStyle)
	}

	mode := "BIOS" // 默认 BIOS
	switch diskStyle {
	case "MBR":
		// MBR:走BIOS分支
		mode = "BIOS"
	case "GPT":
		// GPT:如果固件是UEFI,就走UEFI,否则只能按BIOS尝试
		if fw == fwTypeUefi {
			mode = "UEFI"
		} else {
			mode = "BIOS"
		}
	default:
		// RAW/UNKNOWN：按固件来猜
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
func FixUEFI(osRoot, sysHint, locale string) error {
	winDir := osRoot + "Windows"

	var sysRoot string
	if sysHint != "" {
		r := normRoot(sysHint)
		if r != "" {
			if fs, _, err := getVolumeInfo(r); err == nil && fs == "FAT32" {
				sysRoot = r
				fmt.Println("[FixUEFI] use sysVol hint:", sysRoot)
			} else {
				fmt.Println("[FixUEFI] sysVol hint not FAT32, ignore:", r)
			}
		}
	}

	// 找ESP
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

	// 调用bcdboot
	args := []string{
		winDir,
		"/l", locale,
		"/s", sysRoot,
		"/f", "UEFI",
	}
	out, err := runCmd("bcdboot.exe", nil, args...)
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
	sysRoot := normRoot(sysHint)
	if sysRoot == "" {
		sysRoot = osRoot
	}

	// 修复MBR/PBR
	if out, err := runCmd("bootrec.exe", nil, "/fixmbr"); err != nil {
		fmt.Println("[FixBIOS] bootrec /fixmbr failed (may be ok):", err)
		fmt.Println(out)
	} else {
		fmt.Println("[FixBIOS] bootrec /fixmbr ok")
		fmt.Println(out)
	}
	if out, err := runCmd("bootrec.exe", nil, "/fixboot"); err != nil {
		fmt.Println("[FixBIOS] bootrec /fixboot failed, try bootsect:", err)
		fmt.Println(out)
		if out2, err2 := runCmd("bootsect.exe", nil, "/nt60", sysRoot, "/mbr"); err2 != nil {
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
	out, err := runCmd("bcdboot.exe", nil, args...)
	if err != nil {
		fmt.Println("[FixBIOS] bcdboot failed")
		fmt.Println(out)
		return err
	}
	fmt.Println("[FixBIOS] bcdboot ok")
	fmt.Println(out)
	return nil
}

// DISK_EXTENT
type diskExtent struct {
	DiskNumber     uint32
	_              uint32
	StartingOffset int64
	ExtentLength   int64
}

// VOLUME_DISK_EXTENTS
type volumeDiskExtents struct {
	NumberOfDiskExtents uint32
	_                   uint32
	Extents             [1]diskExtent
}

// 根据分区取第一个物理磁盘号
func GetDiskNum(vol string) (uint32, error) {
	root := normRoot(vol)
	if root == "" {
		return 0, fmt.Errorf("invalid volume: %q", vol)
	}
	// \\.\C:
	volPath := `\\.\` + strings.TrimRight(root, `\`)
	pVol, err := syscall.UTF16PtrFromString(volPath)
	if err != nil {
		return 0, err
	}

	hVol, err := syscall.CreateFile(
		pVol,
		0, // 只读
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		nil,
		syscall.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		return 0, fmt.Errorf("CreateFile volume %s failed: %w", volPath, err)
	}
	defer syscall.CloseHandle(hVol)

	out := make([]byte, 1024)
	var bytesRet uint32
	err = syscall.DeviceIoControl(
		hVol,
		ioctlVolumeGetVolumeDiskExtents,
		nil,
		0,
		&out[0],
		uint32(len(out)),
		&bytesRet,
		nil,
	)
	if err != nil {
		return 0, fmt.Errorf("DeviceIoControl IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS failed: %w", err)
	}
	if bytesRet < uint32(unsafe.Sizeof(volumeDiskExtents{})) {
		return 0, fmt.Errorf("VOLUME_DISK_EXTENTS too small: %d", bytesRet)
	}

	vde := (*volumeDiskExtents)(unsafe.Pointer(&out[0]))
	if vde.NumberOfDiskExtents == 0 {
		return 0, fmt.Errorf("no disk extents for volume %s", volPath)
	}
	//第一个Extent的DiskNumber
	//有个坑，32位偏移量是4开始，64是8开始
	//直接用 Extents[0].DiskNumber，兼容32/64
	diskNum := vde.Extents[0].DiskNumber
	return diskNum, nil
}

// 根据分区取磁盘的分区格式（MBR/GPT/RAW）
// 返回: style ("MBR"/"GPT"/"RAW")、磁盘号 (PhysicalDriveN)、错误
func GetDiskInfo(vol string) (string, uint32, error) {
	diskNum, err := GetDiskNum(vol)
	if err != nil {
		return "", 0, err
	}

	diskPath := fmt.Sprintf(`\\.\PhysicalDrive%d`, diskNum)
	pDisk, err := syscall.UTF16PtrFromString(diskPath)
	if err != nil {
		return "", 0, err
	}

	hDisk, err := syscall.CreateFile(
		pDisk,
		syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		nil,
		syscall.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		return "", 0, fmt.Errorf("CreateFile %s failed: %w", diskPath, err)
	}
	defer syscall.CloseHandle(hDisk)

	out := make([]byte, 4096)
	var bytesRet uint32
	err = syscall.DeviceIoControl(
		hDisk,
		ioctlDiskGetDriveLayoutEx,
		nil,
		0,
		&out[0],
		uint32(len(out)),
		&bytesRet,
		nil,
	)
	if err != nil {
		return "", 0, fmt.Errorf("DeviceIoControl IOCTL_DISK_GET_DRIVE_LAYOUT_EX failed: %w", err)
	}
	if bytesRet < 4 {
		return "", 0, fmt.Errorf("unexpected DRIVE_LAYOUT_INFORMATION_EX size: %d", bytesRet)
	}

	// DRIVE_LAYOUT_INFORMATION_EX 第一个字段就是 PartitionStyle (DWORD)
	styleVal := binary.LittleEndian.Uint32(out[0:4])
	var style string
	switch styleVal {
	case partitionStyleMBR:
		style = "MBR"
	case partitionStyleGPT:
		style = "GPT"
	case partitionStyleRAW:
		style = "RAW"
	default:
		style = "UNKNOWN"
	}

	fmt.Printf("[GetDiskInfo] vol=%s disk=%d style=%s\n", normRoot(vol), diskNum, style)
	return style, diskNum, nil
}

type ImageMeta struct {
	Index       int
	Name        string
	Description string
	Flags       string

	SizeBytes uint64 // 原始字节数
	Size      string // 转换为MB/GB格式

	Edition      string // Professional/WindowsPE/...
	Installation string // Client/Server/WindowsPE/...
	SystemRoot   string // WINDOWS/...
	Arch         string // x86 / x64 / arm64 ...

	IsOS bool // 是否认为是系统
}

// 解析DISM/wimlib-imagex info输出信息
func parseImageInfoText(out string) ([]ImageMeta, error) {
	var (
		res []ImageMeta
		cur *ImageMeta
	)

	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}

		colon := strings.Index(line, ":")
		if colon <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:colon])
		val := strings.TrimSpace(line[colon+1:])

		switch {
		case key == "Index" || key == "Image Index":
			if cur != nil && cur.Index != 0 {
				finalizeImageMeta(cur)
				res = append(res, *cur)
			}
			cur = &ImageMeta{}
			if idx, err := strconv.Atoi(val); err == nil {
				cur.Index = idx
			}

		case key == "Name":
			if cur != nil {
				cur.Name = val
			}

		case key == "Description":
			if cur != nil {
				cur.Description = val
			}

		case key == "Flags":
			if cur != nil {
				cur.Flags = val
			}

		case strings.HasPrefix(key, "Size"):
			if cur != nil {
				cur.SizeBytes = parseSizeBytes(val)
			}

		case strings.HasPrefix(key, "Edition"):
			if cur != nil {
				cur.Edition = val
			}

		case strings.HasPrefix(key, "Installation"):
			if cur != nil {
				cur.Installation = val
			}

		case key == "Architecture" || key == "Arch":
			if cur != nil {
				cur.Arch = val // 例如 "x64" / "x86" / "arm64"
			}

		case strings.HasPrefix(key, "System Root"):
			if cur != nil {
				cur.SystemRoot = val
			}
		}
	}

	if cur != nil && cur.Index != 0 {
		finalizeImageMeta(cur)
		res = append(res, *cur)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(res) == 0 {
		return nil, errors.New("no image info parsed")
	}
	return res, nil
}

// 从 "25,912,203,411 bytes" 这类字符串中提取字节数
func parseSizeBytes(s string) uint64 {
	s = strings.ToLower(s)
	// 去掉"bytes"/"字节"
	if idx := strings.Index(s, "bytes"); idx != -1 {
		s = s[:idx]
	} else if idx := strings.Index(s, "字节"); idx != -1 {
		s = s[:idx]
	}

	// 只保留数字
	var b []rune
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b = append(b, r)
		}
	}
	if len(b) == 0 {
		return 0
	}
	n, _ := strconv.ParseUint(string(b), 10, 64)
	return n
}

// 把字节转成 "xxx MB" 或 "xxx GB"
func bytesToMBGBStr(size uint64) string {
	const (
		mb = 1024 * 1024
		gb = 1024 * 1024 * 1024
	)
	if size == 0 {
		return ""
	}
	if size < gb {
		// 小于 1GB 用 MB，保留 1 位小数
		v := float64(size) / float64(mb)
		return fmt.Sprintf("%.1f MB", v)
	}
	// 大于等于 1GB 用 GB，保留 2 位小数
	v := float64(size) / float64(gb)
	return fmt.Sprintf("%.2f GB", v)
}

// 结合 Installation / Edition / 名称 做系统索引判断 + 填充 Size 文本
func finalizeImageMeta(m *ImageMeta) {
	m.Size = bytesToMBGBStr(m.SizeBytes)

	name := strings.ToLower(m.Name + " " + m.Description)
	inst := strings.ToLower(m.Installation)
	edition := strings.ToLower(m.Edition)

	// 明确是 WinPE/安装环境 的情况
	isPEInstall := strings.Contains(inst, "windowspe") || strings.Contains(inst, "winpe")
	isPEEdition := strings.Contains(edition, "windowspe")

	isSetupName :=
		strings.Contains(name, "setup media") ||
			strings.Contains(name, "windows setup") ||
			strings.Contains(name, "windows pe") ||
			strings.Contains(name, "winpe") ||
			strings.Contains(name, "winre") ||
			strings.Contains(name, "recovery")

	// Client/Server 一般是正常系统
	isClientOrServer := strings.Contains(inst, "client") || strings.Contains(inst, "server")

	// 如果 Installation 根本没被解析到（inst == ""），那我们就不强制要求它里边有 client/server，
	// 只要不是明显 PE / Setup 就当成系统 —— 这样你现在出现 IsOS 全是 false 的情况就能避免。
	if inst == "" && !isPEInstall && !isPEEdition && !isSetupName {
		m.IsOS = true
		return
	}

	// Client/Server 且不是 PE/Setup，认为是系统
	m.IsOS = isClientOrServer && !isPEInstall && !isPEEdition && !isSetupName
}

// 读取WIM/ESD中所有的信息（Index/Name/Description/Flags）。
// 不能传入ISO路径，需要先挂载或解包出WIM/ESD文件。
func ListImageInfos(imagePath string) ([]ImageMeta, error) {
	if _, err := os.Stat(imagePath); err != nil {
		return nil, fmt.Errorf("image not found: %w", err)
	}

	// DISM
	if out, err := runCmd("dism.exe",
		nil,
		"/English", // 固定英文输出
		"/Get-WimInfo",
		"/WimFile:"+imagePath,
	); err == nil {
		if imgs, perr := parseImageInfoText(out); perr == nil && len(imgs) > 0 {
			fmt.Println("[ListImageInfos] use DISM result")
			return imgs, nil
		} else {
			fmt.Println("[ListImageInfos] DISM output parse failed, fallback to wimlib")
			fmt.Println(perr)
		}
	} else {
		fmt.Println("[ListImageInfos] DISM failed, fallback to wimlib:", err)
	}

	// wimlib-imagex
	if out, err := runCmd("wimlib-imagex.exe", nil, "info", imagePath); err == nil {
		if imgs, perr := parseImageInfoText(out); perr == nil && len(imgs) > 0 {
			fmt.Println("[ListImageInfos] use wimlib-imagex result")
			return imgs, nil
		} else {
			fmt.Println("[ListImageInfos] wimlib output parse failed:", perr)
			return nil, perr
		}
	} else {
		return nil, fmt.Errorf("both DISM and wimlib-imagex failed: %w", err)
	}
}

// 把diskpart命令写入临时文件并执行。
// 返回diskpart的输出，便于日志记录/排错。
func RunDiskpart(lines []string) (string, error) {
	if len(lines) == 0 {
		return "", fmt.Errorf("empty diskpart script")
	}

	script := strings.Join(lines, "\r\n") + "\r\n"

	f, err := os.CreateTemp("", "dp_fmt_*.txt")
	if err != nil {
		return "", fmt.Errorf("create temp script failed: %w", err)
	}
	path := f.Name()
	defer os.Remove(path)

	if _, err := f.WriteString(script); err != nil {
		f.Close()
		return "", fmt.Errorf("write temp script failed: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("close temp script failed: %w", err)
	}

	out, err := runCmd("diskpart.exe", nil, "/s", path)
	if err != nil {
		return out, fmt.Errorf("diskpart failed: %w", err)
	}
	return out, nil
}

// 使用 diskpart，按盘符格式化卷。
// letter: 盘符，可以是 "C" / "C:" / "C:\"
// fs: 文件系统，例如 "ntfs" "fat32" "exfat"
// label: 卷标，允许为空
// quick: true：快速格式化, false：全格式
func Format(letter, fs, label string, quick bool) error {
	l := strings.TrimSpace(letter)
	if l == "" {
		return fmt.Errorf("empty volume letter")
	}

	// "C:" -> "C"
	l = strings.ToUpper(l)
	if strings.HasSuffix(l, ":") {
		l = l[:len(l)-1]
	}
	if len(l) != 1 || l[0] < 'A' || l[0] > 'Z' {
		return fmt.Errorf("invalid volume letter: %q", letter)
	}

	if fs == "" {
		fs = "ntfs"
	}
	fs = strings.ToLower(fs)

	cmds := []string{
		fmt.Sprintf("select volume %s", l),
	}

	// 这里加上OVERRIDE强制执行
	fmtCmd := fmt.Sprintf("format fs=%s", fs)
	if label != "" {
		fmtCmd += fmt.Sprintf(" label=\"%s\"", label)
	}
	if quick {
		fmtCmd += " quick"
	}
	fmtCmd += " override" //强制格式化

	cmds = append(cmds, fmtCmd)

	out, err := RunDiskpart(cmds)
	fmt.Println("[Format] diskpart output:\n", out)
	if err != nil {
		return err
	}
	return nil
}

// FormatPartition 使用 diskpart 格式化指定磁盘上的指定分区。
// diskIdx: diskpart里的磁盘编号（list disk）
// partIdx: 该磁盘上的分区编号（list partition）
// fs/label/quick
func FormatPartition(diskIdx, partIdx int, fs, label string, quick bool) error {
	if diskIdx < 0 {
		return fmt.Errorf("invalid disk index: %d", diskIdx)
	}
	if partIdx <= 0 {
		return fmt.Errorf("invalid partition index: %d", partIdx)
	}
	if fs == "" {
		fs = "ntfs"
	}
	fs = strings.ToLower(fs)

	cmds := []string{
		fmt.Sprintf("select disk %d", diskIdx),
		fmt.Sprintf("select partition %d", partIdx),
	}

	// 同样这里加 OVERRIDE
	fmtCmd := fmt.Sprintf("format fs=%s", fs)
	if label != "" {
		fmtCmd += fmt.Sprintf(" label=\"%s\"", label)
	}
	if quick {
		fmtCmd += " quick"
	}
	fmtCmd += " override" // *** 关键：强制格式化 ***

	cmds = append(cmds, fmtCmd)

	out, err := RunDiskpart(cmds)
	fmt.Println("[FormatPartition] diskpart output:\n", out)
	if err != nil {
		return err
	}
	return nil
}

func main() {
	go test1()
	fmt.Println(Findpart())
	//剩余空间需要大于7g（7340032）
	fmt.Println(GetDiskKind("I"))
	Uiinit()
	w.Show(true)
	a.Run()
	//窗口关闭后执行
	a.Exit()

	return
	fmt.Println(GetDiskNum("E:\\"))
	path, err := os.Getwd()
	img, err := ListImageInfos(path + "\\win10.esd")
	fmt.Println(img, err)
	fmt.Println(Format("C", "ntfs", "win10", true))
	//  绑定进度回调
	ImageProgress = func(phase string, pct float64, raw string) {
		// pct < 0 表示这一行没解析到百分比
		if pct >= 0 {
			if phase == "" {
				phase = "Unknown"
			}
			fmt.Printf("[PROGRESS] %-18s %6.2f%%   %s\n", phase, pct, raw)
		} else {
			fmt.Printf("[LOG] %s\n", raw)
		}
	}
	fmt.Println(ApplyImage(path+"\\win10.esd", 7, "C:\\"))

	fmt.Println(FixBoot("C:\\", "", "zh-cn"))
	fmt.Println(Copy(path+"\\win10.xml", "C:\\Windows\\Panther\\Unattend.xml", true, true))
	fmt.Println(Copy(path+"\\drive10.exe", "C:\\drive.exe", true, true))
	fmt.Println(Copy(path+"\\HEU_KMS_Activator.exe", "C:\\HEU_KMS_Activator.exe", true, true))
	fmt.Println(CreateShortcut("C:\\Users\\Public\\Desktop\\", "百度", "https://www.baidu.com"))
	//time.Sleep(30 * time.Second)
	Shutdown(true)
}
func Rew7(file string) int {
	var cd string
	var err error
	tempD := Findpart()[0]
	ext := strings.ToLower(filepath.Ext(file))
	if ext == ".iso" || ext == ".esd" || ext == ".wim" {
		return -1
	}
	if ext == ".iso" {
		cd, err = MountISO(file, 30*time.Second)
		if err != nil {
			err = UnpackISO(file, tempD+"TEMPISO\\")
			if err != nil {
				return -2
			}
			cd = tempD + "TEMPISO\\"
		}
	}
	fmt.Println(cd, err)
	FindFile(cd, "", 3)
	//path, _ := os.Getwd()
	//img, err := ListImageInfos(path + "\\win10.esd")
	return 0
}
func test1() {
	bt := "magnet:?xt=urn:btih:585DF592DE43A067C75CFE5A639B41FC3F24DA6F&dn=cn_windows_7_ultimate_with_sp1_x86_dvd_u_677486.iso&xl=2653276160"
	SHA1 := "B92119F5B732ECE1C0850EDA30134536E18CCCE7"
	fmt.Println(DownloadBT(bt, "D:\\镜像", func(pct int, speed, done, total int64) {
		fmt.Printf("进度: %d%%  速度: %d B/s  已下: %d / %d 字节\n",
			pct, speed, done, total)

		w.SetTitle(fmt.Sprintln("进度: %d%%  速度: %d B/s  已下: %d / %d 字节\n",
			pct, speed, done, total))
		progbar.SetPos(int32(pct))
		progbar.Redraw(false)
		w.Redraw(false)
	}))

	fmt.Println(CheckFileSHA1("D:\\镜像\\cn_windows_7_ultimate_with_sp1_x86_dvd_u_677486.iso", SHA1))
}
