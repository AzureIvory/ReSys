package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/kdomanski/iso9660/util"
	"golang.org/x/text/encoding/simplifiedchinese"
)

var dism, _ = GetDism()

// 用于显示进度条。
var ImageProgress func(phase string, percent float64, raw string)

// 调用ShellExecuteW
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

// 使用ShellExecute挂载ISO，返回新挂载的光驱盘符
func MountISO(isoPath string, wait time.Duration) (string, error) {
	if _, err := os.Stat(isoPath); err != nil {
		return "", fmt.Errorf("iso not found: %w", err)
	}

	// 记录现有CD盘符
	before, err := ListCD()
	if err != nil {
		return "", fmt.Errorf("list cdrom before mount: %w", err)
	}
	beforeSet := make(map[string]struct{}, len(before))
	for _, d := range before {
		beforeSet[d] = struct{}{}
	}

	if err := shellExecuteVerb(isoPath, "mount"); err != nil {
		if err2 := shellExecuteVerb(isoPath, "open"); err2 != nil {
			return "", fmt.Errorf("mount/open iso failed: %v / %v", err, err2)
		}
	}

	// 找新的CD盘符
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		time.Sleep(500 * time.Millisecond)

		now, err := ListCD()
		if err != nil {
			continue
		}
		for _, d := range now {
			if _, ok := beforeSet[d]; !ok {
				return d, nil
			}
		}
	}

	return "", errors.New("timeout: iso mounted but no new cdrom drive detected")
}

// 将ISO的内容解包到指定目录
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

// 执行外部命令，返回stdout+stderr
// input：不为 nil 时写入 stdin
// onLine：不为 nil 时，每输出一行就回调一次。
// dir：工作目录，为空则用 程序目录\tools 。
func runCmd(bin string, input []byte, onLine func(string), dir string, args ...string) (string, error) {
	cmd := exec.Command(bin, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	// 目录：优先用传入的 dir；为空则用 程序目录\tools
	toolDir := strings.TrimSpace(dir)
	if toolDir == "" {
		if exe, err := os.Executable(); err == nil {
			toolDir = filepath.Join(filepath.Dir(exe), "tools")
		}
	}

	// 设置工作目录 + 把该目录加到 PATH 前面
	if toolDir != "" {
		cmd.Dir = toolDir

		env := os.Environ()
		oldPath := os.Getenv("PATH")
		sep := string(os.PathListSeparator)

		newPath := toolDir
		if oldPath != "" {
			newPath = toolDir + sep + oldPath
		}

		replaced := false
		for i := range env {
			if strings.HasPrefix(strings.ToUpper(env[i]), "PATH=") {
				env[i] = "PATH=" + newPath
				replaced = true
				break
			}
		}
		if !replaced {
			env = append(env, "PATH="+newPath)
		}
		cmd.Env = env
	}

	var buf bytes.Buffer

	// 自定义writer
	type lineWriter struct {
		all    *bytes.Buffer
		onLine func(string)
		part   []byte
	}

	lw := &lineWriter{
		all:    &buf,
		onLine: onLine,
		part:   make([]byte, 0, 256),
	}

	writeLine := func(l string) {
		if lw.onLine != nil {
			lw.onLine(l)
		} else {
			fmt.Println(l)
		}
	}

	lwWrite := func(p []byte) {
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

	cmd.Stdout = writerFunc(func(p []byte) (int, error) {
		lwWrite(p)
		return len(p), nil
	})
	cmd.Stderr = cmd.Stdout

	if input != nil {
		cmd.Stdin = bytes.NewReader(input)
	}

	err := cmd.Run()

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

// 获取固件类型（UEFI/BIOS）
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

// 从一行输出中提取百分比,失败返回 -1
func extractPercent(line string) float64 {
	idx := strings.Index(line, "%")
	if idx == -1 {
		return -1
	}

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

// 会优先使用DISM，失败后wimlib-imagex
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
		// 从 DISM 输出解析百分比
		pct := extractPercent(line)
		if pct >= 0 {
			ImageProgress("DISM", pct, line)
		}
	}

	if out, err := runCmd(dism, nil, dismOnLine, "", dismArgs...); err == nil {
		fmt.Println("[ApplyImage] DISM ok")
		fmt.Println(out)
		// DISM 结束
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
	exePath = filepath.Join(filepath.Dir(exePath), "tools\\wimlib-imagex.exe")

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
		}

		pct := extractPercent(line)
		if pct >= 0 || phase != "" {
			ImageProgress(phase, pct, line)
		}
	}

	if out, err := runCmd(exePath, nil, wimOnLine, "", wimArgs...); err == nil {
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

// 安装 WIM 镜像到指定卷。
// wimPath:wim路径
// index:要安装的索引
// targetVol:目标卷，如"C:"、"C:\"
func ApplyWimImage(wimPath string, index int, targetVol string) error {
	if !strings.EqualFold(strings.TrimSpace(
		wimPath[len(wimPath)-4:]), ".wim") && !strings.HasSuffix(strings.ToLower(wimPath), ".wim") {
	}
	return ApplyImage(wimPath, index, targetVol)
}

// 安装ESD镜像到指定卷
func ApplyEsdImage(esdPath string, index int, targetVol string) error {
	return ApplyImage(esdPath, index, targetVol)
}

// 安装ISO镜像到指定卷
func ApplyISOImage(isoPath string, index int, targetVol string) error {
	isoRoot, err := MountISO(isoPath, 30*time.Second)
	if err != nil {
		parts := Findpart()
		if len(parts) == 0 {
			return fmt.Errorf("未找到可用分区用于解包ISO！")
		}
		var lastErr error
		for _, part := range parts {
			tempDir := filepath.Join(part, "TEMPISO")
			if err := os.MkdirAll(tempDir, 0755); err != nil {
				lastErr = err
				continue
			}
			if err := UnpackISO(isoPath, tempDir); err != nil {
				lastErr = err
				continue
			}
			isoRoot = tempDir
			lastErr = nil
			break
		}
		if lastErr != nil || isoRoot == "" {
			return fmt.Errorf("解包ISO失败！")
		}
	}

	installPath := filepath.Join(isoRoot, "sources", "install.wim")
	if _, err := os.Stat(installPath); err != nil {
		installPath = filepath.Join(isoRoot, "sources", "install.esd")
	}
	if _, err := os.Stat(installPath); err != nil {
		found, findErr := FindFile(isoRoot, "install.wim|install.esd", 3)
		if findErr != nil || len(found) == 0 {
			return fmt.Errorf("ISO中未找到安装镜像！")
		}
		installPath = found[0]
	}

	if strings.EqualFold(filepath.Ext(installPath), ".esd") {
		if ApplyEsdImage(installPath, index, targetVol) != nil {
			return fmt.Errorf("应用镜像失败！")
		}
		return nil
	}
	if strings.EqualFold(filepath.Ext(installPath), ".wim") {
		if ApplyWimImage(installPath, index, targetVol) != nil {
			return fmt.Errorf("应用镜像失败！")
		}
		return nil
	}

	return fmt.Errorf("ISO安装镜像类型不支持！")
}

// 找系统分区
func FindOS(hint string) (string, error) {
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

// 找 ESP分区
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

		fs, size, err := GetVolumeInfo(root)
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
	diskStyle, diskNum, err := GetDiskInfo(osRoot)
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
func FixUEFI(osRoot, sysHint, locale string) error {
	winDir := osRoot + "Windows"

	var sysRoot string
	if sysHint != "" {
		r := normRoot(sysHint)
		if r != "" {
			if fs, _, err := GetVolumeInfo(r); err == nil && fs == "FAT32" {
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
	windir := os.Getenv("SystemRoot")
	if windir == "" {
		windir = os.Getenv("WINDIR")
	}
	isWow64 := runtime.GOARCH == "386" && os.Getenv("PROCESSOR_ARCHITEW6432") != ""
	bcdpath := filepath.Join(windir, "System32", "bcdboot.exe")
	if isWow64 {
		bcdpath = filepath.Join(windir, "Sysnative", "bcdboot.exe")
	}

	if _, err := os.Stat(bcdpath); err != nil {
		alt := filepath.Join(windir, "System32", "bcdboot.exe")
		if _, err2 := os.Stat(alt); err2 == nil {
			bcdpath = alt
		} else {
			bcdpath = "bcdboot.exe"
		}
	}

	out, err := runCmd(bcdpath, nil, nil, "", args...)
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
	if out, err := runCmd("bootrec.exe", nil, nil, "", "/fixmbr"); err != nil {
		fmt.Println("[FixBIOS] bootrec /fixmbr failed (may be ok):", err)
		fmt.Println(out)
	} else {
		fmt.Println("[FixBIOS] bootrec /fixmbr ok")
		fmt.Println(out)
	}
	if out, err := runCmd("bootrec.exe", nil, nil, "", "/fixboot"); err != nil {
		fmt.Println("[FixBIOS] bootrec /fixboot failed, try bootsect:", err)
		fmt.Println(out)
		if out2, err2 := runCmd("bootsect.exe", nil, nil, "", "/nt60", sysRoot, "/mbr"); err2 != nil {
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
	windir := os.Getenv("SystemRoot")
	if windir == "" {
		windir = os.Getenv("WINDIR")
	}
	isWow64 := runtime.GOARCH == "386" && os.Getenv("PROCESSOR_ARCHITEW6432") != ""
	bcdpath := filepath.Join(windir, "System32", "bcdboot.exe")
	if isWow64 {
		bcdpath = filepath.Join(windir, "Sysnative", "bcdboot.exe")
	}

	if _, err := os.Stat(bcdpath); err != nil {
		alt := filepath.Join(windir, "System32", "bcdboot.exe")
		if _, err2 := os.Stat(alt); err2 == nil {
			bcdpath = alt
		} else {
			bcdpath = "bcdboot.exe"
		}
	}

	out, err := runCmd(bcdpath, nil, nil, "", args...)
	if err != nil {
		fmt.Println("[FixBIOS] bcdboot failed")
		fmt.Println(out)
		return err
	}
	fmt.Println("[FixBIOS] bcdboot ok")
	fmt.Println(out)
	return nil
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
				cur.Arch = val
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

// 提取字节数
func parseSizeBytes(s string) uint64 {
	s = strings.ToLower(s)
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

// 把字节转成MB/GB
func bytesToMBGBStr(size uint64) string {
	const (
		mb = 1024 * 1024
		gb = 1024 * 1024 * 1024
	)
	if size == 0 {
		return ""
	}
	if size < gb {
		v := float64(size) / float64(mb)
		return fmt.Sprintf("%.1f MB", v)
	}
	v := float64(size) / float64(gb)
	return fmt.Sprintf("%.2f GB", v)
}

// 结合 Installation / Edition / 名称 做系统索引判断 + Size
func finalizeImageMeta(m *ImageMeta) {
	m.Size = bytesToMBGBStr(m.SizeBytes)

	name := strings.ToLower(m.Name + " " + m.Description)
	inst := strings.ToLower(m.Installation)
	edition := strings.ToLower(m.Edition)

	isPEInstall := strings.Contains(inst, "windowspe") || strings.Contains(inst, "winpe")
	isPEEdition := strings.Contains(edition, "windowspe")

	isSetupName :=
		strings.Contains(name, "setup media") ||
			strings.Contains(name, "windows setup") ||
			strings.Contains(name, "windows pe") ||
			strings.Contains(name, "winpe") ||
			strings.Contains(name, "winre") ||
			strings.Contains(name, "recovery")
	isClientOrServer := strings.Contains(inst, "client") || strings.Contains(inst, "server")
	if inst == "" && !isPEInstall && !isPEEdition && !isSetupName {
		m.IsOS = true
		return
	}
	m.IsOS = isClientOrServer && !isPEInstall && !isPEEdition && !isSetupName
}

// 读取WIM/ESD中所有的信息（Index/Name/Description/Flags）。
func ListImageInfos(imagePath string) ([]ImageMeta, error) {
	if _, err := os.Stat(imagePath); err != nil {
		return nil, fmt.Errorf("image not found: %w", err)
	}

	// DISM
	if out, err := runCmd(
		dism,
		nil,
		nil,
		"",
		"/English",
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
	exePath, _ := os.Executable()
	exePath = filepath.Join(filepath.Dir(exePath), "tools\\wimlib-imagex.exe")
	if out, err := runCmd(exePath, nil, nil, "", "info", imagePath); err == nil {
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

// 获取启动模式
// 引导 ：0 BIOS 1 UEFI -1错误
// 安全启动：0 关闭 1开启 -1错误
func GetBootMode() (int, int) {
	if dirExists("tools\\BootMode.exe") != true {
		return -1, -1
	}
	text, err := runCmd("tools\\BootMode.exe", nil, nil, "", "")
	if err != nil {
		return -1, -1
	}
	text = strings.TrimSpace(text)
	parts := strings.Split(text, " | ")
	if len(parts) != 2 {
		return -1, -1
	}
	var mode int
	var safe int
	if parts[0] == "UEFI" || parts[0] == "efi" {
		mode = 1
	} else {
		mode = 0
	}
	if parts[1] == "SecureBoot: disabled" {
		safe = 0
	} else {
		safe = 1
	}
	return mode, safe
}

// pe专用
func PE() int {
	win2()

	if err := RunPEInstall(); err != nil {
		uiShowError("错误", err.Error())
		os.Exit(-1)
		return -1
	}
	return 0
}

func main() {
	if dism == "" {
		dism = "dism.exe"
	}
	Uiinit()
	//判断是否在PE
	if strings.ToUpper(os.Getenv("SystemRoot")) == `X:\WINDOWS` {
		go PE()
	}
	logWrite("Run\n")
	UiRun()
}
