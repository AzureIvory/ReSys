package main

import (
	log "ReSys/src/log"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/kdomanski/iso9660/util"
	"golang.org/x/text/encoding/simplifiedchinese"

	"ReSys/src/utils"
)

var dism, _ = GetDism()

// 用于显示进度条。
var ImageProgress func(phase string, percent float64, raw string)

// 调用ShellExecuteW
func shellExecuteVerb(path string, verb string) error {
	pPath, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		log.LogWrite(0, "[shellExecuteVerb]shellExecuteVerb 路径编码失败: path=%s err=%v", path, err)
		return err
	}
	pVerb, err := syscall.UTF16PtrFromString(verb)
	if err != nil {
		log.LogWrite(0, "[shellExecuteVerb]shellExecuteVerb 动作编码失败: verb=%s err=%v", verb, err)
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
			log.LogWrite(0, "[shellExecuteVerb]shellExecuteVerb 调用失败: path=%s verb=%s err=%v", path, verb, callErr)
			return fmt.Errorf("ShellExecuteW failed: ret=%d err=%w", r, callErr)
		}
		log.LogWrite(0, "[shellExecuteVerb]shellExecuteVerb 调用失败: path=%s verb=%s ret=%d", path, verb, r)
		return fmt.Errorf("ShellExecuteW failed: ret=%d", r)
	}
	return nil
}

// 使用ShellExecute挂载ISO，返回新挂载的光驱盘符
func MountISO(isoPath string, wait time.Duration) (string, error) {
	if _, err := os.Stat(isoPath); err != nil {
		log.LogWrite(0, "[MountISO]MountISO ISO不存在: path=%s err=%v", isoPath, err)
		return "", fmt.Errorf("iso not found: %w", err)
	}

	// 记录现有CD盘符
	before, err := ListCD()
	if err != nil {
		log.LogWrite(0, "[MountISO]MountISO 获取CD盘符失败: err=%v", err)
		return "", fmt.Errorf("list cdrom before mount: %w", err)
	}
	beforeSet := make(map[string]struct{}, len(before))
	for _, d := range before {
		beforeSet[d] = struct{}{}
	}

	if err := shellExecuteVerb(isoPath, "mount"); err != nil {
		if err2 := shellExecuteVerb(isoPath, "open"); err2 != nil {
			log.LogWrite(0, "[MountISO]MountISO 执行挂载失败: mountErr=%v openErr=%v", err, err2)
			return "", fmt.Errorf("mount/open iso failed: %v / %v", err, err2)
		}
	}

	// 找新的CD盘符
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		time.Sleep(500 * time.Millisecond)

		now, err := ListCD()
		if err != nil {
			log.LogWrite(0, "[MountISO]MountISO 获取CD盘符失败: err=%v", err)
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
		log.LogWrite(0, "[UnpackISO]UnpackISO 创建目录失败: dir=%s err=%v", dstDir, err)
		return fmt.Errorf("create dst dir: %w", err)
	}

	f, err := os.Open(isoPath)
	if err != nil {
		log.LogWrite(0, "[UnpackISO]UnpackISO 打开ISO失败: path=%s err=%v", isoPath, err)
		return fmt.Errorf("open iso: %w", err)
	}
	defer f.Close()

	if err := util.ExtractImageToDirectory(f, dstDir); err != nil {
		log.LogWrite(0, "[UnpackISO]UnpackISO 解包失败: path=%s dir=%s err=%v", isoPath, dstDir, err)
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
		log.LogWrite(0, "[runCmd]runCmd 执行失败: bin=%s args=%v err=%v", bin, args, err)
		return out, fmt.Errorf("%s %v failed: %w\n%s", bin, args, err, out)
	}
	return out, nil
}

// 把匿名函数适配成 io.Writer
type writerFunc func(p []byte) (int, error)

// Write 函数。
func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

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
		root, _ := utils.NormalizeDrive(r, 0)
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
		r, _ := utils.NormalizeDrive(sysHint, 0)
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
	bcdpath := utils.GetSystemExe("bcdboot.exe")

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
	sysRoot, _ := utils.NormalizeDrive(sysHint, 0)
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
	bcdpath := utils.GetSystemExe("bcdboot.exe")

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
	//cab,_:=NewCab()
	//cab.Extract("Windows6.1-KB3087873-v2-x64.cab","temp")

	os.Exit(1)

	if dism == "" {
		dism = "dism.exe"
	}
	Uiinit()
	//判断是否在PE
	if strings.ToUpper(os.Getenv("SystemRoot")) == `X:\WINDOWS` {
		go PE()
	}
	log.LogWrite(0, "[main]Run\n")
	UiRun()
}
