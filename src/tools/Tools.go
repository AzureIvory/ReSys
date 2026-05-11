//lint:file-ignore U1000 Preserve the legacy command runner while the newer implementation is being validated.
package tools

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/text/encoding/simplifiedchinese"

	"ReSys/src/log"
	"ReSys/src/tools/mslnk"
)

var (
	Kernel32               = syscall.NewLazyDLL("kernel32.dll")
	User32                 = syscall.NewLazyDLL("user32.dll")
	Advapi32               = syscall.NewLazyDLL("advapi32.dll")
	procExitWindowsEx      = User32.NewProc("ExitWindowsEx")
	procOpenProcessToken   = Advapi32.NewProc("OpenProcessToken")
	procLookupPrivilegeVal = Advapi32.NewProc("LookupPrivilegeValueW")
	procAdjustTokenPriv    = Advapi32.NewProc("AdjustTokenPrivileges")
	Ntdll                  = syscall.NewLazyDLL("ntdll.dll")
	procNtShutdownSystem   = Ntdll.NewProc("NtShutdownSystem")
	procGlobalMemoryStatus = Kernel32.NewProc("GlobalMemoryStatusEx")
	runExeDir              = func() string {
		exe, err := os.Executable()
		if err != nil {
			return ""
		}
		return filepath.Dir(exe)
	}
)

const (
	SE_PRIVILEGE_ENABLED    = 0x00000002
	TOKEN_ADJUST_PRIVILEGES = 0x0020
	TOKEN_QUERY             = 0x0008
	// ExitWindowsEx flags
	EWX_LOGOFF       = 0x00000000 //注销
	EWX_SHUTDOWN     = 0x00000008 //关机
	EWX_REBOOT       = 0x00000002 //重启
	EWX_FORCE        = 0x00000004 //强制关闭应用
	EWX_FORCEIFHUNG  = 0x00000010 //程序无响应，强制关闭
	ShutdownNoReboot = 0          // 只是退出系统，不重启
	ShutdownReboot   = 1          // 重启
	ShutdownPowerOff = 2          // 关机断电
)

// CLSID / IID
var (
	GPTTypeEfiSystem = GUID{0xC12A7328, 0xF81F, 0x11D2, [8]byte{0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B}}
	GPTTypeMsr       = GUID{0xE3C9E316, 0x0B5C, 0x4DB8, [8]byte{0x81, 0x7D, 0xF9, 0x2D, 0xF0, 0x02, 0x15, 0xAE}}
	GPTTypeBasicData = GUID{0xEBD0A0A2, 0xB9E5, 0x4433, [8]byte{0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7}}
	GPTTypeRecovery  = GUID{0xDE94BBA4, 0x06D1, 0x4D40, [8]byte{0xA1, 0x6A, 0xBF, 0xD5, 0x01, 0x79, 0xD6, 0xAC}}
)

type GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

// LUID / TOKEN_PRIVILEGES 结构体
type luid struct {
	LowPart  uint32
	HighPart int32
}
type luidAndAttributes struct {
	Luid       luid
	Attributes uint32
}

type tokenPrivileges struct {
	PrivilegeCount uint32
	Privileges     [1]luidAndAttributes
}

// MEMORYSTATUSEX 结构体（内存）
type memoryStatusEx struct {
	dwLength                uint32
	dwMemoryLoad            uint32
	ullTotalPhys            uint64
	ullAvailPhys            uint64
	ullTotalPageFile        uint64
	ullAvailPageFile        uint64
	ullTotalVirtual         uint64
	ullAvailVirtual         uint64
	ullAvailExtendedVirtual uint64
}

// 执行外部命令，返回stdout+stderr
// input：不为 nil 时写入 stdin
// onLine：不为 nil 时，每输出一行就回调一次。
// dir：工作目录，为空则用 程序目录\tools 。
func RunCmd(bin string, input []byte, onLine func(string), dir string, args ...string) (string, error) {
	return RunCmdContext(context.Background(), bin, input, onLine, dir, args...)
}

func legacyRunCmd(bin string, input []byte, onLine func(string), dir string, args ...string) (string, error) {
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

// RunCmdContext adds context control on top of RunCmd and streams stdout/stderr in real time.
func RunCmdContext(ctx context.Context, bin string, input []byte, onLine func(string), dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	prepareRunCmd(cmd, dir)

	if input != nil {
		cmd.Stdin = bytes.NewReader(input)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", fmt.Errorf("stdout pipe failed: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return "", fmt.Errorf("stderr pipe failed: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return "", err
	}

	var (
		lines   []string
		linesMu sync.Mutex
		readErr error
		readWg  sync.WaitGroup
	)

	emitLine := func(line string) {
		linesMu.Lock()
		lines = append(lines, line)
		linesMu.Unlock()

		if onLine != nil {
			onLine(line)
			return
		}
		fmt.Println(line)
	}

	readPipe := func(r io.Reader) {
		defer readWg.Done()

		reader := bufio.NewReader(r)
		part := make([]byte, 0, 256)
		flush := func() {
			if len(part) == 0 {
				return
			}
			emitLine(decodeConsoleLine(part))
			part = part[:0]
		}

		for {
			chunk, err := reader.ReadBytes('\n')
			if len(chunk) > 0 {
				for _, b := range chunk {
					if b == '\r' || b == '\n' {
						flush()
						continue
					}
					part = append(part, b)
				}
			}
			if err != nil {
				flush()
				if err != io.EOF {
					linesMu.Lock()
					if readErr == nil {
						readErr = err
					}
					linesMu.Unlock()
				}
				return
			}
		}
	}

	readWg.Add(2)
	go readPipe(stdout)
	go readPipe(stderr)

	waitErr := cmd.Wait()
	readWg.Wait()

	linesMu.Lock()
	out := strings.Join(lines, "\n")
	pipeErr := readErr
	linesMu.Unlock()

	if ctxErr := ctx.Err(); ctxErr != nil {
		return out, ctxErr
	}
	if pipeErr != nil {
		return out, fmt.Errorf("read command output failed: %w", pipeErr)
	}
	if waitErr != nil {
		log.LogWrite(0, "[runCmd]runCmd 执行失败: bin=%s args=%v err=%v", bin, args, waitErr)
		return out, fmt.Errorf("%s %v failed: %w\n%s", bin, args, waitErr, out)
	}
	return out, nil
}

func prepareRunCmd(cmd *exec.Cmd, dir string) {
	toolDir := findRunDir(dir)
	if toolDir == "" {
		return
	}

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

func findRunDir(dir string) string {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		if exeDir := runExeDir(); exeDir != "" {
			dir = filepath.Join(exeDir, "tools")
		}
	}
	if dir == "" {
		return ""
	}
	st, err := os.Stat(dir)
	if err != nil || !st.IsDir() {
		return ""
	}
	return dir
}

func decodeConsoleLine(raw []byte) string {
	raw = bytes.TrimRight(raw, "\r\n")
	if len(raw) == 0 {
		return ""
	}
	if utf8.Valid(raw) {
		return string(raw)
	}
	if decoded, err := simplifiedchinese.GB18030.NewDecoder().Bytes(raw); err == nil {
		return string(decoded)
	}
	if decoded, err := simplifiedchinese.GBK.NewDecoder().Bytes(raw); err == nil {
		return string(decoded)
	}
	return string(raw)
}

// 把匿名函数适配成 io.Writer
type writerFunc func(p []byte) (int, error)

// Write 函数。
func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// 在指定目录 dir 下创建一个快捷方式；
// name 为快捷方式文件名，target 为目标（exe 路径或网址）。
func CreateShortcut(dir, name, target string) (string, error) {
	dir = strings.TrimSpace(dir)
	name = strings.TrimSpace(name)
	target = strings.TrimSpace(target)

	if dir == "" {
		return "", fmt.Errorf("dir is empty")
	}
	if name == "" {
		return "", fmt.Errorf("name is empty")
	}
	if target == "" {
		return "", fmt.Errorf("target is empty")
	}

	// 确保目录存在
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", dir, err)
	}

	isURL := isShortcutURL(target)
	fullPath, err := shortcutPath(dir, name, isURL)
	if err != nil {
		return "", fmt.Errorf("abs path: %w", err)
	}

	if isURL {
		if err := writeURLShortcut(fullPath, target); err != nil {
			return "", err
		}
		return fullPath, nil
	}

	if err := writeFileShortcut(fullPath, target); err != nil {
		return "", err
	}
	return fullPath, nil
}

func isShortcutURL(target string) bool {
	target = strings.ToLower(strings.TrimSpace(target))
	return strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://")
}

func shortcutPath(dir, name string, isURL bool) (string, error) {
	ext := ".lnk"
	if isURL {
		ext = ".url"
	}

	gotExt := strings.ToLower(filepath.Ext(name))
	switch gotExt {
	case ext:
	case "":
		name += ext
	default:
		name = strings.TrimSuffix(name, filepath.Ext(name)) + ext
	}
	return filepath.Abs(filepath.Join(dir, name))
}

// 文件快捷方式在 PE 阶段用离线写入，避免目标文件尚不存在时被系统修正成盘根目录。
func writeFileShortcut(path, target string) error {
	opts := mslnk.Options{
		LinkPath:   path,
		TargetPath: target,
		WorkingDir: shortcutWorkDir(target),
	}
	if err := mslnk.CreateLink(opts); err != nil {
		return fmt.Errorf("create shell link %s: %w", path, err)
	}
	return nil
}

func shortcutWorkDir(target string) string {
	target = strings.ReplaceAll(strings.TrimSpace(target), "/", "\\")
	switch {
	case len(target) >= 3 && target[1] == ':' && target[2] == '\\':
		return filepath.Dir(target)
	case len(target) >= 2 && target[1] == ':':
		return filepath.Dir(target[:2] + `\` + strings.TrimLeft(target[2:], `\`))
	case strings.HasPrefix(target, `\`):
		return filepath.Dir(`C:\` + strings.TrimLeft(target, `\`))
	default:
		return ""
	}
}

// 网址快捷方式继续写成 .url，避免引入不必要的壳层依赖。
func writeURLShortcut(path, target string) error {
	content := "[InternetShortcut]\r\nURL=" + target + "\r\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return fmt.Errorf("write url shortcut %s: %w", path, err)
	}
	return nil
}

// 开启当前进程的关机权限
func EnableShutdownPrivilege() error {
	var hToken syscall.Token

	hProc, err := syscall.GetCurrentProcess()
	if err != nil {
		return fmt.Errorf("GetCurrentProcess failed: %w", err)
	}

	// OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &hToken)
	r1, _, e1 := procOpenProcessToken.Call(
		uintptr(hProc),
		uintptr(TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY),
		uintptr(unsafe.Pointer(&hToken)),
	)
	if r1 == 0 {
		if e1 != nil && e1 != syscall.Errno(0) {
			return fmt.Errorf("OpenProcessToken failed: %w", e1)
		}
		return fmt.Errorf("OpenProcessToken failed")
	}
	defer syscall.CloseHandle(syscall.Handle(hToken))

	// LookupPrivilegeValueW("", "SeShutdownPrivilege", &luid)
	var l luid
	seName, _ := syscall.UTF16PtrFromString("SeShutdownPrivilege")
	r2, _, e2 := procLookupPrivilegeVal.Call(
		0,
		uintptr(unsafe.Pointer(seName)),
		uintptr(unsafe.Pointer(&l)),
	)
	if r2 == 0 {
		if e2 != nil && e2 != syscall.Errno(0) {
			return fmt.Errorf("LookupPrivilegeValueW failed: %w", e2)
		}
		return fmt.Errorf("LookupPrivilegeValueW failed")
	}

	var tp tokenPrivileges
	tp.PrivilegeCount = 1
	tp.Privileges[0].Luid = l
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

	r3, _, e3 := procAdjustTokenPriv.Call(
		uintptr(hToken),
		0,
		uintptr(unsafe.Pointer(&tp)),
		0,
		0,
		0,
	)
	if r3 == 0 {
		if e3 != nil && e3 != syscall.Errno(0) {
			return fmt.Errorf("AdjustTokenPrivileges failed: %w", e3)
		}
		return fmt.Errorf("AdjustTokenPrivileges failed")
	}
	return nil
}

// Shutdown
// reboot = true：重启，false：关机
func Shutdown(reboot bool) {
	var flag uint32
	if reboot {
		flag = EWX_REBOOT | EWX_FORCEIFHUNG
	} else {
		flag = EWX_SHUTDOWN | EWX_FORCEIFHUNG
	}

	// ExitWindowsEx
	if err := EnableShutdownPrivilege(); err == nil {
		procExitWindowsEx.Call(
			uintptr(flag),
			0,
		)

	}

	// rundll32 + ExitWindowsEx
	//   rundll32.exe user32.dll,ExitWindowsEx <flag>,0
	flagStr := "8" // EWX_SHUTDOWN
	if reboot {
		flagStr = "2" // EWX_REBOOT
	}
	exec.Command("rundll32.exe", "user32.dll,ExitWindowsEx", flagStr, "0").Run()

	// shutdown.exe
	var args []string
	if reboot {
		args = []string{"/r", "/t", "0", "/f"}
	} else {
		args = []string{"/s", "/t", "0", "/f"}
	}
	exec.Command("shutdown.exe", args...).Run()

	//内核（有些pe可能常规方法无法重启，需要这个）
	time.Sleep(2 * time.Second) // 这个重启是直接关机的，等待一下
	EnableShutdownPrivilege()
	action := uintptr(ShutdownPowerOff)
	if reboot {
		action = uintptr(ShutdownReboot)
	}
	procNtShutdownSystem.Call(action)

}

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

// 返回本机物理内存总量
// 返回值GB
func GetMemory() (float64, error) {
	var m memoryStatusEx
	m.dwLength = uint32(unsafe.Sizeof(m))

	r1, _, e1 := procGlobalMemoryStatus.Call(uintptr(unsafe.Pointer(&m)))
	if r1 == 0 {
		if errno, ok := e1.(syscall.Errno); ok && errno != 0 {
			return 0, errno
		}
		return 0, syscall.EINVAL
	}

	const gib = 1024 * 1024 * 1024
	return float64(m.ullTotalPhys) / float64(gib), nil
}

// 计算文件 MD5 并与期望值比较。
func MatchMD5(path, expect string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return false, err
	}
	got := fmt.Sprintf("%x", h.Sum(nil))
	return strings.EqualFold(strings.TrimSpace(got), strings.TrimSpace(expect)), nil
}
