package tools

import (
	"bytes"
	"fmt"
	"crypto/md5"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/text/encoding/simplifiedchinese"

	"ReSys/src/log"
)

var (
	Kernel32               = syscall.NewLazyDLL("kernel32.dll")
	ole32                  = syscall.NewLazyDLL("ole32.dll")
	procCoInitializeEx     = ole32.NewProc("CoInitializeEx")
	procCoUninitialize     = ole32.NewProc("CoUninitialize")
	procCoCreateInstance   = ole32.NewProc("CoCreateInstance")
	User32                 = syscall.NewLazyDLL("user32.dll")
	Advapi32               = syscall.NewLazyDLL("advapi32.dll")
	procExitWindowsEx      = User32.NewProc("ExitWindowsEx")
	procOpenProcessToken   = Advapi32.NewProc("OpenProcessToken")
	procLookupPrivilegeVal = Advapi32.NewProc("LookupPrivilegeValueW")
	procAdjustTokenPriv    = Advapi32.NewProc("AdjustTokenPrivileges")
	Ntdll                  = syscall.NewLazyDLL("ntdll.dll")
	procNtShutdownSystem   = Ntdll.NewProc("NtShutdownSystem")
	procGlobalMemoryStatus = Kernel32.NewProc("GlobalMemoryStatusEx")
)

const (
	COINIT_APARTMENTTHREADED = 0x2
	CLSCTX_INPROC_SERVER     = 0x1
	SE_PRIVILEGE_ENABLED     = 0x00000002
	TOKEN_ADJUST_PRIVILEGES  = 0x0020
	TOKEN_QUERY              = 0x0008
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
	CLSID_ShellLink  = GUID{0x00021401, 0x0000, 0x0000, [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}
	IID_IShellLinkW  = GUID{0x000214F9, 0x0000, 0x0000, [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}
	IID_IPersistFile = GUID{0x0000010b, 0x0000, 0x0000, [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}
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

// IShellLinkW vtable
type iShellLinkWVtbl struct {
	QueryInterface      uintptr
	AddRef              uintptr
	Release             uintptr
	GetArguments        uintptr
	GetDescription      uintptr
	GetHotkey           uintptr
	GetIconLocation     uintptr
	GetIDList           uintptr
	GetPath             uintptr
	GetShowCmd          uintptr
	GetWorkingDirectory uintptr
	Resolve             uintptr
	SetArguments        uintptr
	SetDescription      uintptr
	SetHotkey           uintptr
	SetIconLocation     uintptr
	SetIDList           uintptr
	SetPath             uintptr
	SetRelativePath     uintptr
	SetShowCmd          uintptr
	SetWorkingDirectory uintptr
}

type IShellLinkW struct {
	lpVtbl *iShellLinkWVtbl
}

// IPersistFile vtable（IUnknown + IPersist + IPersistFile）
type iPersistFileVtbl struct {
	QueryInterface uintptr
	AddRef         uintptr
	Release        uintptr
	GetClassID     uintptr
	IsDirty        uintptr
	Load           uintptr
	Save           uintptr
	SaveCompleted  uintptr
	GetCurFile     uintptr
}

type IPersistFile struct {
	lpVtbl *iPersistFileVtbl
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

// 判断 Windows 的 HRESULT 是否失败。
func hresultFailed(hr uintptr) bool {
	return int32(hr) < 0
}

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

	// 判断是否是网址
	lowerTarget := strings.ToLower(target)
	isURL := strings.HasPrefix(lowerTarget, "http://") ||
		strings.HasPrefix(lowerTarget, "https://")

	ext := strings.ToLower(filepath.Ext(name))
	if ext == "" {
		if isURL {
			ext = ".url"
		} else {
			ext = ".lnk"
		}
		name += ext
	} else if ext != ".lnk" && ext != ".url" {
		ext = ".lnk"
	}

	fullPath, err := filepath.Abs(filepath.Join(dir, name))
	if err != nil {
		return "", fmt.Errorf("abs path: %w", err)
	}

	if isURL || ext == ".url" {
		if err := writeURLShortcut(fullPath, target); err != nil {
			return "", err
		}
		return fullPath, nil
	}

	// WinAPI+COM(IShellLinkW + IPersistFile) 创建 .lnk
	if err := createShellLinkCOM(fullPath, target); err == nil {
		return fullPath, nil
	}

	// COM 失败
	urlPath := strings.TrimSuffix(fullPath, filepath.Ext(fullPath)) + ".url"
	if err := writeURLShortcut(urlPath, target); err != nil {
		return "", fmt.Errorf("create .lnk via COM failed AND fallback .url failed: %w", err)
	}
	return urlPath, nil
}

// .url + COM 创建 .lnk
func writeURLShortcut(path, target string) error {
	content := "[InternetShortcut]\r\nURL=" + target + "\r\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return fmt.Errorf("write url shortcut %s: %w", path, err)
	}
	return nil
}

func createShellLinkCOM(linkPath, targetPath string) error {
	// 固定在一个线程上
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// 初始化 COM
	hr, _, _ := procCoInitializeEx.Call(0, uintptr(COINIT_APARTMENTTHREADED))
	if hresultFailed(hr) {
		return fmt.Errorf("CoInitializeEx failed: 0x%08X", uint32(hr))
	}
	defer procCoUninitialize.Call()

	// CoCreateInstance CLSID_ShellLink -> IShellLinkW*
	var psl *IShellLinkW
	hr, _, _ = procCoCreateInstance.Call(
		uintptr(unsafe.Pointer(&CLSID_ShellLink)),
		0,
		uintptr(CLSCTX_INPROC_SERVER),
		uintptr(unsafe.Pointer(&IID_IShellLinkW)),
		uintptr(unsafe.Pointer(&psl)),
	)
	if hresultFailed(hr) || psl == nil {
		return fmt.Errorf("CoCreateInstance(IShellLinkW) failed: 0x%08X", uint32(hr))
	}
	// Release
	defer syscall.SyscallN(psl.lpVtbl.Release, uintptr(unsafe.Pointer(psl)))

	// 设置目标路径
	targetUTF16, err := syscall.UTF16PtrFromString(targetPath)
	if err != nil {
		return fmt.Errorf("target UTF16: %w", err)
	}
	hr, _, _ = syscall.SyscallN(
		psl.lpVtbl.SetPath,
		uintptr(unsafe.Pointer(psl)),
		uintptr(unsafe.Pointer(targetUTF16)),
	)
	if hresultFailed(hr) {
		return fmt.Errorf("IShellLinkW.SetPath failed: 0x%08X", uint32(hr))
	}

	if dir := filepath.Dir(targetPath); dir != "" {
		if wd, err := syscall.UTF16PtrFromString(dir); err == nil {
			syscall.SyscallN(
				psl.lpVtbl.SetWorkingDirectory,
				uintptr(unsafe.Pointer(psl)),
				uintptr(unsafe.Pointer(wd)),
			)
		}
	}

	// QueryInterface(IPersistFile)
	var ppf *IPersistFile
	hr, _, _ = syscall.SyscallN(
		psl.lpVtbl.QueryInterface,
		uintptr(unsafe.Pointer(psl)),
		uintptr(unsafe.Pointer(&IID_IPersistFile)),
		uintptr(unsafe.Pointer(&ppf)),
	)
	if hresultFailed(hr) || ppf == nil {
		return fmt.Errorf("IShellLinkW.QueryInterface(IPersistFile) failed: 0x%08X", uint32(hr))
	}
	defer syscall.SyscallN(ppf.lpVtbl.Release, uintptr(unsafe.Pointer(ppf)))

	// 保存 .lnk 文件
	linkUTF16, err := syscall.UTF16PtrFromString(linkPath)
	if err != nil {
		return fmt.Errorf("linkPath UTF16: %w", err)
	}
	hr, _, _ = syscall.SyscallN(
		ppf.lpVtbl.Save,
		uintptr(unsafe.Pointer(ppf)),
		uintptr(unsafe.Pointer(linkUTF16)),
		uintptr(1), // TRUE: remember
	)
	if hresultFailed(hr) {
		return fmt.Errorf("IPersistFile.Save failed: 0x%08X", uint32(hr))
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