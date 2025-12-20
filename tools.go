package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

// 以下是创建快捷方式相关代码，参考：https://docs.microsoft.com/en-us/windows/win32/shell/links
var (
	ole32                = syscall.NewLazyDLL("ole32.dll")
	procCoInitializeEx   = ole32.NewProc("CoInitializeEx")
	procCoUninitialize   = ole32.NewProc("CoUninitialize")
	procCoCreateInstance = ole32.NewProc("CoCreateInstance")
)

const (
	COINIT_APARTMENTTHREADED = 0x2
	CLSCTX_INPROC_SERVER     = 0x1
)

type GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

// CLSID / IID
var (
	CLSID_ShellLink  = GUID{0x00021401, 0x0000, 0x0000, [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}
	IID_IShellLinkW  = GUID{0x000214F9, 0x0000, 0x0000, [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}
	IID_IPersistFile = GUID{0x0000010b, 0x0000, 0x0000, [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}
)

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
		// 非 .lnk/.url 的一律当 .lnk 用
		ext = ".lnk"
	}

	fullPath, err := filepath.Abs(filepath.Join(dir, name))
	if err != nil {
		return "", fmt.Errorf("abs path: %w", err)
	}

	// 先处理 .url：直接写文本文件
	if isURL || ext == ".url" {
		if err := writeURLShortcut(fullPath, target); err != nil {
			return "", err
		}
		return fullPath, nil
	}

	// 走到这里就是普通 .lnk（指向文件/程序）

	// 用 WinAPI+COM(IShellLinkW + IPersistFile) 创建 .lnk
	if err := createShellLinkCOM(fullPath, target); err == nil {
		return fullPath, nil
	}

	// COM 失败：退回写一个 .url，当作简易快捷方式
	urlPath := strings.TrimSuffix(fullPath, filepath.Ext(fullPath)) + ".url"
	if err := writeURLShortcut(urlPath, target); err != nil {
		return "", fmt.Errorf("create .lnk via COM failed AND fallback .url failed: %w", err)
	}
	return urlPath, nil
}

//.url + COM 创建 .lnk

func writeURLShortcut(path, target string) error {
	content := "[InternetShortcut]\r\nURL=" + target + "\r\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return fmt.Errorf("write url shortcut %s: %w", path, err)
	}
	return nil
}

func createShellLinkCOM(linkPath, targetPath string) error {
	// 为了满足 COM 单线程模型，把 goroutine 固定在一个 OS 线程上
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
	// 记得 Release
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

// 尝试把src拷贝到dst。
// overwrite=true：覆盖；false：跳过
// createDir=true：目标目录不存在就创建；false：报错
func Copy(src, dst string, overwrite, createDir bool) error {
	si, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("Copy: src not found: %w", err)
	}

	// 负责单个文件的拷贝逻辑
	copyOneFile := func(srcFile, dstFile string, overwrite, createDir bool) error {
		fi, err := os.Stat(srcFile)
		if err != nil {
			return fmt.Errorf("Copy: src not found: %w", err)
		}
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("Copy: src is not a regular file: %s", srcFile)
		}

		// 目标存在处理
		if dfi, err := os.Stat(dstFile); err == nil {
			if dfi.IsDir() {
				return fmt.Errorf("Copy: dst is a directory: %s", dstFile)
			}
			if !overwrite {
				// 跳过
				fmt.Println("[Copy] dst exists, skip file:", dstFile)
				return nil
			}
		}

		// 确保目标目录存在
		if dir := filepath.Dir(dstFile); dir != "" && dir != "." {
			if dfi, err := os.Stat(dir); err != nil {
				if os.IsNotExist(err) {
					if !createDir {
						return fmt.Errorf("Copy: dest dir not exist and createDir=false: %s", dir)
					}
					if err := os.MkdirAll(dir, 0755); err != nil {
						return fmt.Errorf("Copy: MkdirAll(%s) failed: %w", dir, err)
					}
				} else {
					return fmt.Errorf("Copy: stat dest dir failed: %w", err)
				}
			} else if !dfi.IsDir() {
				return fmt.Errorf("Copy: dest parent is not dir: %s", dir)
			}
		}

		// 标准库 io.Copy
		if err := func() error {
			in, err := os.Open(srcFile)
			if err != nil {
				return err
			}
			defer in.Close()

			out, err := os.OpenFile(dstFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, fi.Mode().Perm())
			if err != nil {
				return err
			}
			defer out.Close()

			if _, err := io.Copy(out, in); err != nil {
				return err
			}
			return nil
		}(); err == nil {
			return nil
		} else {
			fmt.Println("[Copy] std copy failed, try cmd.exe:", err)
		}

		// cmd.exe
		if err := func() error {
			srcQ := `"` + srcFile + `"`
			dstQ := `"` + dstFile + `"`

			args := []string{"/C", "copy"}
			if overwrite {
				args = append(args, "/Y")
			} else {
				args = append(args, "/-Y")
			}
			args = append(args, srcQ, dstQ)

			cmd := exec.Command("cmd.exe", args...)
			return cmd.Run()
		}(); err == nil {
			return nil
		} else {
			fmt.Println("[Copy] cmd copy failed, try CopyFileW:", err)
		}

		// WinAPI CopyFileW
		srcW, err := syscall.UTF16PtrFromString(srcFile)
		if err != nil {
			return fmt.Errorf("Copy: src UTF16 failed: %w", err)
		}
		dstW, err := syscall.UTF16PtrFromString(dstFile)
		if err != nil {
			return fmt.Errorf("Copy: dst UTF16 failed: %w", err)
		}

		// bFailIfExists: TRUE(1) 目标存在就失败；FALSE(0) 覆盖
		var failIfExists uintptr = 0
		if !overwrite {
			failIfExists = 1
		}

		r, _, e := procCopyFileW.Call(
			uintptr(unsafe.Pointer(srcW)),
			uintptr(unsafe.Pointer(dstW)),
			failIfExists,
		)
		if r == 0 {
			if !overwrite {
				if errno, ok := e.(syscall.Errno); ok &&
					(errno == syscall.ERROR_FILE_EXISTS || errno == syscall.ERROR_ALREADY_EXISTS) {
					fmt.Println("[Copy] dst exists (CopyFileW), skip:", dstFile)
					return nil
				}
			}
			return fmt.Errorf("Copy: CopyFileW failed: %v", e)
		}
		return nil
	}

	// 目录分支
	if si.IsDir() {
		if dfi, err := os.Stat(dst); err == nil {
			if !dfi.IsDir() {
				return fmt.Errorf("Copy: dst exists and is not directory: %s", dst)
			}
		} else if os.IsNotExist(err) {
			if !createDir {
				return fmt.Errorf("Copy: dst dir not exist and createDir=false: %s", dst)
			}
			if err := os.MkdirAll(dst, si.Mode().Perm()); err != nil {
				return fmt.Errorf("Copy: MkdirAll root dst failed: %w", err)
			}
		} else {
			return fmt.Errorf("Copy: stat dst failed: %w", err)
		}

		// 递归遍历整个目录树
		return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if path == src {
				return nil
			}

			rel, err := filepath.Rel(src, path)
			if err != nil {
				return err
			}
			targetPath := filepath.Join(dst, rel)

			if info.IsDir() {
				if err := os.MkdirAll(targetPath, info.Mode().Perm()); err != nil {
					return err
				}
				return nil
			}

			return copyOneFile(path, targetPath, overwrite, true) // 子目录内部总是需要创建
		})
	}

	// 单文件分支
	return copyOneFile(src, dst, overwrite, createDir)
}

// ExitWindowsEx flags
const (
	EWX_LOGOFF      = 0x00000000 //注销
	EWX_SHUTDOWN    = 0x00000008 //关机
	EWX_REBOOT      = 0x00000002 //重启
	EWX_FORCE       = 0x00000004 //强制关闭应用
	EWX_FORCEIFHUNG = 0x00000010 //程序无响应，强制关闭
	//调用nt内核
	ShutdownNoReboot = 0 // 只是退出系统，不重启
	ShutdownReboot   = 1 // 重启
	ShutdownPowerOff = 2 // 关机断电
)

// token 权限相关
const (
	SE_PRIVILEGE_ENABLED    = 0x00000002
	TOKEN_ADJUST_PRIVILEGES = 0x0020
	TOKEN_QUERY             = 0x0008
)

// 调用nt内核
var modNtdll = syscall.NewLazyDLL("ntdll.dll")
var procNtShutdownSystem = modNtdll.NewProc("NtShutdownSystem")

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

// 开启当前进程的关机权限SeShutdownPrivilege
func enableShutdownPrivilege() error {
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
	if err := enableShutdownPrivilege(); err == nil {
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

	//内核
	enableShutdownPrivilege()
	action := uintptr(ShutdownPowerOff)
	if reboot {
		action = uintptr(ShutdownReboot)
	}
	procNtShutdownSystem.Call(action)

}

var (
	advapi32             = syscall.NewLazyDLL("advapi32.dll")
	procRegLoadKeyW      = advapi32.NewProc("RegLoadKeyW")
	procRegUnLoadKeyW    = advapi32.NewProc("RegUnLoadKeyW")
	procRegOpenKeyExW    = advapi32.NewProc("RegOpenKeyExW")
	procRegCloseKey      = advapi32.NewProc("RegCloseKey")
	procRegQueryValueExW = advapi32.NewProc("RegQueryValueExW")
)

const (
	HKEY_LOCAL_MACHINE = syscall.Handle(0x80000002)
	KEY_READ           = 0x20019 // 标准 KEY_READ
)

// 检测指定盘符上的离线 Windows 版本和架构。
// drive：可以是 "D", "D:", "D:\"
// 返回如: "Windows 7 x64" / "Windows 10 x86" / "Windows 11 x64"
func DetectWin(drive string) (string, error) {
	root, err := normalizeRoot(drive)
	if err != nil {
		return "", err
	}

	winDir := filepath.Join(root, "Windows")
	if !dirExists(winDir) {
		return "", fmt.Errorf("no Windows directory on %s", root)
	}

	// 目录方式先收集一些信息
	pfDir := filepath.Join(root, "Program Files")
	_ = dirExists(pfDir) // 目前只用来兜底
	pfxDir := filepath.Join(root, "Program Files (x86)")
	syswowDir := filepath.Join(winDir, "SysWOW64")

	hasPFx86 := dirExists(pfxDir)
	hasSysWOW := dirExists(syswowDir)

	// 离线注册表 hive 路径
	softwareHive := filepath.Join(winDir, "System32", "config", "SOFTWARE")
	if _, err := os.Stat(softwareHive); err != nil {
		return "", fmt.Errorf("SOFTWARE hive not found: %w", err)
	}
	systemHive := filepath.Join(winDir, "System32", "config", "SYSTEM")
	hasSystemHive := false
	if _, err := os.Stat(systemHive); err == nil {
		hasSystemHive = true
	}

	// 加载 SOFTWARE
	if err := RegLoadHive("Offline_SOFTWARE", softwareHive); err != nil {
		return "", fmt.Errorf("load SOFTWARE hive: %w", err)
	}
	defer RegUnloadHive("Offline_SOFTWARE")

	// 尝试加载 SYSTEM
	systemLoaded := false
	if hasSystemHive {
		if err := RegLoadHive("Offline_SYSTEM", systemHive); err == nil {
			systemLoaded = true
			defer RegUnloadHive("Offline_SYSTEM")
		}
	}

	// 读取版本信息：HKLM\Offline_SOFTWARE\Microsoft\Windows NT\CurrentVersion
	keyPath := `Offline_SOFTWARE\Microsoft\Windows NT\CurrentVersion`
	h, err := RegOpenKey(HKEY_LOCAL_MACHINE, keyPath)
	if err != nil {
		return "", fmt.Errorf("open offline CurrentVersion: %w", err)
	}
	defer RegCloseKey(h)

	productName, _ := RegGetString(h, "ProductName")
	currentVersion, _ := RegGetString(h, "CurrentVersion")

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
			// 用 build 号粗略区分 10 / 11
			buildStr, _ := RegGetString(h, "CurrentBuildNumber")
			if b, err := strconv.Atoi(buildStr); err == nil && b >= 22000 {
				osName = "Windows 11"
			} else if productName != "" {
				// Server 或其他版本，直接用完整名字
				osName = productName
			} else {
				osName = "Windows 10"
			}
		}
	default:
		if productName != "" {
			// 老系统就直接返回 ProductName
			osName = productName
		}
	}

	arch := detectArch(root, hasPFx86, hasSysWOW, systemLoaded)

	return fmt.Sprintf("%s %s", osName, arch), nil
}

// 推测指定盘符的系统架构（32/64）
func detectArch(root string, hasPFx86, hasSysWOW, systemLoaded bool) string {
	// 目录特征
	if hasPFx86 || hasSysWOW {
		return "x64"
	}

	// SYSTEM hive 里的环境变量
	if systemLoaded {
		keyPath := `Offline_SYSTEM\ControlSet001\Control\Session Manager\Environment`
		if h, err := RegOpenKey(HKEY_LOCAL_MACHINE, keyPath); err == nil {
			defer RegCloseKey(h)
			if s, err := RegGetString(h, "PROCESSOR_ARCHITECTURE"); err == nil && s != "" {
				up := strings.ToUpper(s)
				if strings.Contains(up, "64") || up == "AMD64" || up == "ARM64" {
					return "x64"
				}
				return "x86"
			}
		}
	}

	// 只有 Program Files 就按 32 位算
	if dirExists(filepath.Join(root, "Program Files")) {
		return "x86"
	}

	// 实在看不出来就统一当 x86
	return "x86"
}

// 目录是否存在
func dirExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

// 规范化盘符为 "D:\" 这种格式
func normalizeRoot(drive string) (string, error) {
	s := strings.TrimSpace(drive)
	if s == "" {
		return "", fmt.Errorf("empty drive")
	}
	s = strings.ReplaceAll(s, "/", `\`)

	if len(s) == 1 { // "D"
		s = s + ":"
	}
	if len(s) == 2 && s[1] == ':' { // "D:"
		s = s + `\`
	}
	if len(s) != 3 || s[1] != ':' || s[2] != '\\' {
		return "", fmt.Errorf("invalid drive: %q", drive)
	}
	s = strings.ToUpper(s[:1]) + s[1:]
	return s, nil
}

// 获取磁盘剩余空间相关
const (
	ioctlStorageQueryProperty = 0x002D1400 // IOCTL_STORAGE_QUERY_PROPERTY
)

// STORAGE_PROPERTY_ID
const (
	storagePropertyDevice      = 0 // StorageDeviceProperty
	storagePropertySeekPenalty = 7 // StorageDeviceSeekPenaltyProperty
)

// STORAGE_QUERY_TYPE
const (
	storageQueryStandard = 0 // PropertyStandardQuery
)

// STORAGE_BUS_TYPE（只列一些常见的）
const (
	busTypeUnknown = 0
	busTypeScsi    = 1
	busTypeAtapi   = 2
	busTypeAta     = 3
	busTypeUsb     = 7
	busTypeSata    = 8
	busTypeSas     = 9
)

// 对应 STORAGE_PROPERTY_QUERY
type storagePropertyQuery struct {
	PropertyId           uint32
	QueryType            uint32
	AdditionalParameters [1]byte
}

// 对应 STORAGE_DEVICE_SEEK_PENALTY_DESCRIPTOR
type storageDeviceSeekPenaltyDescriptor struct {
	Version           uint32
	Size              uint32
	IncursSeekPenalty byte
	Reserved          [3]byte // 对齐填充
}

// 对应 STORAGE_DEVICE_DESCRIPTOR（只用到 BusType）
type storageDeviceDescriptor struct {
	Version               uint32
	Size                  uint32
	DeviceType            byte
	DeviceTypeModifier    byte
	RemovableMedia        byte
	CommandQueueing       byte
	VendorIdOffset        uint32
	ProductIdOffset       uint32
	ProductRevisionOffset uint32
	SerialNumberOffset    uint32
	BusType               uint32
	RawPropertiesLength   uint32
	// RawDeviceProperties[1] 后面用大 buffer 覆盖
}

// GetDiskKind 判断指定卷所在物理盘是 SSD / HDD / 移动设备 / 光驱。
// vol 可以是 "C" / "C:" / "C:\"。
// 返回值： "SSD" / "HDD" / "Removable" / "CDROM" / "Unknown"
func GetDiskKind(vol string) (string, error) {
	root := normRoot(vol)
	if root == "" {
		return "Unknown", fmt.Errorf("invalid volume: %q", vol)
	}

	// 先看逻辑盘类型
	dt := GetDriveType(root)

	// 光驱 / 挂载的 ISO（Windows 自带挂载会是 CDROM 类型）
	if dt == driveCdrom {
		return "CDROM", nil
	}

	// 后面是非光驱的情况：U 盘 / 机械 / 固态
	// 找到对应的物理磁盘号
	diskNum, err := GetDiskNum(root)
	if err != nil {
		// 如果至少知道是可移动盘，就返回 Removable
		if dt == driveRemov {
			return "Removable", nil
		}
		return "Unknown", fmt.Errorf("GetDiskNum failed: %w", err)
	}

	diskPath := fmt.Sprintf(`\\.\PhysicalDrive%d`, diskNum)
	pDisk, err := syscall.UTF16PtrFromString(diskPath)
	if err != nil {
		if dt == driveRemov {
			return "Removable", nil
		}
		return "Unknown", err
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
		if dt == driveRemov {
			return "Removable", nil
		}
		return "Unknown", fmt.Errorf("CreateFile %s failed: %w", diskPath, err)
	}
	defer syscall.CloseHandle(hDisk)

	// 先查 BusType，看是不是 USB 之类的移动设备
	busType := uint32(busTypeUnknown)
	{
		q := storagePropertyQuery{
			PropertyId: storagePropertyDevice,
			QueryType:  storageQueryStandard,
		}
		out := make([]byte, 512)
		var bytesRet uint32

		err = syscall.DeviceIoControl(
			hDisk,
			ioctlStorageQueryProperty,
			(*byte)(unsafe.Pointer(&q)),
			uint32(unsafe.Sizeof(q)),
			&out[0],
			uint32(len(out)),
			&bytesRet,
			nil,
		)
		if err == nil && bytesRet >= uint32(unsafe.Sizeof(storageDeviceDescriptor{})) {
			dev := (*storageDeviceDescriptor)(unsafe.Pointer(&out[0]))
			busType = dev.BusType
		}
	}

	// USB 总线 / DRIVE_REMOVABLE 一律认为是移动设备
	if dt == driveRemov || busType == busTypeUsb {
		return "Removable", nil
	}

	// 尝试用 SeekPenalty 判断 SSD / HDD
	hasSeekInfo := false
	incursSeek := false
	{
		q := storagePropertyQuery{
			PropertyId: storagePropertySeekPenalty,
			QueryType:  storageQueryStandard,
		}
		out := make([]byte, 32)
		var bytesRet uint32

		err = syscall.DeviceIoControl(
			hDisk,
			ioctlStorageQueryProperty,
			(*byte)(unsafe.Pointer(&q)),
			uint32(unsafe.Sizeof(q)),
			&out[0],
			uint32(len(out)),
			&bytesRet,
			nil,
		)
		if err == nil && bytesRet >= uint32(unsafe.Sizeof(storageDeviceSeekPenaltyDescriptor{})) {
			desc := (*storageDeviceSeekPenaltyDescriptor)(unsafe.Pointer(&out[0]))
			hasSeekInfo = true
			incursSeek = desc.IncursSeekPenalty != 0
		}
	}

	if hasSeekInfo {
		if incursSeek {
			return "HDD", nil // 有寻道惩罚 -> 机械盘
		}
		return "SSD", nil // 无寻道惩罚 -> 固态盘
	}

	//没拿到 SeekPenalty，就根据 BusType 做个保守猜测
	switch busType {
	case busTypeSata, busTypeSas, busTypeScsi, busTypeAta:
		return "HDD", nil // 老接口大多数是机械盘
	}

	return "Unknown", nil
}

// 搜索文件
// root：目录
// pattern：文件，支持通配符，支持*.esd|*.wim|*.iso
// maxDepth：搜索子目录的层数
func FindFile(root string, pattern string, maxDepth int) ([]string, error) {
	if maxDepth < 0 {
		maxDepth = 0
	}

	root = filepath.Clean(root)

	fi, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("stat root: %w", err)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("root is not directory: %s", root)
	}

	// 支持 "*.esd|*.wim|*.iso"
	rawPats := strings.Split(pattern, "|")
	pats := make([]string, 0, len(rawPats))
	for _, p := range rawPats {
		p = strings.TrimSpace(p)
		if p != "" {
			pats = append(pats, p)
		}
	}
	if len(pats) == 0 {
		return nil, fmt.Errorf("empty pattern")
	}

	var matches []string

	var walk func(dir string, depth int) error
	walk = func(dir string, depth int) error {
		if depth > maxDepth {
			return nil
		}

		ents, err := os.ReadDir(dir)
		if err != nil {
			return fmt.Errorf("readdir %s: %w", dir, err)
		}

		for _, ent := range ents {
			name := ent.Name()
			full := filepath.Join(dir, name)

			if ent.Type().IsRegular() {
				for _, pat := range pats {
					ok, err := filepath.Match(pat, name)
					if err != nil {
						return fmt.Errorf("bad pattern %q: %w", pat, err)
					}
					if ok {
						matches = append(matches, full)
						break
					}
				}
			}

			if ent.IsDir() && depth < maxDepth {
				if err := walk(full, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}

	if err := walk(root, 0); err != nil {
		return nil, err
	}
	return matches, nil
}

// 全盘寻找镜像
func Findimg() []string {
	drives, err := ListDrive()
	if err != nil {
		return nil
	}

	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		files []string
	)

	patterns := []string{"*.iso", "*.esd", "*.wim"}
	const maxDepth = 2 // 搜 2 层目录
	const minSize = int64(700) * 1024 * 1024

	skipNames := map[string]struct{}{
		"03pe.wim":    {},
		"11pex64.wim": {},
	}

	for _, root := range drives {
		root := root
		for _, pattern := range patterns {
			pattern := pattern

			wg.Add(1)
			go func() {
				defer wg.Done()

				found, err := FindFile(root, pattern, maxDepth)
				if err != nil {
					return // 忽略错误
				}

				if len(found) > 0 {
					mu.Lock()
					files = append(files, found...)
					mu.Unlock()
				}
			}()
		}
	}

	wg.Wait()

	// 去重 + 过滤
	if len(files) > 0 {
		seen := make(map[string]struct{}, len(files))
		dst := files[:0]

		for _, p := range files {
			lp := strings.ToLower(p)
			base := strings.ToLower(filepath.Base(lp))

			if _, ok := skipNames[base]; ok {
				continue
			}

			fi, err := os.Stat(p)
			if err != nil || fi.IsDir() || fi.Size() < minSize {
				continue
			}

			if _, ok := seen[lp]; ok {
				continue
			}
			seen[lp] = struct{}{}
			dst = append(dst, p)
		}

		files = dst
	}

	// 排列：esd > wim > iso
	sort.Slice(files, func(i, j int) bool {
		pri := func(p string) int {
			switch strings.ToLower(filepath.Ext(p)) {
			case ".esd":
				return 0
			case ".wim":
				return 1
			case ".iso":
				return 2
			default:
				return 3
			}
		}
		pi, pj := pri(files[i]), pri(files[j])
		if pi != pj {
			return pi < pj
		}
		return strings.ToLower(files[i]) < strings.ToLower(files[j])
	})

	return files
}


// 返回没装系统而且有足够大小的分区数组
// SSD>HDD>USB
func Findpart() []string {
	D, err := ListDrive()
	if err != nil {
		return nil
	}

	type cand struct {
		path string
		kind string
		free uint64
		pri  int
	}

	var cs []cand

	for i := 0; i < len(D); i++ {
		root := D[i]

		// 有 Windows 目录的认为已经装系统，跳过
		if dirExists(root + "Windows\\") {
			continue
		}

		// 剩余空间
		freeBytes, err := GetFreeSize(root)
		if err != nil {
			continue
		}
		if freeBytes <= 7516192768 { // > 7g才算
			continue
		}

		// 磁盘类型
		kind, err := GetDiskKind(root)
		if err != nil {
			continue
		}
		if kind == "CDROM" || kind == "Unknown" {
			continue
		}

		// 类型优先级：SSD > HDD > Removable
		pri := 0
		switch kind {
		case "SSD":
			pri = 3
		case "HDD":
			pri = 2
		case "Removable":
			pri = 1
		default:
			pri = 0
		}
		if pri == 0 {
			continue
		}

		cs = append(cs, cand{
			path: root,
			kind: kind,
			free: freeBytes,
			pri:  pri,
		})
	}

	// 排序（SSD > HDD > Removable），再按剩余空间从大到小
	if len(cs) == 0 {
		return nil
	}

	sort.Slice(cs, func(i, j int) bool {
		if cs[i].pri != cs[j].pri {
			return cs[i].pri > cs[j].pri // 类型优先级高的在前
		}
		if cs[i].free != cs[j].free {
			return cs[i].free > cs[j].free // 同一类型剩余空间大的在前
		}
		// 再完全相同就按盘符字母顺序，防止排序不稳定
		return cs[i].path < cs[j].path
	})

	part := make([]string, 0, len(cs))
	for _, c := range cs {
		part = append(part, c.path)
	}
	return part
}

// 加载离线注册表 hive
// subKey：挂载点名称，如"OFFLINE_SYSTEM"
// file:注册表 hive 文件的 完整路径,如"C:\Windows\System32\config\SYSTEM"/"X:\Windows\System32\config\SOFTWARE"
// 需要有 SeBackupPrivilege / SeRestorePrivilege 之类的权限
func RegLoadHive(subKey, file string) error {
	subKeyPtr, err := syscall.UTF16PtrFromString(subKey)
	if err != nil {
		return err
	}
	filePtr, err := syscall.UTF16PtrFromString(file)
	if err != nil {
		return err
	}
	r0, _, e1 := procRegLoadKeyW.Call(
		uintptr(HKEY_LOCAL_MACHINE),
		uintptr(unsafe.Pointer(subKeyPtr)),
		uintptr(unsafe.Pointer(filePtr)),
	)
	if r0 != 0 {
		if e1 != nil && e1 != syscall.Errno(0) {
			return fmt.Errorf("RegLoadKeyW(%s) failed: %v (code=%d)", subKey, e1, r0)
		}
		return fmt.Errorf("RegLoadKeyW(%s) failed: code=%d", subKey, r0)
	}
	return nil
}

// 卸载之前通过 RegLoadKeyW 加载的 hive
// subKey：挂载点名称，如"OFFLINE_SYSTEM"
func RegUnloadHive(subKey string) error {
	subKeyPtr, err := syscall.UTF16PtrFromString(subKey)
	if err != nil {
		return err
	}
	r0, _, e1 := procRegUnLoadKeyW.Call(
		uintptr(HKEY_LOCAL_MACHINE),
		uintptr(unsafe.Pointer(subKeyPtr)),
	)
	if r0 != 0 {
		if e1 != nil && e1 != syscall.Errno(0) {
			return fmt.Errorf("RegUnLoadKeyW(%s) failed: %v (code=%d)", subKey, e1, r0)
		}
		return fmt.Errorf("RegUnLoadKeyW(%s) failed: code=%d", subKey, r0)
	}
	return nil
}

// BuildWIM 使用 tools\wimlib-imagex.exe 将 sources（文件/目录）打包成一个 WIM 文件。
// - sources: 需要打包的文件/目录路径数组
// - outWim: 输出 WIM 路径，例如 "C:\\WIN11.WIM"；若已存在则覆盖（删除后重建）
// 说明：会把每个 source 放到 WIM 根目录下：/basename。若 basename 冲突，会自动改名为 basename_2、basename_3...
func BuildWIM(sources []string, outWim string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("BuildWIM is only supported on Windows (GOOS=%s)", runtime.GOOS)
	}
	if len(sources) == 0 {
		return fmt.Errorf("sources must not be empty")
	}
	if strings.TrimSpace(outWim) == "" {
		return fmt.Errorf("outWim must not be empty")
	}

	// 定位 tools\wimlib-imagex.exe（以当前可执行文件所在目录为基准）
	selfExe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("os.Executable failed: %w", err)
	}
	baseDir := filepath.Dir(selfExe)
	wimlibExe := filepath.Join(baseDir, "tools", "wimlib-imagex.exe")
	if _, err := os.Stat(wimlibExe); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("wimlib-imagex.exe not found: %s", wimlibExe)
		}
		return fmt.Errorf("stat wimlib-imagex.exe failed: %w", err)
	}

	absOut, err := filepath.Abs(outWim)
	if err != nil {
		return fmt.Errorf("abs outWim failed: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(absOut), 0o755); err != nil {
		return fmt.Errorf("create outWim parent dir failed: %w", err)
	}
	// 覆盖：若已存在则先删除（wimlib-imagex capture 通常期望创建新 WIM）
	if _, err := os.Stat(absOut); err == nil {
		if err := os.Remove(absOut); err != nil {
			return fmt.Errorf("remove existing outWim failed: %w", err)
		}
	} else if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("stat outWim failed: %w", err)
	}

	// 生成 --source-list 文件：每行 "source" "target"
	// target 为 WIM 内路径：/name（根目录下）
	tmp, err := os.CreateTemp("", "wim_sources_*.txt")
	if err != nil {
		return fmt.Errorf("create temp source-list failed: %w", err)
	}
	sourceListPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(sourceListPath)
	}()

	quote := func(s string) string {
		// wimlib 允许用单/双引号包含空格的路径；Windows 路径不包含双引号，直接双引号即可。 :contentReference[oaicite:1]{index=1}
		return `"` + s + `"`
	}
	uniqueName := func(base string, used map[string]int) string {
		// 让输出名称在 WIM 根目录下唯一：foo, foo_2, foo_3...
		// 对文件名尽量保持扩展名：a.txt -> a_2.txt
		if base == "" || base == "." || base == `\` || base == "/" {
			base = "root"
		}
		if used[base] == 0 {
			used[base] = 1
			return base
		}
		used[base]++
		n := used[base]

		ext := filepath.Ext(base)
		stem := strings.TrimSuffix(base, ext)
		if ext != "" && stem != "" {
			return fmt.Sprintf("%s_%d%s", stem, n, ext)
		}
		return fmt.Sprintf("%s_%d", base, n)
	}

	used := map[string]int{}
	for _, p := range sources {
		p = strings.TrimSpace(p)
		if p == "" {
			return fmt.Errorf("sources contains empty path")
		}
		absSrc, err := filepath.Abs(p)
		if err != nil {
			return fmt.Errorf("abs source failed (%q): %w", p, err)
		}
		if _, err := os.Stat(absSrc); err != nil {
			return fmt.Errorf("source not accessible (%s): %w", absSrc, err)
		}

		name := uniqueName(filepath.Base(filepath.Clean(absSrc)), used)
		target := "/" + name

		line := fmt.Sprintf("%s %s\n", quote(absSrc), quote(target))
		if _, err := tmp.WriteString(line); err != nil {
			return fmt.Errorf("write source-list failed: %w", err)
		}
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close source-list failed: %w", err)
	}

	// 多源捕获建议加 --norpfix（文档对 multi-source capture 有明确建议）。 :contentReference[oaicite:2]{index=2}
	// 另外加 --check 生成完整性表（可选，但通常有益）。 :contentReference[oaicite:3]{index=3}
	args := []string{
		"capture",
		sourceListPath,
		absOut,
		"Image",
		"--source-list",
		"--norpfix",
		"--check",
	}

	cmd := exec.Command(wimlibExe, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("wimlib-imagex capture failed: %w\nwimlib: %s\noutput:\n%s", err, wimlibExe, string(out))
	}
	return nil
}

// 用7z解压
func Un7z(archivePath, destDir string) error {
	if strings.TrimSpace(archivePath) == "" || strings.TrimSpace(destDir) == "" {
		return fmt.Errorf("archivePath and destDir must not be empty")
	}

	// 以“当前可执行文件所在目录”为基准定位 tools\7z.exe（避免受工作目录影响）
	selfExe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("os.Executable failed: %w", err)
	}
	baseDir := filepath.Dir(selfExe)
	sevenZipExe := filepath.Join(baseDir, "tools", "7z.exe")

	if _, err := os.Stat(sevenZipExe); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("7z.exe not found: %s", sevenZipExe)
		}
		return fmt.Errorf("stat 7z.exe failed: %w", err)
	}

	absArchive, err := filepath.Abs(archivePath)
	if err != nil {
		return fmt.Errorf("abs archivePath failed: %w", err)
	}
	absDest, err := filepath.Abs(destDir)
	if err != nil {
		return fmt.Errorf("abs destDir failed: %w", err)
	}

	if err := os.MkdirAll(absDest, 0o755); err != nil {
		return fmt.Errorf("create destDir failed: %w", err)
	}

	// 7z 参数：
	// x   : 解压并保留目录结构
	// -y  : 全部回答 Yes
	// -aoa: 覆盖所有已存在文件
	// -oDIR: 输出目录（注意 -o 后面不要有空格；这里用 "-o"+absDest）
	args := []string{"x", absArchive, "-y", "-aoa", "-o" + absDest}

	cmd := exec.Command(sevenZipExe, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("7z extract failed: %w\n7z: %s\noutput:\n%s", err, sevenZipExe, string(out))
	}
	return nil
}

// 打开某个注册表子键，获得一个 可读句柄
// root:根键,如syscall.Handle(HKEY_LOCAL_MACHINE)
// path:子路径,如"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
func RegOpenKey(root syscall.Handle, path string) (syscall.Handle, error) {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var h syscall.Handle
	r0, _, e1 := procRegOpenKeyExW.Call(
		uintptr(root),
		uintptr(unsafe.Pointer(pathPtr)),
		0,
		uintptr(KEY_READ),
		uintptr(unsafe.Pointer(&h)),
	)
	if r0 != 0 {
		if e1 != nil && e1 != syscall.Errno(0) {
			return 0, fmt.Errorf("RegOpenKeyExW(%s) failed: %v (code=%d)", path, e1, r0)
		}
		return 0, fmt.Errorf("RegOpenKeyExW(%s) failed: code=%d", path, r0)
	}
	return h, nil
}

// 关闭一个已经打开的注册表键句柄，释放资源
func RegCloseKey(h syscall.Handle) {
	if h == 0 {
		return
	}
	_, _, _ = procRegCloseKey.Call(uintptr(h))
}

// 从指定键下读取一个 字符串类型的值
// h:已经打开的注册表键句柄。
// name:值名称
func RegGetString(h syscall.Handle, name string) (string, error) {
	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return "", err
	}

	var typ uint32
	var dataLen uint32

	// 第一次调用拿长度
	r0, _, e1 := procRegQueryValueExW.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(namePtr)),
		0,
		uintptr(unsafe.Pointer(&typ)),
		0,
		uintptr(unsafe.Pointer(&dataLen)),
	)
	if r0 != 0 {
		if e1 != nil && e1 != syscall.Errno(0) {
			return "", fmt.Errorf("RegQueryValueExW(%s,len) failed: %v (code=%d)", name, e1, r0)
		}
		return "", fmt.Errorf("RegQueryValueExW(%s,len) failed: code=%d", name, r0)
	}
	if dataLen < 2 {
		return "", nil
	}

	buf := make([]uint16, dataLen/2)
	r0, _, e1 = procRegQueryValueExW.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(namePtr)),
		0,
		uintptr(unsafe.Pointer(&typ)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&dataLen)),
	)
	if r0 != 0 {
		if e1 != nil && e1 != syscall.Errno(0) {
			return "", fmt.Errorf("RegQueryValueExW(%s,data) failed: %v (code=%d)", name, e1, r0)
		}
		return "", fmt.Errorf("RegQueryValueExW(%s,data) failed: code=%d", name, r0)
	}

	// 去掉结尾 0
	n := 0
	for ; n < len(buf) && buf[n] != 0; n++ {
	}
	return syscall.UTF16ToString(buf[:n]), nil
}
