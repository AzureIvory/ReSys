package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
	"unicode/utf16"
	"unsafe"
)

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

// 尝试把src拷贝到dst。
// overwrite=true：覆盖；false：跳过
// createDir=true：目标目录不存在就创建；false：报错
func Copy(src, dst string, overwrite, createDir bool) error {
	si, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("Copy: src not found: %w", err)
	}

	copyOneFile := func(srcFile, dstFile string, overwrite, createDir bool) error {
		fi, err := os.Stat(srcFile)
		if err != nil {
			return fmt.Errorf("Copy: src not found: %w", err)
		}
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("Copy: src is not a regular file: %s", srcFile)
		}

		// 目标存在
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

		// io.Copy
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
			cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
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

	return copyOneFile(src, dst, overwrite, createDir)
}

// Remove 删除文件/目录。
// recursive=true：递归删除；false：仅删除文件或空目录
func Remove(path string, recursive bool) error {
	if _, err := os.Lstat(path); err != nil {
		return fmt.Errorf("Remove: stat failed: %w", err)
	}

	// os
	if recursive {
		if err := os.RemoveAll(path); err == nil {
			return nil
		}
	} else {
		if err := os.Remove(path); err == nil {
			return nil
		}
	}
	//winapi
	if pW, err := syscall.UTF16PtrFromString(path); err == nil {
		_, _, _ = procSetFileAttrsW.Call(uintptr(unsafe.Pointer(pW)), uintptr(FILE_ATTRIBUTE_NORMAL))
	}
	if recursive {
		// SHFileOperation 需要 double-null terminated 的 pFrom
		from := syscall.StringToUTF16(path)
		from = append(from, 0) // 再补一个 0，形成双 0 结尾

		op := shFileOpStructW{
			wFunc:  FO_DELETE,
			pFrom:  &from[0],
			fFlags: FOF_SILENT | FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_NOCONFIRMMKDIR,
		}
		r, _, _ := procSHFileOperationW.Call(uintptr(unsafe.Pointer(&op)))
		if r == 0 && op.fAnyOperationsAborted == 0 {
			return nil
		}
	} else {
		if pW, err := syscall.UTF16PtrFromString(path); err == nil {
			if rr, _, _ := procDeleteFileW.Call(uintptr(unsafe.Pointer(pW))); rr != 0 {
				return nil
			}
			if rr, _, _ := procRemoveDirectoryW.Call(uintptr(unsafe.Pointer(pW))); rr != 0 {
				return nil
			}
		}
	}

	// cmd.exe
	pQ := `"` + path + `"`
	if recursive {
		if err := exec.Command("cmd.exe", "/C", "rmdir", "/S", "/Q", pQ).Run(); err == nil {
			return nil
		} else {
			return fmt.Errorf("Remove: cmd rmdir failed: %w", err)
		}
	}

	_ = exec.Command("cmd.exe", "/C", "del", "/F", "/Q", pQ).Run()
	if err := exec.Command("cmd.exe", "/C", "rmdir", pQ).Run(); err == nil {
		return nil
	}
	return fmt.Errorf("Remove: failed (os/winapi/cmd): %s", path)
}

// 开启当前进程的关机权限
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

	pfDir := filepath.Join(root, "Program Files")
	_ = dirExists(pfDir)
	pfxDir := filepath.Join(root, "Program Files (x86)")
	syswowDir := filepath.Join(winDir, "SysWOW64")

	hasPFx86 := dirExists(pfxDir)
	hasSysWOW := dirExists(syswowDir)

	softwareHive := filepath.Join(winDir, "System32", "config", "SOFTWARE")
	if _, err := os.Stat(softwareHive); err != nil {
		return "", fmt.Errorf("SOFTWARE hive not found: %w", err)
	}
	systemHive := filepath.Join(winDir, "System32", "config", "SYSTEM")
	hasSystemHive := false
	if _, err := os.Stat(systemHive); err == nil {
		hasSystemHive = true
	}

	if err := RegLoadHive("Offline_SOFTWARE", softwareHive); err != nil {
		return "", fmt.Errorf("load SOFTWARE hive: %w", err)
	}
	defer RegUnloadHive("Offline_SOFTWARE")

	systemLoaded := false
	if hasSystemHive {
		if err := RegLoadHive("Offline_SYSTEM", systemHive); err == nil {
			systemLoaded = true
			defer RegUnloadHive("Offline_SYSTEM")
		}
	}

	// HKLM\Offline_SOFTWARE\Microsoft\Windows NT\CurrentVersion
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
			// 用build号区分 10 / 11
			buildStr, _ := RegGetString(h, "CurrentBuildNumber")
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

// 返回当前系统是否为 Windows XP（5.1/5.2）。
func isWinXP() bool {
	h, err := RegOpenKey(HKEY_LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`)
	if err != nil {
		return false
	}
	defer RegCloseKey(h)

	currentVersion, err := RegGetString(h, "CurrentVersion")
	if err != nil {
		return false
	}
	return currentVersion == "5.1" || currentVersion == "5.2"
}

// 返回 tools 目录下对应系统/架构的 dism.exe 绝对路径。
// tools/xp/dism.exe 或 tools/32/dism.exe 或 tools/64/dism.exe
func GetDism() (string, error) {
	baseDir := ""
	if exe, err := os.Executable(); err == nil {
		baseDir = filepath.Dir(exe)
	}
	if baseDir == "" {
		baseDir = "."
	}

	subDir := "32"
	if isWinXP() {
		subDir = "xp"
	} else if systemArch() == "64" {
		subDir = "64"
	}

	p := filepath.Join(baseDir, "tools", subDir, "dism.exe")
	if st, err := os.Stat(p); err != nil || st.IsDir() {
		if err != nil {
			return "", fmt.Errorf("dism.exe not found: %s: %w", p, err)
		}
		return "", fmt.Errorf("dism.exe not found: %s", p)
	}
	return p, nil
}

// 推测指定盘符的系统架构（32/64）
func detectArch(root string, hasPFx86, hasSysWOW, systemLoaded bool) string {
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

	// 只有Program Files就32位
	if dirExists(filepath.Join(root, "Program Files")) {
		return "x86"
	}
	return "x86"
}

// 返回当前系统架构（32/64）
func systemArch() string {
	arch := strings.ToLower(os.Getenv("PROCESSOR_ARCHITECTURE"))
	wow := strings.ToLower(os.Getenv("PROCESSOR_ARCHITEW6432"))
	if strings.Contains(arch, "64") || strings.Contains(wow, "64") || runtime.GOARCH == "amd64" {
		return "64"
	}
	return "32"
}

// 目录/文件是否存在
func dirExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
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

// normalizeRootPath 统一盘符为类似 "C:\" 的格式。
func normalizeRootPath(root string) string {
	if root == "" {
		return root
	}
	root = strings.ReplaceAll(root, "/", `\`)
	if len(root) == 2 && root[1] == ':' {
		root += `\`
	}
	if len(root) == 1 {
		root += `:\`
	}
	return root
}

// volumeRootFromPath 从路径中提取盘符根（例如 C:\）。
func volumeRootFromPath(p string) string {
	if len(p) >= 3 && p[1] == ':' {
		return strings.ToUpper(p[:1]) + `:\`
	}
	return ""
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

	// 不进入这些目录
	skipDirs := map[string]struct{}{
		"system volume information": {},
		"$recycle.bin":              {},
		"Windows":                   {},
		"Program Files":             {},
		"Program Files (x86)":       {},
		"ProgramData":               {},
		"AppData":                   {},
		"Music":                     {},
		"Pictures":                  {},
		"Videos":                    {},
		"Temp":                      {},
	}

	var matches []string
	var fatalErr error

	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		if fatalErr != nil {
			return
		}
		if depth > maxDepth {
			return
		}

		ents, err := os.ReadDir(dir)
		if err != nil {
			return
		}

		for _, ent := range ents {
			if fatalErr != nil {
				return
			}

			name := ent.Name()
			full := filepath.Join(dir, name)

			if ent.IsDir() {
				if _, ok := skipDirs[strings.ToLower(name)]; ok {
					continue
				}
				if depth < maxDepth {
					walk(full, depth+1)
				}
				continue
			}

			// 通配符匹配
			if ent.Type().IsRegular() {
				for _, pat := range pats {
					ok, err := filepath.Match(pat, name)
					if err != nil {
						fatalErr = fmt.Errorf("bad pattern %q: %w", pat, err)
						return
					}
					if ok {
						matches = append(matches, full)
						break
					}
				}
			}
		}
	}

	walk(root, 0)

	if fatalErr != nil {
		return nil, fatalErr
	}
	return matches, nil
}

// 全盘寻找镜像,跳过小于1g
func Findimg() ([]string, error) {
	drives, err := ListDrive()
	if err != nil {
		return nil, err
	}

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		files    []string
		firstErr error
	)

	patterns := []string{"*.iso", "*.esd", "*.wim"}
	const maxDepth = 2                            // 搜 2 层目录
	const minSize = int64(1) * 1024 * 1024 * 1024 //跳过小于1g

	skipNames := map[string]struct{}{
		"03pe.wim":    {},
		"11pex64.wim": {},
	}
	validateImage := func(imagePath string) bool {
		if _, err := ListImageInfos(imagePath); err != nil {
			return false
		}
		return true
	}
	validateISO := func(isoPath string) bool {
		isoRoot, err := MountISO(isoPath, 30*time.Second)
		if err != nil {
			return false
		}
		found, err := FindFile(isoRoot, "install.wim|install.esd", 3)
		if err != nil || len(found) == 0 {
			return false
		}
		sort.Strings(found)
		for _, candidate := range found {
			fi, err := os.Stat(candidate)
			if err != nil || fi.IsDir() || fi.Size() < minSize {
				continue
			}
			if validateImage(candidate) {
				return true
			}
		}
		return false
	}

	for _, root := range drives {
		root := root
		if GetDriveType(root) == driveCdrom {
			continue
		}
		for _, pattern := range patterns {
			pattern := pattern

			wg.Add(1)
			go func() {
				defer wg.Done()

				found, err := FindFile(root, pattern, maxDepth)
				if err != nil {
					mu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					mu.Unlock()
					return
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
			ext := strings.ToLower(filepath.Ext(p))
			switch ext {
			case ".iso":
				if !validateISO(p) {
					continue
				}
			case ".wim", ".esd":
				if !validateImage(p) {
					continue
				}
			default:
				continue
			}
			seen[lp] = struct{}{}
			dst = append(dst, p)
		}

		files = dst
	}
	//排列
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

	if firstErr != nil && len(files) == 0 {
		return nil, firstErr
	}
	return files, firstErr
}

// 在所有盘符下搜索指定文件
// pattern：文件名，支持通配符，支持*.esd|*.wim|*.iso
// maxDepth：搜索子目录的层数
func FindFileAll(pattern string, maxDepth int) []string {
	drives, err := ListDrive()
	if err != nil || len(drives) == 0 {
		return []string{}
	}

	limit := runtime.NumCPU()
	if limit < 2 {
		limit = 2
	}
	sem := make(chan struct{}, limit)

	var (
		wg  sync.WaitGroup
		mu  sync.Mutex
		out = make([]string, 0, 128)
	)

	for _, d := range drives {
		driveRoot := d
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			files, e := FindFile(driveRoot, pattern, maxDepth)
			if e != nil || len(files) == 0 {
				return
			}

			mu.Lock()
			out = append(out, files...)
			mu.Unlock()
		}()
	}
	wg.Wait()

	// 去重 + 排序
	if len(out) == 0 {
		return []string{}
	}
	seen := make(map[string]struct{}, len(out))
	dedup := make([]string, 0, len(out))
	for _, p := range out {
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		dedup = append(dedup, p)
	}
	sort.Strings(dedup)
	return dedup
}

// 写入重装文件
func writeResFile(imagePath string) error {
	imagePath, _ = filepath.Abs(imagePath)
	imageRoot := volumeRootFromPath(imagePath)
	var diskPath string
	if imageRoot != "" {
		if diskNum, err := GetDiskNum(imageRoot); err == nil {
			diskPath = fmt.Sprintf(`\\.\PhysicalDrive%d`, diskNum)
		}
	}

	systemDrive := os.Getenv("SystemDrive")
	if systemDrive == "" {
		systemDrive = "C:"
	}
	restallPath := normalizeRootPath(systemDrive) + "restall_win.dat"
	content := fmt.Sprintf("disk=%s\nimage=%s\n", diskPath, imagePath)
	if err := os.WriteFile(restallPath, []byte(content), 0o644); err != nil {
		return err
	}

	if diskPath == "" && imageRoot != "" {
		imgDat := filepath.Join(imageRoot, "restall_img.dat")
		_ = os.WriteFile(imgDat, []byte("image="+imagePath+"\n"), 0o644)
	}
	return nil
}

// 从所有盘符读取 restall_win.dat。
// 返回：目标盘符、物理磁盘路径、镜像路径。
func loadResData() (targetRoot string, diskPath string, imagePath string, err error) {
	drives, err := ListDrive()
	if err != nil {
		return "", "", "", err
	}
	for _, root := range drives {
		cand := filepath.Join(root, "restall_win.dat")
		if _, err := os.Stat(cand); err == nil {
			targetRoot = normalizeRootPath(root)
			b, err := os.ReadFile(cand)
			if err != nil {
				return targetRoot, "", "", err
			}
			lines := strings.Split(string(b), "\n")
			for _, ln := range lines {
				ln = strings.TrimSpace(ln)
				if strings.HasPrefix(ln, "disk=") {
					diskPath = strings.TrimSpace(strings.TrimPrefix(ln, "disk="))
				}
				if strings.HasPrefix(ln, "image=") {
					imagePath = strings.TrimSpace(strings.TrimPrefix(ln, "image="))
				}
			}
			return targetRoot, diskPath, imagePath, nil
		}
	}
	return "", "", "", fmt.Errorf("未找到 restall_win.dat")
}

// 根据 restall 信息定位镜像：
func resolveImagePath(diskPath, imagePath string) (string, error) {
	if imagePath != "" {
		if _, err := os.Stat(imagePath); err == nil {
			return imagePath, nil
		}
	}

	base := filepath.Base(imagePath)
	if diskPath != "" {
		_, roots, err := GetDiskPartitions(diskPath)
		if err == nil && len(roots) > 0 {
			for _, root := range roots {
				root = normalizeRootPath(root)
				if root == "" {
					continue
				}
				if imagePath != "" {
					rel := strings.TrimPrefix(imagePath[2:], `\`)
					cand := filepath.Join(root, rel)
					if _, err := os.Stat(cand); err == nil {
						return cand, nil
					}
				}
				if base != "" {
					found, _ := FindFile(root, base, 3)
					if len(found) > 0 {
						return found[0], nil
					}
				}
			}
		}
	}

	roots, _ := ListDrive()
	for _, root := range roots {
		imgDat := filepath.Join(root, "restall_img.dat")
		if _, err := os.Stat(imgDat); err != nil {
			continue
		}
		b, err := os.ReadFile(imgDat)
		if err != nil {
			continue
		}
		for _, ln := range strings.Split(string(b), "\n") {
			ln = strings.TrimSpace(ln)
			if strings.HasPrefix(ln, "image=") {
				cand := strings.TrimSpace(strings.TrimPrefix(ln, "image="))
				if _, err := os.Stat(cand); err == nil {
					return cand, nil
				}
				base = filepath.Base(cand)
				found, _ := FindFile(root, base, 3)
				if len(found) > 0 {
					return found[0], nil
				}
			}
		}
	}
	return "", fmt.Errorf("未找到镜像文件")
}

// 从 WIM/ESD 或 ISO 中读取镜像元数据。
func detectImageInfos(imagePath string) ([]ImageMeta, error) {
	ext := strings.ToLower(filepath.Ext(imagePath))
	if ext != ".iso" {
		return ListImageInfos(imagePath)
	}
	isoRoot, err := MountISO(imagePath, 30*time.Second)
	if err != nil {
		return nil, err
	}
	installPath := filepath.Join(isoRoot, "sources", "install.wim")
	if _, err := os.Stat(installPath); err != nil {
		installPath = filepath.Join(isoRoot, "sources", "install.esd")
	}
	if _, err := os.Stat(installPath); err != nil {
		found, err := FindFile(isoRoot, "install.wim|install.esd", 3)
		if err != nil || len(found) == 0 {
			return nil, fmt.Errorf("ISO中未找到安装镜像")
		}
		sort.Strings(found)
		installPath = found[0]
	}
	return ListImageInfos(installPath)
}

// 按优先级选择镜像索引
func selectInstallIndex(infos []ImageMeta) int {
	if len(infos) == 0 {
		return 1
	}
	preferred := []string{
		"旗舰版", "ultimate",
		"专业工作站", "professional workstation", "pro workstation",
		"专业教育", "professional education", "pro education",
		"专业版", "professional", "pro",
		"家庭版", "home",
		"企业版", "enterprise",
		"教育版", "education",
		"家庭高级版", "home premium",
		"家庭普通版", "home basic",
		"纯净版", "clean",
	}
	best := 0
	for _, key := range preferred {
		for _, info := range infos {
			if !info.IsOS {
				continue
			}
			text := strings.ToLower(info.Name + " " + info.Description + " " + info.Edition + " " + info.Flags)
			if strings.Contains(text, strings.ToLower(key)) {
				best = info.Index
				return best
			}
		}
	}
	return infos[len(infos)-1].Index
}

// 返回有足够大小的分区数组
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

	// 排序
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
		return cs[i].path < cs[j].path
	})

	part := make([]string, 0, len(cs))
	for _, c := range cs {
		part = append(part, c.path)
	}
	logWrite("Findpart: %v", part)
	return part
}

// 进入PE + 扫描模式：scan=true 时只返回最优 WIM/SDI
// 用法示例：
//
//	ok, wim, sdi, err := GoToPE(true)          // 扫描
//	_, _, _, err := GoToPE(false)             // 设置下次启动进PE
//	ok, wim, sdi, err := GoToPE(true, sdiPath, wimPath)   // 扫描/校验自定义
//	_, _, _, err := GoToPE(false, sdiPath, wimPath)       // 自定义设置启动
func GoToPE(scan bool, paths ...string) (bool, string, string, error) {
	var customSdi, customWim string
	if len(paths) == 0 {
	} else if len(paths) == 2 {
		customSdi = strings.TrimSpace(paths[0])
		customWim = strings.TrimSpace(paths[1])
		if customSdi == "" || customWim == "" {
			return false, "", "", fmt.Errorf("自定义路径需要同时指定 sdi 和 wim（要么都传，要么都不传）")
		}
	} else {
		return false, "", "", fmt.Errorf("参数数量错误：GoToPE(scan) 或 GoToPE(scan, sdiPath, wimPath)")
	}

	dvs, err := ListDrive()
	if err != nil {
		return false, "", "", err
	}

	// ======== arch：按“OS 实际架构”来（WOW64 下也要当 64） ========
	wantArch := func() string {
		isWow64 := runtime.GOARCH == "386" && os.Getenv("PROCESSOR_ARCHITEW6432") != ""
		if isWow64 {
			return "64"
		}
		switch runtime.GOARCH {
		case "amd64", "arm64":
			return "64"
		default:
			return "32"
		}
	}()

	normArch := func(a string) string {
		a = strings.ToLower(strings.TrimSpace(a))
		switch a {
		case "64", "x64", "amd64", "arm64":
			return "64"
		case "32", "x86", "386":
			return "32"
		default:
			return a
		}
	}

	// ======== opts 增加架构字段 a（你要求的格式） ========
	opts := []struct {
		n, s, w, a string
	}{
		{"WEPE", `\WEPE\WEPE.SDI`, `\WEPE\WEPE64.WIM`, "64"},    //64位微PE
		{"WEPE", `\WEPE\WEPE.SDI`, `\WEPE\WEPE32.WIM`, "32"},    //32位微PE（如存在）
		{"FIR", `\FirPE\BOOT.SDI`, `\FirPE\11PEX64.WIM`, "64"},  //64位win11的FirPE
		{"FIR", `\FirPE\BOOT.SDI`, `\FirPE\11PEX86.WIM`, "32"},  //32位FirPE（如存在）
		{"HOT", `\HotPE\boot.sdi`, `\HotPE\Boot.wim`, "64"},     //64位HOTPE（一般为64）
		{"FirPE1", `\boot\boot.sdi`, `\boot\11pex64.wim`, "64"}, //64位FirPE1
		{"FirPE1", `\boot\boot.sdi`, `\boot\11pex86.wim`, "32"}, //32位FirPE1（如存在）
		{"PETEMP", `\PETEMP\*.sdi`, `\PETEMP\*.wim`, ""},        //不强制架构，交给 chooseBestWim
		{"PETEMP", `\PETEMP\*.SDI`, `\PETEMP\*.WIM`, ""},
	}

	// ======== 小工具 ========
	hasGlob := func(s string) bool { return strings.ContainsAny(s, "*?[") }
	hasDrivePrefix := func(p string) bool { return len(p) >= 2 && p[1] == ':' }

	fileExists := func(p string) bool {
		fi, e := os.Stat(p)
		return e == nil && !fi.IsDir()
	}

	// 把 abs 变成相对卷根 \xxx\yyy
	toRel := func(root, abs string) string {
		abs = strings.ReplaceAll(abs, "/", `\`)
		root = strings.ReplaceAll(root, "/", `\`)
		if len(abs) >= len(root) && strings.EqualFold(abs[:len(root)], root) {
			rest := abs[len(root):]
			rest = strings.TrimPrefix(rest, `\`)
			return `\` + rest
		}
		if len(abs) >= 3 && abs[1] == ':' && (abs[2] == '\\' || abs[2] == '/') {
			return `\` + strings.TrimPrefix(abs[3:], `\`)
		}
		return abs
	}

	// 返回所有匹配（大小写不敏感 + 支持通配符）
	allMatchesInsensitive := func(pattern string) ([]string, error) {
		pattern = strings.ReplaceAll(pattern, "/", `\`)

		if !hasGlob(pattern) {
			if fileExists(pattern) {
				return []string{pattern}, nil
			}
			return nil, nil
		}

		dir := filepath.Dir(pattern)
		base := filepath.Base(pattern)

		if hasGlob(dir) {
			ms, _ := filepath.Glob(pattern)
			var out []string
			for _, m := range ms {
				if fileExists(m) {
					out = append(out, m)
				}
			}
			return out, nil
		}

		entries, e := os.ReadDir(dir)
		if e != nil {
			ms, _ := filepath.Glob(pattern)
			var out []string
			for _, m := range ms {
				if fileExists(m) {
					out = append(out, m)
				}
			}
			return out, nil
		}

		patLower := strings.ToLower(base)
		var out []string
		for _, ent := range entries {
			if ent.IsDir() {
				continue
			}
			nameLower := strings.ToLower(ent.Name())
			ok, _ := filepath.Match(patLower, nameLower)
			if ok {
				out = append(out, filepath.Join(dir, ent.Name()))
			}
		}
		return out, nil
	}

	firstMatchInsensitive := func(pattern string) (string, bool) {
		ms, _ := allMatchesInsensitive(pattern)
		if len(ms) > 0 {
			return ms[0], true
		}
		return "", false
	}

	// tools\boot.sdi 源文件定位（尽量稳）
	findToolsBootSdi := func() (string, bool) {
		exe, e := os.Executable()
		if e != nil {
			return "", false
		}
		base := filepath.Dir(exe)

		// Windows 一般不区分大小写，但为了稳妥列几个
		cands := []string{
			filepath.Join(base, "tools", "boot.sdi"),
			filepath.Join(base, "tools", "BOOT.SDI"),
			filepath.Join(base, "tools", "Boot.sdi"),
		}
		for _, p := range cands {
			if fileExists(p) {
				return p, true
			}
		}
		return "", false
	}

	// 把 opts.s（可能带通配符）转成一个“具体 SDI 相对路径”
	materializeSdiRel := func(sPat string) string {
		sPat = strings.ReplaceAll(sPat, "/", `\`)
		if sPat == "" {
			return ""
		}
		if !hasGlob(sPat) {
			return sPat
		}
		// \PETEMP\*.sdi -> \PETEMP\boot.sdi
		dir := filepath.Dir(sPat)
		dst := filepath.Join(dir, "boot.sdi")
		if !strings.HasPrefix(dst, `\`) {
			dst = `\` + dst
		}
		return dst
	}

	// 用 tools\boot.sdi 生成目标 SDI（只在缺 SDI 时调用）
	ensureSdiByCopy := func(root string, sPatRel string, wAbs string) (sAbs string, sRel string, copied bool, err error) {
		src, ok := findToolsBootSdi()
		if !ok {
			return "", "", false, fmt.Errorf("缺少SDI，且未找到 %s", `tools\boot.sdi`)
		}

		dstRel := materializeSdiRel(sPatRel)
		if dstRel == "" {
			// 没有可用的 sPat，就落到 WIM 同目录
			dstAbs := filepath.Join(filepath.Dir(wAbs), "boot.sdi")
			if e := Copy(src, dstAbs, false, true); e != nil {
				return "", "", false, e
			}
			return dstAbs, toRel(root, dstAbs), true, nil
		}

		// 拼绝对路径：root + 去掉开头 '\'
		dstAbs := filepath.Join(root, strings.TrimPrefix(dstRel, `\`))
		if e := Copy(src, dstAbs, false, true); e != nil {
			return "", "", false, e
		}
		return dstAbs, toRel(root, dstAbs), true, nil
	}

	// ======== 候选结构 ========
	type peCand struct {
		nm   string
		arch string // opts 的 a
		lt   string // 盘符字母，如 "C"
		root string // 如 "C:\"
		wAbs string
		wRel string
		sAbs string
		sRel string
		sPat string // opts.s（用于缺 SDI 时决定复制到哪里）
	}

	// wimAbs -> best cand（若同一 wim 由不同 opts 命中，优先保留“有 SDI 的那个”）
	candByWim := map[string]peCand{}
	var allWims []string

	addCand := func(c peCand) {
		if old, ok := candByWim[c.wAbs]; ok {
			// 只做最小规则：优先保留“有 SDI”的
			if old.sAbs == "" && c.sAbs != "" {
				candByWim[c.wAbs] = c
			}
			return
		}
		candByWim[c.wAbs] = c
		allWims = append(allWims, c.wAbs)
	}

	// ======== 收集候选（允许缺 SDI） ========
	collect := func() error {
		if customSdi != "" && customWim != "" {
			sPat := strings.ReplaceAll(customSdi, "/", `\`)
			wPat := strings.ReplaceAll(customWim, "/", `\`)

			// 绝对路径
			if hasDrivePrefix(sPat) || hasDrivePrefix(wPat) {
				var vol string
				if hasDrivePrefix(sPat) {
					vol = strings.ToUpper(string(sPat[0]))
				}
				if hasDrivePrefix(wPat) {
					wVol := strings.ToUpper(string(wPat[0]))
					if vol != "" && vol != wVol {
						return fmt.Errorf("sdi 和 wim 不在同一盘：%s vs %s", vol, wVol)
					}
					if vol == "" {
						vol = wVol
					}
				}
				root := vol + `:\`

				// WIM 必须存在
				wAbs, ok := firstMatchInsensitive(wPat)
				if !ok {
					return fmt.Errorf("未找到WIM: %s", wPat)
				}

				// SDI 允许不存在（后面会补）
				sAbs, _ := firstMatchInsensitive(sPat)

				addCand(peCand{
					nm: "CUSTOM", arch: "",
					lt: vol, root: root,
					wAbs: wAbs, wRel: toRel(root, wAbs),
					sAbs: sAbs, sRel: func() string {
						if sAbs == "" {
							return ""
						}
						return toRel(root, sAbs)
					}(),
					sPat: sPat, // 直接用用户给的 sPat，补 SDI 时会 materialize
				})
				return nil
			}

			// 相对路径：遍历盘符
			for _, d := range dvs {
				if len(d) < 3 {
					continue
				}
				vol := strings.ToUpper(string(d[0]))
				root := vol + `:\`

				wAbs, okW := firstMatchInsensitive(d + strings.TrimPrefix(wPat, `\`))
				if !okW {
					continue
				}
				sAbs, _ := firstMatchInsensitive(d + strings.TrimPrefix(sPat, `\`))

				addCand(peCand{
					nm: "CUSTOM", arch: "",
					lt: vol, root: root,
					wAbs: wAbs, wRel: toRel(root, wAbs),
					sAbs: sAbs, sRel: func() string {
						if sAbs == "" {
							return ""
						}
						return toRel(root, sAbs)
					}(),
					sPat: `\` + strings.TrimPrefix(sPat, `\`),
				})
				return nil
			}
			return fmt.Errorf("未找到匹配的SDI/WIM：SDI=%s WIM=%s", sPat, wPat)
		}

		// 自动：按 opts 扫描所有盘符
		for _, o := range opts {
			// opts 声明了架构的话，就先过滤（你要求“需要考虑架构”）
			if o.a != "" && normArch(o.a) != normArch(wantArch) {
				continue
			}

			for _, d := range dvs {
				if len(d) < 3 {
					continue
				}
				vol := strings.ToUpper(string(d[0]))
				root := vol + `:\`

				// SDI 可缺失（只取第一个匹配）
				sAbs := ""
				sMatches, _ := allMatchesInsensitive(d + strings.TrimPrefix(o.s, `\`))
				if len(sMatches) > 0 {
					sAbs = sMatches[0]
				}

				// WIM 收集全部（尤其 PETEMP）
				wMatches, _ := allMatchesInsensitive(d + strings.TrimPrefix(o.w, `\`))
				for _, wAbs := range wMatches {
					c := peCand{
						nm:   o.n,
						arch: o.a,
						lt:   vol,
						root: root,
						wAbs: wAbs,
						wRel: toRel(root, wAbs),
						sAbs: sAbs,
						sRel: "",
						sPat: o.s,
					}
					if sAbs != "" {
						c.sRel = toRel(root, sAbs)
					}
					addCand(c)
				}
			}
		}
		return nil
	}

	if err := collect(); err != nil {
		if scan {
			// 扫描模式：更像 hasPEFiles，尽量不把“找不到”当致命错误
			return false, "", "", err
		}
		return false, "", "", err
	}

	if len(allWims) == 0 {
		if scan {
			return false, "", "", nil
		}
		return false, "", "", fmt.Errorf("未找到PE引导文件")
	}

	// ======== 最终：用 chooseBestWim 在“全部候选 WIM”里选最优 ========
	bestWim := chooseBestWim(allWims, wantArch)
	best, ok := candByWim[bestWim]
	if !ok || bestWim == "" {
		if scan {
			return false, "", "", nil
		}
		return false, "", "", fmt.Errorf("chooseBestWim 选优失败")
	}

	// ======== 缺 SDI：用 tools\boot.sdi 复制补齐 ========
	if best.sAbs == "" {
		sAbs, sRel, _, e := ensureSdiByCopy(best.root, best.sPat, best.wAbs)
		if e == nil {
			best.sAbs = sAbs
			best.sRel = sRel
			candByWim[best.wAbs] = best
		} else {
			// scan 模式允许返回“wim 有、sdi 仍空”（与旧 hasPEFiles 行为兼容）
			if !scan {
				return true, best.wAbs, "", e
			}
		}
	}

	// scan 模式：直接返回最优路径（绝对路径）
	if scan {
		return true, best.wAbs, best.sAbs, nil
	}

	lt, sdi, wim, nm := best.lt, best.sRel, best.wRel, best.nm

	// 执行模式：仍然必须有 SDI（ramdisk 引导要用）
	if best.sRel == "" {
		return true, best.wAbs, best.sAbs, fmt.Errorf("找到WIM但仍缺少SDI，无法设置ramdisk引导：WIM=%s", best.wAbs)
	}

	fmt.Println("PE:", nm, "DRV:", lt, "SDI:", sdi, "WIM:", wim)

	windir := os.Getenv("SystemRoot")
	if windir == "" {
		windir = os.Getenv("WINDIR")
	}
	isWow64 := runtime.GOARCH == "386" && os.Getenv("PROCESSOR_ARCHITEW6432") != ""
	bcdeditPath := filepath.Join(windir, "System32", "bcdedit.exe")
	if isWow64 {
		bcdeditPath = filepath.Join(windir, "Sysnative", "bcdedit.exe")
	}
	out, err := runCmd(bcdeditPath, nil, "")
	if err != nil && (errors.Is(err, os.ErrNotExist) || errors.Is(err, exec.ErrNotFound)) {
		exe, e := os.Executable()
		if e == nil {
			bcdeditPath = filepath.Join(filepath.Dir(exe), "tools", "bcdedit.exe")
		}
	}

	// /device guid
	out, err = runCmd(bcdeditPath, nil, "", "/create", "/d", "pe", "/device")
	if err != nil {
		return false, "", "", err
	}
	re := regexp.MustCompile(`(?i)\{([a-f0-9-]+)\}`)
	m1 := re.FindStringSubmatch(out)
	if len(m1) < 2 {
		return false, "", "", fmt.Errorf("guid1解析失败: %s", out)
	}
	gd1 := strings.ToLower(m1[1])

	// ramdisksdi*
	_, err = runCmd(bcdeditPath, nil, "", "/set", "{"+gd1+"}", "ramdisksdidevice", "partition="+lt+":")
	if err != nil {
		return false, "", "", err
	}
	_, err = runCmd(bcdeditPath, nil, "", "/set", "{"+gd1+"}", "ramdisksdipath", sdi)
	if err != nil {
		return false, "", "", err
	}

	// /application osloader guid2
	out, err = runCmd(bcdeditPath, nil, "", "/create", "/d", "pe", "/application", "osloader")
	if err != nil {
		return false, "", "", err
	}
	m2 := re.FindStringSubmatch(out)
	if len(m2) < 2 {
		return false, "", "", fmt.Errorf("guid2解析失败: %s", out)
	}
	gd2 := strings.ToLower(m2[1])

	// device/osdevice
	dev := fmt.Sprintf("ramdisk=[%s:]%s,{%s}", lt, wim, gd1)
	_, err = runCmd(bcdeditPath, nil, "", "/set", "{"+gd2+"}", "device", dev)
	if err != nil {
		return false, "", "", err
	}
	_, err = runCmd(bcdeditPath, nil, "", "/set", "{"+gd2+"}", "osdevice", dev)
	if err != nil {
		return false, "", "", err
	}

	// BIOS/UEFI
	fw := 0
	windir = os.Getenv("SystemRoot")
	if windir == "" {
		windir = os.Getenv("WINDIR")
	}
	isWow64 = runtime.GOARCH == "386" && os.Getenv("PROCESSOR_ARCHITEW6432") != ""
	regPath := filepath.Join(windir, "System32", "reg.exe")
	if isWow64 {
		regPath = filepath.Join(windir, "Sysnative", "reg.exe")
	}
	out, er2 := runCmd(regPath, nil, "", "query", `HKLM\SYSTEM\CurrentControlSet\Control`, "/v", "PEFirmwareType")
	if err != nil && (errors.Is(err, os.ErrNotExist) || errors.Is(err, exec.ErrNotFound)) {
		if exe, e := os.Executable(); e == nil {
			out, err = runCmd(filepath.Join(filepath.Dir(exe), "tools", "reg"), nil, "", "query",
				`HKLM\SYSTEM\CurrentControlSet\Control`, "/v", "PEFirmwareType")
		}
	}
	if er2 == nil {
		r2 := regexp.MustCompile(`(?i)0x([0-9a-f]+)`)
		m3 := r2.FindStringSubmatch(out)
		if len(m3) >= 2 {
			if v, e3 := strconv.ParseInt(m3[1], 16, 32); e3 == nil {
				fw = int(v) // 1=BIOS 2=UEFI
			}
		}
	}

	p1 := `\windows\system32\boot\winload.efi`
	p2 := `\windows\system32\boot\winload.exe`
	if fw == 1 {
		p1, p2 = p2, p1
	}
	if _, err = runCmd(bcdeditPath, nil, "", "/set", "{"+gd2+"}", "path", p1); err != nil {
		if _, err = runCmd(bcdeditPath, nil, "", "/set", "{"+gd2+"}", "path", p2); err != nil {
			return false, "", "", err
		}
	}

	if _, err = runCmd(bcdeditPath, nil, "", "/set", "{"+gd2+"}", "systemroot", `\windows`); err != nil {
		return false, "", "", err
	}
	if _, err = runCmd(bcdeditPath, nil, "", "/set", "{"+gd2+"}", "detecthal", "YES"); err != nil {
		return false, "", "", err
	}
	if _, err = runCmd(bcdeditPath, nil, "", "/set", "{"+gd2+"}", "winpe", "YES"); err != nil {
		return false, "", "", err
	}
	if _, err = runCmd(bcdeditPath, nil, "", "/set", "{"+gd2+"}", "nx", "OptIn"); err != nil {
		return false, "", "", err
	}

	// 设置下次启动
	if _, err = runCmd(bcdeditPath, nil, "", "/bootsequence", "{"+gd2+"}"); err != nil {
		return false, "", "", err
	}
	return false, "", "", nil
}

// 修改wim文件，将自身及对应文件写入到wim中，并修改ini
func Patwim(wim string) error {
	if wim == "" {
		return fmt.Errorf("wim为空")
	}
	wimAbs, err := filepath.Abs(wim)
	if err != nil {
		return err
	}
	wim = wimAbs

	// 自身程序
	selfExe, err := os.Executable()
	if err != nil {
		return err
	}
	selfExe, _ = filepath.Abs(selfExe)
	selfName := filepath.Base(selfExe)

	dir := filepath.Dir(selfExe)

	resolveTool := func(name, fallback string) string {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
		if fallback != "" {
			if st, err := os.Stat(fallback); err == nil && !st.IsDir() {
				return fallback
			}
		}
		return ""
	}

	runWithTimeout := func(exe string, args []string, to time.Duration) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), to)
		defer cancel()
		cmd := exec.CommandContext(ctx, exe, args...)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		var buf bytes.Buffer
		cmd.Stdout = &buf
		cmd.Stderr = &buf
		err := cmd.Run()
		out := buf.String()
		if ctx.Err() == context.DeadlineExceeded {
			return out, fmt.Errorf("超时: %s %s", exe, strings.Join(args, " "))
		}
		return out, err
	}

	//把多条命令从 stdin 喂进去
	runUpdateWithStdin := func(exe string, args []string, stdinText string, to time.Duration) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), to)
		defer cancel()
		cmd := exec.CommandContext(ctx, exe, args...)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		cmd.Stdin = strings.NewReader(stdinText)
		var buf bytes.Buffer
		cmd.Stdout = &buf
		cmd.Stderr = &buf
		err := cmd.Run()
		out := buf.String()
		if ctx.Err() == context.DeadlineExceeded {
			return out, fmt.Errorf("超时: %s %s", exe, strings.Join(args, " "))
		}
		return out, err
	}

	qCmdArg := func(s string) string {
		if !strings.ContainsAny(s, " \t") && !strings.Contains(s, `"`) {
			return s
		}
		return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
	}

	// 插入启动项
	appendExecLine := func(b []byte, line string) ([]byte, error) {
		pickNLBytes := func(src []byte) []byte {
			if bytes.Contains(src, []byte("\r\n")) {
				return []byte("\r\n")
			}
			if bytes.Contains(src, []byte("\n")) {
				return []byte("\n")
			}
			return []byte("\r\n")
		}

		lowerASCII := func(c byte) byte {
			if c >= 'A' && c <= 'Z' {
				return c + 32
			}
			return c
		}
		isSpace := func(c byte) bool { return c == ' ' || c == '\t' }

		findEndfileLineStartBytes := func(src []byte) (int, bool) {
			i := 0
			for i < len(src) {
				lineStart := i
				j := bytes.IndexByte(src[i:], '\n')
				if j == -1 {
					i = len(src)
				} else {
					i += j + 1
				}
				lineBytes := src[lineStart:i]
				trimmed := bytes.TrimRight(lineBytes, "\r\n")
				trimmed = bytes.TrimLeft(trimmed, " \t")
				if len(trimmed) < len("_ENDFILE") {
					continue
				}
				ok := true
				for k := 0; k < len("_ENDFILE"); k++ {
					if lowerASCII(trimmed[k]) != lowerASCII("_ENDFILE"[k]) {
						ok = false
						break
					}
				}
				if !ok {
					continue
				}
				if len(trimmed) == len("_ENDFILE") {
					return lineStart, true
				}
				c := trimmed[len("_ENDFILE")]
				if isSpace(c) || c == '/' || c == ';' {
					return lineStart, true
				}
			}
			return 0, false
		}

		containsFoldASCII := func(hay, needle []byte) bool {
			if len(needle) == 0 {
				return true
			}
			for i := 0; i+len(needle) <= len(hay); i++ {
				ok := true
				for j := 0; j < len(needle); j++ {
					if lowerASCII(hay[i+j]) != lowerASCII(needle[j]) {
						ok = false
						break
					}
				}
				if ok {
					return true
				}
			}
			return false
		}

		applyOnBytes := func(src []byte) []byte {
			nl := pickNLBytes(src)
			insertPos := len(src)
			if p, ok := findEndfileLineStartBytes(src); ok {
				insertPos = p
			}
			head := src[:insertPos]
			tail := src[insertPos:]

			if containsFoldASCII(head, []byte(line)) {
				return src
			}

			out := make([]byte, 0, len(src)+len(line)+len(nl)+4)
			out = append(out, head...)
			if len(out) > 0 && out[len(out)-1] != '\n' {
				out = append(out, nl...)
			}
			out = append(out, []byte(line)...)
			out = append(out, nl...)
			out = append(out, tail...)
			return out
		}

		// UTF-16LE BOM：FF FE
		if len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE {
			raw := b[2:]
			if len(raw)%2 != 0 {
				raw = raw[:len(raw)-1]
			}

			u := make([]uint16, len(raw)/2)
			for i := 0; i < len(u); i++ {
				u[i] = binary.LittleEndian.Uint16(raw[i*2 : i*2+2])
			}
			s := string(utf16.Decode(u))

			nl := "\r\n"
			if strings.Contains(s, "\n") && !strings.Contains(s, "\r\n") {
				nl = "\n"
			}

			reEnd := regexp.MustCompile(`(?im)^[ \t]*_endfile\b.*(?:\r?\n|$)`)
			loc := reEnd.FindStringIndex(s)

			head := s
			tail := ""
			if loc != nil {
				head = s[:loc[0]]
				tail = s[loc[0]:]
			}

			if strings.Contains(strings.ToLower(head), strings.ToLower(line)) {
				return b, nil
			}

			if head != "" && !strings.HasSuffix(head, "\n") {
				head += nl
			}
			head += line + nl
			s2 := head + tail

			u2 := utf16.Encode([]rune(s2))
			o := make([]byte, 2+len(u2)*2)
			o[0], o[1] = 0xFF, 0xFE
			for i, v := range u2 {
				binary.LittleEndian.PutUint16(o[2+i*2:2+i*2+2], v)
			}
			return o, nil
		}

		return applyOnBytes(b), nil
	}

	wimlib := resolveTool("wimlib-imagex.exe", filepath.Join(dir, "tools", "wimlib-imagex.exe"))
	if wimlib == "" {
		return fmt.Errorf("找不到 wimlib-imagex.exe（PATH 或 %s）", filepath.Join(dir, "tools", "wimlib-imagex.exe"))
	}

	type wimRes struct {
		src   string
		dst   string
		isDir bool
	}
	resList := []wimRes{
		{src: selfExe, dst: `\Windows\` + selfName, isDir: false},
		{src: filepath.Join(dir, "Windows.json"), dst: `\Windows\Windows.json`, isDir: false},
		{src: filepath.Join(dir, "WinPE.json"), dst: `\Windows\WinPE.json`, isDir: false},
		{src: filepath.Join(dir, "disk.dll"), dst: `\Windows\disk.dll`, isDir: false},
		{src: filepath.Join(dir, "trackers.txt"), dst: `\Windows\trackers.txt`, isDir: false},
		{src: filepath.Join(dir, "tools"), dst: `\Windows\tools`, isDir: true},
	}

	// 资源存在性检查
	keep := make([]wimRes, 0, len(resList))
	for _, r := range resList {
		st, e := os.Stat(r.src)
		if e != nil {
			fmt.Fprintf(os.Stderr, "WARN: 跳过缺少资源: %s (%v)\n", r.src, e)
			continue
		}
		if r.isDir && !st.IsDir() {
			fmt.Fprintf(os.Stderr, "WARN: 跳过资源(应为目录但不是): %s\n", r.src)
			continue
		}
		if !r.isDir && st.IsDir() {
			fmt.Fprintf(os.Stderr, "WARN: 跳过资源(应为文件但却是目录): %s\n", r.src)
			continue
		}
		keep = append(keep, r)
	}
	resList = keep

	wimBase := func(p string) string {
		p = strings.TrimRight(p, `\/`)
		if i := strings.LastIndexAny(p, `\/`); i >= 0 {
			return p[i+1:]
		}
		return p
	}
	wimDir := func(p string) string {
		p = strings.TrimRight(p, `\/`)
		if i := strings.LastIndexAny(p, `\/`); i >= 0 {
			return p[:i]
		}
		return ""
	}
	wimJoin := func(a, b string) string {
		if a == "" {
			return `\` + b
		}
		if strings.HasSuffix(a, `\`) || strings.HasSuffix(a, `/`) {
			return a + b
		}
		return a + `\` + b
	}

	//获取 Index：info 文本 -> info --xml -> 默认 1
	getIdxs := func() ([]int, error) {
		out, err := runWithTimeout(wimlib, []string{"info", wim}, 2*time.Minute)
		if err != nil {
			return nil, fmt.Errorf("wimlib info失败: %w\n%s", err, out)
		}

		reIdx := regexp.MustCompile(`(?m)^\s*Image\s+(\d+)\s*:`)
		ms := reIdx.FindAllStringSubmatch(out, -1)

		seen := map[int]bool{}
		idxs := make([]int, 0, len(ms))
		for _, m := range ms {
			i, _ := strconv.Atoi(m[1])
			if i > 0 && !seen[i] {
				seen[i] = true
				idxs = append(idxs, i)
			}
		}
		if len(idxs) > 0 {
			return idxs, nil
		}

		xout, xerr := runWithTimeout(wimlib, []string{"info", wim, "--xml"}, 2*time.Minute)
		if xerr == nil && len(xout) > 0 {
			b := []byte(xout)
			if len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE {
				raw := b[2:]
				if len(raw)%2 != 0 {
					raw = raw[:len(raw)-1]
				}
				u := make([]uint16, len(raw)/2)
				for i := range u {
					u[i] = binary.LittleEndian.Uint16(raw[i*2 : i*2+2])
				}
				s := string(utf16.Decode(u))

				reXML := regexp.MustCompile(`(?i)<\s*image\b[^>]*\bindex\s*=\s*"(\d+)"`)
				ms2 := reXML.FindAllStringSubmatch(s, -1)

				seen2 := map[int]bool{}
				idxs2 := make([]int, 0, len(ms2))
				for _, m := range ms2 {
					i, _ := strconv.Atoi(m[1])
					if i > 0 && !seen2[i] {
						seen2[i] = true
						idxs2 = append(idxs2, i)
					}
				}
				if len(idxs2) > 0 {
					return idxs2, nil
				}
			} else {
				s := xout
				reXML := regexp.MustCompile(`(?i)<\s*image\b[^>]*\bindex\s*=\s*"(\d+)"`)
				ms2 := reXML.FindAllStringSubmatch(s, -1)

				seen2 := map[int]bool{}
				idxs2 := make([]int, 0, len(ms2))
				for _, m := range ms2 {
					i, _ := strconv.Atoi(m[1])
					if i > 0 && !seen2[i] {
						seen2[i] = true
						idxs2 = append(idxs2, i)
					}
				}
				if len(idxs2) > 0 {
					return idxs2, nil
				}
			}
		}

		return []int{1}, nil
	}

	idxs, err := getIdxs()
	if err != nil {
		return err
	}

	// 启动项
	line := "EXEC %WinDir%\\" + selfName

	for _, idx := range idxs {
		// 列出 \Windows 下的文件
		dout, de := runWithTimeout(wimlib, []string{"dir", wim, strconv.Itoa(idx), `--path=\Windows`}, 2*time.Minute)
		if de != nil {
			return fmt.Errorf("dir失败 idx=%d: %v\n%s", idx, de, dout)
		}

		actual := map[string]string{}
		pecmdActual := ""
		for _, ln := range strings.Split(dout, "\n") {
			f := strings.Fields(strings.TrimSpace(ln))
			if len(f) == 0 {
				continue
			}
			nm := strings.TrimRight(f[len(f)-1], `\/`)
			lm := strings.ToLower(nm)
			if _, ok := actual[lm]; !ok {
				actual[lm] = nm
			}
			if lm == "pecmd.ini" {
				pecmdActual = nm
			}
		}

		// 生成 update 命令脚本
		cmdLines := make([]string, 0, len(resList)*2)
		for _, r := range resList {
			baseLower := strings.ToLower(wimBase(r.dst))
			delPath := r.dst
			if act, ok := actual[baseLower]; ok && act != "" {
				delPath = wimJoin(wimDir(r.dst), act)
			}
			if r.isDir {
				cmdLines = append(cmdLines, "delete --recursive --force "+qCmdArg(delPath))
			} else {
				cmdLines = append(cmdLines, "delete --force "+qCmdArg(delPath))
			}

			cmdLines = append(cmdLines, "add "+qCmdArg(r.src)+" "+qCmdArg(r.dst))
		}
		script := strings.Join(cmdLines, "\n") + "\n"

		uout, ue := runUpdateWithStdin(
			wimlib,
			[]string{"update", wim, strconv.Itoa(idx)},
			script,
			10*time.Minute,
		)
		if ue != nil {
			return fmt.Errorf("写入资源失败 idx=%d: %v\n%s", idx, ue, uout)
		}

		// Pecmd.ini 文件名
		iniName := pecmdActual
		if iniName == "" {
			iniName = "Pecmd.ini"
		}

		// 抽取 Pecmd.ini
		tmp, _ := os.MkdirTemp("", "wim_")
		_, _ = runWithTimeout(wimlib,
			[]string{"extract", wim, strconv.Itoa(idx), `\Windows\` + iniName, "--dest-dir=" + tmp},
			5*time.Minute,
		)

		p1 := filepath.Join(tmp, "Windows", iniName)
		p2 := filepath.Join(tmp, iniName)
		inip := p1
		if _, e1 := os.Stat(p1); e1 != nil {
			inip = p2
		}
		if _, e2 := os.Stat(inip); e2 != nil {
			_ = os.MkdirAll(filepath.Dir(p1), 0o755)
			inip = p1
			_ = os.WriteFile(inip, []byte{}, 0o644)
		}

		b, _ := os.ReadFile(inip)
		updated, err := appendExecLine(b, line)
		if err != nil {
			_ = os.RemoveAll(tmp)
			return fmt.Errorf("修改ini失败 idx=%d: %w", idx, err)
		}
		if err := os.WriteFile(inip, updated, 0o644); err != nil {
			_ = os.RemoveAll(tmp)
			return fmt.Errorf("写入ini失败 idx=%d: %w", idx, err)
		}

		// 写回 Pecmd.ini
		iniDst := `\Windows\` + iniName
		iniScript := strings.Join([]string{
			"delete --force " + qCmdArg(iniDst),
			"add " + qCmdArg(inip) + " " + qCmdArg(iniDst),
		}, "\n") + "\n"

		iout, ie := runUpdateWithStdin(
			wimlib,
			[]string{"update", wim, strconv.Itoa(idx)},
			iniScript,
			10*time.Minute,
		)
		_ = os.RemoveAll(tmp)
		if ie != nil {
			return fmt.Errorf("写ini失败 idx=%d: %v\n%s", idx, ie, iout)
		}
	}

	return nil
}

// 从指定的文件中，按偏移区间 [start, end) 抽取数据，写入到指定的文件中。
// 支持十进制和十六进制的偏移参数
func PeelFile(exePath, start, end, out string) error {
	if exePath == "" {
		return errors.New("exePath 不能为空")
	}
	if out == "" {
		return errors.New("out 不能为空")
	}

	startOffset, err := parseOffsetString(start)
	if err != nil {
		return fmt.Errorf("解析 startOffset 失败: %w", err)
	}
	endOffset, err := parseOffsetString(end)
	if err != nil {
		return fmt.Errorf("解析 endOffset 失败: %w", err)
	}

	if startOffset < 0 || endOffset < 0 {
		return errors.New("startOffset/endOffset 不能为负数")
	}
	if endOffset <= startOffset {
		return fmt.Errorf("endOffset 必须大于 startOffset（区间为 [start,end)），当前 start=%d end=%d", startOffset, endOffset)
	}

	// 输入文件
	in, err := os.Open(exePath)
	if err != nil {
		return fmt.Errorf("打开输入文件失败: %w", err)
	}
	defer in.Close()

	st, err := in.Stat()
	if err != nil {
		return fmt.Errorf("获取输入文件信息失败: %w", err)
	}
	size := st.Size()
	if startOffset >= size {
		return fmt.Errorf("startOffset 超出文件大小: start=%d size=%d", startOffset, size)
	}
	if endOffset > size {
		return fmt.Errorf("endOffset 超出文件大小: end=%d size=%d", endOffset, size)
	}

	if !filepath.IsAbs(out) {
		return fmt.Errorf("out 必须是绝对路径: %s", out)
	}

	outDir := filepath.Dir(out)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("创建输出目录失败: %w", err)
	}

	// 输出文件
	out1, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("创建输出文件失败: %w", err)
	}
	defer func() { _ = out1.Close() }()

	// 只读取指定区间
	length := endOffset - startOffset
	section := io.NewSectionReader(in, startOffset, length)

	// 拷贝
	buf := make([]byte, 1024*1024) // 1MB buffer
	written, err := io.CopyBuffer(out1, section, buf)
	if err != nil {
		return fmt.Errorf("写出失败: %w", err)
	}
	if written != length {
		return fmt.Errorf("写出字节数不一致: expect=%d got=%d", length, written)
	}

	if err := out1.Sync(); err != nil {
		return fmt.Errorf("输出文件 Sync 失败: %w", err)
	}
	return nil
}

// 解析偏移字符串：
func parseOffsetString(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("偏移字符串为空")
	}

	// 处理符号
	if strings.HasPrefix(s, "-") {
		return 0, fmt.Errorf("不允许负数偏移: %s", s)
	}
	s = strings.TrimPrefix(s, "+")

	// 判定进制
	base := 10
	ss := strings.ToLower(s)

	if strings.HasPrefix(ss, "0x") {
		base = 16
		ss = ss[2:]
		if ss == "" {
			return 0, fmt.Errorf("无效十六进制偏移: %s", s)
		}
	} else {
		// 不带 0x：如果包含 a-f，则认为是十六进制；否则十进制
		for _, r := range ss {
			if unicode.IsLetter(r) {
				base = 16
				break
			}
		}
	}

	// 用 uint64 解析
	u, err := strconv.ParseUint(ss, base, 64)
	if err != nil {
		return 0, fmt.Errorf("无法解析偏移 %q (base=%d): %w", s, base, err)
	}
	maxInt64u := ^uint64(0) >> 1 // 0x7FFF... = MaxInt64
	if u > maxInt64u {
		return 0, fmt.Errorf("偏移过大，超出 int64 范围: %d", u)
	}
	return int64(u), nil
}

// 加载离线注册表 hive
// subKey：挂载点名称，如"OFFLINE_SYSTEM"
// file:注册表 hive 文件的 完整路径
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

	n := 0
	for ; n < len(buf) && buf[n] != 0; n++ {
	}
	return syscall.UTF16ToString(buf[:n]), nil
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

const (
	// 你说镜像 <6G，而 Findpart 返回 >7G 的可用分区，所以这里用 7GiB 作为“下载最小安全空间”
	minImageBytes uint64 = 7 * 1024 * 1024 * 1024

	// 临时分区卷标，保持与你现有 PE 逻辑一致（你原来是 "TEMP"）
	tempLabel = "TEMP"

	// 标记文件：用于 PE 里识别“这是我们创建的临时分区”，避免误删
	tempMarkerRel = `RESTALL\temp.marker`
)

// 清理指定分区
func ClearPartition(letter string) error {
	// TODO: your implementation
	return nil
}

// 优先：用“连续未分配空间”创建 TEMP 分区；失败再最后 SplitVolume(C)
// needBytes：你想保证 TEMP 至少能放下的空间（建议=镜像大小+余量）
func ensureTempVolumeForBytes(needBytes uint64) (string, error) {
	// 给点余量
	const extra uint64 = 512 * 1024 * 1024
	if needBytes < minImageBytes {
		needBytes = minImageBytes
	}
	needBytes += extra

	// 1) 先用未分配空间（全盘扫描，支持“另一块盘全未分配”的情况）
	extent, err := PickFreeExtent(needBytes, ExtentPickPolicy{
		PreferNonSystemDisk:   true,
		PreferLargestExtent:   true,
	})
	if err == nil && extent.SizeBytes >= needBytes {
		letter, err2 := CreatePartitionFromFreeExtent(extent, needBytes, "ntfs", tempLabel)
		if err2 == nil {
			root := normalizeRootPath(letter) // 你项目里已有
			if root != "" {
				// 写 marker
				marker := filepath.Join(root, tempMarkerRel)
				_ = os.MkdirAll(filepath.Dir(marker), 0o755)
				_ = os.WriteFile(marker, []byte(time.Now().Format(time.RFC3339)), 0o644)
				logWrite("已使用未分配空间创建 TEMP 分区：%s", root)
				return root, nil
			}
		} else {
			logWrite("CreatePartitionFromFreeExtent失败：%v", err2)
		}
	} else {
		if err != nil {
			logWrite("PickFreeExtent未找到足够大的未分配段：%v", err)
		}
	}

	// 2) 最后兜底：拆分系统盘
	// 尝试先清理一下，增加 shrink 成功率
	_ = ClearPartition("C")

	sizeMB64 := (needBytes + 1024*1024 - 1) / (1024 * 1024)
	sizeMB := int(sizeMB64)
	if sizeMB < 1024 {
		sizeMB = 1024
	}

	newVol, err := SplitVolume("C", sizeMB, "ntfs", tempLabel)
	if err != nil {
		return "", err
	}
	root := normalizeRootPath(newVol)
	if root == "" {
		return "", fmt.Errorf("SplitVolume成功但未解析到新分区盘符: %v", newVol)
	}

	// 写 marker
	marker := filepath.Join(root, tempMarkerRel)
	_ = os.MkdirAll(filepath.Dir(marker), 0o755)
	_ = os.WriteFile(marker, []byte(time.Now().Format(time.RFC3339)), 0o644)

	logWrite("已通过拆分C盘创建 TEMP 分区：%s", root)
	return root, nil
}

// PE 里用：扫描所有盘符找 marker，返回临时分区根路径（例如 "T:\\"）
func findTempRootByMarker() string {
	drives, _ := ListDrive()
	for _, d := range drives {
		root := normalizeRootPath(d)
		if root == "" {
			continue
		}
		if strings.HasPrefix(strings.ToUpper(root), "X:") {
			continue
		}
		marker := filepath.Join(root, tempMarkerRel)
		if st, err := os.Stat(marker); err == nil && !st.IsDir() {
			return root
		}
	}
	return ""
}