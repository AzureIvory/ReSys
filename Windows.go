package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

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
	root, err := NormalizeDrive(drive, 0)
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

// 判断当前系统是否为 Windows XP（5.1/5.2）。
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

// 清除文件只读属性
func clearReadonly(path string) error {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attrs, err := syscall.GetFileAttributes(p)
	if err != nil {
		return err
	}

	// 已经不是只读，直接返回
	if attrs&syscall.FILE_ATTRIBUTE_READONLY == 0 {
		return nil
	}

	attrs &^= syscall.FILE_ATTRIBUTE_READONLY
	return syscall.SetFileAttributes(p, attrs)
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
