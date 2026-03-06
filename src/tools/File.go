package tools

import (

	"ReSys/src/registry"
	"ReSys/src/utils"
	"debug/pe"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"bytes"
	"unsafe"


	"golang.org/x/text/encoding/simplifiedchinese"

	"ReSys/src/log"
)
var(
//文件操作相关
	modKernel32           = syscall.NewLazyDLL("kernel32.dll")
	modShell32            = syscall.NewLazyDLL("shell32.dll")
	procShellExecuteW     = modShell32.NewProc("ShellExecuteW")
	procCopyFileW         = modKernel32.NewProc("CopyFileW")
	procDeleteFileW       = modKernel32.NewProc("DeleteFileW")
	procRemoveDirectoryW  = modKernel32.NewProc("RemoveDirectoryW")
	procSetFileAttributes = modKernel32.NewProc("SetFileAttributesW")
	procFindFirstFileW    = modKernel32.NewProc("FindFirstFileW")
	procFindNextFileW     = modKernel32.NewProc("FindNextFileW")
	procFindClose         = modKernel32.NewProc("FindClose")
	procSetFileAttrsW     = modKernel32.NewProc("SetFileAttributesW")
	procSHFileOperationW  = modShell32.NewProc("SHFileOperationW")
)
const(
	FILE_ATTRIBUTE_NORMAL = 0x00000080
	FO_DELETE             = 0x0003
	FOF_SILENT            = 0x0004
	FOF_NOCONFIRMATION    = 0x0010
	FOF_NOERRORUI         = 0x0400
	FOF_NOCONFIRMMKDIR    = 0x0200
)
// SHFILEOPSTRUCTW 结构体（文件操作）
type shFileOpStructW struct {
	hwnd                  uintptr
	wFunc                 uint32
	pFrom                 *uint16
	pTo                   *uint16
	fFlags                uint16
	fAnyOperationsAborted int32
	hNameMappings         uintptr
	lpszProgressTitle     *uint16
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

// 清除文件只读属性
func ClearReadonly(path string) error {
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