package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"

	"github.com/kdomanski/iso9660/util"
)

var (
	modShell32                  = syscall.NewLazyDLL("shell32.dll")
	procShellExecuteW           = modShell32.NewProc("ShellExecuteW")
	modKernel32                 = syscall.NewLazyDLL("kernel32.dll")
	procGetLogicalDriveStringsW = modKernel32.NewProc("GetLogicalDriveStringsW")
	procGetDriveTypeW           = modKernel32.NewProc("GetDriveTypeW")
)

const (
	driveUnknown = 0
	driveNoRoot  = 1
	driveRemov   = 2
	driveFixed   = 3
	driveRemote  = 4
	driveCdrom   = 5
	driveRamdisk = 6
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

func main() {
	fmt.Println(ListCD())
}
