//go:build windows

package utils

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

var (
	volumeKernel32                 = syscall.NewLazyDLL("kernel32.dll")
	procGetVolumePathNameW         = volumeKernel32.NewProc("GetVolumePathNameW")
	procGetVolumeNameForMountPoint = volumeKernel32.NewProc("GetVolumeNameForVolumeMountPointW")
)

// SameVolume 判断两个路径是否落在同一个卷上。
func SameVolume(pathA, pathB string) bool {
	idA := volumeID(pathA)
	idB := volumeID(pathB)
	if idA != "" && idB != "" {
		return strings.EqualFold(idA, idB)
	}

	rootA := volumeRoot(pathA)
	rootB := volumeRoot(pathB)
	return rootA != "" && rootB != "" && strings.EqualFold(rootA, rootB)
}

// NeedsPE 判断目标分区是否就是当前系统卷。
// 这类场景通常不能在线覆盖安装，需要先进入 PE。
func NeedsPE(targetRoot, systemRoot string) bool {
	targetRoot, err := NormalizeDrive(targetRoot, 0)
	if err != nil || targetRoot == "" {
		return false
	}

	systemRoot = strings.TrimSpace(systemRoot)
	if systemRoot == "" {
		systemRoot = os.Getenv("SystemDrive")
	}
	systemRoot, err = NormalizeDrive(systemRoot, 0)
	if err != nil || systemRoot == "" {
		return false
	}

	return SameVolume(targetRoot, systemRoot)
}

func volumeID(path string) string {
	raw := strings.TrimSpace(strings.ReplaceAll(path, "/", `\`))
	if raw == "" {
		return ""
	}

	lower := strings.ToLower(raw)
	if strings.HasPrefix(lower, `\\?\volume{`) {
		return strings.TrimRight(lower, `\`)
	}

	mountPoint, err := getVolumeMountPoint(raw)
	if err == nil && mountPoint != "" {
		guid, err := getVolumeGUID(mountPoint)
		if err == nil && guid != "" {
			return strings.ToLower(strings.TrimRight(guid, `\`))
		}
		return strings.ToLower(strings.TrimRight(mountPoint, `\`))
	}

	return strings.ToUpper(volumeRoot(raw))
}

func volumeRoot(path string) string {
	if root, err := NormalizeDrive(path, 2); err == nil && root != "" {
		return root
	}
	root, _ := NormalizeDrive(path, 0)
	return root
}

func getVolumeMountPoint(path string) (string, error) {
	pPath, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}

	buf := make([]uint16, 1024)
	r1, _, e1 := procGetVolumePathNameW.Call(
		uintptr(unsafe.Pointer(pPath)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if r1 == 0 {
		if e1 != nil && e1 != syscall.Errno(0) {
			return "", fmt.Errorf("GetVolumePathNameW: %w", e1)
		}
		return "", fmt.Errorf("GetVolumePathNameW failed")
	}

	return syscall.UTF16ToString(buf), nil
}

func getVolumeGUID(mountPoint string) (string, error) {
	mountPoint = strings.TrimSpace(strings.ReplaceAll(mountPoint, "/", `\`))
	if mountPoint == "" {
		return "", fmt.Errorf("empty mount point")
	}
	if !strings.HasSuffix(mountPoint, `\`) {
		mountPoint += `\`
	}

	pMount, err := syscall.UTF16PtrFromString(mountPoint)
	if err != nil {
		return "", err
	}

	buf := make([]uint16, 1024)
	r1, _, e1 := procGetVolumeNameForMountPoint.Call(
		uintptr(unsafe.Pointer(pMount)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if r1 == 0 {
		if e1 != nil && e1 != syscall.Errno(0) {
			return "", fmt.Errorf("GetVolumeNameForVolumeMountPointW: %w", e1)
		}
		return "", fmt.Errorf("GetVolumeNameForVolumeMountPointW failed")
	}

	return syscall.UTF16ToString(buf), nil
}
