//go:build windows

package tools

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	tokenQuery     = 0x0008
	tokenElevation = 20
	swShowNormal   = 1
)

type tokenElevationInfo struct {
	TokenIsElevated uint32
}

var (
	Shell32                 = windows.NewLazySystemDLL("shell32.dll")
	procGetCurrentProcess   = Shell32.NewProc("GetCurrentProcess")
	procCloseHandle         = Shell32.NewProc("CloseHandle")
	procGetTokenInformation = Shell32.NewProc("GetTokenInformation")
)

// 是否是管理员权限运行
func IsAdmin() bool {
	hProc, _, _ := procGetCurrentProcess.Call()

	var token windows.Handle
	r1, _, _ := procOpenProcessToken.Call(
		hProc,
		uintptr(tokenQuery),
		uintptr(unsafe.Pointer(&token)),
	)
	if r1 == 0 {
		return false
	}
	defer procCloseHandle.Call(uintptr(token))

	var elev tokenElevationInfo
	var outLen uint32

	r1, _, _ = procGetTokenInformation.Call(
		uintptr(token),
		uintptr(tokenElevation),
		uintptr(unsafe.Pointer(&elev)),
		unsafe.Sizeof(elev),
		uintptr(unsafe.Pointer(&outLen)),
	)

	return r1 != 0 && elev.TokenIsElevated != 0
}

// 尝试重新以管理员权限运行
func RestartAsAdmin() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}

	exePtr, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return err
	}

	verbPtr, err := windows.UTF16PtrFromString("runas")
	if err != nil {
		return err
	}

	var argsPtr *uint16
	if args := joinArgs(os.Args[1:]); args != "" {
		argsPtr, err = windows.UTF16PtrFromString(args)
		if err != nil {
			return err
		}
	}

	var cwdPtr *uint16
	if cwd, err := os.Getwd(); err == nil && cwd != "" {
		cwdPtr, err = windows.UTF16PtrFromString(cwd)
		if err != nil {
			return err
		}
	}

	r1, _, _ := procShellExecuteW.Call(
		0,
		ptr(verbPtr),
		ptr(exePtr),
		ptr(argsPtr),
		ptr(cwdPtr),
		uintptr(swShowNormal),
	)

	if r1 <= 32 {
		return fmt.Errorf("elevation failed, ShellExecuteW code=%d", r1)
	}

	os.Exit(0)
	return nil
}

func joinArgs(args []string) string {
	if len(args) == 0 {
		return ""
	}
	escaped := make([]string, len(args))
	for i, s := range args {
		escaped[i] = syscall.EscapeArg(s)
	}
	return strings.Join(escaped, " ")
}

func ptr(p *uint16) uintptr {
	if p == nil {
		return 0
	}
	return uintptr(unsafe.Pointer(p))
}
