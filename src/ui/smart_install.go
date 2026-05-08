//go:build windows

package ui

import (
	"ReSys/src/windows"
	"strings"
)

var (
	// curVer 读取当前系统版本与架构。
	curVer = windows.GetCurrentWinVersion
	// dllVer 用 ntdll 版本兜底读取系统版本与架构。
	dllVer = windows.GetCurrentNtdllVersion
)

// pickSmart 选择智能安装要使用的目标系统与架构。
// 规则：
// - Win7 -> win7
// - Win8/8.1/10 -> win10
// - Win11 -> win11
// - 全部失败 -> win11
func pickSmart() (string, string) {
	if target, arch, ok := pickCur(); ok {
		return target, arch
	}
	if target, arch, ok := pickDLL(); ok {
		return target, arch
	}
	return targetWin11, "64"
}

// SmartTar 返回智能重装应使用的目标系统。
func SmartTar() string {
	tar, _ := pickSmart()
	return tar
}

// pickCur 优先用注册表版本判断当前系统。
func pickCur() (string, string, bool) {
	ver, arch, err := curVer()
	if err != nil {
		return "", "", false
	}
	target, ok := mapVer(ver)
	if !ok {
		return "", "", false
	}
	return target, normArch(arch), true
}

// pickDLL 在注册表失败时改用 ntdll 版本兜底。
func pickDLL() (string, string, bool) {
	ver, arch, err := dllVer()
	if err != nil {
		return "", "", false
	}
	target, ok := mapVer(ver)
	if !ok {
		return "", "", false
	}
	return target, normArch(arch), true
}

// mapVer 将内部版本号映射为自动重装目标系统。
func mapVer(ver int) (string, bool) {
	switch ver {
	case 7:
		return targetWin7, true
	case 8, 9, 10:
		return targetWin10, true
	case 11:
		return targetWin11, true
	default:
		return "", false
	}
}

// normArch 将架构文本统一成 32/64 两种内部值。
func normArch(arch string) string {
	switch strings.TrimSpace(arch) {
	case "32", "x86":
		return "32"
	default:
		return "64"
	}
}

// runSmart 处理智能安装按钮点击。
func runSmart() {
	startInstall(SmartTar())
}
