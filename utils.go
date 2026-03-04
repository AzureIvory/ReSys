package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

// ansiToUTF8 函数。
func ansiToUTF8(b []byte) string {
	if len(b) == 0 {
		return ""
	}

	// MultiByteToWideChar(CP_ACP, 0, ...)
	const cpACP = 0
	k32 := syscall.NewLazyDLL("kernel32.dll")
	mb2wc := k32.NewProc("MultiByteToWideChar")

	// 获取所需 UTF-16 长度
	r1, _, _ := mb2wc.Call(
		uintptr(cpACP),
		uintptr(0),
		uintptr(unsafe.Pointer(&b[0])),
		uintptr(len(b)),
		uintptr(0),
		uintptr(0),
	)
	n := int(r1)
	if n <= 0 {
		return string(b)
	}

	w := make([]uint16, n)
	r2, _, _ := mb2wc.Call(
		uintptr(cpACP),
		uintptr(0),
		uintptr(unsafe.Pointer(&b[0])),
		uintptr(len(b)),
		uintptr(unsafe.Pointer(&w[0])),
		uintptr(n),
	)
	if int(r2) <= 0 {
		return string(b)
	}

	// 转为 Go string
	return string(utf16.Decode(w))
}

// NormalizeDrive 统一盘符/路径格式。
// mode 说明：
//
//	0: 盘符根(C:\)，支持输入 C / C: / C:\ / C:\path
//	1: 盘符字母(C)，支持输入 C / C: / C:\ / C:\path
//	2: 从完整路径提取盘符根(C:\)，必须是 C:\path
//	3: 盘符带冒号(C:)，支持输入 C / C: / C:\ / C:\path / \\.\C: / \\?\C:
//	   若输入包含 Volume{GUID}（如 \\?\Volume{...}\），则原样返回
func NormalizeDrive(input string, mode int) (string, error) {
	s := strings.TrimSpace(input)
	if s == "" {
		logWrite(0, "[NormalizeDrive]NormalizeDrive 输入为空")
		return "", fmt.Errorf("empty drive")
	}
	s = strings.ReplaceAll(s, "/", `\`)

	extractLetter := func(val string) (string, error) {
		val = strings.TrimSpace(val)
		if val == "" {
			logWrite(0, "[NormalizeDrive]NormalizeDrive 盘符为空: input=%s", input)
			return "", fmt.Errorf("empty drive letter")
		}
		val = strings.ToUpper(val)
		switch {
		case len(val) >= 2 && val[1] == ':':
			val = val[:1]
		case len(val) >= 3 && val[1] == ':' && (val[2] == '\\' || val[2] == '/'):
			val = val[:1]
		case len(val) == 1:
		default:
			logWrite(0, "[NormalizeDrive]NormalizeDrive 盘符格式异常: input=%s", input)
			return "", fmt.Errorf("invalid drive letter: %q", input)
		}
		if val[0] < 'A' || val[0] > 'Z' {
			logWrite(0, "[NormalizeDrive]NormalizeDrive 盘符范围异常: input=%s", input)
			return "", fmt.Errorf("invalid drive letter: %q", input)
		}
		return val, nil
	}

	switch mode {
	case 0:
		letter, err := extractLetter(s)
		if err == nil {
			return letter + `:\`, nil
		}
		if len(s) >= 3 && s[1] == ':' {
			return strings.ToUpper(s[:1]) + `:\`, nil
		}
		return "", err

	case 1:
		return extractLetter(s)

	case 2:
		if len(s) >= 3 && s[1] == ':' && (s[2] == '\\' || s[2] == '/') {
			return strings.ToUpper(s[:1]) + `:\`, nil
		}
		logWrite(0, "[NormalizeDrive]NormalizeDrive 解析路径失败: input=%s", input)
		return "", fmt.Errorf("invalid path for drive root: %q", input)

	case 3:
		// Volume{GUID} 形式直接透传
		if strings.Contains(strings.ToLower(s), "volume{") {
			return s, nil
		}

		// 支持 \\.\C: 或 \\?\C: 形式
		ss := s
		if strings.HasPrefix(ss, `\\.\`) || strings.HasPrefix(ss, `\\?\`) {
			if len(ss) > 4 {
				ss = ss[4:]
			}
		}

		letter, err := extractLetter(ss)
		if err == nil {
			return letter + `:`, nil
		}

		// 如果像 "C:\xxx" / "C:" 这种还能识别到冒号，直接取前两位
		if len(ss) >= 2 && ss[1] == ':' && ((ss[0] >= 'a' && ss[0] <= 'z') || (ss[0] >= 'A' && ss[0] <= 'Z')) {
			return strings.ToUpper(ss[:2]), nil
		}

		return "", err

	default:
		logWrite(0, "[NormalizeDrive]NormalizeDrive 模式无效: mode=%d input=%s", mode, input)
		return "", fmt.Errorf("invalid normalize mode: %d", mode)
	}
}

// NormalizeArch 统一架构名称，返回 64/32/arm/other
func NormalizeArch(arch string) string {
	a := strings.ToLower(strings.TrimSpace(arch))
	switch a {
	case "64", "x64", "amd64", "arm64":
		return "64"
	case "32", "x86", "386":
		return "32"
	case "arm":
		return "arm"
	default:
		return a
	}
}

// SelfArch 返回当前运行架构。
func SelfArch() string {
	switch runtime.GOARCH {
	case "amd64":
		return "64"
	case "386":
		return "32"
	case "arm", "arm64":
		return "arm"
	default:
		return "other"
	}
}

// windowsDir 返回 Windows 根目录（优先 SystemRoot，其次 WINDIR）。
func windowsDir() string {
	if d := os.Getenv("SystemRoot"); d != "" {
		return d
	}
	return os.Getenv("WINDIR")
}

// 判断当前是否为 32 位进程运行在 64 位 Windows 上。
func is32() bool {
	return runtime.GOARCH == "386" && os.Getenv("PROCESSOR_ARCHITEW6432") != ""
}

// 返回系统命令路径：优先 Sysnative(在 WOW64 下)，其次 System32，最后回退到 exeName（走 PATH）。
func GetSystemExe(exeName string) string {
	windir := windowsDir()
	if windir == "" {
		return exeName
	}

	sysDir := "System32"
	if is32() {
		sysDir = "Sysnative"
	}

	preferred := filepath.Join(windir, sysDir, exeName)
	if fileExists(preferred) {
		return preferred
	}

	alt := filepath.Join(windir, "System32", exeName)
	if fileExists(alt) {
		return alt
	}

	return exeName
}
