package main

import (
	"ReSys/src/tools"
	"ReSys/src/utils"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"ReSys/src/utils"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// 获取当前系统引导 GUID
func GetBootGUID() (string, error) {
	windir := utils.WindowsDir()
	if windir == "" {
		return "", fmt.Errorf("WINDIR/SystemRoot is empty")
	}
	bcdeditPath := utils.GetSystemExe("bcdedit.exe")

	out, err := tools.RunCmd(bcdeditPath, nil, nil, "", "/enum")
	if err != nil && (errors.Is(err, os.ErrNotExist) || errors.Is(err, exec.ErrNotFound)) {
		if exe, e := os.Executable(); e == nil {
			fallback := filepath.Join(filepath.Dir(exe), "tools", "bcdedit.exe")
			out2, err2 := tools.RunCmd(fallback, nil, nil, "", "/enum")
			// 用 fallback 的结果覆盖
			out, err = out2, err2
			bcdeditPath = fallback
		}
	}
	// 这里如果 err != nil，也可能 out 里有内容（你 runCmd 会把输出带回来）
	// 但 bcdedit 通常需要管理员权限/环境正常，否则解析也没意义：直接返回错误更安全。
	if err != nil {
		return "", fmt.Errorf("bcdedit failed (%s): %w", bcdeditPath, err)
	}

	systemDrive := os.Getenv("SystemDrive")
	if systemDrive == "" {
		systemDrive = "C:"
	}
	systemDrive = strings.TrimRight(systemDrive, `\`)

	id, perr := parseBootIdentifier(out, systemDrive)
	if perr != nil {
		return "", perr
	}
	return id, nil
}

// 解析`bcdedit /enum`的输出，找到与当前系统盘匹配的引导项，并返回其 Identifier。
func parseBootIdentifier(out, systemDrive string) (string, error) {
	type entry struct {
		title    string
		id       string
		device   string
		osdevice string
	}

	isDashLine := func(s string) bool {
		s = strings.TrimSpace(s)
		if s == "" {
			return false
		}
		for _, r := range s {
			if r != '-' && r != '—' && r != '─' {
				return false
			}
		}
		return true
	}

	isBootLoaderTitle := func(title string) bool {
		t := strings.ToLower(title)
		// English / Chinese common headings
		return strings.Contains(t, "windows boot loader") ||
			strings.Contains(t, "boot loader") ||
			strings.Contains(title, "Windows 启动加载器") ||
			strings.Contains(title, "启动加载器")
	}

	matchesSystemDrive := func(v string) bool {
		if v == "" {
			return false
		}
		vl := strings.ToLower(v)
		sd := strings.ToLower(systemDrive)
		// 常见形式：partition=C: / partition=C:\ / ...C:
		return strings.Contains(vl, "partition="+sd) ||
			strings.Contains(vl, sd+`\`) ||
			strings.Contains(vl, sd)
	}

	flush := func(e entry) (hit bool, best bool, id string) {
		if e.id == "" {
			return false, false, ""
		}
		if matchesSystemDrive(e.device) || matchesSystemDrive(e.osdevice) {
			if isBootLoaderTitle(e.title) {
				return true, true, e.id // best hit
			}
			return true, false, e.id // hit but not best
		}
		return false, false, ""
	}

	var (
		cur         entry
		bestAnyHit  string // fallback if only non-boot-loader hits
		gotAnyEntry bool
	)

	lines := strings.Split(out, "\n")
	for _, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		trim := strings.TrimSpace(line)

		// block separator
		if trim == "" {
			if gotAnyEntry {
				hit, best, id := flush(cur)
				if best {
					return id, nil
				}
				if hit && bestAnyHit == "" {
					bestAnyHit = id
				}
			}
			cur = entry{}
			gotAnyEntry = false
			continue
		}
		if isDashLine(trim) {
			continue
		}

		// Try detect title line (usually appears before key/value lines)
		// Example: "Windows Boot Loader" / "Windows 启动加载器"
		// We treat a non key-value line as title when current entry hasn't started.
		if !gotAnyEntry {
			low := strings.ToLower(trim)
			if !(strings.HasPrefix(low, "identifier") || strings.HasPrefix(trim, "标识符") ||
				strings.HasPrefix(low, "device") || strings.HasPrefix(trim, "设备") ||
				strings.HasPrefix(low, "osdevice")) {
				// likely a section title
				cur.title = trim
				// still not mark gotAnyEntry yet (no properties)
			}
		}

		fields := strings.Fields(trim)
		if len(fields) < 2 {
			continue
		}
		key := fields[0]
		val := strings.Join(fields[1:], " ")
		gotAnyEntry = true

		kl := strings.ToLower(key)

		// identifier / 标识符
		if kl == "identifier" || key == "标识符" || strings.Contains(trim, "identifier") || strings.Contains(trim, "标识符") {
			// bcdedit identifier is usually last token
			cur.id = fields[len(fields)-1]
			continue
		}

		// osdevice
		if kl == "osdevice" || strings.Contains(kl, "osdevice") {
			cur.osdevice = val
			continue
		}

		// device / 设备
		if kl == "device" || key == "设备" || strings.Contains(trim, " device") || strings.Contains(trim, "设备") {
			cur.device = val
			continue
		}
	}

	// flush last block
	if gotAnyEntry {
		hit, best, id := flush(cur)
		if best {
			return id, nil
		}
		if hit && bestAnyHit == "" {
			bestAnyHit = id
		}
	}

	if bestAnyHit != "" {
		return bestAnyHit, nil
	}
	return "", fmt.Errorf("could not find current boot identifier for SystemDrive=%s", systemDrive)
}

// DetectBootMode 使用 GetFirmwareEnvironmentVariableW 读“空变量”判断启动模式：
// - Legacy BIOS：返回 ERROR_INVALID_FUNCTION (1) => Legacy
// - UEFI：返回其他错误（如 ERROR_NOACCESS / ERROR_ENVVAR_NOT_FOUND 等）=> UEFI
func DetectBootMode() (string, error) {
	k32 := windows.NewLazySystemDLL("kernel32.dll")
	proc := k32.NewProc("GetFirmwareEnvironmentVariableW")
	if err := k32.Load(); err != nil {
		return "Legacy", err
	}
	if err := proc.Find(); err != nil {
		return "Legacy", err
	}

	// lpName = ""（空字符串）
	// lpGuid = "{00000000-0000-0000-0000-000000000000}"（虚拟 GUID）
	name := windows.StringToUTF16Ptr("")
	guid := windows.StringToUTF16Ptr("{00000000-0000-0000-0000-000000000000}")
	var buf [1]byte

	r1, _, e1 := proc.Call(
		uintptr(unsafe.Pointer(name)),
		uintptr(unsafe.Pointer(guid)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)

	if r1 == 0 {
		// LazyProc.Call 返回的 e1 通常就是 GetLastError()
		if errno, ok := e1.(syscall.Errno); ok {
			if errno == windows.ERROR_INVALID_FUNCTION {
				return "Legacy", nil
			}
			// 其他错误基本都视为 UEFI（如 ERROR_NOACCESS / ERROR_ENVVAR_NOT_FOUND）
			return "UEFI", nil
		}
		// 拿不到 errno：保守当作 UEFI
		return "UEFI", nil
	}

	// 成功（很少见，因为我们读的是“空变量”），也说明 UEFI
	return "UEFI", nil
}


// SecureBootEnabled 通过注册表读取 Secure Boot 状态：
// HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State\UEFISecureBootEnabled (DWORD)
// - 1 => true
// - 0 / 不存在（Win7常见）=> false
func SecureBootEnabled() (bool, error) {
	const keyPath = `SYSTEM\CurrentControlSet\Control\SecureBoot\State`
	const valueName = "UEFISecureBootEnabled"

	k, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.QUERY_VALUE)
	if err != nil {
		// Win7 或不支持 Secure Boot 的平台通常没有这个 key：当作 false，不报错
		if errors.Is(err, registry.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	defer k.Close()

	v, _, err := k.GetIntegerValue(valueName)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return v != 0, nil
}
