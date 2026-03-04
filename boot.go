package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// 获取当前系统引导 GUID
func GetBootGUID() (string, error) {
	windir := windowsDir()
	if windir == "" {
		return "", fmt.Errorf("WINDIR/SystemRoot is empty")
	}
	bcdeditPath := GetSystemExe("bcdedit.exe")

	out, err := runCmd(bcdeditPath, nil, nil, "", "/enum")
	if err != nil && (errors.Is(err, os.ErrNotExist) || errors.Is(err, exec.ErrNotFound)) {
		if exe, e := os.Executable(); e == nil {
			fallback := filepath.Join(filepath.Dir(exe), "tools", "bcdedit.exe")
			out2, err2 := runCmd(fallback, nil, nil, "", "/enum")
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
