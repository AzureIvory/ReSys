package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

type progInfo struct {
	pct   int
	speed int64
	done  int64
	total int64
}

// 解析 aria2 的大小字符串，例如 "467MiB"、"2.4GiB"、"0B"
func parseSize(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	re := regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)?)([KMGTP]?i?B)$`)
	m := re.FindStringSubmatch(s)
	if len(m) != 3 {
		return 0
	}
	valStr, unit := m[1], m[2]
	fv, err := strconv.ParseFloat(valStr, 64)
	if err != nil {
		return 0
	}
	mul := float64(1)
	switch unit {
	case "B":
		mul = 1
	case "KiB":
		mul = 1024
	case "MiB":
		mul = 1024 * 1024
	case "GiB":
		mul = 1024 * 1024 * 1024
	case "TiB":
		mul = 1024 * 1024 * 1024 * 1024
	default:
		mul = 1
	}
	return int64(fv*mul + 0.5)
}

// 调用运行目录下的 aria2c.exe 下载BT的magnet链接。
// magnet: 必须是 "magnet:?xt=urn:btih:..." 开头的字符串
// dir:    下载保存目录，为空则用当前目录
// prog:   实时进度回调，0~100
func DownloadBT(magnet, dir string, prog func(pct int, speed, done, total int64)) error {
	if !strings.HasPrefix(strings.ToLower(magnet), "magnet:?xt=urn:btih:") {
		return fmt.Errorf("不是合法的 BT 磁力链接: %s", magnet)
	}
	if dir == "" {
		dir = "."
	}

	// 找到当前程序所在目录，拼出 aria2c.exe 路径
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("获取自身路径失败: %w", err)
	}
	exeDir := filepath.Dir(exePath)
	ariaPath := filepath.Join(exeDir, "aria2c.exe")

	if _, err := os.Stat(ariaPath); err != nil {
		return fmt.Errorf("未找到 aria2c.exe: %s (请放在程序同目录)", ariaPath)
	}

	// 默认内置几条常用公共 trackers
	trackers := []string{
		"udp://tracker.opentrackr.org:1337/announce",
		"udp://open.stealth.si:80/announce",
		"udp://tracker.torrent.eu.org:451/announce",
		"udp://exodus.desync.com:6969/announce",
	}

	//读取运行目录下的trackers.txt
	trkFile := filepath.Join(exeDir, "trackers.txt")
	if f, err := os.Open(trkFile); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			// 支持注释行
			if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
				continue
			}
			trackers = append(trackers, line)
		}
		_ = f.Close()
	}

	trkArg := ""
	if len(trackers) > 0 {
		trkArg = "--bt-tracker=" + strings.Join(trackers, ",")
	}

	args := []string{
		"--enable-color=false",
		"--summary-interval=1", // 每秒输出一次进度
		"--console-log-level=notice",
		"--enable-dht=true",
		"--enable-dht6=false",
		"--bt-enable-lpd=true",
		"--enable-peer-exchange=true",
		"--bt-save-metadata=true",
		"--bt-max-peers=55",
		"--seed-time=0",   // 下完就退出
		"--continue=true", // 允许断点续传
		"--bt-max-peers=32",
	}

	// 有 trackers 参数就加上
	if trkArg != "" {
		args = append(args, trkArg)
	}

	// 下载目录和 magnet
	args = append(args,
		"-d", dir,
		magnet,
	)

	cmd := exec.Command(ariaPath, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow: true,
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("获取 stdout 失败: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("获取 stderr 失败: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动 aria2c 失败: %w", err)
	}

	// 单独丢弃 stderr，避免阻塞
	go func() {
		_, _ = io.Copy(io.Discard, stderr)
	}()

	reMain := regexp.MustCompile(`#\S+\s+([0-9.]+[KMGTP]?i?B)/([0-9.]+[KMGTP]?i?B)\(([0-9.]+)%\)`)
	reSpeed := regexp.MustCompile(`DL:([0-9.]+[KMGTP]?i?B)`)

	var cand *progInfo
	var last *progInfo

	sc := bufio.NewScanner(stdout)
	for sc.Scan() {
		line := sc.Text()

		// 解析主进度行
		if m := reMain.FindStringSubmatch(line); len(m) == 4 {
			doneStr := m[1]
			totalStr := m[2]
			pctStr := m[3]

			doneBytes := parseSize(doneStr)
			totalBytes := parseSize(totalStr)

			fv, err := strconv.ParseFloat(pctStr, 64)
			if err != nil {
				fv = 0
			}
			pct := int(fv + 0.5)
			if pct < 0 {
				pct = 0
			}
			if pct > 100 {
				pct = 100
			}

			// 解析速度，可能没有DL字段
			var speedBytes int64
			if m2 := reSpeed.FindStringSubmatch(line); len(m2) == 2 {
				speedBytes = parseSize(m2[1])
			}

			cand = &progInfo{
				pct:   pct,
				speed: speedBytes,
				done:  doneBytes,
				total: totalBytes,
			}
		}

		// FILE行里可以区分是不是metadata任务
		if strings.Contains(line, "FILE:") {
			if strings.Contains(line, "[MEMORY][METADATA]") {
				cand = nil
				continue
			}
			if cand != nil {
				info := *cand // 拷贝一份
				cand = nil

				if prog != nil && (last == nil || info.pct != last.pct) {
					prog(info.pct, info.speed, info.done, info.total)
					last = &info
				}
			}
		}
	}
	_ = sc.Err()

	if err := cmd.Wait(); err != nil {
		if prog != nil && last != nil {
			prog(last.pct, last.speed, last.done, last.total)
		}
		return fmt.Errorf("aria2c 退出错误: %w", err)
	}

	// 成功结束但没有 100%，补一次 100%
	if prog != nil {
		if last != nil && last.pct < 100 {
			done := last.total
			total := last.total
			prog(100, 0, done, total)
		} else if last == nil {
			// 理论上不会到这
			prog(100, 0, 0, 0)
		}
	}
	return nil
}

// CheckFileSHA1 计算文件的 SHA1，并和给定的 sha1Hex 比较。
// - path: 文件路径
// - sha1Hex: 期望的 SHA1 字符串（不区分大小写，可带/不带空格）
// 返回：是否匹配、实际计算出的 SHA1（大写）、错误信息
func CheckFileSHA1(path, sha1Hex string) (bool, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, "", fmt.Errorf("打开文件失败: %w", err)
	}
	defer f.Close()

	h := sha1.New()

	// 使用缓冲区流式读取
	buf := make([]byte, 4*1024*1024) // 4MB
	for {
		n, err := f.Read(buf)
		if n > 0 {
			if _, wErr := h.Write(buf[:n]); wErr != nil {
				return false, "", fmt.Errorf("计算 SHA1 写入失败: %w", wErr)
			}
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return false, "", fmt.Errorf("读取文件失败: %w", err)
		}
	}

	sum := h.Sum(nil)
	got := strings.ToUpper(hex.EncodeToString(sum))

	// 规范化传入的SHA1字符串
	exp := strings.TrimSpace(sha1Hex)
	// 有些情况下可能会带空格或其他东西，这里只保留前 40 个十六进制字符
	exp = strings.ToUpper(exp)
	if len(exp) >= 40 {
		exp = exp[:40]
	}

	ok := (got == exp)
	return ok, got, nil
}
