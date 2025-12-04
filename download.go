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

// 调用运行目录下的 aria2c.exe 下载BT的magnet链接。
// magnet: 必须是 "magnet:?xt=urn:btih:..." 开头的字符串
// dir:    下载保存目录，为空则用当前目录
// prog:   实时进度回调，0~100
func DownloadBT(magnet, dir string, prog func(int)) error {
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

	// 为了“稳定”，这里参数偏保守：
	// - 只允许 1 个并发任务
	// - 限制整体速度 1M/s（可以按需要改大/删掉）
	// - 预分配文件，减少碎片
	args := []string{
		"--enable-color=false",
		"--summary-interval=1",            // 每 1 秒输出一次进度
		"--console-log-level=notice",      // 只要关键日志
		"--seed-time=0",                   // 下完就退出，不做种
		"--max-concurrent-downloads=1",    // 稳定一点，只下一个任务
		"--file-allocation=prealloc",      // 预分配，减少磁盘抖动
		"--continue=true",                 // 允许断点续传
		"--max-overall-download-limit=1M", // 限速 1MB/s，追求稳定（可修改/删除）
		"--bt-max-peers=32",               // 限制连接的 peers 数量
		"-d", dir,                         // 下载目录
		magnet,
	}

	cmd := exec.Command(ariaPath, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow: true, // 关键：隐藏黑色控制台窗口
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("获取 stdout 失败: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("获取 stderr 失败: %w", err)
	}

	// 启动 aria2c
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动 aria2c 失败: %w", err)
	}

	// 单独丢弃 stderr，避免阻塞
	go func() {
		_, _ = io.Copy(io.Discard, stderr)
	}()

	// 解析类似：
	// [#c1a5b0 11MiB/101MiB(10%) CN:5 DL:1.2MiB]
	// 里面的 10%
	rePct := regexp.MustCompile(`(\d+(?:\.\d+)?)%`)

	last := -1
	sc := bufio.NewScanner(stdout)
	for sc.Scan() {
		line := sc.Text()
		matches := rePct.FindAllStringSubmatch(line, -1)
		if len(matches) == 0 {
			continue
		}
		// 取最后一个百分比
		raw := matches[len(matches)-1][1]
		fv, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			continue
		}
		pct := int(fv + 0.5)
		if pct < 0 {
			pct = 0
		}
		if pct > 100 {
			pct = 100
		}
		if pct != last && prog != nil {
			last = pct
			prog(pct) // 把实时进度回调给你，自己去更新进度条
		}
	}
	// 忽略扫描错误（一般是进程退出导致 EOF）
	_ = sc.Err()

	// 等待进程结束，拿到退出码
	if err := cmd.Wait(); err != nil {
		// 如果失败时有进度（比如 90%），最后一次也回调一下
		if prog != nil && last >= 0 {
			prog(last)
		}
		return fmt.Errorf("aria2c 退出错误: %w", err)
	}

	// 确保最终给到 100%
	if prog != nil && last < 100 {
		prog(100)
	}
	return nil
}

// CheckFileSHA1 计算文件的 SHA1，并和给定的 sha1Hex 比较。
// - path: 文件路径
// - sha1Hex: 期望的 SHA1 字符串（不区分大小写，可带/不带空格）
// 返回：是否匹配、实际计算出的 SHA1（大写）、错误信息
func CheckFileSHA1(path, sha1Hex string) (bool, string, error) {
	// 打开文件
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
