package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/anacrolix/torrent"
)

// trackers.txt订阅URL列表
var trackerTxtURLs = []string{
	"https://raw.githubusercontent.com/adysec/tracker/main/trackers_best.txt",
	"https://down.adysec.com/trackers_best.txt",
}

// 最后用
const fallbackTrackerURL = "https://example.com/fallback-trackers.txt"

// 下载bt
// dir:    下载保存目录，空字符串则使用当前目录
// prog:   进度回调（0~100，speed 为 B/s，done/total 为字节数）
func DownloadBT(magnet, dir string, prog func(pct int, speed, done, total int64)) error {
	magnet = strings.TrimSpace(magnet)
	if !strings.HasPrefix(strings.ToLower(magnet), "magnet:?xt=urn:btih:") {
		return fmt.Errorf("不是合法的 BT 磁力链接: %s", magnet)
	}

	if dir == "" {
		dir = "."
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("解析目录失败: %w", err)
	}
	if err := os.MkdirAll(absDir, 0o755); err != nil {
		return fmt.Errorf("创建下载目录失败: %w", err)
	}

	// 运行目录下的本地 trackers.txt
	exePath, _ := os.Executable()
	exeDir := filepath.Dir(exePath)
	localTrackerPath := filepath.Join(exeDir, "trackers.txt")

	trackers, err := loadTrackersWithFallback(trackerTxtURLs, fallbackTrackerURL, localTrackerPath)
	if err != nil {
		fmt.Println("警告: 加载 trackers 失败，将仅依赖 DHT/PEX:", err)
	}

	cfg := torrent.NewDefaultClientConfig()
	cfg.DataDir = absDir          // 用数据目录实现断点续传
	cfg.Seed = false              // 下载完不长期做种
	cfg.NoUpload = false          // 按需上传，保持默认即可
	cfg.DownloadRateLimiter = nil //不限下载速度

	cl, err := torrent.NewClient(cfg)
	if err != nil {
		return fmt.Errorf("创建 BT 客户端失败: %w", err)
	}
	defer cl.Close()

	spec, err := torrent.TorrentSpecFromMagnetUri(magnet)
	if err != nil {
		return fmt.Errorf("解析 magnet 失败: %w", err)
	}
	if len(trackers) > 0 {
		spec.Trackers = [][]string{trackers} // 所有 tracker 放在同一 tier
	}

	t, _, err := cl.AddTorrentSpec(spec)
	if err != nil {
		return fmt.Errorf("添加 torrent 失败: %w", err)
	}

	// 等待获取种子信息
	<-t.GotInfo()

	// 并发连接数
	t.SetMaxEstablishedConns(512)

	// 整个种子都下载
	t.DownloadAll()

	var lastDone int64
	var lastTime time.Time

	for {
		total := t.Length()
		done := t.BytesCompleted()

		// 计算百分比
		pct := 0
		if total > 0 {
			pct = int(float64(done) * 100 / float64(total))
			if pct < 0 {
				pct = 0
			}
			if pct > 100 {
				pct = 100
			}
		}

		// 计算下载速度
		now := time.Now()
		var speed int64
		if !lastTime.IsZero() {
			delta := done - lastDone
			dt := now.Sub(lastTime).Seconds()
			if dt > 0 && delta >= 0 {
				bps := float64(delta) / dt // bytes per second
				if bps < 0 {
					bps = 0
				}
				speed = int64(bps + 0.5) // 四舍五入到整数 B/s
			}
		}
		lastTime = now
		lastDone = done

		if prog != nil {
			prog(pct, speed, done, total)
		}

		// BytesMissing == 0 表示管理器认为没有缺失的数据了
		if total > 0 && t.BytesMissing() == 0 {
			break
		}

		time.Sleep(500 * time.Millisecond) // 500ms回调
	}

	// 补一次 100%
	if prog != nil {
		total := t.Length()
		if total == 0 {
			total = lastDone
		}
		prog(100, 0, total, total)
	}

	return nil
}

func loadTrackersWithFallback(urls []string, fallbackURL, localPath string) ([]string, error) {
	httpClient := &http.Client{
		Timeout: 8 * time.Second,
	}

	var all []string
	var firstErr error

	for _, u := range urls {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		lines, err := fetchTrackersOne(httpClient, u)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		all = append(all, lines...)
	}

	if len(all) == 0 && strings.TrimSpace(fallbackURL) != "" {
		lines, err := fetchTrackersOne(httpClient, fallbackURL)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
		} else {
			all = append(all, lines...)
		}
	}

	// URL失败，用trackers.txt
	if len(all) == 0 && strings.TrimSpace(localPath) != "" {
		f, err := os.Open(localPath)
		if err == nil {
			defer f.Close()
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				if line == "" {
					continue
				}
				if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "//") {
					continue
				}
				all = append(all, line)
			}
			if err := sc.Err(); err != nil && firstErr == nil {
				firstErr = err
			}
		} else {
			if firstErr == nil {
				firstErr = err
			}
		}
	}

	if len(all) == 0 {
		if firstErr != nil {
			return nil, firstErr
		}
		return nil, fmt.Errorf("未能从任何来源加载 trackers")
	}

	return uniqueStrings(all), nil
}

func fetchTrackersOne(c *http.Client, url string) ([]string, error) {
	resp, err := c.Get(url)
	if err != nil {
		return nil, fmt.Errorf("GET %s 失败: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s 返回状态码 %d", url, resp.StatusCode)
	}

	var res []string
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "//") {
			continue
		}
		res = append(res, line)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("读取 %s 失败: %w", url, err)
	}
	return res, nil
}

func uniqueStrings(in []string) []string {
	m := make(map[string]struct{})
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := m[s]; ok {
			continue
		}
		m[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// 计算文件的 SHA1，并和sha1Hex比较。
// path: 文件路径
// sha1Hex: 期望的 SHA1 字符串（不区分大小写，可带/不带空格）
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
	// 只保留前 40 个十六进制字符
	exp = strings.ToUpper(exp)
	if len(exp) >= 40 {
		exp = exp[:40]
	}

	ok := (got == exp)
	return ok, got, nil
}
