package download

import (
	"ReSys/src/log"
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var trackerTxtURLs = []string{
	"https://raw.githubusercontent.com/adysec/tracker/main/trackers_best.txt",
	"https://down.adysec.com/trackers_best.txt",
}

const fallbackTrackerURL = "https://api.ttraw.com/trackers.txt"

func pickBTOutputFile(root string) (string, error) {
	// 优先挑这些扩展名
	priority := map[string]int{
		".iso":  1,
		".wim":  2,
		".esd":  3,
		".swm":  4,
		".img":  5,
		".vhd":  6,
		".vhdx": 7,
	}

	type cand struct {
		path string
		ext  string
		size int64
		pr   int
	}

	var best *cand

	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		st, e := os.Stat(p)
		if e != nil || st.Size() <= 0 {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		pr, ok := priority[ext]
		if !ok {
			pr = 999 // 非目标扩展名排后
		}
		c := cand{path: p, ext: ext, size: st.Size(), pr: pr}
		if best == nil {
			best = &c
			return nil
		}
		// 先比 pr（越小越优先），再比 size（越大越优先）
		if c.pr < best.pr || (c.pr == best.pr && c.size > best.size) {
			best = &c
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if best == nil {
		return "", fmt.Errorf("BT 下载目录中找不到任何文件: %s", root)
	}
	return best.path, nil
}

// 下载bt
// dir:    下载保存目录，空字符串则使用当前目录
// prog:   进度回调（0~100，speed 为 B/s，done/total 为字节数）
func DownloadBT(magnet, dir string, prog func(pct int, speed, done, total int64)) (string, error) {
	magnet = strings.TrimSpace(magnet)
	if !strings.HasPrefix(strings.ToLower(magnet), "magnet:?xt=urn:btih:") {
		return "", fmt.Errorf("不是合法的 BT 磁力链接: %s", magnet)
	}

	if dir == "" {
		dir = "."
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("解析目录失败: %w", err)
	}
	if err := os.MkdirAll(absDir, 0o755); err != nil {
		return "", fmt.Errorf("创建下载目录失败: %w", err)
	}

	// 用磁链 hash 做隔离目录，避免误扫旧文件
	sum := sha1.Sum([]byte(strings.ToLower(magnet)))
	tag := hex.EncodeToString(sum[:])[:12]
	dataDir := filepath.Join(absDir, ".btdata", tag)
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return "", fmt.Errorf("创建 BT 数据目录失败: %w", err)
	}

	exePath, _ := os.Executable()
	exeDir := filepath.Dir(exePath)
	localTrackerPath := filepath.Join(exeDir, "trackers.txt")

	trackers, err := loadTrackersWithFallback(trackerTxtURLs, fallbackTrackerURL, localTrackerPath)
	if err != nil {
		fmt.Println("警告: 加载 trackers 失败，将使用 aria2 默认 DHT/PEX:", err)
	}

	c, err := Newaria2()
	if err != nil {
		return "", fmt.Errorf("初始化 aria2 失败: %w", err)
	}
	defer c.Close()

	res, err := c.DownloadBtContext(context.Background(), magnet, Options{
		Dir:      dataDir,
		Trackers: trackers,
	}, func(p Progress) {
		if prog == nil {
			return
		}
		pct := int(p.Percent + 0.5)
		if pct < 0 {
			pct = 0
		}
		if pct > 100 {
			pct = 100
		}
		prog(pct, p.DownBps, p.Done, p.Total)
	})
	if err != nil {
		return "", err
	}

	realPath := strings.TrimSpace(res.Path)
	if realPath != "" {
		if st, e := os.Stat(realPath); e == nil && !st.IsDir() && st.Size() > 0 {
			if prog != nil {
				prog(100, 0, st.Size(), st.Size())
			}
			return realPath, nil
		}
	}

	// 只扫本次隔离目录，不扫整个 tempimg
	realPath, err = pickBTOutputFile(dataDir)
	if err != nil {
		return "", err
	}
	if prog != nil {
		if st, e := os.Stat(realPath); e == nil && !st.IsDir() && st.Size() > 0 {
			prog(100, 0, st.Size(), st.Size())
		}
	}
	return realPath, nil
}

// loadTrackersWithFallback 函数。
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

// fetchTrackersOne 函数。
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

// uniqueStrings 函数。
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

// 下载文件
// - 写入 dstPath+".part"，成功后重命名为 dstPath。
// - 若 .part 已存在，会尝试用续传；若服务器不支持 Range，会自动从头下载。
func DownloadFile(ctx context.Context, url, dstPath string, progressCallback func(float64, int64)) error {
	if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
		log.LogWrite(0, "[DownloadFile] 创建目录失败: path=%s err=%v", dstPath, err)
		return fmt.Errorf("create dir: %w", err)
	}
	if progressCallback == nil {
		progressCallback = func(float64, int64) {}
	}

	c, err := Newaria2()
	if err != nil {
		log.LogWrite(0, "[DownloadFile] 初始化 aria2 失败: err=%v", err)
		return err
	}
	defer c.Close()

	opt := Options{
		Dir: filepath.Dir(dstPath),
		Out: filepath.Base(dstPath),
	}

	_, err = c.DownloadContext(ctx, url, opt, func(p Progress) {
		percent := p.Percent
		if percent < 0 {
			percent = 0
		}
		if percent > 100 {
			percent = 100
		}
		progressCallback(percent, p.DownBps)
	})
	if err != nil {
		log.LogWrite(0, "[DownloadFile] aria2 下载失败: url=%s dst=%s err=%v", url, dstPath, err)
		return err
	}

	// aria2 正常 complete 后，目标文件应已直接落在 dstPath
	st, statErr := os.Stat(dstPath)
	if statErr != nil {
		log.LogWrite(0, "[DownloadFile] 下载完成但文件不存在: path=%s err=%v", dstPath, statErr)
		return fmt.Errorf("stat %s 失败: %w", dstPath, statErr)
	}
	if st.IsDir() || st.Size() <= 0 {
		log.LogWrite(0, "[DownloadFile] 下载结果异常: path=%s size=%d", dstPath, st.Size())
		return fmt.Errorf("下载结果异常: %s", dstPath)
	}

	progressCallback(100, 0)
	return nil
}

// 判断网络是否连通。
// 返回：ok=是否连通；err=具体失败原因
func CheckNetwork(ctx context.Context) (ok bool, err error) {
	dialer := &net.Dialer{
		Timeout: 3 * time.Second,
	}

	transport := &http.Transport{
		Proxy:       http.ProxyFromEnvironment,
		DialContext: dialer.DialContext,

		TLSHandshakeTimeout:   3 * time.Second,
		ResponseHeaderTimeout: 3 * time.Second,
		ForceAttemptHTTP2:     true,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.baidu.com", nil)
	if err != nil {
		return false, err
	}

	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return false, fmt.Errorf("network check failed: %w", err)
	}
	defer resp.Body.Close()

	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false, fmt.Errorf("network check failed: http status %s", resp.Status)
	}

	return true, nil
}

// 校验url
func HttpStatus(raw string) bool {
	return true
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

// 取下载链接的文件名
func GetlinkName(link string) string {
	raw := strings.TrimSpace(link)
	if raw == "" {
		return ""
	}
	raw = strings.SplitN(raw, "?", 2)[0]
	base := filepath.Base(raw)
	if base == "" || base == "." || base == "/" {
		return ""
	}
	return base
}
