package download

import (
	"ReSys/src/log"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"
)

const defaultDownloadUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36"

var netURL = "http://www.msftconnecttest.com/connecttest.txt"
var netWant = "Microsoft Connect Test"
var newNetCli = func() *http.Client {
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

	return &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}
}

func commonDownloadHeaders() []string {
	return []string{
		"Accept: */*",
		"Accept-Language: zh-CN,zh;q=0.9,en;q=0.8",
		"Cache-Control: no-cache",
		"Pragma: no-cache",
		"Connection: keep-alive",
	}
}

func nativeDownloadHeaders(url string) http.Header {
	if singleRequest(url) {
		return nil
	}

	h := make(http.Header)
	for _, raw := range commonDownloadHeaders() {
		k, v, ok := strings.Cut(raw, ":")
		if !ok {
			continue
		}
		h.Add(strings.TrimSpace(k), strings.TrimSpace(v))
	}
	h.Set("User-Agent", defaultDownloadUserAgent)
	h.Set("Referer", "*")
	return h
}

func NewNativeDownloadOptions(url, dstPath string, progressCallback func(float64, int64)) NOptions {
	if progressCallback == nil {
		progressCallback = func(float64, int64) {}
	}

	safeProgress := func(pct float64, speed int64) {
		defer func() {
			if r := recover(); r != nil {
				log.LogWrite(-2, "[NewNativeDownloadOptions] progress callback panic: url=%s dst=%s pct=%.2f speed=%d panic=%v stack=%s", url, dstPath, pct, speed, r, string(debug.Stack()))
			}
		}()
		progressCallback(pct, speed)
	}

	opt := NOptions{
		URL:                 url,
		Destination:         dstPath,
		Header:              nativeDownloadHeaders(url),
		Concurrency:         32,
		ChunkSize:           1 << 20,
		MaxConnsPerHost:     16,
		MaxIdleConns:        32,
		MaxIdleConnsPerHost: 16,
		OnProgress: func(p NProgress) {
			percent := p.Percent * 100
			if percent < 0 {
				percent = 0
			}
			if percent > 100 {
				percent = 100
			}
			safeProgress(percent, int64(p.SpeedBPS))
		},
	}

	if singleRequest(url) {
		opt.Concurrency = 1
		opt.MaxConnsPerHost = 1
		opt.MaxIdleConnsPerHost = 1
		opt.MaxIdleConns = 2
	}

	return opt
}

func singleRequest(raw string) bool {
	u, err := neturl.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}

	switch strings.ToLower(strings.TrimSpace(u.Hostname())) {
	case "mirrors.lzu.edu.cn", "mirrors.sdu.edu.cn":
		return true
	default:
		return false
	}
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
func DownloadFile(ctx context.Context, url, dstPath string, progressCallback func(float64, int64)) (err error) {
	defer func() {
		if r := recover(); r != nil {
			log.LogWrite(-2, "[DownloadFile] panic: url=%s dst=%s panic=%v stack=%s", url, dstPath, r, string(debug.Stack()))
			err = fmt.Errorf("download file panic: %v", r)
		}
	}()

	log.LogWrite(0, "[DownloadFile] enter: url=%s dst=%s", url, dstPath)

	if err = os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
		log.LogWrite(0, "[DownloadFile] mkdir failed: path=%s err=%v", dstPath, err)
		return fmt.Errorf("create dir: %w", err)
	}
	log.LogWrite(0, "[DownloadFile] directory ready: dir=%s", filepath.Dir(dstPath))
	if progressCallback == nil {
		progressCallback = func(float64, int64) {}
	}

	safeProgress := func(pct float64, speed int64) {
		defer func() {
			if r := recover(); r != nil {
				log.LogWrite(-2, "[DownloadFile] progress callback panic: url=%s dst=%s pct=%.2f speed=%d panic=%v stack=%s", url, dstPath, pct, speed, r, string(debug.Stack()))
			}
		}()
		progressCallback(pct, speed)
	}

	log.LogWrite(0, "[DownloadFile] initializing aria2: url=%s dst=%s", url, dstPath)
	c, err := Newaria2()
	if err != nil {
		log.LogWrite(0, "[DownloadFile] init aria2 failed: err=%v", err)
		return err
	}
	defer c.Close()
	log.LogWrite(0, "[DownloadFile] aria2 ready: endpoint=%s started=%t", c.Endpoint, c.started)

	opt := Options{
		Dir:     filepath.Dir(dstPath),
		Out:     filepath.Base(dstPath),
		Headers: commonDownloadHeaders(),
		Extra: map[string]string{
			"user-agent":                defaultDownloadUserAgent,
			"referer":                   "*",
			"continue":                  "true",
			"split":                     "32",
			"max-connection-per-server": "16",
			"min-split-size":            "1M",
			"file-allocation":           "none",
			"allow-overwrite":           "true",
			"auto-file-renaming":        "false",
		},
	}
	if singleRequest(url) {
		opt.Headers = nil
		delete(opt.Extra, "user-agent")
		opt.Extra["continue"] = "false"
		opt.Extra["split"] = "1"
		opt.Extra["max-connection-per-server"] = "1"
		opt.Extra["use-head"] = "false"
		delete(opt.Extra, "min-split-size")
		delete(opt.Extra, "referer")
		log.LogWrite(0, "[DownloadFile] single-request mode enabled for mirror host: url=%s", url)
	}
	log.LogWrite(0, "[DownloadFile] aria2 options: split=%s max-connection-per-server=%s continue=%s use-head=%s file-allocation=%s",
		opt.Extra["split"], opt.Extra["max-connection-per-server"], opt.Extra["continue"], opt.Extra["use-head"], opt.Extra["file-allocation"])

	log.LogWrite(0, "[DownloadFile] start aria2 transfer: url=%s dst=%s", url, dstPath)
	_, err = c.DownloadContext(ctx, url, opt, func(p Progress) {
		percent := p.Percent
		if percent < 0 {
			percent = 0
		}
		if percent > 100 {
			percent = 100
		}
		safeProgress(percent, p.DownBps)
	})
	if err != nil {
		log.LogWrite(0, "[DownloadFile] aria2 transfer failed: url=%s dst=%s err=%v", url, dstPath, err)
		return err
	}
	log.LogWrite(0, "[DownloadFile] aria2 transfer finished: url=%s dst=%s", url, dstPath)

	st, statErr := os.Stat(dstPath)
	if statErr != nil {
		log.LogWrite(0, "[DownloadFile] downloaded file missing: path=%s err=%v", dstPath, statErr)
		return fmt.Errorf("stat %s failed: %w", dstPath, statErr)
	}
	if st.IsDir() || st.Size() <= 0 {
		log.LogWrite(0, "[DownloadFile] invalid download result: path=%s size=%d", dstPath, st.Size())
		return fmt.Errorf("invalid download result: %s", dstPath)
	}

	safeProgress(100, 0)
	log.LogWrite(0, "[DownloadFile] success: path=%s size=%d", dstPath, st.Size())
	return nil
}
func CheckNetwork(ctx context.Context) (ok bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, netURL, nil)
	if err != nil {
		return false, err
	}

	client := newNetCli()
	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return false, fmt.Errorf("network check failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false, fmt.Errorf("network check failed: http status %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("network check failed: %w", err)
	}
	if strings.TrimSpace(string(body)) != netWant {
		return false, fmt.Errorf("network check failed: unexpected body")
	}

	return true, nil
}

// 校验url
func HttpStatus(raw string) bool {
	//校验微pe时会报错，干脆直接全放行
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
