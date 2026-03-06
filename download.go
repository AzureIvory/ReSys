package main

import (
	log "ReSys/src/log"
	tools "ReSys/src/tools"
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	g "github.com/anacrolix/generics"
	"github.com/anacrolix/torrent"
	"github.com/anacrolix/torrent/metainfo"
	"github.com/anacrolix/torrent/storage"
)

var trackerTxtURLs = []string{
	"https://raw.githubusercontent.com/adysec/tracker/main/trackers_best.txt",
	"https://down.adysec.com/trackers_best.txt",
}

const fallbackTrackerURL = "https://api.ttraw.com/trackers.txt"

func magnetInfoHash(magnet string) (string, error) {
	s := strings.TrimSpace(magnet)
	low := strings.ToLower(s)
	key := "xt=urn:btih:"
	i := strings.Index(low, key)
	if i < 0 {
		return "", fmt.Errorf("magnet 缺少 btih: %s", magnet)
	}
	i += len(key)
	j := i
	for j < len(s) {
		if s[j] == '&' || s[j] == '#' {
			break
		}
		j++
	}
	h := strings.TrimSpace(s[i:j])
	if h == "" {
		return "", fmt.Errorf("无法解析 infohash: %s", magnet)
	}
	return strings.ToLower(h), nil
}

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

	// 用 infohash 隔离本次下载内容（避免目录里有其他旧文件被误判）
	ih, err := magnetInfoHash(magnet)
	if err != nil {
		return "", err
	}
	// 截短一下目录名，足够区分即可
	tag := ih
	if len(tag) > 12 {
		tag = tag[:12]
	}

	// BT 数据输出目录（真正的文件落盘位置）
	dataDir := filepath.Join(absDir, ".btdata", tag)
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return "", fmt.Errorf("创建 BT 数据目录失败: %w", err)
	}

	// BT 缓存目录（元数据、piece completion 等）
	cacheDir := filepath.Join(absDir, ".btcache", tag)
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return "", fmt.Errorf("创建 BT 缓存目录失败: %w", err)
	}

	// 运行目录下的本地 trackers.txt
	exePath, _ := os.Executable()
	exeDir := filepath.Dir(exePath)
	localTrackerPath := filepath.Join(exeDir, "trackers.txt")

	trackers, err := loadTrackersWithFallback(trackerTxtURLs, fallbackTrackerURL, localTrackerPath)
	if err != nil {
		fmt.Println("警告: 加载 trackers 失败，将仅依赖 DHT/PEX:", err)
	}

	pc, err := storage.NewDefaultPieceCompletionForDir(cacheDir)
	if err != nil {
		return "", fmt.Errorf("创建 PieceCompletion 失败: %w", err)
	}

	cfg := torrent.NewDefaultClientConfig()
	cfg.DataDir = cacheDir        // 客户端自身元数据
	cfg.Seed = false              // 下载完不长期做种
	cfg.NoUpload = false          // 按需上传
	cfg.DownloadRateLimiter = nil // 不限速

	// 关键：DefaultStorage 的 ClientBaseDir 指向 dataDir（真实落盘目录）
	cfg.DefaultStorage = storage.NewFileOpts(storage.NewFileClientOpts{
		ClientBaseDir: dataDir,

		FilePathMaker: func(opts storage.FilePathMakerOpts) string {
			info := opts.Info
			fi := opts.File

			// 安全兜底
			if info == nil {
				if fi != nil && len(fi.Path) > 0 {
					return fi.Path[len(fi.Path)-1]
				}
				return "torrent.data"
			}

			// 单文件种子
			if !info.IsDir() {
				name := info.BestName()
				if name == "" || name == metainfo.NoName {
					if fi != nil && len(fi.Path) > 0 {
						name = fi.Path[len(fi.Path)-1]
					} else {
						name = "torrent.data"
					}
				}
				return name
			}

			// 多文件种子：保持 “种子名/子目录/文件” 结构
			if fi != nil {
				comps := append([]string{info.BestName()}, fi.BestPath()...)
				// 防止 .. 之类逃出目录
				safe, e := storage.ToSafeFilePath(comps...)
				if e != nil {
					return filepath.Join(comps...)
				}
				return safe
			}

			return info.BestName()
		},

		// 不额外创建子目录（因为我们已经用 infohash 隔离了 dataDir）
		TorrentDirMaker: func(baseDir string, info *metainfo.Info, ih metainfo.Hash) string {
			return baseDir
		},

		// 断点续传
		PieceCompletion: pc,

		// 关闭 .part 文件，直接写最终文件
		UsePartFiles: g.Some(false),
	})

	cl, err := torrent.NewClient(cfg)
	if err != nil {
		return "", fmt.Errorf("创建 BT 客户端失败: %w", err)
	}
	defer cl.Close()

	spec, err := torrent.TorrentSpecFromMagnetUri(magnet)
	if err != nil {
		return "", fmt.Errorf("解析 magnet 失败: %w", err)
	}
	if len(trackers) > 0 {
		spec.Trackers = [][]string{trackers} // 所有 tracker 放在同一 tier
	}

	t, _, err := cl.AddTorrentSpec(spec)
	if err != nil {
		return "", fmt.Errorf("添加 torrent 失败: %w", err)
	}

	// 等待获取种子信息（GotInfo 后才能确定文件结构/长度）
	<-t.GotInfo()

	// 并发连接数（可按需调优）
	t.SetMaxEstablishedConns(512)

	// 整个种子都下载
	t.DownloadAll()

	var lastDone int64
	var lastTime time.Time

	for {
		total := t.Length()
		done := t.BytesCompleted() // 已经完成并通过校验的字节数

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

		// 下载速度
		now := time.Now()
		var speed int64
		if !lastTime.IsZero() {
			delta := done - lastDone
			dt := now.Sub(lastTime).Seconds()
			if dt > 0 && delta >= 0 {
				bps := float64(delta) / dt
				if bps < 0 {
					bps = 0
				}
				speed = int64(bps + 0.5)
			}
		}
		lastTime = now
		lastDone = done

		if prog != nil {
			prog(pct, speed, done, total)
		}

		// 下载完成或进入做种状态就退出循环
		if (total > 0 && done >= total) || t.Seeding() {
			break
		}

		time.Sleep(1000 * time.Millisecond)
	}

	// 补100%
	if prog != nil {
		total := t.Length()
		if total == 0 {
			total = lastDone
		}
		prog(100, 0, total, total)
	}

	// 关键：从 dataDir 中选出真正的输出文件路径并返回（不要猜 dstPath）
	realPath, err := pickBTOutputFile(dataDir)
	if err != nil {
		return "", err
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

// findCurl 函数。
func findCurl() (string, error) {
	// PATH
	if p, err := exec.LookPath("curl"); err == nil {
		return p, nil
	}
	// ./tools/curl.exe
	exe, err := os.Executable()
	if err == nil {
		toolsDir := filepath.Join(filepath.Dir(exe), "tools")

		p := filepath.Join(toolsDir, "curl.exe")
		if st, e := os.Stat(p); e == nil && !st.IsDir() {
			return p, nil
		}

		p2 := filepath.Join(toolsDir, "curl")
		if st, e := os.Stat(p2); e == nil && !st.IsDir() {
			return p2, nil
		}
	}

	return "", fmt.Errorf("curl not found in PATH and not found in ./tools")
}

// 下载大文件（仅 curl）。
// - 写入 dstPath+".part"，成功后重命名为 dstPath。
// - 若 .part 已存在，会尝试用 curl 的 -C - 续传；若服务器不支持 Range，会自动从头下载。
func DownloadFile(ctx context.Context, url, dstPath string, progressCallback func(float64, int64)) error {
	if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
		log.LogWrite(0, "[DownloadFile]DownloadFile 创建目录失败: path=%s err=%v", dstPath, err)
		return fmt.Errorf("create dir: %w", err)
	}
	if progressCallback == nil {
		progressCallback = func(float64, int64) {}
	}

	const stallLimit = 15 * time.Second

	curlPath, err := findCurl()
	if err != nil {
		log.LogWrite(0, "[DownloadFile]DownloadFile 未找到 curl: err=%v", err)
		return err
	}

	tmpPath := dstPath + ".part"
	total := contentLength(ctx, url) // -1 表示未知

	// 是否有已存在 part
	var hasPart bool
	if st, e := os.Stat(tmpPath); e == nil && !st.IsDir() && st.Size() > 0 {
		hasPart = true
	}

	runCurl := func(withResume bool) error {
		curlCtx, cancel := context.WithCancel(ctx)
		defer cancel()

		args := []string{
			"-L", "--fail", "--silent", "--show-error",
			"--connect-timeout", "5",
			"--max-time", "0", // 0=不限制总时长（按需）
			"--output", tmpPath,
		}

		// 强制跳过证书校验
		args = append(args, "--insecure")

		if withResume {
			args = append(args, "-C", "-")
		}
		args = append(args, url)

		cmd := exec.CommandContext(curlCtx, curlPath, args...)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

		var stderr bytes.Buffer
		cmd.Stderr = &stderr

		if err := cmd.Start(); err != nil {
			return fmt.Errorf("start curl (%s): %w", curlPath, err)
		}
		go func() {
			<-curlCtx.Done()
			if cmd.Process != nil {
				_, _ = tools.RunCmd("taskkill", nil, nil, "", "/F", "/T", "/PID", strconv.Itoa(cmd.Process.Pid))
			}
		}()

		done := make(chan struct{})
		stallCh := make(chan error, 1)
		go func() {
			ticker := time.NewTicker(1 * time.Second)
			defer ticker.Stop()

			var lastBytes int64
			var lastTime = time.Now()
			var zeroDuration time.Duration

			for {
				select {
				case <-ctx.Done():
					return
				case <-done:
					return
				case <-ticker.C:
					var nowBytes int64
					if st, e := os.Stat(tmpPath); e == nil {
						nowBytes = st.Size()
					}
					now := time.Now()
					dt := now.Sub(lastTime).Seconds()
					if dt <= 0 {
						dt = 1
					}
					speed := int64(float64(nowBytes-lastBytes) / dt)
					if speed < 0 {
						speed = 0
					}
					if speed == 0 {
						zeroDuration += now.Sub(lastTime)
					} else {
						zeroDuration = 0
					}

					percent := 0.0
					if total > 0 {
						percent = float64(nowBytes) * 100 / float64(total)
						if percent > 99.9 {
							percent = 99.9
						}
						if percent < 0 {
							percent = 0
						}
					}
					progressCallback(percent, speed)

					lastBytes = nowBytes
					lastTime = now

					if zeroDuration >= stallLimit {
						select {
						case stallCh <- fmt.Errorf("下载速度为 0 超过 %s", stallLimit):
						default:
						}
						cancel()
						return
					}
				}
			}
		}()

		err := cmd.Wait()
		close(done)

		select {
		case stallErr := <-stallCh:
			return stallErr
		default:
		}

		if err == nil {
			_ = Remove(dstPath, false)
			if err := os.Rename(tmpPath, dstPath); err != nil {
				return fmt.Errorf("rename %s -> %s: %w", tmpPath, dstPath, err)
			}
			progressCallback(100, 0)
			return nil
		}

		if curlCtx.Err() != nil {
			return curlCtx.Err()
		}

		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return fmt.Errorf("curl failed: %w: %s", err, msg)
		}
		return fmt.Errorf("curl failed: %w", err)
	}

	// 续传
	// 下载 + 断点续传 + 大小校验
	const maxAttempts = 3
	attempts := 0
	withResume := hasPart

	for {
		attempts++
		if attempts > maxAttempts {
			log.LogWrite(0, "[DownloadFile]DownloadFile 超过最大尝试次数: url=%s dst=%s", url, dstPath)
			return fmt.Errorf("下载失败: 超过最大尝试次数")
		}

		err := runCurl(withResume)
		if err != nil {
			log.LogWrite(0, "[DownloadFile]DownloadFile curl失败: url=%s dst=%s err=%v", url, dstPath, err)
			if withResume {
				_ = os.Remove(tmpPath)
			}
			if withResume || hasPart {
				withResume = false
				continue
			}
			return err
		}

		if total <= 0 {
			return nil
		}

		// 从头下载
		st, statErr := os.Stat(dstPath)
		if statErr != nil {
			log.LogWrite(0, "[DownloadFile]DownloadFile Stat失败: path=%s err=%v", dstPath, statErr)
			return fmt.Errorf("stat %s 失败: %w", dstPath, statErr)
		}

		if st.Size() == total {
			return nil
		}

		if st.Size() > total {
			_ = Remove(dstPath, false)
			log.LogWrite(0, "[DownloadFile]DownloadFile 大小异常: got=%d expect=%d url=%s", st.Size(), total, url)
			return fmt.Errorf("下载文件大小异常: got=%d expect=%d", st.Size(), total)
		}

		// 小于预期大小，尝试继续下载
		if err := os.Rename(dstPath, tmpPath); err != nil {
			log.LogWrite(0, "[DownloadFile]DownloadFile 续传准备失败: path=%s err=%v", dstPath, err)
			return fmt.Errorf("续传准备失败: %w", err)
		}
		hasPart = true
		withResume = true
	}
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

// 尽量拿到 Content-Length；拿不到返回 -1（percent 就只能给 0~99.9 的“未知总量”模式）
func contentLength(ctx context.Context, url string) int64 {
	client := &http.Client{
		Transport: &http.Transport{DisableCompression: true},
	}

	// HEAD
	if req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil); err == nil {
		if resp, err := client.Do(req); err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 400 && resp.ContentLength > 0 {
				return resp.ContentLength
			}
		}
	}

	// Range: 0-0 -> Content-Range: bytes 0-0/total
	if req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil); err == nil {
		req.Header.Set("Range", "bytes=0-0")
		if resp, err := client.Do(req); err == nil {
			_ = resp.Body.Close()
			cr := resp.Header.Get("Content-Range")
			if i := strings.LastIndex(cr, "/"); i >= 0 && i+1 < len(cr) {
				if n, err := strconv.ParseInt(strings.TrimSpace(cr[i+1:]), 10, 64); err == nil && n > 0 {
					return n
				}
			}
			if resp.ContentLength > 0 {
				return resp.ContentLength
			}
		}
	}
	return -1
}

// 校验url
func httpStatus(raw string) bool {
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
