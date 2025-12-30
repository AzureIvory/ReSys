package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
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
	"github.com/cavaliergopher/grab/v3"
)

// trackers.txt订阅URL列表
var trackerTxtURLs = []string{
	"https://raw.githubusercontent.com/adysec/tracker/main/trackers_best.txt",
	"https://down.adysec.com/trackers_best.txt",
}

// 备用 trackers.txt URL
const fallbackTrackerURL = "https://api.ttraw.com/trackers.txt"

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

	// 用来存放 BT 元数据 / piece completion 的缓存目录
	cacheDir := filepath.Join(absDir, ".btcache")
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return fmt.Errorf("创建 BT 缓存目录失败: %w", err)
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
		return fmt.Errorf("创建 PieceCompletion 失败: %w", err)
	}

	cfg := torrent.NewDefaultClientConfig()
	cfg.DataDir = cacheDir        // 客户端自身元数据
	cfg.Seed = false              // 下载完不长期做种
	cfg.NoUpload = false          // 按需上传
	cfg.DownloadRateLimiter = nil // 不限速

	cfg.DefaultStorage = storage.NewFileOpts(storage.NewFileClientOpts{
		ClientBaseDir: absDir,

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
				safe, err := storage.ToSafeFilePath(comps...)
				if err != nil {
					// 出问题就退回普通拼接
					return filepath.Join(comps...)
				}
				return safe
			}

			return info.BestName()
		},

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
				bps := float64(delta) / dt // bytes per second
				if bps < 0 {
					bps = 0
				}
				speed = int64(bps + 0.5) //B/s
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

		time.Sleep(1000 * time.Millisecond) // 1000ms 回调
	}

	// 补100%
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

// 下载大文件。
// - 会先写 dstPath+".part"，成功后再重命名为 dstPath。
// - 如果 .part 已存在且服务器支持 Range，会自动从已有位置续传。
func DownloadFile(ctx context.Context, url, dstPath string, progressCallback func(float64, int64)) error {
	if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
		return fmt.Errorf("create dir: %w", err)
	}
	if progressCallback == nil {
		progressCallback = func(float64, int64) {}
	}

	tmpPath := dstPath + ".part"

	// 尝试找到curl
	var curlPath string
	if p, err := exec.LookPath("curl"); err == nil {
		curlPath = p
	} else {
		exe, e2 := os.Executable()
		if e2 == nil {
			name := "curl.exe"
			p2 := filepath.Join(filepath.Dir(exe), "tools", name)
			if st, e3 := os.Stat(p2); e3 == nil && !st.IsDir() {
				curlPath = p2
			}
		}
	}

	//curl
	var curlErr error
	if curlPath == "" {
		curlErr = fmt.Errorf("curl not found in PATH and not found in ./tools")
	} else {
		total := contentLength(ctx, url) // -1 表示未知
		cmd := exec.CommandContext(ctx, curlPath,
			"-L", "--fail", "--silent", "--show-error",
			"--output", tmpPath,
			url,
		)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		var stderr bytes.Buffer
		cmd.Stderr = &stderr

		if err := cmd.Start(); err != nil {
			curlErr = fmt.Errorf("start curl (%s): %w", curlPath, err)
		} else {
			done := make(chan struct{})
			go func() {
				ticker := time.NewTicker(1 * time.Second)
				defer ticker.Stop()
				var lastBytes int64
				lastTime := time.Now()

				for {
					select {
					case <-ctx.Done():
						return
					case <-done:
						return
					case <-ticker.C:
						var nowBytes int64
						if st, err := os.Stat(tmpPath); err == nil {
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
					}
				}
			}()

			err := cmd.Wait()
			close(done)

			if err == nil {
				_ = os.Remove(dstPath) // Windows rename 不覆盖，先删更稳
				if err := os.Rename(tmpPath, dstPath); err != nil {
					return fmt.Errorf("rename %s -> %s: %w", tmpPath, dstPath, err)
				}
				progressCallback(100, 0)
				return nil
			}

			if ctx.Err() != nil {
				return ctx.Err()
			}
			msg := strings.TrimSpace(stderr.String())
			if msg != "" {
				curlErr = fmt.Errorf("curl failed (%s): %w: %s", curlPath, err, msg)
			} else {
				curlErr = fmt.Errorf("curl failed (%s): %w", curlPath, err)
			}
		}
	}

	// 用户取消/超时就不再 fallback
	if ctx.Err() != nil {
		return ctx.Err()
	}
	_ = os.Remove(tmpPath) // 清理 curl 残留

	// grab
	req, err := grab.NewRequest(tmpPath, url)
	if err != nil {
		return fmt.Errorf("grab new request: %w (curlErr=%v)", err, curlErr)
	}
	req = req.WithContext(ctx)
	resp := grab.NewClient().Do(req)

	done2 := make(chan struct{})
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-done2:
				return
			case <-ticker.C:
				p := resp.Progress() * 100
				if p > 99.9 {
					p = 99.9
				}
				s := int64(resp.BytesPerSecond())
				if s < 0 {
					s = 0
				}
				progressCallback(p, s)
			}
		}
	}()

	grabErr := resp.Err()
	close(done2)

	if grabErr == nil {
		_ = os.Remove(dstPath)
		if err := os.Rename(tmpPath, dstPath); err != nil {
			return fmt.Errorf("rename %s -> %s: %w", tmpPath, dstPath, err)
		}
		progressCallback(100, 0)
		return nil
	}

	if ctx.Err() != nil {
		return ctx.Err()
	}
	return fmt.Errorf("download failed (curl then grab): curl=%v; grab=%w", curlErr, grabErr)
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

// 使用 HEAD 快速检测 URL 是否可用
func httpStatus(raw string) bool {
	req, err := http.NewRequest(http.MethodHead, raw, nil)
	if err != nil {
		return false
	}
	resp, err := hc.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
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
