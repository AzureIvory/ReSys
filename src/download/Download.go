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
	"os"
	"path/filepath"
	"strings"
	"time"

	g "github.com/anacrolix/generics"
	"github.com/anacrolix/torrent"
	"github.com/anacrolix/torrent/metainfo"
	"github.com/anacrolix/torrent/storage"
)

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
func downloadBTAria2(magnet, dir string, prog func(pct int, speed, done, total int64)) (string, error) {
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

	sum := sha1.Sum([]byte(strings.ToLower(magnet)))
	tag := hex.EncodeToString(sum[:])[:12]
	dataDir := filepath.Join(absDir, ".btdata", tag)
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return "", fmt.Errorf("创建 BT 数据目录失败: %w", err)
	}

	trackers, err := loadSubscribedTrackers()
	if err != nil {
		fmt.Println("警告: 加载 trackers 失败，将使用 aria2 默认 DHT/PEX:", err)
	}

	c, err := Newaria2()
	if err != nil {
		return "", fmt.Errorf("初始化 aria2 失败: %w", err)
	}
	defer c.Close()

	// 第一阶段：只拿 metadata，并保存成 .torrent
	_, err = c.DownloadBtContext(context.Background(), magnet, Options{
		Dir:            dataDir,
		Trackers:       trackers,
		BTMetadataOnly: true,
		BTSaveMetadata: true,
		FollowTorrent:  "false",
	}, nil)
	if err != nil {
		return "", fmt.Errorf("获取 BT metadata 失败: %w", err)
	}

	torrentPath, err := pickTorrentFile(dataDir)
	if err != nil {
		return "", err
	}

	// 第二阶段：显式用 .torrent 开始真正内容下载
	res, err := c.DownloadBtContext(context.Background(), torrentPath, Options{
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

	realPath, err := pickBTOutputFile(dataDir)
	if err != nil {
		// 兜底用 aria2 返回的 path
		fallbackPath := strings.TrimSpace(res.Path)
		if fallbackPath != "" {
			if st, e := os.Stat(fallbackPath); e == nil && !st.IsDir() && st.Size() > 0 {
				return fallbackPath, nil
			}
		}
		return "", err
	}

	if prog != nil {
		if st, e := os.Stat(realPath); e == nil && !st.IsDir() && st.Size() > 0 {
			prog(100, 0, st.Size(), st.Size())
		}
	}
	return realPath, nil
}
func downloadBTTorrentLegacy(magnet, dir string, prog func(pct int, speed, done, total int64)) (string, error) {
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

	ih, err := magnetInfoHash(magnet)
	if err != nil {
		return "", err
	}
	tag := ih
	if len(tag) > 12 {
		tag = tag[:12]
	}

	dataDir := filepath.Join(absDir, ".btdata", tag)
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return "", fmt.Errorf("创建 BT 数据目录失败: %w", err)
	}
	cacheDir := filepath.Join(absDir, ".btcache", tag)
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return "", fmt.Errorf("创建 BT 缓存目录失败: %w", err)
	}

	trackers, err := loadSubscribedTrackers()
	if err != nil {
		fmt.Println("警告: 加载 trackers 失败，将仅依赖 DHT/PEX:", err)
	}

	pc, err := storage.NewDefaultPieceCompletionForDir(cacheDir)
	if err != nil {
		return "", fmt.Errorf("创建 PieceCompletion 失败: %w", err)
	}

	cfg := torrent.NewDefaultClientConfig()
	cfg.DataDir = cacheDir
	cfg.Seed = false
	cfg.NoUpload = false
	cfg.DownloadRateLimiter = nil
	cfg.DefaultStorage = storage.NewFileOpts(storage.NewFileClientOpts{
		ClientBaseDir: dataDir,
		FilePathMaker: func(opts storage.FilePathMakerOpts) string {
			info := opts.Info
			fi := opts.File

			if info == nil {
				if fi != nil && len(fi.Path) > 0 {
					return fi.Path[len(fi.Path)-1]
				}
				return "torrent.data"
			}

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

			if fi != nil {
				comps := append([]string{info.BestName()}, fi.BestPath()...)
				safe, e := storage.ToSafeFilePath(comps...)
				if e != nil {
					return filepath.Join(comps...)
				}
				return safe
			}

			return info.BestName()
		},
		TorrentDirMaker: func(baseDir string, info *metainfo.Info, ih metainfo.Hash) string {
			return baseDir
		},
		PieceCompletion: pc,
		UsePartFiles:    g.Some(false),
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
		spec.Trackers = mergeTorrentTrackers(spec.Trackers, trackers)
	}

	t, _, err := cl.AddTorrentSpec(spec)
	if err != nil {
		return "", fmt.Errorf("添加 torrent 失败: %w", err)
	}

	defer t.Drop()
	<-t.GotInfo()
	t.SetMaxEstablishedConns(512)
	t.DownloadAll()

	var lastDone int64
	var lastTime time.Time

	for {
		total := t.Length()
		done := t.BytesCompleted()

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

		// With Seed enabled, Seeding() only means uploads are allowed, not that download is complete.
		if total > 0 && done >= total {
			break
		}

		time.Sleep(time.Second)
	}

	if prog != nil {
		total := t.Length()
		if total == 0 {
			total = lastDone
		}
		prog(100, 0, total, total)
	}

	realPath, err := pickBTOutputFile(dataDir)
	if err != nil {
		return "", err
	}
	return realPath, nil
}

func downloadBTSharedBroken(magnet, dir string, prog func(pct int, speed, done, total int64)) (string, error) {
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

	ih, err := magnetInfoHash(magnet)
	if err != nil {
		return "", err
	}
	tag := ih
	if len(tag) > 12 {
		tag = tag[:12]
	}

	dataDir := filepath.Join(absDir, ".btdata", tag)
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return "", fmt.Errorf("创建 BT 数据目录失败: %w", err)
	}

	trackers, err := loadSubscribedTrackers()
	if err != nil {
		fmt.Println("警告: 加载 trackers 失败，将仅依赖 DHT/PEX:", err)
	}

	cl, err := getBTClient()
	if err != nil {
		return "", fmt.Errorf("创建 BT 客户端失败: %w", err)
	}

	spec, err := torrent.TorrentSpecFromMagnetUri(magnet)
	if err != nil {
		return "", fmt.Errorf("解析 magnet 失败: %w", err)
	}
	spec.Storage = newBTStorage(dataDir)

	t, _, err := cl.AddTorrentSpec(spec)
	if err != nil {
		return "", fmt.Errorf("添加 torrent 失败: %w", err)
	}
	// Drop 只释放连接和元数据句柄，不会删除已落盘的文件。
	defer t.Drop()

	if len(trackers) > 0 {
		t.AddTrackers(trackerAnnounceList(trackers))
	}
	<-t.GotInfo()
	t.SetMaxEstablishedConns(512)
	t.DownloadAll()
	t.AllowDataDownload()

	var lastDone int64
	var lastRead int64
	var lastTime time.Time

	for {
		total := t.Length()
		done := t.BytesCompleted()
		stats := t.Stats()
		read := (&stats.BytesReadUsefulData).Int64()

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

		now := time.Now()
		var speed int64
		if !lastTime.IsZero() {
			delta := read - lastRead
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
		lastRead = read

		if prog != nil {
			prog(pct, speed, done, total)
		}

		if (total > 0 && done >= total) || t.Seeding() {
			break
		}

		time.Sleep(time.Second)
	}

	if prog != nil {
		total := t.Length()
		if total == 0 {
			total = lastDone
		}
		prog(100, 0, total, total)
	}

	realPath, err := pickBTOutputFile(dataDir)
	if err != nil {
		return "", err
	}
	return realPath, nil
}

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

	ih, err := magnetInfoHash(magnet)
	if err != nil {
		return "", err
	}
	tag := ih
	if len(tag) > 12 {
		tag = tag[:12]
	}

	dataDir := filepath.Join(absDir, ".btdata", tag)
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return "", fmt.Errorf("创建 BT 数据目录失败: %w", err)
	}

	trackers, err := loadSubscribedTrackers()
	if err != nil {
		fmt.Println("警告: 加载 trackers 失败，将仅依赖 DHT/PEX:", err)
	}

	cl, err := getBTClient()
	if err != nil {
		return "", fmt.Errorf("创建 BT 客户端失败: %w", err)
	}

	spec, err := torrent.TorrentSpecFromMagnetUri(magnet)
	if err != nil {
		return "", fmt.Errorf("解析 magnet 失败: %w", err)
	}
	spec.Storage = newBTStorage(dataDir)

	t, isNew, err := cl.AddTorrentSpec(spec)
	if err != nil {
		return "", fmt.Errorf("添加 torrent 失败: %w", err)
	}
	if !isNew {
		t.Drop()
		t, _, err = cl.AddTorrentSpec(spec)
		if err != nil {
			return "", fmt.Errorf("重新添加 torrent 失败: %w", err)
		}
	}
	// Drop 只释放句柄和连接，不会删除已落盘的文件。
	defer t.Drop()
	if len(trackers) > 0 {
		t.AddTrackers(trackerAnnounceList(trackers))
	}
	<-t.GotInfo()
	t.SetMaxEstablishedConns(512)
	t.DownloadAll()
	t.AllowDataDownload()

	var lastDone int64
	var lastRead int64
	var lastTime time.Time

	for {
		total := t.Length()
		done := t.BytesCompleted()
		stats := t.Stats()
		read := (&stats.BytesReadUsefulData).Int64()

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

		now := time.Now()
		var speed int64
		if !lastTime.IsZero() {
			delta := read - lastRead
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
		lastRead = read

		if prog != nil {
			prog(pct, speed, done, total)
		}

		if total > 0 && done >= total {
			break
		}

		time.Sleep(time.Second)
	}

	if prog != nil {
		total := t.Length()
		if total == 0 {
			total = lastDone
		}
		prog(100, 0, total, total)
	}

	realPath, err := pickBTOutputFile(dataDir)
	if err != nil {
		return "", err
	}
	return realPath, nil
}

func magnetInfoHash(magnet string) (string, error) {
	m, err := metainfo.ParseMagnetUri(strings.TrimSpace(magnet))
	if err != nil {
		return "", fmt.Errorf("解析 magnet infohash 失败: %w", err)
	}
	if m.InfoHash.IsZero() {
		return "", fmt.Errorf("magnet 缺少 infohash: %s", magnet)
	}
	return strings.ToLower(m.InfoHash.HexString()), nil
}

func mergeTorrentTrackers(existing [][]string, extra []string) [][]string {
	if len(extra) == 0 {
		return existing
	}

	merged := make([]string, 0, len(extra))
	for _, tier := range existing {
		merged = append(merged, tier...)
	}
	merged = append(merged, extra...)
	merged = uniqueStrings(merged)
	if len(merged) == 0 {
		return nil
	}
	return [][]string{merged}
}

func pickTorrentFile(root string) (string, error) {
	var best string
	var bestMod time.Time

	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if strings.ToLower(filepath.Ext(p)) != ".torrent" {
			return nil
		}
		st, e := os.Stat(p)
		if e != nil {
			return nil
		}
		if best == "" || st.ModTime().After(bestMod) {
			best = p
			bestMod = st.ModTime()
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if best == "" {
		return "", fmt.Errorf("未找到 metadata 保存下来的 .torrent 文件: %s", root)
	}
	return best, nil
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
