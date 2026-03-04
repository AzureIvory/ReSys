package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Client 是一个 aria2 JSON-RPC 客户端封装。
// - Endpoint：aria2 RPC 地址（默认 127.0.0.1:6800/jsonrpc）
// - hc：HTTP 客户端
// - seq：JSON-RPC 请求自增 ID
// - cmd/started：当本库自行启动 aria2c 进程时，用于进程生命周期管理
type Client struct {
	Endpoint string // default: http://127.0.0.1:6800/jsonrpc

	hc  *http.Client
	seq uint64

	// process management (only if we started aria2c ourselves)
	cmd     *exec.Cmd
	started bool
}

// Options 表示一次下载的可选参数：
// - Dir：下载目录
// - Out：输出文件名（aria2 的 out 参数）
// - Trackers：BT tracker 列表（会拼成 bt-tracker 参数）
type Options struct {
	Dir      string
	Out      string
	Trackers []string
}

// Progress 表示下载过程中的进度信息（每次轮询 tellStatus 得到并加工后回调给用户）。
// 字段含义：
// - GID：aria2 任务 ID
// - Status：任务状态（active/complete/error/removed 等）
// - Path：文件路径（从 tellStatus 的 files[0].path 推断）
// - Total / Done：总字节数 / 已完成字节数
// - DownBps：当前下载速度（bytes/s）
// - Percent：完成百分比（0~100）
// - SpeedMBps：速度换算成 MiB/s（bytes/(1024*1024)）
// - ETA：预计剩余时间
// - ErrCode / ErrMsg：失败时的错误码/错误信息（来自 aria2）
type Progress struct {
	GID       string
	Status    string
	Path      string
	Total     int64 // bytes
	Done      int64 // bytes
	DownBps   int64 // bytes/s
	Percent   float64
	SpeedMBps float64 // MB/s (MiB, i.e., bytes/(1024*1024))
	ETA       time.Duration
	ErrCode   string
	ErrMsg    string
}

// Result 表示最终结果（完成/错误/移除都会返回一个 Result；错误时同时返回 error）。
type Result struct {
	GID     string
	Status  string
	Path    string
	Total   int64
	Done    int64
	DownBps int64
	ErrCode string
	ErrMsg  string
}

// ProgressFunc 是进度回调函数类型：每次轮询得到新进度都会调用一次。
type ProgressFunc func(p Progress)

// Newaria2 创建一个 Client，并确保 aria2 RPC 可用：
// - 先尝试 ping 已存在的 aria2 RPC；
// - 若不可用，则尝试从当前程序目录下的 ./tools/aria2c.exe 启动一个 aria2c 并等待其就绪。
func Newaria2() (*Client, error) {
	c := &Client{
		Endpoint: "http://127.0.0.1:6800/jsonrpc",
		hc: &http.Client{
			Transport: &http.Transport{
				Proxy:               http.ProxyFromEnvironment,
				MaxIdleConns:        32,
				IdleConnTimeout:     60 * time.Second,
				TLSHandshakeTimeout: 10 * time.Second,
			},
			Timeout: 15 * time.Second,
		},
	}
	if err := c.ensureRPCReady(); err != nil {
		return nil, err
	}
	return c, nil
}

// Close 关闭客户端占用的资源：
// - 只有当本库自己启动了 aria2c（c.started=true）时才会尝试杀进程；
// - 若 aria2c 不是本库启动的，则 Close 不做任何事。
func (c *Client) Close() error {
	if c == nil || !c.started || c.cmd == nil || c.cmd.Process == nil {
		return nil
	}
	_ = c.cmd.Process.Kill()
	_, _ = c.cmd.Process.Wait()
	return nil
}

// Download 以默认 context.Background() 下载普通 URL 资源。
// src 必须是 URL（http/https/ftp/sftp）。
func (c *Client) Download(src string, opt Options, cb ProgressFunc) (Result, error) {
	return c.DownloadContext(context.Background(), src, opt, cb)
}

// DownloadBt 以默认 context.Background() 下载 BT 资源：magnet 或 .torrent（本地/远程）。
func (c *Client) DownloadBt(src string, opt Options, cb ProgressFunc) (Result, error) {
	return c.DownloadBtContext(context.Background(), src, opt, cb)
}

// DownloadContext 使用指定 ctx 下载普通 URL 资源：
// 1) 参数校验（client 非空、src 是 URL）
// 2) addAny 创建 aria2 任务并返回 gid
// 3) wait 轮询任务状态直到完成/错误/移除/ctx 取消
func (c *Client) DownloadContext(ctx context.Context, src string, opt Options, cb ProgressFunc) (Result, error) {
	if c == nil {
		return Result{}, errors.New("nil client")
	}
	if !looksLikeURL(src) {
		return Result{}, fmt.Errorf("Download expects a URL, got: %q", src)
	}
	gid, err := c.addAny(ctx, src, opt)
	if err != nil {
		return Result{}, err
	}
	return c.wait(ctx, gid, cb)
}

// DownloadBtContext 使用指定 ctx 下载 BT 资源（magnet 或 .torrent）：
// 1) 参数校验（client 非空、src 是 magnet 或 torrent）
// 2) addAny 创建 aria2 任务并返回 gid
// 3) wait 轮询任务状态直到结束
func (c *Client) DownloadBtContext(ctx context.Context, src string, opt Options, cb ProgressFunc) (Result, error) {
	if c == nil {
		return Result{}, errors.New("nil client")
	}
	if !isMagnet(src) && !isTorrent(src) {
		return Result{}, fmt.Errorf("DownloadBt expects magnet or .torrent, got: %q", src)
	}
	gid, err := c.addAny(ctx, src, opt)
	if err != nil {
		return Result{}, err
	}
	return c.wait(ctx, gid, cb)
}

// DefaultProgressPrinter 默认的进度打印器：
// - 使用 \r 复写同一行输出进度；
// - 当任务 complete/error/removed 时追加换行。
func DefaultProgressPrinter(p Progress) {
	totalMB := float64(p.Total) / (1024 * 1024)
	doneMB := float64(p.Done) / (1024 * 1024)

	eta := "--"
	if p.ETA > 0 {
		eta = p.ETA.Truncate(time.Second).String()
	}

	// \r rewrites the same line; add newline when finished/error
	fmt.Printf("\r%.2f%%  %.2f/%.2f MB  %.2f MB/s  ETA %s  %s",
		p.Percent, doneMB, totalMB, p.SpeedMBps, eta, filepath.Base(p.Path))

	if p.Status == "complete" || p.Status == "error" || p.Status == "removed" {
		fmt.Println()
	}
}

// ----------------- internal: rpc -----------------

// rpcReq 表示 aria2 JSON-RPC 请求结构体。
type rpcReq struct {
	JSONRPC string `json:"jsonrpc"`
	ID      uint64 `json:"id"`
	Method  string `json:"method"`
	Params  []any  `json:"params,omitempty"`
}

// rpcResp 表示 aria2 JSON-RPC 响应结构体：
// - Result：成功时的返回 JSON
// - Error：失败时的错误码/错误信息
type rpcResp struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      uint64          `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// call 执行一次 JSON-RPC 调用：
// 1) 自增请求 ID 并序列化请求体
// 2) POST 到 c.Endpoint
// 3) 读取并解析响应
// 4) 如果 RPC 层报错，转成 Go error
func (c *Client) call(ctx context.Context, method string, params ...any) (json.RawMessage, error) {
	id := atomic.AddUint64(&c.seq, 1)
	body, err := json.Marshal(rpcReq{
		JSONRPC: "2.0",
		ID:      id,
		Method:  method,
		Params:  params,
	})
	if err != nil {
		return nil, fmt.Errorf("rpc encode failed: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("rpc read failed: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("rpc http %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}

	var rr rpcResp
	if err := json.Unmarshal(b, &rr); err != nil {
		return nil, fmt.Errorf("rpc decode failed: %w, body=%s", err, string(b))
	}
	if rr.Error != nil {
		return nil, fmt.Errorf("rpc error(%d): %s", rr.Error.Code, rr.Error.Message)
	}
	return rr.Result, nil
}

// ensureRPCReady 确保 aria2 RPC 可用：
// - 先快速 ping 一次已有 aria2；若成功直接返回；
// - 否则尝试启动 ./tools/aria2c.exe，并在 6 秒内轮询等待 RPC 就绪；
// - 若仍失败则关闭进程并返回清晰错误（可能端口被占用等）。
func (c *Client) ensureRPCReady() error {
	// quick ping existing aria2
	if err := c.pingOnce(800 * time.Millisecond); err == nil {
		return nil
	}

	// start aria2 from tools folder near the running program
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot locate executable: %w", err)
	}
	exeDir := filepath.Dir(exePath)
	aria2Path := filepath.Join(exeDir, "tools", "aria2c.exe")

	if _, err := os.Stat(aria2Path); err != nil {
		return fmt.Errorf("aria2c not found: %s (expected in ./tools). err=%v", aria2Path, err)
	}

	// If port is occupied by something else, aria2 won't start; we surface a clear error later.
	args := []string{
		"--enable-rpc=true",
		"--rpc-listen-port=6800",
		"--rpc-listen-all=false", // local-only
		"--rpc-allow-origin-all=true",
		"--log-level=warn",
	}

	cmd := exec.Command(aria2Path, args...)
	cmd.Dir = exeDir
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard

	if runtime.GOOS == "windows" {
		// HideWindow best-effort（这里不额外引入 syscall，保持依赖简单）
		// 如果需要更严格隐藏窗口，可加：cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start aria2c failed: %w", err)
	}

	c.cmd = cmd
	c.started = true

	// Wait for RPC ready
	deadline := time.Now().Add(6 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		if err := c.pingOnce(800 * time.Millisecond); err == nil {
			return nil
		} else {
			lastErr = err
		}
		time.Sleep(200 * time.Millisecond)
	}

	_ = c.Close()
	return fmt.Errorf("aria2 rpc not ready on 127.0.0.1:6800 (maybe port occupied). last=%v", lastErr)
}

// pingOnce 使用短超时调用 aria2.getVersion，用于探测 RPC 是否可达。
func (c *Client) pingOnce(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	_, err := c.call(ctx, "aria2.getVersion")
	return err
}

// addAny 根据 src 类型（URL/magnet/torrent）创建 aria2 任务并返回 GID。
// - URL/magnet：走 aria2.addUri
// - torrent：加载 .torrent bytes（本地/远程），base64 后走 aria2.addTorrent
func (c *Client) addAny(ctx context.Context, src string, opt Options) (string, error) {
	options := map[string]string{}
	if opt.Dir != "" {
		options["dir"] = opt.Dir
	}
	if opt.Out != "" {
		options["out"] = opt.Out
	}
	if len(opt.Trackers) > 0 {
		options["bt-tracker"] = strings.Join(opt.Trackers, ",")
	}

	// magnet 或普通 URL（且不是 .torrent URL）直接 addUri
	if isMagnet(src) || (looksLikeURL(src) && !isTorrent(src)) {
		uris := []string{src}
		res, err := c.call(ctx, "aria2.addUri", uris, options)
		if err != nil {
			return "", err
		}
		var gid string
		_ = json.Unmarshal(res, &gid)
		if gid == "" {
			return "", errors.New("aria2.addUri returned empty gid")
		}
		return gid, nil
	}

	// torrent: local path or remote URL
	if isTorrent(src) {
		data, err := loadTorrentBytes(ctx, src, c.hc)
		if err != nil {
			return "", err
		}
		b64 := base64.StdEncoding.EncodeToString(data)

		res, err := c.call(ctx, "aria2.addTorrent", b64, []string{}, options)
		if err != nil {
			return "", err
		}
		var gid string
		_ = json.Unmarshal(res, &gid)
		if gid == "" {
			return "", errors.New("aria2.addTorrent returned empty gid")
		}
		return gid, nil
	}

	return "", fmt.Errorf("unsupported src: %q", src)
}

// wait 每秒轮询一次 aria2.tellStatus，并通过 cb 回调进度。
// 结束条件：
// - status=complete：返回结果 nil error
// - status=error/removed：返回结果 + error（含 code/msg）
// - ctx 被取消：返回最新结果 + ctx.Err()
func (c *Client) wait(ctx context.Context, gid string, cb ProgressFunc) (Result, error) {
	if cb == nil {
		cb = DefaultProgressPrinter
	}

	keys := []string{
		"gid", "status", "totalLength", "completedLength", "downloadSpeed",
		"errorCode", "errorMessage", "files",
	}

	// immediate first tick（让用户立刻看到一次进度）
	p, err := c.tellStatus(ctx, gid, keys)
	if err == nil {
		cb(p)
	}

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// best-effort fetch latest status
			latest, _ := c.tellStatus(context.Background(), gid, keys)
			return toResult(latest), ctx.Err()
		case <-ticker.C:
			st, err := c.tellStatus(ctx, gid, keys)
			if err != nil {
				return Result{GID: gid}, err
			}
			cb(st)

			switch st.Status {
			case "complete":
				return toResult(st), nil
			case "error", "removed":
				msg := st.ErrMsg
				if msg == "" {
					msg = "download stopped"
				}
				return toResult(st), fmt.Errorf("aria2 %s (code=%s): %s", st.Status, st.ErrCode, msg)
			}
		}
	}
}

// tellStatusResp 是 aria2.tellStatus 返回 JSON 的结构体映射。
// 注意：aria2 的数字字段经常以字符串形式返回。
type tellStatusResp struct {
	GID             string `json:"gid"`
	Status          string `json:"status"`
	TotalLength     string `json:"totalLength"`
	CompletedLength string `json:"completedLength"`
	DownloadSpeed   string `json:"downloadSpeed"`
	ErrorCode       string `json:"errorCode"`
	ErrorMessage    string `json:"errorMessage"`
	Files           []struct {
		Path string `json:"path"`
	} `json:"files"`
}

// tellStatus 调用 aria2.tellStatus 并将返回结果转换为 Progress：
// - 把字符串数字转为 int64
// - 计算百分比/速度/ETA
// - 提取第一个文件路径作为展示路径
func (c *Client) tellStatus(ctx context.Context, gid string, keys []string) (Progress, error) {
	res, err := c.call(ctx, "aria2.tellStatus", gid, keys)
	if err != nil {
		return Progress{GID: gid}, err
	}

	var ts tellStatusResp
	if err := json.Unmarshal(res, &ts); err != nil {
		return Progress{GID: gid}, err
	}

	total := parseI64(ts.TotalLength)
	done := parseI64(ts.CompletedLength)
	down := parseI64(ts.DownloadSpeed)

	path := ""
	if len(ts.Files) > 0 {
		path = ts.Files[0].Path
	}

	pct := 0.0
	if total > 0 {
		pct = (float64(done) / float64(total)) * 100
	}

	speedMB := float64(down) / (1024 * 1024)

	eta := time.Duration(0)
	if down > 0 && total > 0 && done < total {
		eta = time.Duration((total-done)/down) * time.Second
	}

	return Progress{
		GID:       ts.GID,
		Status:    ts.Status,
		Path:      path,
		Total:     total,
		Done:      done,
		DownBps:   down,
		Percent:   pct,
		SpeedMBps: speedMB,
		ETA:       eta,
		ErrCode:   ts.ErrorCode,
		ErrMsg:    ts.ErrorMessage,
	}, nil
}

// toResult 将 Progress 转换为最终 Result（字段基本一一对应）。
func toResult(p Progress) Result {
	return Result{
		GID:     p.GID,
		Status:  p.Status,
		Path:    p.Path,
		Total:   p.Total,
		Done:    p.Done,
		DownBps: p.DownBps,
		ErrCode: p.ErrCode,
		ErrMsg:  p.ErrMsg,
	}
}

// loadTorrentBytes 加载 .torrent 文件内容：
// - 若 src 是 URL，则通过 HTTP GET 拉取；
// - 否则视为本地路径并 os.ReadFile。
func loadTorrentBytes(ctx context.Context, src string, hc *http.Client) ([]byte, error) {
	if looksLikeURL(src) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
		if err != nil {
			return nil, err
		}
		resp, err := hc.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode/100 != 2 {
			b, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("fetch torrent failed: %s: %s", resp.Status, strings.TrimSpace(string(b)))
		}
		return io.ReadAll(resp.Body)
	}
	return os.ReadFile(src)
}

// looksLikeURL 粗略判断是否为 URL（支持 http/https/ftp/sftp）。
func looksLikeURL(s string) bool {
	ss := strings.ToLower(strings.TrimSpace(s))
	return strings.HasPrefix(ss, "http://") || strings.HasPrefix(ss, "https://") ||
		strings.HasPrefix(ss, "ftp://") || strings.HasPrefix(ss, "sftp://")
}

// isMagnet 判断字符串是否为 magnet 链接（前缀 magnet:）。
func isMagnet(s string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(s)), "magnet:")
}

// isTorrent 判断 src 是否为 .torrent：
// - 若是 URL，则检查 URL path 的扩展名是否为 .torrent；
// - 若是本地路径，则检查文件扩展名。
func isTorrent(s string) bool {
	ss := strings.TrimSpace(s)
	if looksLikeURL(ss) {
		u, err := url.Parse(ss)
		if err != nil {
			return false
		}
		return strings.EqualFold(filepath.Ext(u.Path), ".torrent")
	}
	return strings.EqualFold(filepath.Ext(ss), ".torrent")
}

// parseI64 把 aria2 返回的“数字字符串”解析成 int64。
// aria2 有时返回浮点风格字符串，这里做容错：先 ParseInt，失败再 ParseFloat。
func parseI64(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	// aria2 returns numbers as strings; be tolerant
	n, err := strconv.ParseInt(s, 10, 64)
	if err == nil {
		return n
	}
	// fallback: try float
	f, err2 := strconv.ParseFloat(s, 64)
	if err2 == nil {
		return int64(f)
	}
	return 0
}

// main1 演示用入口：
// - 例1：HTTP 文件下载
// - 例2：BT/magnet 下载（注释掉了，需要你自行替换 magnet 链接）
func main1() {
	c, err := Newaria2()
	if err != nil {
		logWrite(-2, err.Error())
	}
	defer c.Close()

	// 例1：普通文件下载（URL）
	url := "https://speed.hetzner.de/100MB.bin"

	// 你可以传 nil，让库默认每秒打印进度（MB/s）
	res, err := c.Download(url, Options{
		Dir: "downloads",
		Out: "100MB.bin",
	}, nil)
	if err != nil {
		logWrite(-2, err.Error())
	}
	fmt.Println("下载完成:", res.Path)

	// 例2：BT / magnet（把 magnet 链接换成你的）
	/*
		magnet := "magnet:?xt=urn:btih:...."
		_, err = c.DownloadBt(magnet, aria2dl.Options{
			Dir: "downloads",
		}, func(p aria2dl.Progress) {
			// 自定义回调：每秒都会进来一次
			fmt.Printf("\rBT %.2f%%  %.2f MB/s", p.Percent, p.SpeedMBps)
			if p.Status == "complete" || p.Status == "error" {
				fmt.Println()
			}
		})
		if err != nil {
			log.Fatal(err)
		}
	*/
}
