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

// Client is a lightweight aria2 JSON-RPC client for local-only use (127.0.0.1).
// It can auto-start aria2c.exe from ./tools when RPC is not available.
type Client struct {
	Endpoint string // default: http://127.0.0.1:6800/jsonrpc

	hc  *http.Client
	seq uint64

	// process management (only if we started aria2c ourselves)
	cmd     *exec.Cmd
	started bool
}

// Options controls download behavior.
type Options struct {
	Dir      string   // download directory (relative is allowed)
	Out      string   // output filename (HTTP/HTTPS single file only; BT may ignore)
	Trackers []string // optional bt-tracker list (helps magnets / cold torrents)
}

// Progress is reported once per second while waiting.
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

// Result is returned when download completes (or errors).
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

// ProgressFunc is called once per second while waiting.
// If nil, the client uses DefaultProgressPrinter.
type ProgressFunc func(p Progress)

// NewLocal creates a local-only client and ensures aria2 RPC is ready.
// It will try to reuse an existing aria2 RPC on 127.0.0.1:6800.
// If not available, it starts ./tools/aria2c.exe (relative to the running program).
func NewLocal() (*Client, error) {
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

// Close stops aria2c only if it was started by this client.
// If aria2 was already running, Close does nothing.
func (c *Client) Close() error {
	if c == nil || !c.started || c.cmd == nil || c.cmd.Process == nil {
		return nil
	}
	_ = c.cmd.Process.Kill()
	_, _ = c.cmd.Process.Wait()
	return nil
}

// Download downloads a normal URL (http/https/ftp/sftp...) via aria2.
// It waits until complete/error, and calls cb once per second.
// If cb is nil, it prints progress once per second to stdout.
func (c *Client) Download(src string, opt Options, cb ProgressFunc) (Result, error) {
	return c.DownloadContext(context.Background(), src, opt, cb)
}

// DownloadBt downloads a magnet or .torrent (local path or remote URL) via aria2.
// It waits until complete/error, and calls cb once per second.
// If cb is nil, it prints progress once per second to stdout.
func (c *Client) DownloadBt(src string, opt Options, cb ProgressFunc) (Result, error) {
	return c.DownloadBtContext(context.Background(), src, opt, cb)
}

// DownloadContext is the context-aware variant of Download.
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

// DownloadBtContext is the context-aware variant of DownloadBt.
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

// DefaultProgressPrinter prints one-line progress each second.
// You can pass it as cb: aria2dl.DefaultProgressPrinter
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

type rpcReq struct {
	JSONRPC string `json:"jsonrpc"`
	ID      uint64 `json:"id"`
	Method  string `json:"method"`
	Params  []any  `json:"params,omitempty"`
}

type rpcResp struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      uint64          `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// call performs a JSON-RPC call to aria2.
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

// ensureRPCReady tries to ping aria2 RPC; if not available, starts ./tools/aria2c.exe and waits for readiness.
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
		// HideWindow best-effort (no extra imports, keep simple)
		// If you want it strictly, add: cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
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

// pingOnce calls aria2.getVersion with a short timeout to verify RPC availability.
func (c *Client) pingOnce(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	_, err := c.call(ctx, "aria2.getVersion")
	return err
}

// addAny adds URL/magnet/torrent to aria2 and returns GID.
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

// wait polls aria2.tellStatus once per second and calls cb with progress.
// It returns on complete/error/removed or ctx cancellation.
func (c *Client) wait(ctx context.Context, gid string, cb ProgressFunc) (Result, error) {
	if cb == nil {
		cb = DefaultProgressPrinter
	}

	keys := []string{
		"gid", "status", "totalLength", "completedLength", "downloadSpeed",
		"errorCode", "errorMessage", "files",
	}

	// immediate first tick (so user sees progress instantly)
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

func looksLikeURL(s string) bool {
	ss := strings.ToLower(strings.TrimSpace(s))
	return strings.HasPrefix(ss, "http://") || strings.HasPrefix(ss, "https://") ||
		strings.HasPrefix(ss, "ftp://") || strings.HasPrefix(ss, "sftp://")
}

func isMagnet(s string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(s)), "magnet:")
}

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

func main1() {
	c, err := NewLocal()
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
