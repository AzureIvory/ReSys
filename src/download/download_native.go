package download

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	retryablehttp "github.com/hashicorp/go-retryablehttp"
)

type Status string

const (
	StatusQueued      Status = "queued"
	StatusProbing     Status = "probing"
	StatusDownloading Status = "downloading"
	StatusVerifying   Status = "verifying"
	StatusCompleted   Status = "completed"
	StatusFailed      Status = "failed"
	StatusCanceled    Status = "canceled"
)

type ChecksumConfig struct {
	Name        string
	New         func() hash.Hash
	ExpectedHex string
}

type NOptions struct {
	URL         string
	Destination string

	Header http.Header

	// Skip the probe request and use a single GET directly.
	SkipProbe bool

	Concurrency int
	ChunkSize   int64

	RetryMax     int
	RetryWaitMin time.Duration
	RetryWaitMax time.Duration

	ChunkRetryMax int

	ProgressInterval time.Duration

	MaxConnsPerHost     int
	MaxIdleConns        int
	MaxIdleConnsPerHost int

	ResponseHeaderTimeout time.Duration

	TempSuffix           string
	RemovePartialOnError bool

	VerifyChecksum *ChecksumConfig

	OnProgress func(NProgress)
}
type NProgress struct {
	Status Status

	BytesDownloaded int64
	BytesVerified   int64
	BytesTotal      int64

	Percent         float64
	SpeedBPS        float64
	AverageSpeedBPS float64
	Elapsed         time.Duration

	ActiveWorkers   int32
	ChunksCompleted int32
	ChunksTotal     int32

	StartedAt time.Time
	UpdatedAt time.Time
}
type NResult struct {
	URL         string
	Destination string
	TempPath    string

	Status Status

	ProbeStatusCode    int
	DownloadStatusCode int

	UsedRanges  bool
	Concurrency int

	Size         int64
	ETag         string
	LastModified string

	StartedAt   time.Time
	CompletedAt time.Time
	Duration    time.Duration

	FinalProgress NProgress

	ChecksumName string
	ChecksumHex  string

	ResponseHeader http.Header

	ErrorReason string
}

type DownloadError struct {
	Op         string
	URL        string
	StatusCode int
	Reason     string
	Part       *ByteRange
	Err        error
}

func (e *DownloadError) Error() string {
	if e == nil {
		return "<nil>"
	}
	base := e.Op
	if e.Part != nil {
		base = fmt.Sprintf("%s part[%d-%d]", base, e.Part.Start, e.Part.End)
	}
	if e.StatusCode > 0 {
		base = fmt.Sprintf("%s status=%d", base, e.StatusCode)
	}
	if e.Reason != "" {
		base = fmt.Sprintf("%s: %s", base, e.Reason)
	}
	if e.Err != nil {
		base = fmt.Sprintf("%s: %v", base, e.Err)
	}
	return base
}

func (e *DownloadError) Unwrap() error { return e.Err }

type ByteRange struct {
	Index int
	Start int64
	End   int64
}

func (r ByteRange) Len() int64 { return r.End - r.Start + 1 }

type probeInfo struct {
	Size            int64
	SupportsRanges  bool
	ProbeStatusCode int
	Headers         http.Header
	ETag            string
	LastModified    string
	StrongETag      string
}

type contentRange struct {
	Start int64
	End   int64
	Size  int64
}

type stats struct {
	total           int64
	startedAt       time.Time
	downloaded      atomic.Int64
	verified        atomic.Int64
	activeWorkers   atomic.Int32
	chunksCompleted atomic.Int32
	chunksTotal     int32
	status          atomic.Value // Status
}

func newStats(total int64, chunksTotal int32) *stats {
	s := &stats{total: total, startedAt: time.Now(), chunksTotal: chunksTotal}
	s.status.Store(StatusQueued)
	return s
}

func (s *stats) setStatus(st Status) {
	s.status.Store(st)
}

func (s *stats) snapshot(now time.Time, speed float64) NProgress {
	downloaded := s.downloaded.Load()
	verified := s.verified.Load()
	elapsed := now.Sub(s.startedAt)
	avg := 0.0
	if elapsed > 0 {
		avg = float64(downloaded) / elapsed.Seconds()
	}
	pct := 0.0
	if s.total > 0 {
		pct = float64(downloaded) / float64(s.total)
		if pct < 0 {
			pct = 0
		}
		if pct > 1 {
			pct = 1
		}
	}

	st, _ := s.status.Load().(Status)
	return NProgress{
		Status:          st,
		BytesDownloaded: downloaded,
		BytesVerified:   verified,
		BytesTotal:      s.total,
		Percent:         pct,
		SpeedBPS:        speed,
		AverageSpeedBPS: avg,
		Elapsed:         elapsed,
		ActiveWorkers:   s.activeWorkers.Load(),
		ChunksCompleted: s.chunksCompleted.Load(),
		ChunksTotal:     s.chunksTotal,
		StartedAt:       s.startedAt,
		UpdatedAt:       now,
	}
}

type progressReporter struct {
	stats    *stats
	interval time.Duration
	fn       func(NProgress)

	mu       sync.Mutex
	lastAt   time.Time
	lastByte int64

	done chan struct{}
	wg   sync.WaitGroup
}

func newProgressReporter(stats *stats, interval time.Duration, fn func(NProgress)) *progressReporter {
	if interval <= 0 {
		interval = 500 * time.Millisecond
	}
	return &progressReporter{
		stats:    stats,
		interval: interval,
		fn:       fn,
		lastAt:   stats.startedAt,
		done:     make(chan struct{}),
	}
}

func (r *progressReporter) Start() {
	if r == nil || r.fn == nil {
		return
	}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		ticker := time.NewTicker(r.interval)
		defer ticker.Stop()
		r.emit(time.Now())
		for {
			select {
			case <-ticker.C:
				r.emit(time.Now())
			case <-r.done:
				return
			}
		}
	}()
}

func (r *progressReporter) emit(now time.Time) {
	if r == nil || r.fn == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	downloaded := r.stats.downloaded.Load()
	dt := now.Sub(r.lastAt)
	speed := 0.0
	if downloaded < r.lastByte {
		r.lastByte = downloaded
		r.lastAt = now
	}
	if dt > 0 {
		delta := downloaded - r.lastByte
		if delta < 0 {
			delta = 0
		}
		speed = float64(delta) / dt.Seconds()
	}
	snap := r.stats.snapshot(now, speed)
	r.lastAt = now
	r.lastByte = downloaded
	r.fn(snap)
}

func (r *progressReporter) StopAndEmitFinal() NProgress {
	if r == nil {
		return NProgress{}
	}
	if r.fn != nil {
		close(r.done)
		r.wg.Wait()
		now := time.Now()
		r.emit(now)
		r.mu.Lock()
		defer r.mu.Unlock()
		return r.stats.snapshot(now, 0)
	}
	return r.stats.snapshot(time.Now(), 0)
}

type discardLogger struct{}

func (discardLogger) Printf(string, ...interface{}) {}

func withDefaults(opt NOptions) NOptions {
	if opt.Concurrency <= 0 {
		opt.Concurrency = 4
	}
	if opt.ChunkSize <= 0 {
		opt.ChunkSize = 4 << 20 // 4 MiB
	}
	if opt.RetryMax < 0 {
		opt.RetryMax = 0
	}
	if opt.RetryMax == 0 {
		opt.RetryMax = 4
	}
	if opt.ChunkRetryMax < 0 {
		opt.ChunkRetryMax = 0
	}
	if opt.ChunkRetryMax == 0 {
		opt.ChunkRetryMax = 2
	}
	if opt.RetryWaitMin <= 0 {
		opt.RetryWaitMin = 300 * time.Millisecond
	}
	if opt.RetryWaitMax <= 0 {
		opt.RetryWaitMax = 3 * time.Second
	}
	if opt.ProgressInterval <= 0 {
		opt.ProgressInterval = 500 * time.Millisecond
	}
	if opt.ResponseHeaderTimeout <= 0 {
		opt.ResponseHeaderTimeout = 20 * time.Second
	}
	if opt.TempSuffix == "" {
		opt.TempSuffix = ".part"
	}
	if !opt.RemovePartialOnError {
		opt.RemovePartialOnError = true
	}
	if opt.MaxConnsPerHost <= 0 {
		opt.MaxConnsPerHost = clamp(opt.Concurrency+1, 2, 6)
	}
	if opt.MaxIdleConnsPerHost <= 0 {
		opt.MaxIdleConnsPerHost = opt.MaxConnsPerHost
	}
	if opt.MaxIdleConns <= 0 {
		opt.MaxIdleConns = maxInt(8, opt.MaxIdleConnsPerHost*2)
	}
	if opt.Header == nil {
		opt.Header = make(http.Header)
	}
	return opt
}
func validateOptions(opt NOptions) error {
	if opt.URL == "" {
		return errors.New("url is required")
	}
	if opt.Destination == "" {
		return errors.New("destination is required")
	}
	if opt.VerifyChecksum != nil {
		if opt.VerifyChecksum.New == nil {
			return errors.New("VerifyChecksum.New must not be nil")
		}
	}
	return nil
}

func extractDownloadErrorStatusCode(err error) int {
	var derr *DownloadError
	if errors.As(err, &derr) {
		return derr.StatusCode
	}
	return 0
}

func shouldDowngradeProbeError(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	var derr *DownloadError
	if !errors.As(err, &derr) {
		return false
	}

	return strings.HasPrefix(derr.Op, "probe_") && derr.Op != "probe_build"
}

func adjustFinalProgress(progress *NProgress, size int64) {
	if progress == nil {
		return
	}
	if size > 0 && progress.BytesTotal == 0 {
		progress.BytesTotal = size
	}
	if progress.Status == StatusCompleted {
		progress.Percent = 1
	}
}

func Download(ctx context.Context, opt NOptions) (*NResult, error) {
	opt = withDefaults(opt)
	if err := validateOptions(opt); err != nil {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Dir(opt.Destination), 0o755); err != nil {
		return nil, fmt.Errorf("mkdir destination dir: %w", err)
	}

	retryClient := newRetryClient(opt)

	result := &NResult{
		URL:         opt.URL,
		Destination: opt.Destination,
		TempPath:    opt.Destination + opt.TempSuffix,
		StartedAt:   time.Now(),
	}

	_ = os.Remove(result.TempPath)

	probe := probeInfo{Size: -1}
	skipProbe := opt.SkipProbe

	if !skipProbe {
		probeStats := newStats(0, 0)
		probeStats.setStatus(StatusProbing)
		probeReporter := newProgressReporter(probeStats, opt.ProgressInterval, opt.OnProgress)
		probeReporter.Start()

		probe, err := probeResource(ctx, retryClient, opt)
		if err != nil {
			result.ProbeStatusCode = extractDownloadErrorStatusCode(err)
			if shouldDowngradeProbeError(err) {
				skipProbe = true
				probe = probeInfo{Size: -1}
				probeStats.setStatus(StatusDownloading)
				_ = probeReporter.StopAndEmitFinal()
			} else {
				probeStats.setStatus(statusFromContext(ctx, err))
				final := probeReporter.StopAndEmitFinal()
				result.Status = final.Status
				result.FinalProgress = final
				result.CompletedAt = time.Now()
				result.Duration = result.CompletedAt.Sub(result.StartedAt)
				result.ErrorReason = err.Error()
				return result, err
			}
		} else {
			result.ProbeStatusCode = probe.ProbeStatusCode
			result.ResponseHeader = cloneHeader(probe.Headers)
			result.ETag = probe.ETag
			result.LastModified = probe.LastModified
			result.Size = probe.Size

			probeStats.setStatus(StatusDownloading)
			_ = probeReporter.StopAndEmitFinal()
		}
	}

	if !skipProbe && probe.Size == 0 {
		file, err := os.OpenFile(result.TempPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			derr := &DownloadError{Op: "create_temp", URL: opt.URL, Reason: "create temp file for empty resource", Err: err}
			result.Status = StatusFailed
			result.CompletedAt = time.Now()
			result.Duration = result.CompletedAt.Sub(result.StartedAt)
			result.ErrorReason = derr.Error()
			return result, derr
		}
		_ = file.Close()
		if err := replaceFile(result.TempPath, result.Destination); err != nil {
			derr := &DownloadError{Op: "rename", URL: opt.URL, Reason: "rename empty temp file", Err: err}
			result.Status = StatusFailed
			result.CompletedAt = time.Now()
			result.Duration = result.CompletedAt.Sub(result.StartedAt)
			result.ErrorReason = derr.Error()
			return result, derr
		}
		result.Status = StatusCompleted
		result.CompletedAt = time.Now()
		result.Duration = result.CompletedAt.Sub(result.StartedAt)
		result.FinalProgress = NProgress{
			Status:          StatusCompleted,
			BytesDownloaded: 0,
			BytesVerified:   0,
			BytesTotal:      0,
			Percent:         1,
			StartedAt:       result.StartedAt,
			UpdatedAt:       result.CompletedAt,
			Elapsed:         result.Duration,
		}
		return result, nil
	}

	parts := splitByteRanges(probe.Size, opt.ChunkSize)
	usedRanges := !skipProbe && probe.SupportsRanges && len(parts) > 1 && opt.Concurrency > 1
	result.UsedRanges = usedRanges

	var chunksTotal int32 = 1
	if usedRanges {
		chunksTotal = int32(len(parts))
	}
	progressTotal := probe.Size
	if progressTotal < 0 {
		progressTotal = 0
	}
	dlStats := newStats(progressTotal, chunksTotal)
	dlStats.setStatus(StatusDownloading)
	reporter := newProgressReporter(dlStats, opt.ProgressInterval, opt.OnProgress)
	reporter.Start()

	file, err := os.OpenFile(result.TempPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		derr := &DownloadError{Op: "open_temp", URL: opt.URL, Reason: "open temp file", Err: err}
		dlStats.setStatus(StatusFailed)
		result.Status = StatusFailed
		result.CompletedAt = time.Now()
		result.Duration = result.CompletedAt.Sub(result.StartedAt)
		result.ErrorReason = derr.Error()
		result.FinalProgress = reporter.StopAndEmitFinal()
		return result, derr
	}

	cleanup := func(remove bool) {
		_ = file.Close()
		if remove && opt.RemovePartialOnError {
			_ = os.Remove(result.TempPath)
		}
	}

	if probe.Size > 0 {
		if err := file.Truncate(probe.Size); err != nil {
			cleanup(true)
			derr := &DownloadError{Op: "truncate_temp", URL: opt.URL, Reason: "preallocate temp file", Err: err}
			dlStats.setStatus(StatusFailed)
			result.Status = StatusFailed
			result.CompletedAt = time.Now()
			result.Duration = result.CompletedAt.Sub(result.StartedAt)
			result.ErrorReason = derr.Error()
			result.FinalProgress = reporter.StopAndEmitFinal()
			return result, derr
		}
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	downloadStatusCode := 0
	if usedRanges {
		result.Concurrency = minInt(opt.Concurrency, len(parts))
		downloadStatusCode, err = downloadMultipart(ctx, retryClient, file, probe, parts, dlStats, opt)
	} else {
		result.Concurrency = 1
		downloadStatusCode, err = downloadSingle(ctx, retryClient, file, &probe, dlStats, opt)
	}
	result.DownloadStatusCode = downloadStatusCode

	if err != nil {
		dlStats.setStatus(statusFromContext(ctx, err))
		cleanup(true)
		result.Status = statusFromContext(ctx, err)
		result.CompletedAt = time.Now()
		result.Duration = result.CompletedAt.Sub(result.StartedAt)
		result.ErrorReason = err.Error()
		result.FinalProgress = reporter.StopAndEmitFinal()
		return result, err
	}

	if err := file.Sync(); err != nil {
		cleanup(true)
		derr := &DownloadError{Op: "sync_temp", URL: opt.URL, Reason: "sync temp file", Err: err}
		dlStats.setStatus(StatusFailed)
		result.Status = StatusFailed
		result.CompletedAt = time.Now()
		result.Duration = result.CompletedAt.Sub(result.StartedAt)
		result.ErrorReason = derr.Error()
		result.FinalProgress = reporter.StopAndEmitFinal()
		return result, derr
	}
	if err := file.Close(); err != nil {
		if opt.RemovePartialOnError {
			_ = os.Remove(result.TempPath)
		}
		derr := &DownloadError{Op: "close_temp", URL: opt.URL, Reason: "close temp file", Err: err}
		dlStats.setStatus(StatusFailed)
		result.Status = StatusFailed
		result.CompletedAt = time.Now()
		result.Duration = result.CompletedAt.Sub(result.StartedAt)
		result.ErrorReason = derr.Error()
		result.FinalProgress = reporter.StopAndEmitFinal()
		return result, derr
	}

	st, statErr := os.Stat(result.TempPath)
	if statErr != nil {
		if opt.RemovePartialOnError {
			_ = os.Remove(result.TempPath)
		}
		derr := &DownloadError{Op: "stat_temp", URL: opt.URL, Reason: "stat temp file", Err: statErr}
		dlStats.setStatus(StatusFailed)
		result.Status = StatusFailed
		result.CompletedAt = time.Now()
		result.Duration = result.CompletedAt.Sub(result.StartedAt)
		result.ErrorReason = derr.Error()
		result.FinalProgress = reporter.StopAndEmitFinal()
		return result, derr
	}
	result.Size = st.Size()
	if probe.Size > 0 && st.Size() != probe.Size {
		if opt.RemovePartialOnError {
			_ = os.Remove(result.TempPath)
		}
		derr := &DownloadError{
			Op:     "verify_size",
			URL:    opt.URL,
			Reason: fmt.Sprintf("final size mismatch: got %d want %d", st.Size(), probe.Size),
		}
		dlStats.setStatus(StatusFailed)
		result.Status = StatusFailed
		result.CompletedAt = time.Now()
		result.Duration = result.CompletedAt.Sub(result.StartedAt)
		result.ErrorReason = derr.Error()
		result.FinalProgress = reporter.StopAndEmitFinal()
		return result, derr
	}
	if probe.Headers != nil && (result.ResponseHeader == nil || skipProbe) {
		result.ResponseHeader = cloneHeader(probe.Headers)
	}
	if probe.ETag != "" {
		result.ETag = probe.ETag
	}
	if probe.LastModified != "" {
		result.LastModified = probe.LastModified
	}

	dlStats.setStatus(StatusVerifying)
	reporter.emit(time.Now())

	if opt.VerifyChecksum != nil {
		checksumHex, err := computeFileChecksum(result.TempPath, opt.VerifyChecksum.New)
		if err != nil {
			if opt.RemovePartialOnError {
				_ = os.Remove(result.TempPath)
			}
			derr := &DownloadError{Op: "verify_checksum", URL: opt.URL, Reason: "compute checksum", Err: err}
			dlStats.setStatus(StatusFailed)
			result.Status = StatusFailed
			result.CompletedAt = time.Now()
			result.Duration = result.CompletedAt.Sub(result.StartedAt)
			result.ErrorReason = derr.Error()
			result.FinalProgress = reporter.StopAndEmitFinal()
			return result, derr
		}
		result.ChecksumName = opt.VerifyChecksum.Name
		result.ChecksumHex = checksumHex
		if expected := strings.TrimSpace(strings.ToLower(opt.VerifyChecksum.ExpectedHex)); expected != "" {
			if strings.ToLower(checksumHex) != expected {
				if opt.RemovePartialOnError {
					_ = os.Remove(result.TempPath)
				}
				derr := &DownloadError{
					Op:     "verify_checksum",
					URL:    opt.URL,
					Reason: fmt.Sprintf("checksum mismatch: got %s want %s", checksumHex, expected),
				}
				dlStats.setStatus(StatusFailed)
				result.Status = StatusFailed
				result.CompletedAt = time.Now()
				result.Duration = result.CompletedAt.Sub(result.StartedAt)
				result.ErrorReason = derr.Error()
				result.FinalProgress = reporter.StopAndEmitFinal()
				return result, derr
			}
		}
	}

	if err := replaceFile(result.TempPath, result.Destination); err != nil {
		if opt.RemovePartialOnError {
			_ = os.Remove(result.TempPath)
		}
		derr := &DownloadError{Op: "rename", URL: opt.URL, Reason: "rename temp file to destination", Err: err}
		dlStats.setStatus(StatusFailed)
		result.Status = StatusFailed
		result.CompletedAt = time.Now()
		result.Duration = result.CompletedAt.Sub(result.StartedAt)
		result.ErrorReason = derr.Error()
		result.FinalProgress = reporter.StopAndEmitFinal()
		return result, derr
	}

	dlStats.setStatus(StatusCompleted)
	result.Status = StatusCompleted
	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(result.StartedAt)
	result.FinalProgress = reporter.StopAndEmitFinal()
	adjustFinalProgress(&result.FinalProgress, result.Size)
	return result, nil
}
func newRetryClient(opt NOptions) *retryablehttp.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DisableCompression = true
	tr.MaxConnsPerHost = opt.MaxConnsPerHost
	tr.MaxIdleConns = opt.MaxIdleConns
	tr.MaxIdleConnsPerHost = opt.MaxIdleConnsPerHost
	tr.ResponseHeaderTimeout = opt.ResponseHeaderTimeout

	client := retryablehttp.NewClient()
	client.HTTPClient = &http.Client{Transport: tr}
	client.RetryMax = opt.RetryMax
	client.RetryWaitMin = opt.RetryWaitMin
	client.RetryWaitMax = opt.RetryWaitMax
	client.Backoff = retryablehttp.RateLimitLinearJitterBackoff
	client.CheckRetry = checkRetryPolicy
	client.ErrorHandler = retryablehttp.PassthroughErrorHandler
	client.Logger = discardLogger{}
	return client
}

func checkRetryPolicy(ctx context.Context, resp *http.Response, err error) (bool, error) {
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	if err != nil {
		return true, nil
	}
	if resp == nil {
		return false, nil
	}
	switch resp.StatusCode {
	case http.StatusRequestTimeout, // 408
		http.StatusTooManyRequests,     // 429
		http.StatusInternalServerError, // 500
		http.StatusBadGateway,          // 502
		http.StatusServiceUnavailable,  // 503
		http.StatusGatewayTimeout:      // 504
		return true, nil
	default:
		return false, nil
	}
}

func probeResource(ctx context.Context, client *retryablehttp.Client, opt NOptions) (probeInfo, error) {
	headers := cloneHeader(opt.Header)

	headStatus := 0
	var headHeader http.Header
	if headReq, err := retryablehttp.NewRequestWithContext(ctx, http.MethodHead, opt.URL, nil); err == nil {
		applyRequestHeaders(headReq.Header, headers)
		resp, err := client.Do(headReq)
		if err == nil && resp != nil {
			headStatus = resp.StatusCode
			headHeader = cloneHeader(resp.Header)
			_ = resp.Body.Close()
		}
	}

	rangeReq, err := retryablehttp.NewRequestWithContext(ctx, http.MethodGet, opt.URL, nil)
	if err != nil {
		return probeInfo{}, &DownloadError{Op: "probe_build", URL: opt.URL, Reason: "build probe request", Err: err}
	}
	applyRequestHeaders(rangeReq.Header, headers)
	rangeReq.Header.Set("Range", "bytes=0-0")

	resp, err := client.Do(rangeReq)
	if err != nil {
		return probeInfo{}, &DownloadError{Op: "probe_do", URL: opt.URL, Reason: "probe request failed", Err: err}
	}
	defer resp.Body.Close()

	info := probeInfo{
		ProbeStatusCode: resp.StatusCode,
		Headers:         cloneHeader(resp.Header),
		ETag:            strings.TrimSpace(resp.Header.Get("ETag")),
		LastModified:    strings.TrimSpace(resp.Header.Get("Last-Modified")),
	}
	if info.ETag == "" && headHeader != nil {
		info.ETag = strings.TrimSpace(headHeader.Get("ETag"))
	}
	if info.LastModified == "" && headHeader != nil {
		info.LastModified = strings.TrimSpace(headHeader.Get("Last-Modified"))
	}
	if isStrongETag(info.ETag) {
		info.StrongETag = info.ETag
	}

	switch resp.StatusCode {
	case http.StatusPartialContent:
		cr, err := parseContentRange(resp.Header.Get("Content-Range"))
		if err != nil {
			return probeInfo{}, &DownloadError{Op: "probe_parse_content_range", URL: opt.URL, StatusCode: resp.StatusCode, Reason: "invalid Content-Range on probe", Err: err}
		}
		if cr.Start != 0 || cr.End != 0 {
			return probeInfo{}, &DownloadError{Op: "probe_validate_content_range", URL: opt.URL, StatusCode: resp.StatusCode, Reason: fmt.Sprintf("unexpected probe range %d-%d", cr.Start, cr.End)}
		}
		info.SupportsRanges = true
		info.Size = cr.Size
		_, _ = io.Copy(io.Discard, resp.Body)
		return info, nil

	case http.StatusOK:
		info.SupportsRanges = false
		if resp.ContentLength > 0 {
			info.Size = resp.ContentLength
		} else if headHeader != nil {
			info.Size = parseContentLength(headHeader.Get("Content-Length"))
		} else {
			info.Size = parseContentLength(resp.Header.Get("Content-Length"))
		}
		return info, nil

	case http.StatusRequestedRangeNotSatisfiable:
		cr, err := parseContentRange(resp.Header.Get("Content-Range"))
		if err == nil && cr.Size == 0 {
			info.SupportsRanges = true
			info.Size = 0
			return info, nil
		}
		return probeInfo{}, &DownloadError{Op: "probe_range", URL: opt.URL, StatusCode: resp.StatusCode, Reason: "range probe returned 416"}

	default:
		if headStatus >= 200 && headStatus < 300 {
			info.ProbeStatusCode = headStatus
			info.Headers = cloneHeader(headHeader)
			info.Size = parseContentLength(headHeader.Get("Content-Length"))
			info.ETag = firstNonEmpty(info.ETag, strings.TrimSpace(headHeader.Get("ETag")))
			info.LastModified = firstNonEmpty(info.LastModified, strings.TrimSpace(headHeader.Get("Last-Modified")))
			if isStrongETag(info.ETag) {
				info.StrongETag = info.ETag
			}
			accepts := strings.TrimSpace(strings.ToLower(headHeader.Get("Accept-Ranges")))
			info.SupportsRanges = accepts == "bytes" && info.Size > 0
			return info, nil
		}
		return probeInfo{}, &DownloadError{Op: "probe_status", URL: opt.URL, StatusCode: resp.StatusCode, Reason: "unexpected probe status"}
	}
}
func downloadMultipart(ctx context.Context, client *retryablehttp.Client, file *os.File, probe probeInfo, parts []ByteRange, st *stats, opt NOptions) (int, error) {
	workers := minInt(opt.Concurrency, len(parts))
	jobs := make(chan ByteRange)

	var firstErr error
	var firstErrMu sync.Mutex
	setErr := func(err error) {
		firstErrMu.Lock()
		defer firstErrMu.Unlock()
		if firstErr == nil {
			firstErr = err
		}
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st.activeWorkers.Add(1)
			defer st.activeWorkers.Add(-1)
			for part := range jobs {
				status, err := downloadPartWithRetry(ctx, client, file, probe, part, st, opt)
				if err != nil {
					setErr(err)
					cancel()
					return
				}
				if status != http.StatusPartialContent {
					setErr(&DownloadError{Op: "part_status", URL: opt.URL, StatusCode: status, Part: &part, Reason: "expected 206 Partial Content"})
					cancel()
					return
				}
			}
		}()
	}

pushLoop:
	for _, part := range parts {
		select {
		case <-ctx.Done():
			break pushLoop
		case jobs <- part:
		}
	}
	close(jobs)
	wg.Wait()

	if firstErr != nil {
		return 0, firstErr
	}
	if ctx.Err() != nil {
		return 0, ctx.Err()
	}
	return http.StatusPartialContent, nil
}

func downloadPartWithRetry(ctx context.Context, client *retryablehttp.Client, file *os.File, probe probeInfo, part ByteRange, st *stats, opt NOptions) (int, error) {
	var lastErr error
	var lastStatus int
	for attempt := 0; attempt <= opt.ChunkRetryMax; attempt++ {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		status, err := downloadPartOnce(ctx, client, file, probe, part, st, opt)
		if err == nil {
			return status, nil
		}
		lastErr = err
		lastStatus = status
		if attempt < opt.ChunkRetryMax {
			sleepWithContext(ctx, backoffDuration(opt.RetryWaitMin, opt.RetryWaitMax, attempt+1))
			continue
		}
	}
	if derr, ok := lastErr.(*DownloadError); ok {
		if derr.StatusCode == 0 {
			derr.StatusCode = lastStatus
		}
		return lastStatus, derr
	}
	return lastStatus, &DownloadError{Op: "part_retry_exhausted", URL: opt.URL, Part: &part, StatusCode: lastStatus, Reason: "range part exhausted retries", Err: lastErr}
}
func downloadPartOnce(ctx context.Context, client *retryablehttp.Client, file *os.File, probe probeInfo, part ByteRange, st *stats, opt NOptions) (int, error) {
	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodGet, opt.URL, nil)
	if err != nil {
		return 0, &DownloadError{Op: "part_build", URL: opt.URL, Part: &part, Reason: "build range request", Err: err}
	}
	applyRequestHeaders(req.Header, opt.Header)
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", part.Start, part.End))
	applyConsistencyHeaders(req.Header, probe)

	resp, err := client.Do(req)
	if err != nil {
		return 0, &DownloadError{Op: "part_do", URL: opt.URL, Part: &part, Reason: "range request failed", Err: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusPartialContent {
		return resp.StatusCode, &DownloadError{Op: "part_status", URL: opt.URL, Part: &part, StatusCode: resp.StatusCode, Reason: fmt.Sprintf("unexpected status %s", resp.Status)}
	}

	if err := validatePartResponse(resp, probe, part); err != nil {
		return resp.StatusCode, &DownloadError{Op: "part_validate", URL: opt.URL, Part: &part, StatusCode: resp.StatusCode, Reason: "range response validation failed", Err: err}
	}

	expected := int(part.Len())
	buf := bytes.NewBuffer(make([]byte, 0, expected))
	scratch := make([]byte, 128*1024)
	var readBytes int64
	for {
		n, readErr := resp.Body.Read(scratch)
		if n > 0 {
			if _, werr := buf.Write(scratch[:n]); werr != nil {
				st.downloaded.Add(-readBytes)
				return resp.StatusCode, &DownloadError{Op: "part_buffer", URL: opt.URL, Part: &part, StatusCode: resp.StatusCode, Reason: "buffer chunk", Err: werr}
			}
			readBytes += int64(n)
			st.downloaded.Add(int64(n))
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			st.downloaded.Add(-readBytes)
			return resp.StatusCode, &DownloadError{Op: "part_read", URL: opt.URL, Part: &part, StatusCode: resp.StatusCode, Reason: "read range response body", Err: readErr}
		}
	}

	if readBytes != part.Len() {
		st.downloaded.Add(-readBytes)
		return resp.StatusCode, &DownloadError{Op: "part_short_read", URL: opt.URL, Part: &part, StatusCode: resp.StatusCode, Reason: fmt.Sprintf("short read: got %d want %d", readBytes, part.Len())}
	}

	if _, err := file.WriteAt(buf.Bytes(), part.Start); err != nil {
		st.downloaded.Add(-readBytes)
		return resp.StatusCode, &DownloadError{Op: "part_write_at", URL: opt.URL, Part: &part, StatusCode: resp.StatusCode, Reason: "write range to file", Err: err}
	}

	st.verified.Add(part.Len())
	st.chunksCompleted.Add(1)
	return resp.StatusCode, nil
}

func downloadSingle(ctx context.Context, client *retryablehttp.Client, file *os.File, probe *probeInfo, st *stats, opt NOptions) (int, error) {
	st.activeWorkers.Add(1)
	defer st.activeWorkers.Add(-1)

	var lastErr error
	var lastStatus int
	for attempt := 0; attempt <= opt.ChunkRetryMax; attempt++ {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		if err := file.Truncate(0); err != nil {
			return 0, &DownloadError{Op: "single_truncate", URL: opt.URL, Reason: "truncate file before single download retry", Err: err}
		}
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			return 0, &DownloadError{Op: "single_seek", URL: opt.URL, Reason: "seek file before single download retry", Err: err}
		}
		st.downloaded.Store(0)
		st.verified.Store(0)
		st.chunksCompleted.Store(0)

		status, err := downloadSingleOnce(ctx, client, file, probe, st, opt)
		if err == nil {
			return status, nil
		}
		lastErr = err
		lastStatus = status
		if attempt < opt.ChunkRetryMax {
			sleepWithContext(ctx, backoffDuration(opt.RetryWaitMin, opt.RetryWaitMax, attempt+1))
			continue
		}
	}
	if derr, ok := lastErr.(*DownloadError); ok {
		if derr.StatusCode == 0 {
			derr.StatusCode = lastStatus
		}
		return lastStatus, derr
	}
	return lastStatus, &DownloadError{Op: "single_retry_exhausted", URL: opt.URL, StatusCode: lastStatus, Reason: "single download exhausted retries", Err: lastErr}
}
func downloadSingleOnce(ctx context.Context, client *retryablehttp.Client, file *os.File, probe *probeInfo, st *stats, opt NOptions) (int, error) {
	currentProbe := probeInfo{}
	if probe != nil {
		currentProbe = *probe
	}

	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodGet, opt.URL, nil)
	if err != nil {
		return 0, &DownloadError{Op: "single_build", URL: opt.URL, Reason: "build GET request", Err: err}
	}
	applyRequestHeaders(req.Header, opt.Header)
	applyConsistencyHeaders(req.Header, currentProbe)

	resp, err := client.Do(req)
	if err != nil {
		return 0, &DownloadError{Op: "single_do", URL: opt.URL, Reason: "GET request failed", Err: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, &DownloadError{Op: "single_status", URL: opt.URL, StatusCode: resp.StatusCode, Reason: fmt.Sprintf("unexpected status %s", resp.Status)}
	}
	if err := validateSingleResponse(resp, currentProbe); err != nil {
		return resp.StatusCode, &DownloadError{Op: "single_validate", URL: opt.URL, StatusCode: resp.StatusCode, Reason: "single response validation failed", Err: err}
	}

	buf := make([]byte, 128*1024)
	var offset int64
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if _, err := file.WriteAt(buf[:n], offset); err != nil {
				return resp.StatusCode, &DownloadError{Op: "single_write_at", URL: opt.URL, StatusCode: resp.StatusCode, Reason: "write response to file", Err: err}
			}
			offset += int64(n)
			st.downloaded.Add(int64(n))
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return resp.StatusCode, &DownloadError{Op: "single_read", URL: opt.URL, StatusCode: resp.StatusCode, Reason: "read response body", Err: readErr}
		}
	}

	if currentProbe.Size > 0 && offset != currentProbe.Size {
		return resp.StatusCode, &DownloadError{Op: "single_short_read", URL: opt.URL, StatusCode: resp.StatusCode, Reason: fmt.Sprintf("short read: got %d want %d", offset, currentProbe.Size)}
	}

	if probe != nil {
		probe.Headers = cloneHeader(resp.Header)
		probe.ETag = firstNonEmpty(strings.TrimSpace(resp.Header.Get("ETag")), probe.ETag)
		probe.LastModified = firstNonEmpty(strings.TrimSpace(resp.Header.Get("Last-Modified")), probe.LastModified)
		if isStrongETag(probe.ETag) {
			probe.StrongETag = probe.ETag
		}
		probe.Size = offset
	}

	st.verified.Store(offset)
	st.chunksCompleted.Store(1)
	return resp.StatusCode, nil
}
func validatePartResponse(resp *http.Response, probe probeInfo, part ByteRange) error {
	cr, err := parseContentRange(resp.Header.Get("Content-Range"))
	if err != nil {
		return fmt.Errorf("parse Content-Range: %w", err)
	}
	if cr.Start != part.Start || cr.End != part.End {
		return fmt.Errorf("unexpected Content-Range %d-%d, want %d-%d", cr.Start, cr.End, part.Start, part.End)
	}
	if probe.Size > 0 && cr.Size != probe.Size {
		return fmt.Errorf("total size mismatch in Content-Range: got %d want %d", cr.Size, probe.Size)
	}
	if resp.ContentLength > 0 && resp.ContentLength != part.Len() {
		return fmt.Errorf("Content-Length mismatch: got %d want %d", resp.ContentLength, part.Len())
	}
	if err := validateValidators(resp.Header, probe); err != nil {
		return err
	}
	return nil
}

func validateSingleResponse(resp *http.Response, probe probeInfo) error {
	if probe.Size > 0 && resp.ContentLength > 0 && resp.ContentLength != probe.Size {
		return fmt.Errorf("Content-Length mismatch: got %d want %d", resp.ContentLength, probe.Size)
	}
	if err := validateValidators(resp.Header, probe); err != nil {
		return err
	}
	return nil
}

func validateValidators(h http.Header, probe probeInfo) error {
	if probe.StrongETag != "" {
		got := strings.TrimSpace(h.Get("ETag"))
		if got != "" && got != probe.StrongETag {
			return fmt.Errorf("ETag changed during download: got %q want %q", got, probe.StrongETag)
		}
	}
	if probe.LastModified != "" {
		got := strings.TrimSpace(h.Get("Last-Modified"))
		if got != "" && got != probe.LastModified {
			return fmt.Errorf("Last-Modified changed during download: got %q want %q", got, probe.LastModified)
		}
	}
	return nil
}

func applyConsistencyHeaders(h http.Header, probe probeInfo) {
	if probe.StrongETag != "" {
		h.Set("If-Match", probe.StrongETag)
		return
	}
	if probe.LastModified != "" {
		h.Set("If-Unmodified-Since", probe.LastModified)
	}
}

func splitByteRanges(size int64, chunkSize int64) []ByteRange {
	if size <= 0 {
		return nil
	}
	if chunkSize <= 0 {
		chunkSize = size
	}
	var parts []ByteRange
	index := 0
	for start := int64(0); start < size; start += chunkSize {
		end := start + chunkSize - 1
		if end >= size {
			end = size - 1
		}
		parts = append(parts, ByteRange{Index: index, Start: start, End: end})
		index++
	}
	return parts
}

func applyRequestHeaders(dst http.Header, src http.Header) {
	for k, vv := range src {
		if strings.EqualFold(k, "Range") || strings.EqualFold(k, "If-Match") || strings.EqualFold(k, "If-Unmodified-Since") {
			continue
		}
		vvCopy := append([]string(nil), vv...)
		dst[k] = vvCopy
	}
}
func cloneHeader(h http.Header) http.Header {
	if h == nil {
		return nil
	}
	out := make(http.Header, len(h))
	for k, vv := range h {
		out[k] = append([]string(nil), vv...)
	}
	return out
}

func parseContentRange(v string) (contentRange, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return contentRange{}, errors.New("empty Content-Range")
	}
	parts := strings.Fields(v)
	if len(parts) != 2 {
		return contentRange{}, fmt.Errorf("invalid Content-Range %q", v)
	}
	if strings.ToLower(parts[0]) != "bytes" {
		return contentRange{}, fmt.Errorf("unsupported range unit %q", parts[0])
	}
	segAndSize := strings.Split(parts[1], "/")
	if len(segAndSize) != 2 {
		return contentRange{}, fmt.Errorf("invalid Content-Range body %q", parts[1])
	}
	size, err := strconv.ParseInt(segAndSize[1], 10, 64)
	if err != nil {
		return contentRange{}, fmt.Errorf("invalid complete length %q", segAndSize[1])
	}
	if segAndSize[0] == "*" {
		return contentRange{Start: -1, End: -1, Size: size}, nil
	}
	se := strings.Split(segAndSize[0], "-")
	if len(se) != 2 {
		return contentRange{}, fmt.Errorf("invalid byte range %q", segAndSize[0])
	}
	start, err := strconv.ParseInt(se[0], 10, 64)
	if err != nil {
		return contentRange{}, fmt.Errorf("invalid range start %q", se[0])
	}
	end, err := strconv.ParseInt(se[1], 10, 64)
	if err != nil {
		return contentRange{}, fmt.Errorf("invalid range end %q", se[1])
	}
	if end < start {
		return contentRange{}, fmt.Errorf("invalid range %d-%d", start, end)
	}
	return contentRange{Start: start, End: end, Size: size}, nil
}

func parseContentLength(v string) int64 {
	v = strings.TrimSpace(v)
	if v == "" {
		return -1
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return -1
	}
	return n
}

func computeFileChecksum(path string, newHash func() hash.Hash) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := newHash()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func replaceFile(src, dst string) error {
	_ = os.Remove(dst)
	return os.Rename(src, dst)
}

func isStrongETag(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return false
	}
	return !strings.HasPrefix(v, "W/")
}

func backoffDuration(minWait, maxWait time.Duration, attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	d := minWait << (attempt - 1)
	if d > maxWait {
		return maxWait
	}
	return d
}

func sleepWithContext(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

func statusFromContext(ctx context.Context, err error) Status {
	if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
		return StatusCanceled
	}
	return StatusFailed
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
