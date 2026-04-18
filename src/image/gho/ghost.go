package gho

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	rslog "ReSys/src/log"
	"ReSys/src/tools"
)

type Partition struct {
	Letter          string
	DiskNumber      uint32
	PartitionNumber uint32
}

type Progress struct {
	Percentage          uint8
	Status              string
	BytesProcessed      uint64
	BytesTotal          uint64
	SpeedBytesPerSecond uint64
	Estimated           bool
	RawLine             string
}

type ImageInfo struct {
	FilePath              string
	FileSize              int64
	Signature             [2]byte
	Version               uint32
	HeaderOffset          int64
	HasPassword           bool
	PasswordLength        int
	PasswordVariant       string
	DecodeMethod          string
	MetadataEstimate      bool
	EstimatedRestoreBytes uint64
	Warnings              []string
}

type commandRunner interface {
	Run(ctx context.Context, bin string, input []byte, onLine func(string), dir string, args ...string) (string, error)
}

type toolsRunner struct{}

func (toolsRunner) Run(ctx context.Context, bin string, input []byte, onLine func(string), dir string, args ...string) (string, error) {
	return tools.RunCmdContext(ctx, bin, input, onLine, dir, args...)
}

type Ghost struct {
	execPath string
	workDir  string
	runner   commandRunner
	now      func() time.Time
}

type commandResult struct {
	output string
	err    error
}

type progressTracker struct {
	mu               sync.Mutex
	start            time.Time
	estimatedTotal   uint64
	estimatedWindow  time.Duration
	status           string
	realProgressSeen bool
	lastSent         Progress
}

var (
	percentPattern  = regexp.MustCompile(`(?i)(\d{1,3})(?:\.\d+)?\s*%`)
	fractionPattern = regexp.MustCompile(`(?i)(\d+(?:\.\d+)?)\s*(KB|MB|GB|TB|B)\s*/\s*(\d+(?:\.\d+)?)\s*(KB|MB|GB|TB|B)`)
	speedPattern    = regexp.MustCompile(`(?i)(\d+(?:\.\d+)?)\s*(KB|MB|GB|TB|B)\s*/\s*(s|sec|secs|second|seconds|秒|m|min|mins|minute|minutes|分)`)
)

func NewGhost(execPath string) *Ghost {
	return newGhostWithRunner(execPath, toolsRunner{})
}

func newGhostWithRunner(execPath string, runner commandRunner) *Ghost {
	resolvedPath, workDir := resolveGhostPath(execPath)
	if runner == nil {
		runner = toolsRunner{}
	}

	return &Ghost{
		execPath: resolvedPath,
		workDir:  workDir,
		runner:   runner,
		now:      time.Now,
	}
}

func (g *Ghost) IsAvailable() bool {
	return isFile(g.execPath)
}

func (g *Ghost) ValidateImage(path string) error {
	return ValidateImage(path)
}

func (g *Ghost) GetImageInfo(path string) (ImageInfo, error) {
	header, err := InspectImage(path)
	if err != nil {
		return ImageInfo{}, err
	}
	password := ReadPasswordInfo(path)

	info := ImageInfo{
		FilePath:              header.FilePath,
		FileSize:              header.FileSize,
		Signature:             header.Signature,
		Version:               header.Version,
		HeaderOffset:          header.HeaderOffset,
		HasPassword:           password.HasPassword,
		PasswordLength:        password.PasswordLength,
		PasswordVariant:       password.FormatVariant,
		DecodeMethod:          password.DecodeMethod,
		MetadataEstimate:      true,
		EstimatedRestoreBytes: estimateRestoreBytes(uint64(header.FileSize)),
		Warnings:              append([]string(nil), header.Warnings...),
	}
	for _, warning := range password.Warnings {
		info.Warnings = appendWarning(info.Warnings, warning)
	}
	return info, nil
}

// RestoreImage keeps diskNumber/partitionNumber as 1-based values for Ghost CLI.
func (g *Ghost) RestoreImage(ctx context.Context, ghoFile string, diskNumber uint32, partitionNumber uint32, progress chan<- Progress) error {
	if err := g.ensureReady(ghoFile); err != nil {
		return err
	}
	if diskNumber == 0 || partitionNumber == 0 {
		return fmt.Errorf("%w: disk=%d partition=%d", ErrInvalidPartition, diskNumber, partitionNumber)
	}

	status := "正在恢复 Ghost 镜像"
	args := buildRestoreArgs(ghoFile, diskNumber, partitionNumber)
	info, _ := g.GetImageInfo(ghoFile)
	return g.runOperation(ctx, status, info.EstimatedRestoreBytes, progress, args...)
}

// RestoreImageToLetter maps Windows 0-based disk numbers to Ghost 1-based numbers; partition numbers are already 1-based, so no offset is applied.
func (g *Ghost) RestoreImageToLetter(ctx context.Context, ghoFile string, letter string, partitions []Partition, progress chan<- Progress) error {
	target, err := normalizeLetter(letter)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPartition, err)
	}

	var matched *Partition
	for i := range partitions {
		current, err := normalizeLetter(partitions[i].Letter)
		if err != nil {
			continue
		}
		if strings.EqualFold(current, target) {
			matched = &partitions[i]
			break
		}
	}
	if matched == nil {
		return fmt.Errorf("%w: drive %s not found", ErrInvalidPartition, target)
	}
	if matched.PartitionNumber == 0 {
		return fmt.Errorf("%w: drive %s has invalid partition number", ErrInvalidPartition, target)
	}

	ghostDisk := matched.DiskNumber + 1
	ghostPartition := matched.PartitionNumber
	return g.RestoreImage(ctx, ghoFile, ghostDisk, ghostPartition, progress)
}

func (g *Ghost) CreateImage(ctx context.Context, diskNumber uint32, partitionNumber uint32, outFile string, compression uint8, progress chan<- Progress) error {
	if !g.IsAvailable() {
		return fmt.Errorf("%w: %s", ErrExecutableNotFound, g.execPath)
	}
	if diskNumber == 0 || partitionNumber == 0 {
		return fmt.Errorf("%w: disk=%d partition=%d", ErrInvalidPartition, diskNumber, partitionNumber)
	}
	if strings.TrimSpace(outFile) == "" {
		return fmt.Errorf("%w: output file is empty", ErrInvalidImage)
	}

	if parent := filepath.Dir(outFile); parent != "" && parent != "." {
		if err := os.MkdirAll(parent, 0o755); err != nil {
			return fmt.Errorf("%w: create output dir: %v", ErrExecutionFailed, err)
		}
	}

	status := "正在创建 Ghost 镜像"
	args := buildCreateArgs(diskNumber, partitionNumber, outFile, compression)
	return g.runOperation(ctx, status, 0, progress, args...)
}

func (g *Ghost) ensureReady(ghoFile string) error {
	if !g.IsAvailable() {
		return fmt.Errorf("%w: %s", ErrExecutableNotFound, g.execPath)
	}
	if err := ValidateImage(ghoFile); err != nil {
		return err
	}
	return nil
}

func (g *Ghost) runOperation(ctx context.Context, status string, estimatedTotal uint64, progress chan<- Progress, args ...string) error {
	if ctx == nil {
		ctx = context.Background()
	}

	tracker := newProgressTracker(g.now(), estimatedTotal, status)
	emitProgress(progress, Progress{
		Percentage: 0,
		Status:     status,
		BytesTotal: estimatedTotal,
		Estimated:  estimatedTotal > 0,
	})

	resultCh := make(chan commandResult, 1)
	go func() {
		out, err := g.runner.Run(ctx, g.execPath, nil, func(line string) {
			rslog.LogWrite(0, "[runOperation]Ghost 输出: %s", line)
			if parsed, ok := parseProgressLine(line); ok {
				tracker.publishReal(progress, parsed)
			}
		}, g.workDir, args...)
		resultCh <- commandResult{output: out, err: err}
	}()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			g.terminateProcessTree(ctx)
			result := <-resultCh
			_ = result
			return fmt.Errorf("%w: %v", ErrCancelled, ctx.Err())
		case <-ticker.C:
			tracker.publishEstimate(progress, g.now())
		case result := <-resultCh:
			if result.err != nil {
				if ctx.Err() != nil || errors.Is(result.err, context.Canceled) || errors.Is(result.err, context.DeadlineExceeded) {
					return fmt.Errorf("%w: %v", ErrCancelled, ctx.Err())
				}
				return fmt.Errorf("%w: %v", ErrExecutionFailed, result.err)
			}

			tracker.publishDone(progress)
			return nil
		}
	}
}

func (g *Ghost) terminateProcessTree(ctx context.Context) {
	// 扩展点：如后续需要 taskkill /T 杀进程树，可集中放在这里。
	// 当前依赖 RunCmdContext/CommandContext 在取消时结束 Ghost 主进程。
}

func buildRestoreArgs(ghoFile string, diskNumber uint32, partitionNumber uint32) []string {
	target := ghostTarget(diskNumber, partitionNumber)
	return []string{
		fmt.Sprintf("-clone,mode=pload,src=%s,dst=%s", ghoFile, target),
		"-sure",
		"-fx",
		"-batch",
	}
}

func buildCreateArgs(diskNumber uint32, partitionNumber uint32, outFile string, compression uint8) []string {
	if compression < 1 {
		compression = 1
	}
	if compression > 9 {
		compression = 9
	}

	source := ghostTarget(diskNumber, partitionNumber)
	return []string{
		fmt.Sprintf("-clone,mode=pdump,src=%s,dst=%s", source, outFile),
		"-sure",
		"-fx",
		"-batch",
		fmt.Sprintf("-z%d", compression),
	}
}

func ghostTarget(diskNumber uint32, partitionNumber uint32) string {
	return strconv.FormatUint(uint64(diskNumber), 10) + ":" + strconv.FormatUint(uint64(partitionNumber), 10)
}

func resolveGhostPath(execPath string) (string, string) {
	path := strings.TrimSpace(execPath)
	if path == "" {
		if exe, err := os.Executable(); err == nil {
			path = filepath.Join(filepath.Dir(exe), "tools", "Ghost.exe")
		} else {
			path = filepath.Join("tools", "Ghost.exe")
		}
	}

	absPath, err := filepath.Abs(path)
	if err == nil {
		path = absPath
	}

	return path, filepath.Dir(path)
}

func normalizeLetter(letter string) (string, error) {
	s := strings.TrimSpace(letter)
	s = strings.TrimRight(s, `\/`)
	s = strings.ToUpper(s)

	if len(s) >= 2 && s[1] == ':' {
		s = s[:2]
	}
	if len(s) == 1 {
		s += ":"
	}
	if len(s) != 2 || s[1] != ':' || s[0] < 'A' || s[0] > 'Z' {
		return "", fmt.Errorf("invalid drive letter %q", letter)
	}
	return s, nil
}

func isFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func newProgressTracker(start time.Time, estimatedTotal uint64, status string) *progressTracker {
	return &progressTracker{
		start:           start,
		estimatedTotal:  estimatedTotal,
		estimatedWindow: estimateDurationForBytes(estimatedTotal),
		status:          status,
	}
}

func (t *progressTracker) publishReal(ch chan<- Progress, progress Progress) {
	t.mu.Lock()
	defer t.mu.Unlock()

	progress.Estimated = false
	if progress.Status == "" {
		progress.Status = t.status
	}
	if progress.Percentage < t.lastSent.Percentage {
		progress.Percentage = t.lastSent.Percentage
	}
	t.realProgressSeen = true
	if !shouldEmitProgress(t.lastSent, progress) {
		return
	}
	t.lastSent = progress
	emitProgress(ch, progress)
}

func (t *progressTracker) publishEstimate(ch chan<- Progress, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.realProgressSeen {
		return
	}

	progress := Progress{
		Percentage:     estimatePercentage(t.start, now, t.estimatedWindow),
		Status:         t.status,
		BytesTotal:     t.estimatedTotal,
		Estimated:      true,
		BytesProcessed: scaledBytes(t.estimatedTotal, estimatePercentage(t.start, now, t.estimatedWindow)),
	}
	if !shouldEmitProgress(t.lastSent, progress) {
		return
	}
	t.lastSent = progress
	emitProgress(ch, progress)
}

func (t *progressTracker) publishDone(ch chan<- Progress) {
	t.mu.Lock()
	defer t.mu.Unlock()

	done := Progress{
		Percentage:     100,
		Status:         t.status,
		BytesTotal:     t.estimatedTotal,
		BytesProcessed: t.estimatedTotal,
	}
	if !t.realProgressSeen && t.estimatedTotal > 0 {
		done.Estimated = true
	}
	t.lastSent = done
	emitProgress(ch, done)
}

func shouldEmitProgress(last Progress, next Progress) bool {
	return next.Percentage > last.Percentage || next.Status != last.Status || next.RawLine != last.RawLine
}

func emitProgress(ch chan<- Progress, progress Progress) {
	if ch == nil {
		return
	}
	select {
	case ch <- progress:
	default:
	}
}

func parseProgressLine(line string) (Progress, bool) {
	text := strings.TrimSpace(line)
	if text == "" {
		return Progress{}, false
	}

	progress := Progress{
		Status:  text,
		RawLine: text,
	}

	if match := fractionPattern.FindStringSubmatch(text); len(match) == 5 {
		processed := parseSizedValue(match[1], match[2])
		total := parseSizedValue(match[3], match[4])
		if total > 0 {
			progress.BytesProcessed = processed
			progress.BytesTotal = total
			progress.Percentage = uint8((processed * 100) / total)
			if progress.Percentage > 100 {
				progress.Percentage = 100
			}
		}
	}

	if match := speedPattern.FindStringSubmatch(text); len(match) == 4 {
		speed := parseSizedValue(match[1], match[2])
		switch strings.ToLower(match[3]) {
		case "m", "min", "mins", "minute", "minutes", "分":
			speed /= 60
		}
		progress.SpeedBytesPerSecond = speed
	}

	if match := percentPattern.FindStringSubmatch(text); len(match) == 2 {
		value, err := strconv.Atoi(match[1])
		if err == nil {
			if value < 0 {
				value = 0
			}
			if value > 100 {
				value = 100
			}
			progress.Percentage = uint8(value)
		}
	}

	if progress.Percentage == 0 && progress.BytesTotal == 0 {
		return Progress{}, false
	}
	return progress, true
}

func parseSizedValue(number string, unit string) uint64 {
	value, err := strconv.ParseFloat(number, 64)
	if err != nil || value <= 0 {
		return 0
	}

	multiplier := float64(1)
	switch strings.ToUpper(unit) {
	case "KB":
		multiplier = 1024
	case "MB":
		multiplier = 1024 * 1024
	case "GB":
		multiplier = 1024 * 1024 * 1024
	case "TB":
		multiplier = 1024 * 1024 * 1024 * 1024
	}

	return uint64(value * multiplier)
}

func estimateRestoreBytes(fileSize uint64) uint64 {
	if fileSize == 0 {
		return 0
	}

	maxUint := ^uint64(0)
	if fileSize > maxUint/2 {
		return maxUint
	}
	return fileSize * 2
}

func estimateDurationForBytes(total uint64) time.Duration {
	if total == 0 {
		return 5 * time.Minute
	}

	const bytesPerSecond = uint64(100 * 1024 * 1024)
	seconds := total / bytesPerSecond
	if total%bytesPerSecond != 0 {
		seconds++
	}
	if seconds < 60 {
		seconds = 60
	}
	if seconds > 12*60*60 {
		seconds = 12 * 60 * 60
	}
	return time.Duration(seconds) * time.Second
}

func estimatePercentage(start time.Time, now time.Time, window time.Duration) uint8 {
	if window <= 0 {
		return 0
	}
	if now.Before(start) {
		return 0
	}

	elapsed := now.Sub(start)
	if elapsed <= 0 {
		return 0
	}
	if elapsed >= window {
		return 95
	}

	pct := (elapsed * 95) / window
	if pct < 0 {
		return 0
	}
	if pct > 95 {
		return 95
	}
	return uint8(pct)
}

func scaledBytes(total uint64, percent uint8) uint64 {
	if total == 0 || percent == 0 {
		return 0
	}
	return (total * uint64(percent)) / 100
}
