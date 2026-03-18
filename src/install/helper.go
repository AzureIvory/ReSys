package install

import (
	"ReSys/src/dism"
	"ReSys/src/log"
	"ReSys/src/ui"
	"fmt"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	TargetWin7  = "win7"
	TargetWin10 = "win10"
	TargetWin11 = "win11"
)

const (
	peLinksID                       = "pe_links"
	minImageBytes            uint64 = 7 * 1024 * 1024 * 1024
	driverBackupReserveBytes uint64 = 8 * 1024 * 1024 * 1024
	tempMarkerRel                   = `RESTALL\temp.marker`
	driverBackupDirName             = "driverbackup"
	driverBackupOEMDir              = "oem"
	driverBackupGUIDDir             = "classguid"

	statePreparedPE     = "prepared_pe"
	stateFailedPEImages = "failed_pe_images"
	stateSkipLocalWePE  = "skip_local_wepe"
	stateImageInfos     = "image_infos"
)

var (
	failedLinksMu sync.Mutex
	failedLinks   = map[string]struct{}{}
)

type ProgressReporter struct {
	base, span int32
	uiEvery    time.Duration
	logEvery   time.Duration
	lastUI     time.Time
	lastLog    time.Time
	statusFmt  string
	logFmt     string
	enableLog  bool
}

// Update 按节流策略刷新界面和日志中的进度。
func (p *ProgressReporter) Update(pct float64, speedBytes int64) {
	defer func() {
		if r := recover(); r != nil {
			log.LogWrite(-2, "[ProgressReporter.Update] panic: pct=%.2f speed=%d panic=%v stack=%s", pct, speedBytes, r, string(debug.Stack()))
		}
	}()

	now := time.Now()
	if p.uiEvery <= 0 {
		p.uiEvery = 200 * time.Millisecond
	}
	if p.lastUI.IsZero() || now.Sub(p.lastUI) >= p.uiEvery || pct >= 100 {
		ui.UiSetStatus(fmt.Sprintf(p.statusFmt, pct, float64(speedBytes)/1024.0/1024.0))
		ui.UiSetProgress(MapPct(p.base, p.span, pct))
		p.lastUI = now
	}

	if !p.enableLog {
		return
	}
	if p.logEvery <= 0 {
		p.logEvery = time.Second
	}
	if p.lastLog.IsZero() || now.Sub(p.lastLog) >= p.logEvery || pct >= 100 {
		log.LogWrite(0, p.logFmt, pct, float64(speedBytes)/1024.0/1024.0)
		p.lastLog = now
	}
}

// MapPct 将局部百分比映射到全局进度区间。
func MapPct(base, span int32, pct float64) int32 {
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	return base + int32(pct*float64(span)/100.0+0.5)
}

// NewProgressReporter 创建带节流控制的进度上报器。
func NewProgressReporter(base, span int32, uiEvery, logEvery time.Duration, statusFmt, logFmt string, enableLog bool) *ProgressReporter {
	return &ProgressReporter{
		base:      base,
		span:      span,
		uiEvery:   uiEvery,
		logEvery:  logEvery,
		statusFmt: statusFmt,
		logFmt:    logFmt,
		enableLog: enableLog,
	}
}

// markFailedLink 记录已失败的下载链接。
func markFailedLink(link string) {
	link = strings.TrimSpace(link)
	if link == "" {
		return
	}

	failedLinksMu.Lock()
	defer failedLinksMu.Unlock()
	failedLinks[link] = struct{}{}
}

// isFailedLink 判断下载链接是否已被标记失败。
func isFailedLink(link string) bool {
	link = strings.TrimSpace(link)
	if link == "" {
		return false
	}

	failedLinksMu.Lock()
	defer failedLinksMu.Unlock()
	_, ok := failedLinks[link]
	return ok
}

// logLinkSwitch 记录下载链路切换的原因。
func logLinkSwitch(scope, fromLink, toLink, reason string) {
	fromLink = strings.TrimSpace(fromLink)
	toLink = strings.TrimSpace(toLink)
	reason = strings.TrimSpace(strings.ReplaceAll(reason, "\n", " "))
	if fromLink == "" || toLink == "" || strings.EqualFold(fromLink, toLink) {
		return
	}
	if reason == "" {
		reason = "previous link became unavailable"
	}
	log.LogWrite(0, "[%s] switched download link: %s -> %s reason: %s", scope, fromLink, toLink, reason)
}

// parsePlanBool 解析计划文件中的布尔值。
func parsePlanBool(v string) bool {
	ok, err := strconv.ParseBool(strings.TrimSpace(v))
	return err == nil && ok
}

// fileSize 返回文件大小并拒绝目录路径。
func fileSize(path string) (uint64, error) {
	st, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	if st.IsDir() {
		return 0, fmt.Errorf("image path is a directory: %s", path)
	}
	return uint64(st.Size()), nil
}

// formatImageInfos 将镜像元数据格式化为日志字符串。
func formatImageInfos(infos []dism.ImageMeta) string {
	var parts []string
	for _, info := range infos {
		parts = append(parts, fmt.Sprintf("Index=%d Name=%s Desc=%s Edition=%s Flags=%s Arch=%s",
			info.Index, info.Name, info.Description, info.Edition, info.Flags, info.Arch))
	}
	return strings.Join(parts, " | ")
}
