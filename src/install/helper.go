package install

import (
	"ReSys/src/disk"
	"ReSys/src/dism"
	"ReSys/src/file"
	"ReSys/src/log"
	"ReSys/src/ui"
	"ReSys/src/utils"
	"fmt"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const (
	TargetWin7  = "win7"
	TargetWin10 = "win10"
	TargetWin11 = "win11"
)

const (
	enableDriverBackupFlow          = false
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

	installKernel32                 = syscall.NewLazyDLL("kernel32.dll")
	procGetVolumePathNameW          = installKernel32.NewProc("GetVolumePathNameW")
	procGetVolumeNameForMountPointW = installKernel32.NewProc("GetVolumeNameForVolumeMountPointW")
)

func driverBackupEnabled() bool {
	return enableDriverBackupFlow
}

func driverBackupWorkspaceReserveBytes() uint64 {
	if driverBackupEnabled() {
		return driverBackupReserveBytes
	}
	return 0
}

// sameVolumePath compares real volume identities so mounted partitions under the
// same drive letter are not mistaken for the system partition.
func sameVolumePath(pathA, pathB string) bool {
	idA := volumeIdentityForPath(pathA)
	idB := volumeIdentityForPath(pathB)
	if idA != "" && idB != "" {
		return strings.EqualFold(idA, idB)
	}

	rootA := normalizedVolumeRoot(pathA)
	rootB := normalizedVolumeRoot(pathB)
	return rootA != "" && rootB != "" && strings.EqualFold(rootA, rootB)
}

func volumeIdentityForPath(path string) string {
	raw := strings.TrimSpace(strings.ReplaceAll(path, "/", `\`))
	if raw == "" {
		return ""
	}

	lower := strings.ToLower(raw)
	if strings.HasPrefix(lower, `\\?\volume{`) {
		return strings.TrimRight(lower, `\`)
	}

	if mountPoint, err := getVolumeMountPoint(raw); err == nil && mountPoint != "" {
		if guid, err := getVolumeGUIDForMountPoint(mountPoint); err == nil && guid != "" {
			return strings.ToLower(strings.TrimRight(guid, `\`))
		}
		return strings.ToLower(strings.TrimRight(mountPoint, `\`))
	}

	root := normalizedVolumeRoot(raw)
	if root == "" {
		return ""
	}

	if vols, err := disk.ListVolumes(); err == nil {
		for _, vol := range vols {
			volRoot, _ := utils.NormalizeDrive(vol.RootPath, 0)
			if volRoot == "" || !strings.EqualFold(volRoot, root) {
				continue
			}
			if guid := strings.TrimSpace(vol.VolumeGuidPath); guid != "" {
				return strings.ToLower(strings.TrimRight(guid, `\`))
			}
			if guid := strings.TrimSpace(vol.PartitionGuid); guid != "" {
				return "partition:" + strings.ToLower(guid)
			}
			return fmt.Sprintf("disk:%d@%d", vol.DiskNumber, vol.OffsetBytes)
		}
	}

	return strings.ToUpper(root)
}

func normalizedVolumeRoot(path string) string {
	if root, err := utils.NormalizeDrive(path, 2); err == nil && root != "" {
		return root
	}
	root, _ := utils.NormalizeDrive(path, 0)
	return root
}

func getVolumeMountPoint(path string) (string, error) {
	pPath, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}

	buf := make([]uint16, 1024)
	r1, _, e1 := procGetVolumePathNameW.Call(
		uintptr(unsafe.Pointer(pPath)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if r1 == 0 {
		if e1 != nil && e1 != syscall.Errno(0) {
			return "", fmt.Errorf("GetVolumePathNameW: %w", e1)
		}
		return "", fmt.Errorf("GetVolumePathNameW failed")
	}

	return syscall.UTF16ToString(buf), nil
}

func getVolumeGUIDForMountPoint(mountPoint string) (string, error) {
	mp := strings.TrimSpace(strings.ReplaceAll(mountPoint, "/", `\`))
	if mp == "" {
		return "", fmt.Errorf("empty mount point")
	}
	if !strings.HasSuffix(mp, `\`) {
		mp += `\`
	}

	pMount, err := syscall.UTF16PtrFromString(mp)
	if err != nil {
		return "", err
	}

	buf := make([]uint16, 1024)
	r1, _, e1 := procGetVolumeNameForMountPointW.Call(
		uintptr(unsafe.Pointer(pMount)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if r1 == 0 {
		if e1 != nil && e1 != syscall.Errno(0) {
			return "", fmt.Errorf("GetVolumeNameForVolumeMountPointW: %w", e1)
		}
		return "", fmt.Errorf("GetVolumeNameForVolumeMountPointW failed")
	}

	return syscall.UTF16ToString(buf), nil
}

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

func cleanupDownloadArtifacts(dstPath string) error {
	targets := []string{
		strings.TrimSpace(dstPath),
		strings.TrimSpace(dstPath) + ".aria2",
		strings.TrimSpace(dstPath) + ".part",
		strings.TrimSpace(dstPath) + ".part.aria2",
	}

	for _, path := range targets {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		if _, err := os.Stat(path); err != nil {
			continue
		}
		if err := file.Remove(path, false); err != nil {
			return err
		}
	}

	return nil
}

func isLocalDownloadConflict(err error) bool {
	if err == nil {
		return false
	}

	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "exists, but a control file(*.aria2) does not exist") ||
		strings.Contains(msg, "control file(*.aria2) does not exist") ||
		strings.Contains(msg, "same file already exists") ||
		strings.Contains(msg, "file already exists")
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
