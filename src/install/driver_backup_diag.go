package install

import (
	driversvc "ReSys/src/driver"
	"ReSys/src/utils"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// DriverBackupSnapshot describes the current state of a driver backup tree.
type DriverBackupSnapshot struct {
	Root          string
	Exists        bool
	SubdirCount   int
	FileCount     int
	INFCount      int
	EmptyDirs     []string
	GUIDINFCounts map[string]int
}

var (
	driverBackupProbeSinkMu sync.Mutex
	driverBackupProbeSink   func(string)
)

// probeOn 返回当前是否处于 probe 观测模式。
func probeOn() bool {
	driverBackupProbeSinkMu.Lock()
	defer driverBackupProbeSinkMu.Unlock()
	return driverBackupProbeSink != nil
}

// SetDriverBackupProbeSink registers a line sink used by probe tooling.
func SetDriverBackupProbeSink(fn func(string)) func() {
	driverBackupProbeSinkMu.Lock()
	prev := driverBackupProbeSink
	driverBackupProbeSink = fn
	driverBackupProbeSinkMu.Unlock()

	return func() {
		driverBackupProbeSinkMu.Lock()
		driverBackupProbeSink = prev
		driverBackupProbeSinkMu.Unlock()
	}
}

// CollectDriverBackupSnapshot collects a recursive snapshot for a backup root.
func CollectDriverBackupSnapshot(root string) (DriverBackupSnapshot, error) {
	snapshot := DriverBackupSnapshot{
		Root:          root,
		GUIDINFCounts: map[string]int{},
	}

	root = strings.TrimSpace(root)
	snapshot.Root = root
	if root == "" {
		return snapshot, fmt.Errorf("driver backup root is empty")
	}

	info, err := os.Stat(root)
	if err != nil {
		if os.IsNotExist(err) {
			return snapshot, nil
		}
		return snapshot, err
	}
	if !info.IsDir() {
		return snapshot, fmt.Errorf("driver backup root is not a directory: %s", root)
	}
	snapshot.Exists = true

	err = filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		if d.IsDir() {
			snapshot.SubdirCount++
			entries, readErr := os.ReadDir(path)
			if readErr != nil {
				return readErr
			}
			if len(entries) == 0 {
				rel, relErr := filepath.Rel(root, path)
				if relErr != nil {
					rel = path
				}
				snapshot.EmptyDirs = append(snapshot.EmptyDirs, rel)
			}
			return nil
		}

		snapshot.FileCount++
		if strings.EqualFold(filepath.Ext(path), ".inf") {
			snapshot.INFCount++
		}
		return nil
	})
	if err != nil {
		return snapshot, err
	}

	guidRoot := filepath.Join(root, driverBackupGUIDDir)
	if st, statErr := os.Stat(guidRoot); statErr == nil && st.IsDir() {
		entries, readErr := os.ReadDir(guidRoot)
		if readErr != nil {
			return snapshot, readErr
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			dir := filepath.Join(guidRoot, entry.Name())
			infCount, countErr := countINFUnderDir(dir)
			if countErr != nil {
				return snapshot, countErr
			}
			snapshot.GUIDINFCounts[entry.Name()] = infCount
		}
	}

	sort.Strings(snapshot.EmptyDirs)
	return snapshot, nil
}

// CollectDriverBackupSnapshotForPlan collects a snapshot from the plan-derived backup root.
func CollectDriverBackupSnapshotForPlan(plan *InstallPlan) (DriverBackupSnapshot, error) {
	root, err := driverBackupRoot(plan)
	if err != nil {
		return DriverBackupSnapshot{}, err
	}
	return CollectDriverBackupSnapshot(root)
}

func driverBackupSummaryLines(label string, snapshot DriverBackupSnapshot) []string {
	lines := []string{
		fmt.Sprintf(
			"[driverBackupSummary] stage=%s root=%s exists=%t dirs=%d files=%d infs=%d empty_dirs=%d guid_dirs=%d",
			label,
			snapshot.Root,
			snapshot.Exists,
			snapshot.SubdirCount,
			snapshot.FileCount,
			snapshot.INFCount,
			len(snapshot.EmptyDirs),
			len(snapshot.GUIDINFCounts),
		),
	}

	for idx, dir := range snapshot.EmptyDirs {
		lines = append(lines, fmt.Sprintf("[driverBackupSummary] stage=%s empty_dir[%d]=%s", label, idx+1, dir))
	}

	if len(snapshot.GUIDINFCounts) > 0 {
		keys := make([]string, 0, len(snapshot.GUIDINFCounts))
		for key := range snapshot.GUIDINFCounts {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			lines = append(lines, fmt.Sprintf("[driverBackupSummary] stage=%s guid_inf_count[%s]=%d", label, key, snapshot.GUIDINFCounts[key]))
		}
	}

	return lines
}

// emitDriverBackupProbeLine 只把探针行转发给 probe sink，不写正式日志。
func emitDriverBackupProbeLine(line string) {
	driverBackupProbeSinkMu.Lock()
	sink := driverBackupProbeSink
	driverBackupProbeSinkMu.Unlock()
	if sink != nil {
		sink(line)
	}
}

func emitDriverBackupProbef(format string, args ...any) {
	emitDriverBackupProbeLine(fmt.Sprintf(format, args...))
}

// logDriverBackupSnapshot 仅在 probe 模式下采集并输出目录摘要。
func logDriverBackupSnapshot(label, root string) {
	if !probeOn() {
		return
	}
	snapshot, err := CollectDriverBackupSnapshot(root)
	if err != nil {
		emitDriverBackupProbef("[driverBackupSummary] stage=%s root=%s snapshot_error=%v", label, root, err)
		return
	}
	for _, line := range driverBackupSummaryLines(label, snapshot) {
		emitDriverBackupProbeLine(line)
	}
}

// logDriverBackupPlan 仅在 probe 模式下输出驱动备份计划摘要。
func logDriverBackupPlan(label string, plan *InstallPlan) {
	if !probeOn() {
		return
	}
	if plan == nil {
		emitDriverBackupProbef("[driverBackupPlan] stage=%s plan=nil", label)
		return
	}

	imageRoot, _ := utils.NormalizeDrive(plan.ImagePath, 2)
	targetRoot, _ := utils.NormalizeDrive(plan.TargetRoot, 0)
	emitDriverBackupProbef(
		"[driverBackupPlan] stage=%s image=%s image_root=%s target=%s backup=%t restore=%t file_rules=%v guid_rules=%v",
		label,
		plan.ImagePath,
		imageRoot,
		targetRoot,
		plan.Flags.NeedBackupBeforePE,
		plan.Flags.NeedOfflineDrivers,
		driversvc.NormalizeINFPatterns(plan.DriverFiles),
		uniqueTrimmedStrings(plan.DriverGUIDs),
	)
}
