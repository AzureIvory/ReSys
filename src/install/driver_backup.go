package install

import (
	"ReSys/src/disk"
	"ReSys/src/dism"
	driversvc "ReSys/src/driver"
	"ReSys/src/log"
	"ReSys/src/ui"
	"ReSys/src/utils"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// backupDriversBeforeEnterPE 按 JSON 规则备份在线驱动。
//
// 当前支持两类规则：
// 1. file: 按 OEM INF 文件名通配符筛选；
// 2. guid: 按设备类 GUID 单独导出。
func backupDriversBeforeEnterPE(ctx *InstallContext) error {
	if ctx == nil || ctx.Plan == nil {
		return fmt.Errorf("install context is nil")
	}
	if !ctx.Plan.Flags.NeedBackupBeforePE {
		log.LogWrite(0, "[backupDriversBeforeEnterPE] skip: backup not requested")
		return nil
	}

	if err := ensureDriverBackupWorkspace(ctx.Plan); err != nil {
		return err
	}

	backupRoot, err := driverBackupRoot(ctx.Plan)
	if err != nil {
		return err
	}
	if err := resetDriverBackupRoot(backupRoot); err != nil {
		return err
	}

	fileRules := trimDriverRules(ctx.Plan.DriverFiles)
	guidRules := trimDriverRules(ctx.Plan.DriverGUIDs)
	if len(fileRules) == 0 && len(guidRules) == 0 {
		log.LogWrite(0, "[backupDriversBeforeEnterPE] skip: no file/guid rule configured")
		return SaveInstallPlan(ctx.Plan)
	}

	if len(fileRules) > 0 {
		oemDir := filepath.Join(backupRoot, driverBackupOEMDir)
		ui.UiSetStatus(ui.Tr("install.driver.backupOEM"))
		log.LogWrite(0, "[backupDriversBeforeEnterPE] OEM backup root=%s image=%s dir=%s", backupRoot, ctx.Plan.ImagePath, oemDir)

		dismSvc := dism.NewDism()
		if err := dismSvc.ExportDriversOnlineCmd(oemDir, nil); err != nil {
			return fmt.Errorf("backup online OEM drivers failed: %w", err)
		}
		if err := filterDriverDirs(oemDir, fileRules); err != nil {
			return err
		}
	}

	if len(guidRules) > 0 {
		guidRoot := filepath.Join(backupRoot, driverBackupGUIDDir)
		for _, guid := range guidRules {
			dirName := driverGUIDDirName(guid)
			dstDir := filepath.Join(guidRoot, dirName)
			count, err := driversvc.ExportDriversByClassGUID(dstDir, guid)
			if err != nil {
				return fmt.Errorf("backup guid %s drivers failed: %w", guid, err)
			}
			log.LogWrite(0, "[backupDriversBeforeEnterPE] guid backup completed: guid=%s count=%d dir=%s", guid, count, dstDir)
		}
	}

	infCount, err := countINFUnderDir(backupRoot)
	if err != nil {
		return err
	}
	log.LogWrite(0, "[backupDriversBeforeEnterPE] backup completed: dir=%s infCount=%d", backupRoot, infCount)
	return SaveInstallPlan(ctx.Plan)
}

func restoreBackedUpDrivers(ctx *InstallContext) error {
	if ctx == nil || ctx.Plan == nil {
		return fmt.Errorf("install context is nil")
	}
	if !ctx.Plan.Flags.NeedOfflineDrivers {
		log.LogWrite(0, "[restoreBackedUpDrivers] skip: restore not requested")
		return nil
	}
	if ctx.Plan.TargetRoot == "" {
		return fmt.Errorf("install target root is empty")
	}

	backupRoot, err := driverBackupRoot(ctx.Plan)
	if err != nil {
		return err
	}
	if st, err := os.Stat(backupRoot); err != nil || !st.IsDir() {
		return fmt.Errorf("driver backup directory not found: %s", backupRoot)
	}

	infCount, err := countINFUnderDir(backupRoot)
	if err != nil {
		return err
	}
	if infCount == 0 {
		log.LogWrite(0, "[restoreBackedUpDrivers] skip: no inf found under %s", backupRoot)
		return nil
	}

	ui.UiSetStatus(ui.Tr("install.driver.restore"))
	log.LogWrite(0, "[restoreBackedUpDrivers] restore start: offlineRoot=%s backupRoot=%s infCount=%d", ctx.Plan.TargetRoot, backupRoot, infCount)

	success, fail, err := driversvc.ImportDriversOffline(ctx.Plan.TargetRoot, backupRoot)
	if err != nil {
		return fmt.Errorf("restore backed up drivers failed: %w", err)
	}

	log.LogWrite(0, "[restoreBackedUpDrivers] restore completed: success=%d fail=%d backupRoot=%s", success, fail, backupRoot)
	return nil
}

func ensureDriverBackupWorkspace(plan *InstallPlan) error {
	if plan == nil {
		return fmt.Errorf("install plan is nil")
	}
	imagePath := plan.ImagePath
	if imagePath == "" {
		return fmt.Errorf("install image path is empty")
	}

	imageRoot, _ := utils.NormalizeDrive(imagePath, 2)
	if imageRoot == "" {
		return nil
	}

	if freeBytes, err := disk.GetFreeSize(imageRoot); err == nil && freeBytes >= driverBackupReserveBytes {
		return nil
	}

	needBytes, err := fileSize(imagePath)
	if err != nil {
		return err
	}

	if movedPath, moved, err := moveImageToDisk(imagePath, imageRoot, needBytes); err != nil {
		return err
	} else if moved {
		plan.ImagePath = movedPath
		log.LogWrite(0, "[ensureDriverBackupWorkspace] moved image to larger fixed drive: %s", movedPath)
		return nil
	}

	movedPath, err := moveImageToTemp(imagePath, needBytes)
	if err != nil {
		return err
	}
	plan.ImagePath = movedPath
	log.LogWrite(0, "[ensureDriverBackupWorkspace] moved image to temp workspace: %s", movedPath)
	return nil
}

func driverBackupRoot(plan *InstallPlan) (string, error) {
	if plan == nil {
		return "", fmt.Errorf("install plan is nil")
	}
	imagePath := filepath.Clean(plan.ImagePath)
	if imagePath == "." || imagePath == "" {
		return "", fmt.Errorf("install image path is empty")
	}
	return filepath.Join(filepath.Dir(imagePath), driverBackupDirName), nil
}

func resetDriverBackupRoot(dir string) error {
	if dir == "" {
		return fmt.Errorf("driver backup dir is empty")
	}
	if _, err := os.Stat(dir); err == nil {
		if err := os.RemoveAll(dir); err != nil {
			return err
		}
	}
	return os.MkdirAll(dir, 0o755)
}

func countINFUnderDir(root string) (int, error) {
	count := 0
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		if filepath.Ext(path) == ".inf" || filepath.Ext(path) == ".INF" {
			count++
		}
		return nil
	})
	return count, err
}

func trimDriverRules(items []string) []string {
	if len(items) == 0 {
		return []string{}
	}

	out := make([]string, 0, len(items))
	seen := map[string]struct{}{}
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		key := strings.ToLower(item)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	return out
}

func matchDriverFile(name string, patterns []string) bool {
	name = strings.ToLower(strings.TrimSpace(filepath.Base(name)))
	if name == "" {
		return false
	}
	for _, pattern := range patterns {
		pattern = strings.ToLower(strings.TrimSpace(filepath.Base(pattern)))
		if pattern == "" {
			continue
		}
		if ok, err := filepath.Match(pattern, name); err == nil && ok {
			return true
		}
	}
	return false
}

func filterDriverDirs(root string, patterns []string) error {
	patterns = trimDriverRules(patterns)
	if len(patterns) == 0 {
		return nil
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		path := filepath.Join(root, entry.Name())
		keep, err := keepDriverPath(path, patterns)
		if err != nil {
			return err
		}
		if !keep {
			if err := os.RemoveAll(path); err != nil {
				return err
			}
		}
	}
	return nil
}

func keepDriverPath(path string, patterns []string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	if !info.IsDir() {
		return matchDriverFile(path, patterns), nil
	}

	keep := false
	err = filepath.WalkDir(path, func(filePath string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		if !strings.EqualFold(filepath.Ext(filePath), ".inf") {
			return nil
		}
		if matchDriverFile(filePath, patterns) {
			keep = true
		}
		return nil
	})
	return keep, err
}

func driverGUIDDirName(guid string) string {
	guid = strings.TrimSpace(strings.Trim(guid, "{}"))
	guid = strings.ReplaceAll(guid, "-", "_")
	guid = strings.ReplaceAll(guid, ":", "_")
	guid = strings.ToLower(guid)
	if guid == "" {
		return "guid"
	}
	return guid
}
