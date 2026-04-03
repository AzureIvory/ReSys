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
)

type driverBackupSpec struct {
	Label string
	GUID  string
	Dir   string
}

var driverBackupSpecs = []driverBackupSpec{
	{Label: "USB devices", GUID: "{88BAE032-5A81-49F0-BC3D-A4FF138216D6}", Dir: "usb_devices"},
	{Label: "Printers", GUID: "{4D36E979-E325-11CE-BFC1-08002BE10318}", Dir: "printers"},
	{Label: "Dot4 printers", GUID: "{49CE6AC8-6F86-11D2-B1E5-0080C72E74A2}", Dir: "dot4_printers"},
	{Label: "Network adapters", GUID: "{4D36E972-E325-11CE-BFC1-08002BE10318}", Dir: "network_adapters"},
	{Label: "Bluetooth", GUID: "{E0CBF06C-CD8B-4647-BB8A-263B43F0F974}", Dir: "bluetooth"},
	{Label: "Keyboards", GUID: "{4D36E96B-E325-11CE-BFC1-08002BE10318}", Dir: "keyboards"},
	{Label: "Mice", GUID: "{4D36E96F-E325-11CE-BFC1-08002BE10318}", Dir: "mice"},
}

func backupDriversBeforeEnterPE(ctx *InstallContext) error {
	if ctx == nil || ctx.Plan == nil {
		return fmt.Errorf("install context is nil")
	}
	if !driverBackupEnabled() {
		log.LogWrite(0, "[backupDriversBeforeEnterPE] skip: driver backup disabled")
		return nil
	}
	if !ctx.Plan.Flags.NeedBackupBeforePE {
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

	ui.UiSetStatus("正在备份驱动...")
	log.LogWrite(0, "[backupDriversBeforeEnterPE] backup root=%s image=%s", backupRoot, ctx.Plan.ImagePath)

	dismSvc := dism.NewDism()
	oemDir := filepath.Join(backupRoot, driverBackupOEMDir)
	if err := dismSvc.ExportDriversOnlineCmd(oemDir, nil); err != nil {
		return fmt.Errorf("backup online OEM drivers failed: %w", err)
	}

	guidRoot := filepath.Join(backupRoot, driverBackupGUIDDir)
	for _, spec := range driverBackupSpecs {
		dstDir := filepath.Join(guidRoot, spec.Dir)
		count, err := driversvc.ExportDriversByClassGUID(dstDir, spec.GUID)
		if err != nil {
			return fmt.Errorf("backup %s drivers failed: %w", spec.Label, err)
		}
		log.LogWrite(0, "[backupDriversBeforeEnterPE] exported %s drivers: guid=%s count=%d dir=%s", spec.Label, spec.GUID, count, dstDir)
	}

	infCount, err := countINFUnderDir(backupRoot)
	if err != nil {
		return err
	}
	log.LogWrite(0, "[backupDriversBeforeEnterPE] completed: backupRoot=%s infCount=%d", backupRoot, infCount)
	return SaveInstallPlan(ctx.Plan)
}

func restoreBackedUpDrivers(ctx *InstallContext) error {
	if ctx == nil || ctx.Plan == nil {
		return fmt.Errorf("install context is nil")
	}
	if !driverBackupEnabled() {
		log.LogWrite(0, "[restoreBackedUpDrivers] skip: driver restore disabled")
		return nil
	}
	if !ctx.Plan.Flags.NeedOfflineDrivers {
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

	ui.UiSetStatus("正在恢复备份驱动...")
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
	if !driverBackupEnabled() {
		return nil
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
