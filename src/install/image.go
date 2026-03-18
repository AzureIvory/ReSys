package install

import (
	"ReSys/src/data"
	"ReSys/src/disk"
	"ReSys/src/dism"
	"ReSys/src/download"
	"ReSys/src/file"
	"ReSys/src/image"
	"ReSys/src/log"
	"ReSys/src/ui"
	"ReSys/src/utils"
	"ReSys/src/windows"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ===== 镜像获取 =====

// AcquireInstallImage 定位或下载可用的安装镜像。
func AcquireInstallImage(plan *InstallPlan) (string, error) {
	if err := NormalizeInstallPlan(plan); err != nil {
		return "", err
	}

	imgPath, err := findInstallImage(plan)
	if err != nil {
		return "", err
	}

	imgPath, err = relocateInstallImage(imgPath)
	if err != nil {
		return "", err
	}

	plan.ImagePath = imgPath
	return imgPath, nil
}

// RecoverOrAcquireInstallImage 优先恢复镜像路径，失败后重新获取镜像。
func RecoverOrAcquireInstallImage(plan *InstallPlan) (string, error) {
	if plan == nil {
		return "", fmt.Errorf("install plan is nil")
	}

	if recovered, err := RecoverInstallImagePath(plan); err == nil && strings.TrimSpace(recovered) != "" {
		return recovered, nil
	}

	return AcquireInstallImage(plan)
}

// findInstallImage 优先查找本地镜像，再回退到下载。
func findInstallImage(plan *InstallPlan) (string, error) {
	if local, err := image.FindLocalImage(plan.TargetOS, plan.ImageArch); err == nil && strings.TrimSpace(local) != "" {
		return local, nil
	}

	if plan.TargetOS == TargetWin10 || plan.TargetOS == TargetWin11 {
		if imgPath, err := downloadMSImage(plan.TargetOS, plan.ImageArch); err == nil && strings.TrimSpace(imgPath) != "" {
			return imgPath, nil
		} else if err != nil {
			log.LogWrite(0, "[AcquireInstallImage] Microsoft direct download failed: %v", err)
		}
	}

	return DownloadImage(plan.TargetOS, plan.ImageArch)
}

// RecoverInstallImagePath 根据持久化线索恢复镜像路径。
func RecoverInstallImagePath(plan *InstallPlan) (string, error) {
	if plan == nil {
		return "", fmt.Errorf("install plan is nil")
	}

	if path := strings.TrimSpace(plan.ImagePath); path != "" {
		if _, err := os.Stat(path); err == nil {
			plan.ImagePath = path
			return path, nil
		}
		log.LogWrite(0, "[RecoverInstallImagePath] persisted image path unavailable: %s", path)
	}

	base := filepath.Base(strings.TrimSpace(plan.ImagePath))
	if base == "" && strings.TrimSpace(plan.ImageRel) != "" {
		base = filepath.Base(plan.ImageRel)
	}

	tryRoot := func(root string) (string, bool) {
		if nr, err := utils.NormalizeDrive(root, 0); err == nil {
			root = nr
		}
		if root == "" {
			return "", false
		}

		if rel := strings.TrimSpace(plan.ImageRel); rel != "" {
			cand := filepath.Join(root, strings.TrimPrefix(rel, `\`))
			if _, err := os.Stat(cand); err == nil {
				return cand, true
			}
		}

		if plan.ImageRel == "" && strings.TrimSpace(plan.ImagePath) != "" && len(plan.ImagePath) > 2 {
			cand := filepath.Join(root, strings.TrimPrefix(plan.ImagePath[2:], `\`))
			if _, err := os.Stat(cand); err == nil {
				return cand, true
			}
		}

		if base != "" {
			found, _ := file.FindFile(root, base, 3)
			if len(found) > 0 {
				return found[0], true
			}
		}

		return "", false
	}

	if volumeGUID := strings.TrimSpace(plan.VolumeGUID); volumeGUID != "" {
		if vols, err := disk.ListVolumes(); err == nil {
			for _, v := range vols {
				if strings.EqualFold(strings.TrimRight(v.VolumeGuidPath, `\`), strings.TrimRight(volumeGUID, `\`)) {
					root := v.RootPath
					if root == "" {
						root = v.VolumeGuidPath
					}
					if cand, ok := tryRoot(root); ok {
						plan.ImagePath = cand
						return cand, nil
					}
					log.LogWrite(0, "[RecoverInstallImagePath] volume guid matched but image missing: %s", volumeGUID)
					break
				}
			}
		} else {
			log.LogWrite(0, "[RecoverInstallImagePath] list volumes failed: %v", err)
		}
	}

	if diskUniqueID := strings.TrimSpace(plan.DiskUniqueID); diskUniqueID != "" {
		if disks, err := disk.ListPhysicalDisks(); err == nil {
			for _, d := range disks {
				if strings.EqualFold(strings.TrimSpace(d.UniqueId), diskUniqueID) {
					if _, roots, derr := disk.GetDiskPartitions(fmt.Sprintf("%d", d.DiskNumber)); derr == nil {
						for _, root := range roots {
							if cand, ok := tryRoot(root); ok {
								plan.ImagePath = cand
								return cand, nil
							}
						}
						log.LogWrite(0, "[RecoverInstallImagePath] disk unique id matched but image missing: %s", diskUniqueID)
					} else {
						log.LogWrite(0, "[RecoverInstallImagePath] disk unique id matched but partitions unavailable: %s err=%v", diskUniqueID, derr)
					}
					break
				}
			}
		} else {
			log.LogWrite(0, "[RecoverInstallImagePath] list physical disks failed: %v", err)
		}
	}

	if diskPath := strings.TrimSpace(plan.DiskPath); diskPath != "" {
		if _, roots, err := disk.GetDiskPartitions(diskPath); err == nil {
			for _, root := range roots {
				if cand, ok := tryRoot(root); ok {
					plan.ImagePath = cand
					return cand, nil
				}
			}
			log.LogWrite(0, "[RecoverInstallImagePath] physical disk matched but image missing: %s", diskPath)
		} else {
			log.LogWrite(0, "[RecoverInstallImagePath] get disk partitions failed: %s err=%v", diskPath, err)
		}
	}

	roots, _ := disk.ListDrive()
	for _, root := range roots {
		imgDat := filepath.Join(root, "restall_img.dat")
		if _, err := os.Stat(imgDat); err != nil {
			continue
		}

		b, err := os.ReadFile(imgDat)
		if err != nil {
			continue
		}
		for _, ln := range strings.Split(string(b), "\n") {
			ln = strings.TrimSpace(ln)
			if !strings.HasPrefix(ln, "image=") {
				continue
			}

			cand := strings.TrimSpace(strings.TrimPrefix(ln, "image="))
			if _, err := os.Stat(cand); err == nil {
				plan.ImagePath = cand
				return cand, nil
			}

			base = filepath.Base(cand)
			found, _ := file.FindFile(root, base, 3)
			if len(found) > 0 {
				plan.ImagePath = found[0]
				return found[0], nil
			}
		}
	}

	return "", fmt.Errorf("未找到镜像文件")
}

// verifyMSImage 校验微软直链镜像是否完整。
func verifyMSImage(info data.MSWinURL, imagePath string) error {
	if strings.TrimSpace(info.SHA1) != "" {
		ok, got, err := download.CheckFileSHA1(imagePath, info.SHA1)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("SHA1 mismatch: %s", got)
		}
		return nil
	}

	_, err := image.DetectImageInfos(imagePath)
	return err
}

// validateImageFile 校验通用镜像文件是否可复用。
func validateImageFile(it data.WinImg, imagePath string) error {
	if strings.TrimSpace(it.SHA1) != "" {
		ok, got, err := download.CheckFileSHA1(imagePath, it.SHA1)
		if err != nil {
			return fmt.Errorf("SHA1 verification failed: %w", err)
		}
		if !ok {
			return fmt.Errorf("SHA1 mismatch: %s", got)
		}
		return nil
	}

	switch strings.ToLower(filepath.Ext(imagePath)) {
	case ".iso", ".wim", ".esd":
		if _, err := image.DetectImageInfos(imagePath); err != nil {
			return fmt.Errorf("image is corrupted: %w", err)
		}
	}
	return nil
}

// relocateInstallImage 在镜像落在系统盘时将其迁走。
func relocateInstallImage(imgPath string) (string, error) {
	systemRoot, _ := utils.NormalizeDrive(windows.SystemDriveRoot(), 0)
	imageRoot, _ := utils.NormalizeDrive(imgPath, 2)
	if systemRoot == "" || imageRoot == "" || !strings.EqualFold(systemRoot, imageRoot) {
		return imgPath, nil
	}

	needBytes, err := fileSize(imgPath)
	if err != nil {
		return "", err
	}

	if movedPath, moved, err := moveImageToDisk(imgPath, systemRoot, needBytes); err != nil {
		return "", err
	} else if moved {
		return movedPath, nil
	}

	return moveImageToTemp(imgPath, needBytes)
}

// EnsureInstallImageOutsideTarget 确保镜像不与目标分区重叠。
func EnsureInstallImageOutsideTarget(plan *InstallPlan) error {
	if plan == nil || strings.TrimSpace(plan.ImagePath) == "" || strings.TrimSpace(plan.TargetRoot) == "" {
		return nil
	}

	imageRoot, _ := utils.NormalizeDrive(plan.ImagePath, 2)
	targetRoot, _ := utils.NormalizeDrive(plan.TargetRoot, 0)
	if imageRoot == "" || targetRoot == "" || !strings.EqualFold(imageRoot, targetRoot) {
		return nil
	}

	needBytes, err := fileSize(plan.ImagePath)
	if err != nil {
		return err
	}

	if movedPath, moved, err := moveImageToDisk(plan.ImagePath, targetRoot, needBytes); err != nil {
		return err
	} else if moved {
		plan.ImagePath = movedPath
		return nil
	}

	movedPath, err := moveImageToTemp(plan.ImagePath, needBytes)
	if err != nil {
		return err
	}
	plan.ImagePath = movedPath
	return nil
}

// moveImageToDisk 优先把镜像迁移到其他固定盘。
func moveImageToDisk(imgPath, systemRoot string, needBytes uint64) (string, bool, error) {
	const extraBytes uint64 = 512*1024*1024 + driverBackupReserveBytes

	var (
		bestRoot string
		bestFree uint64
	)

	for _, root := range getotherVolumes(systemRoot) {
		freeBytes, err := disk.GetFreeSize(root)
		if err != nil {
			continue
		}
		if freeBytes >= needBytes+extraBytes && freeBytes > bestFree {
			bestRoot = root
			bestFree = freeBytes
		}
	}

	if bestRoot == "" {
		return "", false, nil
	}

	ui.UiSetStatus("镜像位于系统盘，正在迁移到其他固定盘...")
	movedPath, err := moveImageFile(imgPath, bestRoot, "tempimg")
	if err != nil {
		return "", false, err
	}
	log.LogWrite(0, "[moveImageToDisk] image moved to %s", movedPath)
	return movedPath, true, nil
}

// moveImageToTemp 把镜像迁移到临时分区。
func moveImageToTemp(imgPath string, needBytes uint64) (string, error) {
	ui.UiSetStatus("镜像位于系统盘，正在创建 TEMP 分区并迁移镜像...")

	tmpRoot, err := disk.EnsureTempVolumeForBytes(needBytes + driverBackupReserveBytes)
	if err != nil {
		return "", err
	}

	movedPath, err := moveImageFile(imgPath, tmpRoot, "tempimg")
	if err != nil {
		return "", err
	}

	log.LogWrite(0, "[moveImageToTemp] image moved to %s", movedPath)
	return movedPath, nil
}

// moveImageFile 将镜像复制到目标目录并切换路径。
func moveImageFile(srcPath, root, subDir string) (string, error) {
	dstDir := filepath.Join(root, subDir)
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return "", err
	}

	dstPath := filepath.Join(dstDir, filepath.Base(srcPath))
	log.LogWrite(0, "[moveImageFile] %s -> %s", srcPath, dstPath)
	if err := file.Copy(srcPath, dstPath, true, true); err != nil {
		_ = file.Remove(dstPath, false)
		return "", err
	}
	if _, err := os.Stat(dstPath); err != nil {
		return "", err
	}
	if !strings.EqualFold(srcPath, dstPath) {
		if err := file.Remove(srcPath, false); err != nil {
			return "", err
		}
	}
	return dstPath, nil
}

// ===== 镜像索引选择 =====

// ResolveInstallImageIndex 读取镜像元数据并选择安装索引。
func ResolveInstallImageIndex(ctx *InstallContext) error {
	if ctx == nil || ctx.Plan == nil {
		return fmt.Errorf("install context is nil")
	}

	infos, err := image.DetectImageInfos(ctx.Plan.ImagePath)
	if err != nil {
		return err
	}

	if ctx.State == nil {
		ctx.State = map[string]any{}
	}
	ctx.State[stateImageInfos] = infos

	if ctx.Plan.ImageIndex <= 0 {
		ctx.Plan.ImageIndex = SelectInstallIndex(infos)
	}
	if strings.TrimSpace(ctx.Plan.TargetOS) == "" {
		if target := image.DetectTargetFromInfos(infos); target != "" {
			ctx.Plan.TargetOS = target
		}
	}

	return nil
}

// installImageInfosFromContext 读取上下文缓存的镜像元数据。
func installImageInfosFromContext(ctx *InstallContext) []dism.ImageMeta {
	if ctx == nil || ctx.State == nil {
		return nil
	}
	infos, ok := ctx.State[stateImageInfos].([]dism.ImageMeta)
	if !ok {
		return nil
	}
	return infos
}

// SelectInstallIndex 按预设优先级选择镜像索引。
func SelectInstallIndex(infos []dism.ImageMeta) int {
	if len(infos) == 0 {
		return 1
	}

	preferred := []string{
		"旗舰版", "ultimate",
		"专业工作站", "professional workstation", "pro workstation",
		"专业教育", "professional education", "pro education",
		"专业版", "professional", "pro",
		"家庭版", "home",
		"企业版", "enterprise",
		"教育版", "education",
		"家庭高级版", "home premium",
		"家庭普通版", "home basic",
		"纯净版", "clean",
	}
	for _, key := range preferred {
		for _, info := range infos {
			if !info.IsOS {
				continue
			}
			text := strings.ToLower(info.Name + " " + info.Description + " " + info.Edition + " " + info.Flags)
			if strings.Contains(text, strings.ToLower(key)) {
				return info.Index
			}
		}
	}
	return infos[len(infos)-1].Index
}
