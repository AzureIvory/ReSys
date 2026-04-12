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

// 安装镜像获取相关辅助函数。

// AcquireInstallImage 为当前安装计划准备可用的安装镜像。
//
// 它会规范化计划、查找或下载镜像，并在必要时迁移镜像位置。
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

// RecoverOrAcquireInstallImage 优先恢复历史镜像路径，失败时再走完整获取流程。
func RecoverOrAcquireInstallImage(plan *InstallPlan) (string, error) {
	if plan == nil {
		return "", fmt.Errorf("安装计划为空")
	}

	if recovered, err := RecoverInstallImagePath(plan); err == nil && strings.TrimSpace(recovered) != "" {
		return recovered, nil
	}

	return AcquireInstallImage(plan)
}

// findInstallImage 先尝试本地镜像，找不到时再触发下载。
func findInstallImage(plan *InstallPlan) (string, error) {
	if local, err := image.FindLocalImage(plan.TargetOS, plan.ImageArch); err == nil && strings.TrimSpace(local) != "" {
		return local, nil
	}

	return DownloadImage(plan.TargetOS, plan.ImageArch)
}

// RecoverInstallImagePath 根据安装计划中持久化的信息恢复镜像路径。
//
// 它会依次尝试绝对路径、相对路径、卷 GUID、磁盘标识和恢复记录。
func RecoverInstallImagePath(plan *InstallPlan) (string, error) {
	if plan == nil {
		return "", fmt.Errorf("安装计划为空")
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

// validateImageFile 校验本地镜像文件是否仍然可用。
//
// 规则里提供了 SHA1 时优先做哈希校验，否则退化为镜像结构探测。
func validateImageFile(it data.RuleItem, imagePath string) error {
	if strings.TrimSpace(it.Hash.Sha1) != "" {
		ok, got, err := download.CheckFileSHA1(imagePath, it.Hash.Sha1)
		if err != nil {
			return fmt.Errorf("SHA1 校验失败: %w", err)
		}
		if !ok {
			return fmt.Errorf("SHA1 不匹配: %s", got)
		}
		return nil
	}

	switch strings.ToLower(filepath.Ext(imagePath)) {
	case ".iso", ".wim", ".esd":
		if _, err := image.DetectImageInfos(imagePath); err != nil {
			return fmt.Errorf("镜像文件已损坏: %w", err)
		}
	}
	return nil
}

// relocateInstallImage 在镜像位于系统盘时，把它迁移到更安全的位置。
func relocateInstallImage(imgPath string) (string, error) {
	systemRoot := windows.SystemDriveRoot()
	if strings.TrimSpace(systemRoot) == "" || !utils.SameVolume(imgPath, systemRoot) {
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

// EnsureInstallImageOutsideTarget 确保安装镜像不留在即将被重分区或格式化的目标卷上。
func EnsureInstallImageOutsideTarget(plan *InstallPlan) error {
	if plan == nil || strings.TrimSpace(plan.ImagePath) == "" || strings.TrimSpace(plan.TargetRoot) == "" {
		return nil
	}

	targetRoot, _ := utils.NormalizeDrive(plan.TargetRoot, 0)
	if targetRoot == "" || !utils.SameVolume(plan.ImagePath, targetRoot) {
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

// moveImageToDisk 尝试把镜像迁移到其他固定数据盘。
func moveImageToDisk(imgPath, systemRoot string, needBytes uint64) (string, bool, error) {
	extraBytes := uint64(512*1024*1024) + driverBackupWorkspaceReserveBytes()

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

	ui.UiSetStatus(ui.Tr("install.image.moveToOtherDisk"))
	movedPath, err := moveImageFile(imgPath, bestRoot, "tempimg")
	if err != nil {
		return "", false, err
	}
	log.LogWrite(0, "[moveImageToDisk] image moved to %s", movedPath)
	return movedPath, true, nil
}

// moveImageToTemp 把镜像迁移到临时卷。
func moveImageToTemp(imgPath string, needBytes uint64) (string, error) {
	ui.UiSetStatus(ui.Tr("install.image.moveToTempVolume"))

	tmpRoot, err := disk.NewTempVolume(needBytes + driverBackupWorkspaceReserveBytes())
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

// moveImageFile 把镜像复制到目标目录，并在成功后切换到新路径。
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

// 安装镜像索引选择相关辅助函数。

// ResolveInstallImageIndex 读取镜像元数据，并回填安装索引和目标系统信息。
func ResolveInstallImageIndex(ctx *InstallContext) error {
	if ctx == nil || ctx.Plan == nil {
		return fmt.Errorf("安装上下文为空")
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

// installImageInfosFromContext 从安装上下文状态中读取缓存的镜像元数据。
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

// SelectInstallIndex 委托 image 包执行镜像索引选择，保持统一策略。
func SelectInstallIndex(infos []dism.ImageMeta) int {
	return image.SelectInstallIndex(infos)
}
