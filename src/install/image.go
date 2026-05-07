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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var detectImageInfos = image.DetectImageInfos
var findLocalHit = image.FindLocalHit
var downloadImage = DownloadImage

// ErrInstallCanceled 用户主动取消安装（例如在索引无效弹窗中点击取消）。
var ErrInstallCanceled = errors.New("用户取消安装")

// ImageJsonEntry image.json 中的单个镜像条目。
type ImageJsonEntry struct {
	File    string `json:"file"`    // image/ 目录下的文件名
	Index   int    `json:"index"`   // 安装索引：正数=固定索引，-1/0=自动选择
	Version string `json:"version"` // 目标系统版本："7" / "10" / "11"
	Arch    string `json:"arch"`    // 目标架构："32" / "64"，空=不限制
	Verify  *bool  `json:"verify"`  // 是否校验镜像结构：nil 或 true=校验，false=跳过
}

// ImageJsonConfig image.json 文件的根结构。
type ImageJsonConfig struct {
	Images []ImageJsonEntry `json:"images"`
}

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

// findInstallImage 按优先级查找安装镜像：plan 已记录路径 → image.json → 全局本地扫描 → 下载。
func findInstallImage(plan *InstallPlan) (string, error) {
	if path, ok := planImage(plan); ok {
		return path, nil
	}

	if path, err := findImageJsonHit(plan); err != nil {
		return "", err // 用户取消等致命错误，直接返回
	} else if path != "" {
		return path, nil
	}

	if local, err := findLocalHit(plan.TargetOS, plan.ImageArch); err == nil && strings.TrimSpace(local) != "" {
		return local, nil
	}

	return downloadImage(plan.TargetOS, plan.ImageArch)
}

// imageJsonPath 返回可执行文件同级目录下的 image/image.json 路径。
func imageJsonPath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(exe), "image", "image.json"), nil
}

// findImageJsonHit 读取 image/image.json，优先匹配计划所需的镜像。
//
// 前置条件：image/ 目录下至少存在一个镜像文件（.iso/.wim/.esd/.gho），否则跳过解析。
//
// 匹配规则：
//   - version 与 plan.TargetOS 做归一化比较（"10" 等价于 "win10"）
//   - arch 为空或与 plan.ImageArch 一致
//   - 按 images 数组顺序依次尝试，首个匹配且校验通过的条目即为命中
//
// 返回值：
//   - (path, nil)：命中，path 已写入 plan.ImagePath，plan.ImageIndex 也已设置
//   - ("", ErrInstallCanceled)：用户在弹窗中选择取消安装
//   - ("", nil)：未命中，调用方应继续后续查找
func findImageJsonHit(plan *InstallPlan) (string, error) {
	jsonPath, err := imageJsonPath()
	if err != nil {
		log.LogWrite(0, "[findImageJsonHit] executable path error: %v", err)
		return "", nil
	}

	// 镜像所在目录
	imgDir := filepath.Dir(jsonPath)

	// 前置检查：image/ 目录下是否有镜像文件，没有则跳过整个 JSON 解析
	if !dirHasImageFiles(imgDir) {
		log.LogWrite(0, "[findImageJsonHit] image/ directory has no image files, skip json parsing")
		return "", nil
	}

	data, err := os.ReadFile(jsonPath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.LogWrite(0, "[findImageJsonHit] read %s failed: %v", jsonPath, err)
		}
		return "", nil
	}

	var cfg ImageJsonConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.LogWrite(0, "[findImageJsonHit] parse %s failed: %v", jsonPath, err)
		return "", nil
	}

	if len(cfg.Images) == 0 {
		log.LogWrite(0, "[findImageJsonHit] image.json has no entries")
		return "", nil
	}

	// 归一化目标版本：去除 "win" 前缀以便与 JSON 中的 "10"/"11"/"7" 比较
	targetVer := strings.TrimPrefix(plan.TargetOS, "win")

	for i, entry := range cfg.Images {
		entryFile := strings.TrimSpace(entry.File)
		if entryFile == "" {
			continue
		}

		// 匹配目标系统版本（归一化后比较："10" == "10", "win10" == "win10"）
		entryVer := strings.TrimPrefix(strings.TrimSpace(entry.Version), "win")
		if entryVer != targetVer {
			log.LogWrite(0, "[findImageJsonHit] entry %d: version mismatch (want=%s got=%s), skip", i, targetVer, entryVer)
			continue
		}

		// 匹配目标架构
		if entry.Arch != "" && entry.Arch != plan.ImageArch {
			log.LogWrite(0, "[findImageJsonHit] entry %d: arch mismatch (want=%s got=%s), skip", i, plan.ImageArch, entry.Arch)
			continue
		}

		imgPath := filepath.Join(imgDir, entryFile)
		log.LogWrite(0, "[findImageJsonHit] entry %d: trying %s (index=%d)", i, imgPath, entry.Index)

		// 基本检查：文件是否存在
		if _, err := os.Stat(imgPath); err != nil {
			log.LogWrite(0, "[findImageJsonHit] entry %d: file not found: %s", i, imgPath)
			continue
		}

		// 确定是否需要校验：Verify 为 nil 时默认 true（校验）
		shouldVerify := entry.Verify == nil || *entry.Verify

		if shouldVerify {
			infos, err := detectImageInfos(imgPath)
			if err != nil {
				log.LogWrite(0, "[findImageJsonHit] entry %d: verify failed: %v", i, err)
				continue
			}

			// 校验指定索引是否存在（index <= 0 时不校验，交由后续自动选择）
			if entry.Index > 0 && !imageHasIndex(infos, entry.Index) {
				action := ui.ShowImageIndexError(filepath.Base(imgPath), entry.Index)
				switch action {
				case ui.ImageIndexAuto:
					// 不设置 ImageIndex，ResolveInstallImageIndex 自动选择
				case ui.ImageIndexSkip:
					continue
				default: // ui.ImageIndexCancel
					return "", ErrInstallCanceled
				}
			} else if entry.Index > 0 {
				plan.ImageIndex = entry.Index
			}
		} else {
			if entry.Index > 0 {
				plan.ImageIndex = entry.Index
			}
		}

		plan.ImagePath = imgPath
		log.LogWrite(0, "[findImageJsonHit] hit: %s (index=%d)", imgPath, plan.ImageIndex)
		return imgPath, nil
	}

	log.LogWrite(0, "[findImageJsonHit] no matching image found in image.json")
	return "", nil
}

// dirHasImageFiles 检查目录下是否存在镜像文件（.iso / .wim / .esd / .gho）。
// 用于快速判断是否需要解析 image.json。
func dirHasImageFiles(dir string) bool {
	exts := []string{".iso", ".wim", ".esd", ".gho"}
	for _, ext := range exts {
		pattern := filepath.Join(dir, "*"+ext)
		matches, err := filepath.Glob(pattern)
		if err == nil && len(matches) > 0 {
			return true
		}
	}
	return false
}

// imageHasIndex 检查镜像元数据列表中是否存在指定的索引。
func imageHasIndex(infos []dism.ImageMeta, index int) bool {
	for _, info := range infos {
		if info.Index == index {
			return true
		}
	}
	return false
}

func planImage(plan *InstallPlan) (string, bool) {
	if plan == nil {
		return "", false
	}

	path := strings.TrimSpace(plan.ImagePath)
	if path == "" {
		return "", false
	}
	if _, err := os.Stat(path); err != nil {
		log.LogWrite(0, "[findInstallImage] configured image path unavailable: %s err=%v", path, err)
		return "", false
	}
	if _, err := detectImageInfos(path); err != nil {
		log.LogWrite(0, "[findInstallImage] configured image path invalid: %s err=%v", path, err)
		return "", false
	}
	return path, true
}

// RecoverInstallImagePath 根据安装计划中持久化的信息恢复镜像路径。
//
// 它会依次尝试绝对路径、相对路径、磁盘标识和恢复记录。
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
		imgDat := imageHintPath(root)
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
	requiredBytes := needBytes + extraBytes

	var (
		bestRoot string
		bestFree uint64
	)

	log.LogWrite(
		0,
		"[moveImageToDisk] evaluate candidates: image=%s exclude=%s need=%d(%.2fGiB) extra=%d(%.2fGiB) required=%d(%.2fGiB)",
		imgPath,
		systemRoot,
		needBytes,
		float64(needBytes)/1024/1024/1024,
		extraBytes,
		float64(extraBytes)/1024/1024/1024,
		requiredBytes,
		float64(requiredBytes)/1024/1024/1024,
	)

	for _, root := range getotherVolumes(systemRoot) {
		freeBytes, err := disk.GetFreeSize(root)
		if err != nil {
			log.LogWrite(0, "[moveImageToDisk] read free size failed: root=%s err=%v", root, err)
			continue
		}
		log.LogWrite(
			0,
			"[moveImageToDisk] candidate root=%s free=%d(%.2fGiB) required=%d(%.2fGiB)",
			root,
			freeBytes,
			float64(freeBytes)/1024/1024/1024,
			requiredBytes,
			float64(requiredBytes)/1024/1024/1024,
		)
		if freeBytes >= requiredBytes && freeBytes > bestFree {
			bestRoot = root
			bestFree = freeBytes
		}
	}

	if bestRoot == "" {
		log.LogWrite(0, "[moveImageToDisk] no fixed volume satisfies required=%d(%.2fGiB)", requiredBytes, float64(requiredBytes)/1024/1024/1024)
		return "", false, nil
	}
	log.LogWrite(0, "[moveImageToDisk] choose destination root=%s free=%d(%.2fGiB)", bestRoot, bestFree, float64(bestFree)/1024/1024/1024)

	ui.UiSetStatus(ui.Tr("install.image.moveToOtherDisk"))
	movedPath, err := moveImageFile(imgPath, bestRoot, appDownloadDirName())
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

	movedPath, err := moveImageFile(imgPath, tmpRoot, appDownloadDirName())
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
		_ = file.Remove(dstPath, false, false)
		return "", err
	}
	if _, err := os.Stat(dstPath); err != nil {
		return "", err
	}
	if !strings.EqualFold(srcPath, dstPath) {
		if err := file.Remove(srcPath, false, false); err != nil {
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
