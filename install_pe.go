package main

import (
	"ReSys/src/boot"
	"ReSys/src/disk"
	D "ReSys/src/dism"
	"ReSys/src/file"
	"ReSys/src/log"
	"ReSys/src/pe"
	"ReSys/src/utils"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// RunPEInstallForCompare PE环境内安装流程
func RunPEInstallForCompare() error {
	uiSetProgress(0)
	uiSetStatus("正在读取重装信息...")
	log.LogWrite(0, "[RunPEInstallForCompare]进入PE安装流程")
	if pe.IsWePE() {
		log.LogWrite(0, "[RunPEInstallForCompare]检测到微PE环境，使用非EX的分区工具调用")
	}

	progress := newPECompareProgressHandler()

	targetRoot, imagePath, savedTarget, savedArch, savedIndex, err := resolveInstallInputsInPE()
	if err != nil {
		return err
	}
	log.LogWrite(0, "[RunPEInstallForCompare]最终使用镜像：%s", imagePath)
	log.LogWrite(0, "[RunPEInstallForCompare]目标分区：%s", targetRoot)

	tempVol, imagePath, err := prepareImageStorageForPE(targetRoot, imagePath, progress)
	if err != nil {
		return err
	}

	if err := formatInstallTargetForPE(targetRoot, tempVol, progress); err != nil {
		return err
	}

	infos, index, err := applyInstallImageInPE(targetRoot, imagePath, savedIndex)
	if err != nil {
		return err
	}
	_ = index

	if err := boot.FixBoot(targetRoot, "", "zh-cn"); err != nil {
		return err
	}
	log.LogWrite(0, "[RunPEInstallForCompare]引导修复完成")

	targetOS := strings.TrimSpace(savedTarget)
	if targetOS == "" {
		targetOS = detectTargetFromInfos(infos)
	}
	if targetOS == "" {
		targetOS = targetWin10
	}
	if err := postInstallTasks(targetRoot, targetOS); err != nil {
		return err
	}
	log.LogWrite(0, "[RunPEInstallForCompare]安装后处理完成")

	if err := cleanupTempVolumeForPE(targetRoot, tempVol, progress); err != nil {
		return err
	}

	uiSetStatus("安装完成，正在重启...")
	uiSetProgress(100)
	log.LogWrite(0, "[RunPEInstallForCompare]PE安装流程完成，准备重启")
	Message("安装完成,测试模式", "请查看日志确定无误后手动重启")
	//Shutdown(true)
	_ = savedArch
	return nil
}

// newPECompareProgressHandler 创建 PE 对照流程使用的节流进度回调工厂。
func newPECompareProgressHandler() func(base, span int32, statusFmt, logFmt string) func(int) {
	return func(base, span int32, statusFmt, logFmt string) func(int) {
		var lastUI time.Time
		var lastLog time.Time
		return func(v int) {
			if v < 0 {
				return
			}
			now := time.Now()
			if statusFmt != "" {
				if lastUI.IsZero() || now.Sub(lastUI) >= 500*time.Millisecond || v >= 100 {
					uiSetStatus(fmt.Sprintf(statusFmt, v))
					uiSetProgress(mapPct(base, span, float64(v)))
					lastUI = now
				}
			}
			if logFmt != "" {
				if lastLog.IsZero() || now.Sub(lastLog) >= 1*time.Second || v >= 100 {
					log.LogWrite(0, logFmt, v)
					lastLog = now
				}
			}
		}
	}
}

// resolveInstallInputsInPE 读取重装信息并定位镜像/目标分区。
func resolveInstallInputsInPE() (targetRoot, imagePath, savedTarget, savedArch string, savedIndex int, err error) {
	targetRoot, diskPath, imagePath, volumeGuid, diskUniqueID, imageRel, savedTarget, savedArch, savedIndex, err := loadResData()
	if err != nil {
		log.LogWrite(0, "[RunPEInstallForCompare]读取重装信息失败：%v", err)
		return "", "", "", "", 0, err
	}

	imagePath = strings.TrimSpace(imagePath)
	if imagePath != "" {
		if resolved, rerr := resolveImagePath(diskPath, volumeGuid, diskUniqueID, imagePath, imageRel); rerr == nil {
			imagePath = resolved
		}
	}

	t := strings.TrimSpace(savedTarget)
	a := strings.TrimSpace(savedArch)
	if imagePath == "" {
		uiSetStatus("未找到重装镜像，尝试本地搜索...")
		if local, lerr := findLocalImage(t, a); lerr == nil {
			imagePath = local
		}
	}
	if imagePath == "" {
		if t == "" {
			t = targetWin10
		}
		if a == "" {
			a = "64"
		}
		uiSetStatus("未找到本地镜像，尝试下载Win10...")
		if dl, derr := downloadImage(t, a); derr == nil {
			imagePath = dl
		} else {
			return "", "", "", "", 0, fmt.Errorf("未找到镜像且下载失败: %w", derr)
		}
	}

	if targetRoot == "" {
		targetRoot = chooseInstallTargetRoot()
		if targetRoot == "" {
			return "", "", "", "", 0, fmt.Errorf("未找到可用系统分区")
		}
	}
	if nr, nerr := utils.NormalizeDrive(targetRoot, 0); nerr == nil {
		targetRoot = nr
	}

	return targetRoot, imagePath, savedTarget, savedArch, savedIndex, nil
}

// prepareImageStorageForPE 处理镜像与目标分区同盘的问题，必要时搬运或拆分 TEMP。
func prepareImageStorageForPE(targetRoot, imagePath string, progress func(base, span int32, statusFmt, logFmt string) func(int)) (string, string, error) {
	uiSetProgress(10)
	uiSetStatus("正在准备分区...")
	tempVol := ""
	imagePath = strings.TrimSpace(imagePath)

	imageRoot, _ := utils.NormalizeDrive(imagePath, 2)
	if !strings.EqualFold(imageRoot, targetRoot) {
		return tempVol, imagePath, nil
	}

	fi, err := os.Stat(imagePath)
	if err != nil {
		return "", "", err
	}
	imageBytes := uint64(fi.Size())
	const extraBytes uint64 = 512 * 1024 * 1024
	needBytes := imageBytes + extraBytes

	var moved bool
	for _, v := range otherInstallVolumes(targetRoot) {
		altRoot, _ := utils.NormalizeDrive(v, 0)
		if altRoot == "" || strings.EqualFold(altRoot, targetRoot) {
			continue
		}
		if strings.EqualFold(altRoot, "X:\\") || strings.EqualFold(strings.TrimRight(altRoot, `\\`), "X:") {
			continue
		}
		if disk.GetDriveType(altRoot) != driveFixed {
			continue
		}
		freeBytes, ferr := disk.GetFreeSize(altRoot)
		if ferr != nil || freeBytes < needBytes {
			continue
		}

		dstDir := filepath.Join(altRoot, "install_images")
		_ = os.MkdirAll(dstDir, 0o755)
		dstPath := filepath.Join(dstDir, filepath.Base(imagePath))
		if err := file.Copy(imagePath, dstPath, true, true); err != nil {
			_ = file.Remove(dstPath, false)
			continue
		}
		if dfi, derr := os.Stat(dstPath); derr != nil || dfi.Size() <= 0 {
			_ = file.Remove(dstPath, false)
			continue
		}
		imagePath = dstPath
		moved = true
		break
	}

	if moved {
		return tempVol, imagePath, nil
	}

	sizeMB := int((int64(imageBytes) + 512*1024*1024) / (1024 * 1024))
	if sizeMB < 1024 {
		sizeMB = 1024
	}
	splitCb := progress(10, 5, "正在拆分分区... %d%%", "拆分分区进度：%d%%")
	splitCb(0)
	newVol, err := disk.SplitVolume(targetRoot, sizeMB, "ntfs", "TEMP")
	if err != nil {
		return "", "", err
	}
	splitCb(100)
	if nr, nerr := utils.NormalizeDrive(newVol, 0); nerr == nil {
		tempVol = nr
	}

	newPath := filepath.Join(tempVol, filepath.Base(imagePath))
	if err := file.Copy(imagePath, newPath, true, true); err != nil {
		return "", "", err
	}
	if _, err := os.Stat(newPath); err != nil {
		return "", "", err
	}
	return tempVol, newPath, nil
}

// formatInstallTargetForPE 格式化目标分区并同步进度。
func formatInstallTargetForPE(targetRoot, tempVol string, progress func(base, span int32, statusFmt, logFmt string) func(int)) error {
	formatBase := int32(10)
	formatSpan := int32(10)
	if tempVol != "" {
		formatBase = 15
		formatSpan = 5
	}
	formatCb := progress(formatBase, formatSpan, "正在格式化分区... %d%%", "格式化进度：%d%%")
	formatCb(0)
	err := disk.Format(strings.ReplaceAll(strings.ReplaceAll(targetRoot, "\\", ""), ":", ""), "ntfs", "Windows", true)
	if err == nil {
		formatCb(100)
	}
	return err
}

// applyInstallImageInPE 解析并应用镜像，返回镜像索引元数据与最终索引。
func applyInstallImageInPE(targetRoot, imagePath string, savedIndex int) ([]D.ImageMeta, int, error) {
	uiSetProgress(20)
	uiSetStatus("正在解析镜像...")
	infos, err := detectImageInfos(imagePath)
	index := 1
	if savedIndex > 0 {
		index = savedIndex
	} else if err == nil {
		index = selectInstallIndex(infos)
	}

	switch strings.ToLower(filepath.Ext(imagePath)) {
	case ".esd":
		if err := ApplyEsdImage(imagePath, index, targetRoot); err != nil {
			return infos, index, err
		}
	case ".wim":
		if err := ApplyWimImage(imagePath, index, targetRoot); err != nil {
			return infos, index, err
		}
	case ".iso":
		if err := ApplyISOImage(imagePath, index, targetRoot); err != nil {
			return infos, index, err
		}
	default:
		return infos, index, fmt.Errorf("不支持的镜像类型: %s", imagePath)
	}
	return infos, index, nil
}

// cleanupTempVolumeForPE 尝试删除并合并临时分区。
func cleanupTempVolumeForPE(targetRoot, tempVol string, progress func(base, span int32, statusFmt, logFmt string) func(int)) error {
	if tempVol == "" {
		if mr := findTempRootByMarker(); mr != "" {
			if nr, err := utils.NormalizeDrive(mr, 0); err == nil {
				tempVol = nr
			}
		}
	}
	if tempVol == "" || strings.EqualFold(tempVol, targetRoot) {
		return nil
	}

	deleteCb := progress(85, 5, "正在删除临时分区... %d%%", "删除临时分区进度：%d%%")
	mergeCb := progress(90, 5, "正在合并临时分区... %d%%", "合并临时分区进度：%d%%")
	deleteCb(0)
	if err := disk.DeleteVolume(tempVol); err == nil {
		deleteCb(100)
	}
	mergeCb(0)
	if err := disk.MergeVolume(targetRoot, 0); err == nil {
		mergeCb(100)
	}
	return nil
}
