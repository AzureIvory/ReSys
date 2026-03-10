package install

import (
	"ReSys/src/boot"
	"ReSys/src/disk"
	D "ReSys/src/dism"
	"ReSys/src/image"
	"ReSys/src/log"
	"ReSys/src/ui"
	"ReSys/src/windows"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	TargetWin7  = "win7"
	TargetWin10 = "win10"
	TargetWin11 = "win11"
)

func init() {
	ui.StartInstall = StartInstall
}

func StartInstall(target string) {
	imgArch := windows.DesiredArch()
	peArch := windows.SystemArch()
	log.LogWrite(0, "[StartInstall]开始重装流程，目标系统=%s，镜像期望架构=%s，PE架构=%s", target, imgArch, peArch)
	ui.UiSetProgress(0)
	ui.UiSetStatus("正在寻找镜像...")

	imgPath, ok := retryLoopWithResult("镜像准备", func() (string, error) {
		return findOrDownloadImage(target, imgArch)
	})
	if !ok {
		return
	}

	ui.UiSetProgress(60)
	ui.UiSetStatus("正在写入重装信息...")
	if !retryLoop("写入重装信息", func() error {
		preferIndex := 0
		if infos, err := image.DetectImageInfos(imgPath); err == nil {
			preferIndex = selectInstallIndex(infos)
		}
		return WriteResFile(imgPath, target, imgArch, preferIndex)
	}) {
		return
	}

	ui.UiSetProgress(70)
	ui.UiSetStatus("正在准备PE环境...")
	if !retryLoop("准备PE", func() error {
		return ensurePEAndReboot(peArch)
	}) {
		return
	}

	ui.UiSetProgress(100)
	ui.UiSetStatus("即将重启进入PE...")
	log.LogWrite(0, "[StartInstall]准备完成，重启进入PE")
}

func RunPEInstall() error {
	ui.UiSetProgress(0)
	ui.UiSetStatus("正在读取重装信息...")
	log.LogWrite(0, "[RunPEInstall]进入PE安装流程")

	targetRoot, diskPath, imagePath, volumeGuid, diskUniqueID, imageRel, savedTarget, savedArch, savedIndex, err := LoadResData()
	if err != nil {
		return err
	}
	if strings.TrimSpace(imagePath) != "" {
		if resolved, rerr := ResolveImagePath(diskPath, volumeGuid, diskUniqueID, imagePath, imageRel); rerr == nil {
			imagePath = resolved
		}
	}
	if strings.TrimSpace(imagePath) == "" {
		if local, lerr := image.FindLocalImage(savedTarget, savedArch); lerr == nil {
			imagePath = local
		}
	}
	if strings.TrimSpace(imagePath) == "" {
		t := strings.TrimSpace(savedTarget)
		if t == "" {
			t = TargetWin10
		}
		a := strings.TrimSpace(savedArch)
		if a == "" {
			a = "64"
		}
		dl, derr := DownloadImage(t, a)
		if derr != nil {
			return fmt.Errorf("未找到镜像且下载失败: %w", derr)
		}
		imagePath = dl
	}

	if targetRoot == "" {
		targetRoot = chooseInstallTargetRoot()
		if targetRoot == "" {
			return fmt.Errorf("未找到可用系统分区")
		}
	}

	ui.UiSetProgress(10)
	ui.UiSetStatus("正在格式化分区...")
	if err := disk.Format(strings.ReplaceAll(strings.ReplaceAll(targetRoot, "\\", ""), ":", ""), "ntfs", "Windows", true); err != nil {
		return err
	}

	ui.UiSetProgress(20)
	ui.UiSetStatus("正在解析镜像...")
	infos, _ := image.DetectImageInfos(imagePath)
	index := 1
	if savedIndex > 0 {
		index = savedIndex
	} else {
		index = selectInstallIndex(infos)
	}
	log.LogWrite(0, "[RunPEInstall]镜像索引列表：%s", formatImageInfos(infos))

	progressCb := func(phase string, pct float64, raw string) {
		_ = raw
		ui.UiSetStatus(fmt.Sprintf("正在应用镜像（%s）... %0.1f%%", phase, pct))
		ui.UiSetProgress(MapPct(20, 50, pct))
	}
	if err := applyImageByExt(imagePath, targetRoot, index, progressCb); err != nil {
		return err
	}

	ui.UiSetStatus("正在修复引导...")
	ui.UiSetProgress(75)
	if err := boot.FixBoot(targetRoot, "", "zh-cn"); err != nil {
		return err
	}

	targetOS := strings.TrimSpace(savedTarget)
	if targetOS == "" {
		targetOS = image.DetectTargetFromInfos(infos)
	}
	if targetOS == "" {
		targetOS = TargetWin10
	}
	if err := postInstallTasks(targetRoot, targetOS); err != nil {
		return err
	}

	ui.UiSetStatus("安装完成，正在重启...")
	ui.UiSetProgress(100)
	log.LogWrite(0, "[RunPEInstall]PE安装流程完成")
	return nil
}

func applyImageByExt(imagePath, targetRoot string, index int, progress func(string, float64, string)) error {
	ext := strings.ToLower(filepath.Ext(imagePath))
	dism := D.NewDism()
	var applyPath = imagePath
	if ext == ".iso" {
		isoRoot, err := image.MountISO(imagePath, 30*time.Second)
		if err != nil {
			return err
		}
		applyPath = filepath.Join(isoRoot, "sources", "install.wim")
		if _, err := os.Stat(applyPath); err != nil {
			applyPath = filepath.Join(isoRoot, "sources", "install.esd")
		}
	}
	return dism.ApplyImageCmd(applyPath, targetRoot, uint32(index), progress)
}
