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
	log.LogWrite(0, "[StartInstall]寮€濮嬮噸瑁呮祦绋嬶紝鐩爣绯荤粺=%s锛岄暅鍍忔湡鏈涙灦鏋?%s锛孭E鏋舵瀯=%s", target, imgArch, peArch)
	ui.UiSetProgress(0)
	ui.UiSetStatus("姝ｅ湪瀵绘壘闀滃儚...")

	imgPath, ok := retryLoopWithResult("镜像准备", func() (string, error) {
		return prepareInstallImagePlanOnce(target, imgArch)
	})
	if !ok {
		return
	}

	if _, ok := retryLoopWithResult("写入重装信息", func() (int, error) {
		return parseImageAndWriteResData(imgPath, target, imgArch)
	}); !ok {
		return
	}
	ui.UiSetProgress(70)
	ui.UiSetStatus("姝ｅ湪鍑嗗PE鐜...")
	if !retryLoop("鍑嗗PE", func() error {
		return ensurePEAndReboot(peArch)
	}) {
		return
	}

	ui.UiSetProgress(100)
	ui.UiSetStatus("鍗冲皢閲嶅惎杩涘叆PE...")
	log.LogWrite(0, "[StartInstall]鍑嗗瀹屾垚锛岄噸鍚繘鍏E")
}

func RunPEInstall() error {
	ui.UiSetProgress(0)
	ui.UiSetStatus("姝ｅ湪璇诲彇閲嶈淇℃伅...")
	log.LogWrite(0, "[RunPEInstall]杩涘叆PE瀹夎娴佺▼")

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
		dl, derr := findOrDownloadImage(t, a)
		if derr != nil {
			return fmt.Errorf("鏈壘鍒伴暅鍍忎笖涓嬭浇澶辫触: %w", derr)
		}
		imagePath = dl
	}

	if targetRoot == "" {
		targetRoot = chooseInstallTargetRoot()
		if targetRoot == "" {
			return fmt.Errorf("鏈壘鍒板彲鐢ㄧ郴缁熷垎鍖?)
		}
	}

	ui.UiSetProgress(10)
	ui.UiSetStatus("姝ｅ湪鏍煎紡鍖栧垎鍖?..")
	if err := disk.Format(strings.ReplaceAll(strings.ReplaceAll(targetRoot, "\\", ""), ":", ""), "ntfs", "Windows", true); err != nil {
		return err
	}

	ui.UiSetProgress(20)
	ui.UiSetStatus("姝ｅ湪瑙ｆ瀽闀滃儚...")
	infos, _ := image.DetectImageInfos(imagePath)
	index := 1
	if savedIndex > 0 {
		index = savedIndex
	} else {
		index = SelectInstallIndex(infos)
	}
	log.LogWrite(0, "[RunPEInstall]闀滃儚绱㈠紩鍒楄〃锛?s", formatImageInfos(infos))

	progressCb := func(phase string, pct float64, raw string) {
		_ = raw
		ui.UiSetStatus(fmt.Sprintf("姝ｅ湪搴旂敤闀滃儚锛?s锛?.. %0.1f%%", phase, pct))
		ui.UiSetProgress(MapPct(20, 50, pct))
	}
	if err := applyImageByExt(imagePath, targetRoot, index, progressCb); err != nil {
		return err
	}

	ui.UiSetStatus("姝ｅ湪淇寮曞...")
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

	ui.UiSetStatus("瀹夎瀹屾垚锛屾鍦ㄩ噸鍚?..")
	ui.UiSetProgress(100)
	log.LogWrite(0, "[RunPEInstall]PE瀹夎娴佺▼瀹屾垚")
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
	var progressCh chan D.DismProgress
	if progress != nil {
		progressCh = make(chan D.DismProgress, 16)
		done := make(chan struct{})
		go func() {
			defer close(done)
			for p := range progressCh {
				progress("apply", float64(p.Percentage), p.Status)
			}
		}()

		err := dism.ApplyImageCmd(applyPath, targetRoot, uint32(index), progressCh)
		close(progressCh)
		<-done
		return err
	}

	return dism.ApplyImageCmd(applyPath, targetRoot, uint32(index), nil)
}
