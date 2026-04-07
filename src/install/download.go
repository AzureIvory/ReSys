package install

import (
	"ReSys/src/data"
	"ReSys/src/disk"
	"ReSys/src/download"
	"ReSys/src/file"
	"ReSys/src/image"
	"ReSys/src/log"
	"ReSys/src/ui"
	"ReSys/src/utils"
	"ReSys/src/windows"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ===== 闂傚倵鍋撴繝濠傚暙閸撶厧鈽夐幘鎰佸創婵?=====

// downloadFileWithRetry 闁革负鍔岄ˇ鈺呮偠閸℃ɑ鎷遍柛锔惧閻ｎ偊鎮惧▎鎰€ù鐘烘硾閸熻法绮ｆ担瑙勵槯闁煎浜滄慨鈺併€掗崨顖涘€為柛姘叄閸ｅ摜鎷犻弴姘鳖伇婵炲枴鎵冲亾?
func downloadFileWithRetry(link, dstPath string, progress func(float64, int64)) error {
	if err := cleanupDownloadArtifacts(dstPath); err != nil {
		log.LogWrite(0, "[downloadImage] cleanup existing download target failed: path=%s err=%v", dstPath, err)
	}

	var lastErr error
	for attempt := 1; attempt <= 2; attempt++ {
		ctx, cancel := context.WithCancel(context.Background())
		err := download.DownloadFile(ctx, link, dstPath, progress)
		cancel()
		if err == nil {
			return nil
		}

		lastErr = err
		if !isLocalDownloadConflict(err) {
			return err
		}

		log.LogWrite(0, "[downloadImage] local file conflict, removing stale target and retrying: path=%s err=%v", dstPath, err)
		if cleanupErr := cleanupDownloadArtifacts(dstPath); cleanupErr != nil {
			log.LogWrite(0, "[downloadImage] cleanup after local conflict failed: path=%s err=%v", dstPath, cleanupErr)
			return err
		}
	}

	return lastErr
}

// DownloadImage 婵炲濮撮柊锝夊储閵堝洨纾炬い鏃傚亾閻ｉ亶姊婚埀顒€顭ㄩ崘銊ュ濠电姍鍕缂佹鎳忓顏堟偩瀹€鍕帣缂傚倷鑳堕崰鏍汲閸涙潙纾介煫鍥ь儌閸?
func DownloadImage(target, arch string) (string, error) {
	ent, err := data.GetWinImgs(target)
	if err != nil {
		log.LogWrite(0, "[downloadImage] failed to load image list: %v", err)
		return "", err
	}

	candidates := image.FilterWinImgsByArch(ent, arch)
	if len(candidates) == 0 && arch == "32" {
		candidates = image.FilterWinImgsByArch(ent, "64")
	}
	if len(candidates) == 0 {
		candidates = ent
	}
	log.LogWrite(0, "[downloadImage] available image count: %d", len(candidates))

	root := chooseDownloadRoot()
	if root == "" {
		log.LogWrite(0, "[downloadImage] no usable download volume found")
		return "", fmt.Errorf("no usable download volume found")
	}

	dstDir := filepath.Join(root, "tempimg")
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return "", err
	}

	var errs []string

	for _, it := range candidates {
		if !strings.EqualFold(strings.TrimSpace(it.Type), "url") {
			continue
		}

		links := []string{strings.TrimSpace(it.Link), strings.TrimSpace(it.Link2)}
		prevLink := ""
		switchReason := ""

		for _, link := range links {
			link = strings.TrimSpace(link)
			if link == "" {
				continue
			}
			if isFailedLink(link) {
				prevLink = link
				switchReason = "link marked as failed"
				continue
			}
			if !download.HttpStatus(link) {
				log.LogWrite(0, "[downloadImage] URL link unavailable: %s", link)
				markFailedLink(link)
				prevLink = link
				switchReason = "link precheck failed"
				continue
			}

			if prevLink != "" && switchReason != "" {
				logLinkSwitch("downloadImage", prevLink, link, switchReason)
				switchReason = ""
			}

			name := data.ImgName(it, link)
			if strings.TrimSpace(it.File) != "" {
				name = strings.TrimSpace(it.File)
			}
			dstPath := filepath.Join(dstDir, name)

			if st, err := os.Stat(dstPath); err == nil && !st.IsDir() && st.Size() > 0 {
				if err := validateImageFile(it, dstPath); err != nil {
					log.LogWrite(0, "[downloadImage] image verification failed, removing and retrying: %s err=%v", dstPath, err)
					_ = cleanupDownloadArtifacts(dstPath)
				} else {
					log.LogWrite(0, "[downloadImage] image already exists: %s", dstPath)
					ui.UiSetProgress(60)
					return dstPath, nil
				}
			}
			_ = cleanupDownloadArtifacts(dstPath)
			ui.UiSetProgress(0)
			ui.UiSetStatus("濠殿喗绻愮徊钘夛耿椤忓懐鈻旈悗锝庡幗缁佷即姊婚埀顒€顭ㄩ崘銊ュ... 0.0% 闂備緡鍋嗛崰搴ｂ偓? 0.00 MB/s")
			log.LogWrite(0, "[downloadImage] starting image download (URL): %s -> %s", link, dstPath)

			pr := NewProgressReporter(
				0, 60,
				time.Second, time.Second,
				"濠殿喗绻愮徊钘夛耿椤忓懐鈻旈悗锝庡幗缁佷即姊婚埀顒€顭ㄩ崘銊ュ... %.1f%% 闂備緡鍋嗛崰搴ｂ偓? %.2f MB/s",
				"闂傚倵鍋撴繝濠傚暙閸撶厧鈽夐幘鎰佸創婵炴潙娲﹀璇测槈濡警鍞? %.1f%% 闂備緡鍋嗛崰搴ｂ偓? %.2f MB/s",
				true,
			)

			err := downloadFileWithRetry(link, dstPath, func(pct float64, speed int64) {
				pr.Update(pct, speed)
			})
			log.LogWrite(0, "[downloadImage] DownloadFile returned: link=%s dst=%s err=%v", link, dstPath, err)
			if err != nil {
				prevLink = link
				switchReason = fmt.Sprintf("download error: %v", err)
			}

			if err == nil {
				if vErr := validateImageFile(it, dstPath); vErr != nil {
					markFailedLink(link)
					_ = cleanupDownloadArtifacts(dstPath)
					log.LogWrite(0, "[downloadImage] image verification failed, removing and retrying: %s err=%v", dstPath, vErr)
					errs = append(errs, fmt.Sprintf("URL verification failed link=%s err=%v", link, vErr))
					prevLink = link
					switchReason = fmt.Sprintf("download completed but verification failed: %v", vErr)
					continue
				}

				log.LogWrite(0, "[downloadImage] image download completed: %s", dstPath)
				ui.UiSetProgress(60)
				return dstPath, nil
			}

			_ = cleanupDownloadArtifacts(dstPath)
			log.LogWrite(0, "[downloadImage] image download failed (URL): link=%s err=%v", link, err)
			errs = append(errs, fmt.Sprintf("URL failed link=%s err=%v", link, err))
		}
	}

	for _, it := range candidates {
		if strings.EqualFold(strings.TrimSpace(it.Type), "url") {
			continue
		}

		link, lerr := data.ImgLink(it)
		if lerr != nil {
			errs = append(errs, fmt.Sprintf("failed to get BT link file=%s err=%v", it.File, lerr))
			continue
		}
		link = strings.TrimSpace(link)
		if link == "" || isFailedLink(link) {
			continue
		}

		name := data.ImgName(it, link)
		if strings.TrimSpace(it.File) != "" {
			name = strings.TrimSpace(it.File)
		}
		dstPath := filepath.Join(dstDir, name)

		if st, err := os.Stat(dstPath); err == nil && !st.IsDir() && st.Size() > 0 {
			if err := validateImageFile(it, dstPath); err != nil {
				log.LogWrite(0, "[downloadImage] image verification failed, removing and retrying: %s err=%v", dstPath, err)
				_ = cleanupDownloadArtifacts(dstPath)
			} else {
				log.LogWrite(0, "[downloadImage] image already exists: %s", dstPath)
				ui.UiSetProgress(60)
				return dstPath, nil
			}
		}

		log.LogWrite(0, "[downloadImage] starting image download (BT): %s -> %s", link, dstDir)
		lastLog := time.Time{}
		lastUI := time.Time{}

		realPath, err := download.DownloadBT(link, dstDir, func(pct int, speed, done, total int64) {
			now := time.Now()
			if lastUI.IsZero() || now.Sub(lastUI) >= time.Second || pct >= 100 {
				ui.UiSetStatus(fmt.Sprintf("濠殿喗绻愮徊钘夛耿椤忓懐鈻旈悗锝庡幗缁佷即姊婚埀顒€顭ㄩ崘銊ュ... %d%% 闂備緡鍋嗛崰搴ｂ偓? %.2f MB/s", pct, float64(speed)/1024/1024))
				ui.UiSetProgress(MapPct(0, 60, float64(pct)))
				lastUI = now
			}
			if lastLog.IsZero() || now.Sub(lastLog) >= time.Second || pct >= 100 {
				log.LogWrite(0, "[downloadImage] BT download progress: %d%% speed: %.2f MB/s", pct, float64(speed)/1024/1024)
				lastLog = now
			}
		})

		if err == nil {
			finalPath := realPath
			if realPath != "" && !strings.EqualFold(realPath, dstPath) {
				_ = cleanupDownloadArtifacts(dstPath)
				if rErr := os.Rename(realPath, dstPath); rErr == nil {
					finalPath = dstPath
				} else if cErr := file.Copy(realPath, dstPath, true, true); cErr == nil {
					finalPath = dstPath
					_ = file.Remove(realPath, false)
				} else {
					log.LogWrite(0, "[downloadImage] failed to normalize BT output path: real=%s dst=%s err=%v", realPath, dstPath, cErr)
					finalPath = realPath
				}
			}

			if vErr := validateImageFile(it, finalPath); vErr != nil {
				markFailedLink(link)
				_ = cleanupDownloadArtifacts(finalPath)
				log.LogWrite(0, "[downloadImage] image verification failed, removing and retrying: %s err=%v", finalPath, vErr)
				errs = append(errs, fmt.Sprintf("BT verification failed link=%s err=%v", link, vErr))
				continue
			}

			log.LogWrite(0, "[downloadImage] image download completed (BT): %s", finalPath)
			ui.UiSetProgress(60)
			return finalPath, nil
		}

		log.LogWrite(0, "[downloadImage] image download failed (BT): link=%s err=%v", link, err)
		errs = append(errs, fmt.Sprintf("BT failed link=%s err=%v", link, err))
	}

	if len(errs) > 0 {
		return "", fmt.Errorf("all image download links failed: %s", strings.Join(errs, " | "))
	}
	return "", fmt.Errorf("no usable image download link found")
}

// chooseDownloadRoot 闂備緡鍋勯ˇ鎵偓姘ュ姂濮婄懓顭ㄩ崘銊ュ婵炴垶鎸搁鍫澝归崶顒佸剭闁告洦鍘界粣妤呮煛瀹ュ懏鎼愰柛銊ラ叄瀹曠娀骞侀幒鍡椾壕?
func chooseDownloadRoot() string {
	systemDrive := strings.ToUpper(os.Getenv("SystemDrive"))
	parts := disk.Findpart()
	needBytes := minImageBytes + driverBackupReserveBytes

	if len(parts) > 1 {
		for _, p := range parts {
			if systemDrive != "" && strings.EqualFold(strings.TrimSuffix(p, `\`), systemDrive) {
				continue
			}
			if free, err := disk.GetFreeSize(p); err == nil && free >= needBytes {
				return p
			}
		}
	}

	root := ""
	if systemDrive != "" {
		root = systemDrive + `\`
	} else {
		root = windows.SystemDriveRoot()
	}
	if nr, err := utils.NormalizeDrive(root, 0); err == nil {
		root = nr
	}

	if root != "" {
		if free, err := disk.GetFreeSize(root); err == nil && free >= needBytes {
			return root
		}
	}

	tmp, err := disk.EnsureTempVolumeForBytes(needBytes)
	if err == nil && tmp != "" {
		return tmp
	}

	drives, _ := disk.ListDrive()
	for _, d := range drives {
		if systemDrive != "" && strings.EqualFold(strings.TrimSuffix(d, `\`), systemDrive) {
			continue
		}
		if disk.GetDriveType(d) == 3 {
			if free, err := disk.GetFreeSize(d); err == nil && free >= needBytes {
				return d
			}
		}
	}
	for _, d := range drives {
		if systemDrive != "" && strings.EqualFold(strings.TrimSuffix(d, `\`), systemDrive) {
			continue
		}
		if disk.GetDriveType(d) == 3 {
			return d
		}
	}
	if systemDrive != "" {
		return systemDrive + `\`
	}
	return ""
}
