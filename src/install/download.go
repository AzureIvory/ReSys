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

// ===== 镜像下载 =====

// downloadMSImage 下载并校验微软官方直链镜像。
func downloadMSImage(target, imgArch string) (string, error) {
	systemCode := ""
	switch strings.ToLower(strings.TrimSpace(target)) {
	case TargetWin10:
		systemCode = "10"
	case TargetWin11:
		systemCode = "11"
	default:
		return "", fmt.Errorf("unsupported microsoft image target: %s", target)
	}

	urls, err := data.GetMSWinUrl(systemCode, "zh-cn", strings.TrimSpace(imgArch), "")
	log.LogWrite(0, "[downloadMSImage] url=%v err=%v", urls, err)
	if err != nil {
		return "", err
	}
	if len(urls) == 0 {
		return "", fmt.Errorf("未找到微软官方镜像直链")
	}

	root := chooseDownloadRoot()
	log.LogWrite(0, "[downloadMSImage] chooseDownloadRoot=%s", root)
	if strings.TrimSpace(root) == "" {
		return "", fmt.Errorf("未找到可用下载分区")
	}

	dstDir := filepath.Join(root, "tempimg")
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return "", err
	}

	var errs []string
	prevLink := ""
	switchReason := ""
	for _, info := range urls {
		link := strings.TrimSpace(info.URL)
		if link == "" {
			continue
		}
		if isFailedLink(link) {
			prevLink = link
			switchReason = "链接已被标记为失败"
			continue
		}
		if !download.HttpStatus(link) {
			markFailedLink(link)
			errs = append(errs, fmt.Sprintf("Microsoft direct link unavailable: %s", link))
			prevLink = link
			switchReason = "链接预检查失败"
			continue
		}

		if prevLink != "" && switchReason != "" {
			logLinkSwitch("downloadMSImage", prevLink, link, switchReason)
			switchReason = ""
		}

		name := strings.TrimSpace(info.FileName)
		if name == "" {
			name = filepath.Base(strings.Split(link, "?")[0])
		}
		if name == "" || name == "." || name == "/" {
			name = fmt.Sprintf("windows_%s_%s.iso", systemCode, strings.TrimSpace(imgArch))
		}

		dstPath := filepath.Join(dstDir, name)
		if st, err := os.Stat(dstPath); err == nil && !st.IsDir() && st.Size() > 0 {
			if err := verifyMSImage(info, dstPath); err == nil {
				return dstPath, nil
			}
			_ = file.Remove(dstPath, false)
		}

		ui.UiSetProgress(0)
		ui.UiSetStatus("正在下载镜像... 0.0% 速度: 0.00 MB/s")

		pr := NewProgressReporter(
			0, 60,
			time.Second, time.Second,
			"正在下载镜像... %.1f%% 速度: %.2f MB/s",
			"镜像下载进度: %.1f%% 速度: %.2f MB/s",
			true,
		)

		ctx, cancel := context.WithCancel(context.Background())
		err := download.DownloadFile(ctx, link, dstPath, func(pct float64, speed int64) {
			pr.Update(pct, speed)
		})
		cancel()
		if err != nil {
			markFailedLink(link)
			_ = file.Remove(dstPath, false)
			errs = append(errs, fmt.Sprintf("Microsoft direct download failed: %v", err))
			prevLink = link
			switchReason = fmt.Sprintf("download error: %v", err)
			continue
		}

		if err := verifyMSImage(info, dstPath); err != nil {
			markFailedLink(link)
			_ = file.Remove(dstPath, false)
			errs = append(errs, fmt.Sprintf("Microsoft image verification failed: %v", err))
			prevLink = link
			switchReason = fmt.Sprintf("download completed but verification failed: %v", err)
			continue
		}

		ui.UiSetProgress(60)
		return dstPath, nil
	}

	if len(errs) > 0 {
		return "", fmt.Errorf("%s", strings.Join(errs, " | "))
	}
	return "", fmt.Errorf("Microsoft direct download failed")
}

// DownloadImage 从配置的镜像源下载系统镜像。
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
		log.LogWrite(0, "[downloadImage] 未找到可用下载分区")
		return "", fmt.Errorf("未找到可用下载分区")
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
		triedLink := false
		prevLink := ""
		switchReason := ""

		for _, link := range links {
			link = strings.TrimSpace(link)
			if link == "" {
				continue
			}
			if isFailedLink(link) {
				prevLink = link
				switchReason = "链接已被标记为失败"
				continue
			}
			if !download.HttpStatus(link) {
				log.LogWrite(0, "[downloadImage] URL link unavailable: %s", link)
				markFailedLink(link)
				prevLink = link
				switchReason = "链接预检查失败"
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
					_ = file.Remove(dstPath, false)
				} else {
					log.LogWrite(0, "[downloadImage] image already exists: %s", dstPath)
					ui.UiSetProgress(60)
					return dstPath, nil
				}
			}
			if triedLink {
				_ = file.Remove(dstPath+".part", false)
			}

			_ = file.Remove(dstPath, false)
			triedLink = true
			ui.UiSetProgress(0)
			ui.UiSetStatus("正在下载镜像... 0.0% 速度: 0.00 MB/s")
			log.LogWrite(0, "[downloadImage] starting image download (URL): %s -> %s", link, dstPath)

			pr := NewProgressReporter(
				0, 60,
				time.Second, time.Second,
				"正在下载镜像... %.1f%% 速度: %.2f MB/s",
				"镜像下载进度: %.1f%% 速度: %.2f MB/s",
				true,
			)

			ctx, cancel := context.WithCancel(context.Background())
			err := download.DownloadFile(ctx, link, dstPath, func(pct float64, speed int64) {
				pr.Update(pct, speed)
			})
			cancel()
			log.LogWrite(0, "[downloadImage] DownloadFile returned: link=%s dst=%s err=%v", link, dstPath, err)
			if err != nil {
				prevLink = link
				switchReason = fmt.Sprintf("download error: %v", err)
			}

			if err == nil {
				if vErr := validateImageFile(it, dstPath); vErr != nil {
					markFailedLink(link)
					_ = file.Remove(dstPath, false)
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

			markFailedLink(link)
			_ = file.Remove(dstPath, false)
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
				_ = file.Remove(dstPath, false)
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
				ui.UiSetStatus(fmt.Sprintf("正在下载镜像... %d%% 速度: %.2f MB/s", pct, float64(speed)/1024/1024))
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
				_ = file.Remove(dstPath, false)
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
				_ = file.Remove(finalPath, false)
				log.LogWrite(0, "[downloadImage] image verification failed, removing and retrying: %s err=%v", finalPath, vErr)
				errs = append(errs, fmt.Sprintf("BT verification failed link=%s err=%v", link, vErr))
				continue
			}

			log.LogWrite(0, "[downloadImage] image download completed (BT): %s", finalPath)
			ui.UiSetProgress(60)
			return finalPath, nil
		}

		markFailedLink(link)
		log.LogWrite(0, "[downloadImage] image download failed (BT): link=%s err=%v", link, err)
		errs = append(errs, fmt.Sprintf("BT failed link=%s err=%v", link, err))
	}

	if len(errs) > 0 {
		return "", fmt.Errorf("all image download links failed: %s", strings.Join(errs, " | "))
	}
	return "", fmt.Errorf("未找到可用镜像下载链接")
}

// chooseDownloadRoot 选择镜像下载的目标分区。
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
