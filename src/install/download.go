package install

import (
	"ReSys/src/config"
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

var loadDownloadAppConfig = config.LoadAppConfig
var getImgItems = data.GetInstallImageItems

func normLanguageCode(lang string) string {
	lang = strings.TrimSpace(lang)
	if lang == "" {
		return ""
	}
	lang = strings.ToLower(strings.ReplaceAll(lang, "_", "-"))
	return lang
}

func defaultImageLanguage() string {
	return normLanguageCode(config.DefaultAppImageLanguage)
}

func loadImageDefaultLanguage() (string, error) {
	def := defaultImageLanguage()
	cfg, err := loadDownloadAppConfig()
	if err != nil {
		return def, err
	}
	lang := normLanguageCode(cfg.Language.ImageDefaultLanguage)
	if lang == "" {
		return def, nil
	}
	return lang, nil
}

func preferredImageLanguage() string {
	langs, err := windows.GetUserPreferredUILanguages()
	if err == nil {
		for _, lang := range langs {
			norm := normLanguageCode(lang)
			if norm == "" {
				continue
			}
			log.LogWrite(0, "[downloadImage] preferred image language from system UI: %s", norm)
			return norm
		}
		log.LogWrite(0, "[downloadImage] system UI language list is empty, fallback to config")
	} else {
		log.LogWrite(0, "[downloadImage] get system UI language failed: %v, fallback to config", err)
	}

	cfgLang, cfgErr := loadImageDefaultLanguage()
	if cfgErr != nil {
		log.LogWrite(0, "[downloadImage] load image default language from config failed: %v", cfgErr)
		log.LogWrite(0, "[downloadImage] preferred image language fallback to config default: %s", cfgLang)
		return cfgLang
	}

	log.LogWrite(0, "[downloadImage] preferred image language from config: %s", cfgLang)
	return cfgLang
}

func isMSImageSource(source string) bool {
	source = strings.ToLower(strings.TrimSpace(source))
	return source == "win10-ms" || source == "win11-ms"
}

func filterMSCandidatesByLanguage(candidates []data.RuleItem, preferredLang string) []data.RuleItem {
	preferredLang = normLanguageCode(preferredLang)
	if preferredLang == "" {
		return candidates
	}

	out := make([]data.RuleItem, 0, len(candidates))
	msTotal := 0
	msMatched := 0
	for _, it := range candidates {
		if !isMSImageSource(it.Source) {
			out = append(out, it)
			continue
		}

		msTotal++
		if normLanguageCode(it.Language) == preferredLang {
			out = append(out, it)
			msMatched++
		}
	}

	if msTotal > 0 {
		log.LogWrite(
			0,
			"[downloadImage] MS source language filter: preferred=%s total=%d matched=%d",
			preferredLang,
			msTotal,
			msMatched,
		)
	}
	if msTotal > 0 && msMatched == 0 {
		log.LogWrite(0, "[downloadImage] no MS candidates matched preferred language, keep original candidates")
		return candidates
	}
	return out
}

// downloadFileWithRetry 下载单个 HTTP/HTTPS 链接，并在检测到本地冲突时清理后重试一次。
func downloadFileWithRetry(it data.RuleItem, link, dstPath string, progress func(float64, int64)) error {
	if err := cleanupDownloadArtifacts(dstPath); err != nil {
		log.LogWrite(0, "[downloadImage] cleanup existing download target failed: path=%s err=%v", dstPath, err)
	}

	var lastErr error
	for attempt := 1; attempt <= 2; attempt++ {
		ctx, cancel := context.WithCancel(context.Background())
		opt := download.NewNativeDownloadOptions(link, dstPath, progress)
		opt.ProgressSizeHint = it.Size
		opt.ProgressSizeHintUnit = it.SizeUnit
		opt.VerifyChecksum = imageChecksumConfig(it)
		_, err := download.Download(
			ctx,
			opt,
		)
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

// ruleItemLinks 返回规则项里的有效下载链接，并去掉空值和重复值。
func ruleItemLinks(it data.RuleItem) []string {
	out := make([]string, 0, len(it.Link.Links))
	seen := make(map[string]struct{}, len(it.Link.Links))
	for _, link := range it.Link.Links {
		link = strings.TrimSpace(link)
		if link == "" {
			continue
		}
		if _, ok := seen[link]; ok {
			continue
		}
		seen[link] = struct{}{}
		out = append(out, link)
	}
	return out
}

// prepareImageDestination 计算规则项对应的目标文件路径，并尽量复用已校验通过的本地文件。
func prepareImageDestination(it data.RuleItem, dstDir, link string) (string, bool) {
	dstPath := filepath.Join(dstDir, data.RuleItemFileName(it, link))
	if st, err := os.Stat(dstPath); err == nil && !st.IsDir() && st.Size() > 0 {
		if err := validateDownloadedImageFile(it, dstPath); err != nil {
			log.LogWrite(0, "[downloadImage] image verification failed, removing and retrying: %s err=%v", dstPath, err)
			_ = cleanupDownloadArtifacts(dstPath)
		} else {
			return dstPath, true
		}
	}
	_ = cleanupDownloadArtifacts(dstPath)
	return dstPath, false
}

// DownloadImage 根据目标系统和架构解析候选镜像，并下载第一个通过校验的镜像文件。
//
// 选择顺序固定为：先用聚合后的规则列表，再按架构筛选，最后区分 URL 与非 URL。
// 每个下载完成的镜像都会再做一次校验。
func DownloadImage(target, arch string) (string, error) {
	if err := needNet("访问镜像资源"); err != nil {
		return "", err
	}

	ent, err := getImgItems(target)
	if err != nil {
		log.LogWrite(0, "[downloadImage] failed to load image list: %v", err)
		return "", err
	}

	candidates := image.FilterRuleItemsByArch(ent, arch)
	if len(candidates) == 0 && arch == "32" {
		candidates = image.FilterRuleItemsByArch(ent, "64")
	}
	if len(candidates) == 0 {
		candidates = ent
	}
	preferredLang := preferredImageLanguage()
	candidates = filterMSCandidatesByLanguage(candidates, preferredLang)
	log.LogWrite(0, "[downloadImage] available image count: %d", len(candidates))

	root := chooseDownloadRoot()
	if root == "" {
		log.LogWrite(0, "[downloadImage] no usable download volume found")
		return "", fmt.Errorf("未找到可用的下载磁盘")
	}

	dstDir := downloadWorkspaceDir(root)
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return "", err
	}

	var errs []string

	for _, it := range candidates {
		if !strings.EqualFold(strings.TrimSpace(it.Link.Type), "url") {
			continue
		}

		links := ruleItemLinks(it)
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

			dstPath, reused := prepareImageDestination(it, dstDir, link)
			if reused {
				log.LogWrite(0, "[downloadImage] image already exists: %s", dstPath)
				ui.UiSetProgress(60)
				return dstPath, nil
			}
			if err := needNet("下载镜像"); err != nil {
				return "", err
			}
			ui.UiSetProgress(0)
			ui.UiSetStatus(ui.Tr("install.download.start"))
			log.LogWrite(0, "[downloadImage] starting image download (URL): %s -> %s", link, dstPath)

			pr := NewProgressReporter(
				0, 60,
				time.Second, time.Second,
				ui.Tr("install.download.progress"),
				"Waiting for install image data... %.1f%% Speed: %.2f MB/s",
				true,
			)

			err := downloadFileWithRetry(it, link, dstPath, func(pct float64, speed int64) {
				pr.Update(pct, speed)
			})
			log.LogWrite(0, "[downloadImage] DownloadFile returned: link=%s dst=%s err=%v", link, dstPath, err)
			if err != nil {
				prevLink = link
				switchReason = fmt.Sprintf("download error: %v", err)
			}

			if err == nil {
				if vErr := validateDownloadedImageFile(it, dstPath); vErr != nil {
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
		if strings.EqualFold(strings.TrimSpace(it.Link.Type), "url") {
			continue
		}

		links := ruleItemLinks(it)
		if len(links) == 0 {
			errs = append(errs, fmt.Sprintf("failed to get non-URL link file=%s err=no usable link", it.FileName))
			continue
		}

		prevLink := ""
		switchReason := ""
		for _, link := range links {
			if isFailedLink(link) {
				prevLink = link
				switchReason = "link marked as failed"
				continue
			}

			if prevLink != "" && switchReason != "" {
				logLinkSwitch("downloadImage", prevLink, link, switchReason)
				switchReason = ""
			}

			dstPath, reused := prepareImageDestination(it, dstDir, link)
			if reused {
				log.LogWrite(0, "[downloadImage] image already exists: %s", dstPath)
				ui.UiSetProgress(60)
				return dstPath, nil
			}
			if err := needNet("下载镜像"); err != nil {
				return "", err
			}

			log.LogWrite(0, "[downloadImage] starting image download (BT): %s -> %s", link, dstDir)
			lastLog := time.Time{}
			lastUI := time.Time{}

			realPath, err := download.DownloadBT(link, dstDir, func(pct int, speed, done, total int64) {
				now := time.Now()
				if lastUI.IsZero() || now.Sub(lastUI) >= time.Second || pct >= 100 {
					ui.UiSetStatus(ui.Trf("install.download.progressInt", pct, float64(speed)/1024/1024))
					ui.UiSetProgress(MapPct(0, 60, float64(pct)))
					lastUI = now
				}
				if lastLog.IsZero() || now.Sub(lastLog) >= time.Second || pct >= 100 {
					log.LogWrite(0, "[downloadImage] BT download progress: %d%% speed: %.2f MB/s", pct, float64(speed)/1024/1024)
					lastLog = now
				}
			})

			if err != nil {
				log.LogWrite(0, "[downloadImage] image download failed (BT): link=%s err=%v", link, err)
				errs = append(errs, fmt.Sprintf("BT failed link=%s err=%v", link, err))
				prevLink = link
				switchReason = fmt.Sprintf("download error: %v", err)
				continue
			}

			finalPath := realPath
			if realPath != "" && !strings.EqualFold(realPath, dstPath) {
				_ = cleanupDownloadArtifacts(dstPath)
				if rErr := os.Rename(realPath, dstPath); rErr == nil {
					finalPath = dstPath
				} else if cErr := file.Copy(realPath, dstPath, true, true); cErr == nil {
					finalPath = dstPath
					_ = file.Remove(realPath, false, false)
				} else {
					log.LogWrite(0, "[downloadImage] failed to normalize BT output path: real=%s dst=%s err=%v", realPath, dstPath, cErr)
					finalPath = realPath
				}
			}

			if vErr := validateDownloadedImageFile(it, finalPath); vErr != nil {
				markFailedLink(link)
				_ = cleanupDownloadArtifacts(finalPath)
				log.LogWrite(0, "[downloadImage] image verification failed, removing and retrying: %s err=%v", finalPath, vErr)
				errs = append(errs, fmt.Sprintf("BT verification failed link=%s err=%v", link, vErr))
				prevLink = link
				switchReason = fmt.Sprintf("download completed but verification failed: %v", vErr)
				continue
			}

			log.LogWrite(0, "[downloadImage] image download completed (BT): %s", finalPath)
			ui.UiSetProgress(60)
			return finalPath, nil
		}
	}

	if len(errs) > 0 {
		return "", fmt.Errorf("所有镜像下载链接都失败了: %s", strings.Join(errs, " | "))
	}
	return "", fmt.Errorf("未找到可用的镜像下载链接")
}

// chooseDownloadRoot 选择存放下载文件的目标盘符。
//
// 优先使用非系统盘且空间足够的卷，不满足时再回退到系统盘或临时卷。
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

	tmp, err := disk.NewTempVolume(needBytes)
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
