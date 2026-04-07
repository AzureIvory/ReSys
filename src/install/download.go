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

// Image download and selection helpers.

// downloadFileWithRetry downloads one HTTP/HTTPS link and retries once after
// cleaning stale local artifacts when the downloader reports a local conflict.
//
// Large image downloads are often interrupted and leave behind partial files,
// `.aria2` sidecars, or other temporary artifacts. Those leftovers make the
// next attempt fail immediately on the destination path. This helper performs
// a pre-cleanup before the first attempt and one more cleanup before the retry
// so callers can treat local-conflict recovery as part of the normal flow.
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

// ruleItemLinks returns the usable download links declared by a rule item.
//
// The data package already normalizes image rules during aggregation. This
// helper keeps the install package defensive by trimming blanks and removing
// duplicates again, so both URL and non-URL download branches can iterate the
// same cleaned list without re-implementing the same checks.
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

// prepareImageDestination decides the final path for a rule/link pair and
// reuses an existing verified file when possible.
//
// If a file with the expected name already exists, it is validated first.
// Valid files are returned directly. Invalid files and stale side artifacts are
// removed so the caller always receives a clean destination path for download.
func prepareImageDestination(it data.RuleItem, dstDir, link string) (string, bool) {
	dstPath := filepath.Join(dstDir, data.RuleItemFileName(it, link))
	if st, err := os.Stat(dstPath); err == nil && !st.IsDir() && st.Size() > 0 {
		if err := validateImageFile(it, dstPath); err != nil {
			log.LogWrite(0, "[downloadImage] image verification failed, removing and retrying: %s err=%v", dstPath, err)
			_ = cleanupDownloadArtifacts(dstPath)
		} else {
			return dstPath, true
		}
	}
	_ = cleanupDownloadArtifacts(dstPath)
	return dstPath, false
}

// DownloadImage resolves candidate install images for the requested system and
// architecture, then downloads the first candidate that passes validation.
//
// Selection is intentionally stable:
//  1. use the data package's aggregated and de-duplicated RuleItem list
//  2. prefer the requested architecture, with 32-bit falling back to 64-bit
//  3. try URL links before non-URL links and validate every completed image
func DownloadImage(target, arch string) (string, error) {
	ent, err := data.GetInstallImageItems(target)
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
			ui.UiSetProgress(0)
			ui.UiSetStatus("Downloading install image... 0.0% Speed: 0.00 MB/s")
			log.LogWrite(0, "[downloadImage] starting image download (URL): %s -> %s", link, dstPath)

			pr := NewProgressReporter(
				0, 60,
				time.Second, time.Second,
				"Downloading install image... %.1f%% Speed: %.2f MB/s",
				"Waiting for install image data... %.1f%% Speed: %.2f MB/s",
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

			log.LogWrite(0, "[downloadImage] starting image download (BT): %s -> %s", link, dstDir)
			lastLog := time.Time{}
			lastUI := time.Time{}

			realPath, err := download.DownloadBT(link, dstDir, func(pct int, speed, done, total int64) {
				now := time.Now()
				if lastUI.IsZero() || now.Sub(lastUI) >= time.Second || pct >= 100 {
					ui.UiSetStatus(fmt.Sprintf("Downloading install image... %d%% Speed: %.2f MB/s", pct, float64(speed)/1024/1024))
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
		return "", fmt.Errorf("all image download links failed: %s", strings.Join(errs, " | "))
	}
	return "", fmt.Errorf("no usable image download link found")
}

// chooseDownloadRoot picks the preferred root directory for storing downloads.
//
// The order intentionally favors non-system volumes with enough free space so
// large ISO or WIM downloads do not fill the system drive unnecessarily. If no
// such volume exists, the function falls back to the system drive, then to a
// temporary volume provisioned by the disk package, and finally to any fixed
// disk that is still available.
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
