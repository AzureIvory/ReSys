package install

import (
	"ReSys/src/data"
	"ReSys/src/disk"
	"ReSys/src/download"
	"ReSys/src/file"
	"ReSys/src/log"
	"ReSys/src/pe"
	"ReSys/src/tools"
	"ReSys/src/ui"
	"ReSys/src/utils"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ===== PE 准备 =====

// preparedPE 记录已准备好的 PE 路径和生命周期标记。
type preparedPE struct {
	WIMPath   string
	SDIPath   string
	ID        string
	Temporary bool
}

// PreparePEEnvironment 准备可启动的 PE 并写入当前程序。
func PreparePEEnvironment(ctx *InstallContext) error {
	if ctx == nil || ctx.Plan == nil {
		return fmt.Errorf("install context is nil")
	}

	arch := strings.TrimSpace(ctx.Plan.PEArch)
	if arch == "" {
		arch = "64"
		ctx.Plan.PEArch = arch
	}

	if prepared, ok := preparedPEFromContext(ctx); ok && strings.TrimSpace(prepared.WIMPath) != "" && utils.FileExists(prepared.WIMPath) {
		return nil
	}

	failedPEImages := failedPEImages(ctx)

	found, wimPath, sdiPath, err := pe.GoToPE(true)
	if err != nil {
		log.LogWrite(0, "[PreparePEEnvironment] PE scan failed: %v", err)
	}
	if found && strings.TrimSpace(wimPath) != "" {
		prepared := preparedPE{
			WIMPath: wimPath,
			SDIPath: sdiPath,
		}
		if err := patchPreparedPE(ctx, prepared); err != nil {
			return err
		}
		log.LogWrite(0, "[PreparePEEnvironment] using scanned PE: %s", wimPath)
		return nil
	}

	if !shouldSkipLocalWePE(ctx) {
		localWim, err := extractWePE(arch)
		if err != nil {
			log.LogWrite(0, "[PreparePEEnvironment] local WePE unavailable: %v", err)
			setSkipLocalWePE(ctx, true)
		} else if strings.TrimSpace(localWim) != "" {
			prepared := preparedPE{
				WIMPath:   localWim,
				SDIPath:   resolveSdiPath(localWim),
				ID:        "local-wepe",
				Temporary: true,
			}
			if err := patchPreparedPE(ctx, prepared); err != nil {
				return err
			}
			log.LogWrite(0, "[PreparePEEnvironment] using local WePE installer: %s", localWim)
			return nil
		}
	}

	log.LogWrite(0, "[PreparePEEnvironment] no local PE found, downloading one")
	wimPath, id, err := downloadPE(arch, failedPEImages)
	if err != nil {
		log.LogWrite(0, "[PreparePEEnvironment] downloadPE failed: %v", err)
		return fmt.Errorf("准备 PE 失败: %w", err)
	}

	prepared := preparedPE{
		WIMPath:   wimPath,
		SDIPath:   resolveSdiPath(wimPath),
		ID:        id,
		Temporary: strings.Contains(strings.ToLower(wimPath), `\petemp\`),
	}
	if err := patchPreparedPE(ctx, prepared); err != nil {
		return err
	}
	return nil
}

// patchPreparedPE 将当前程序写入准备好的 PE 镜像。
func patchPreparedPE(ctx *InstallContext, prepared preparedPE) error {
	ui.UiSetStatus("正在写入自身到PE...")
	if err := pe.Patwim(prepared.WIMPath); err != nil {
		log.LogWrite(0, "[PreparePEEnvironment] Patwim failed: %v", err)
		cleanupFailedPE(ctx, prepared)
		return fmt.Errorf("写入 PE 失败: %w", err)
	}

	rememberPreparedPE(ctx, prepared)
	if err := persistPreparedPESelection(ctx, prepared); err != nil {
		log.LogWrite(0, "[PreparePEEnvironment] persist prepared PE failed: %v", err)
		cleanupFailedPE(ctx, prepared)
		return fmt.Errorf("保存 PE 信息失败: %w", err)
	}
	return nil
}

// SetNextBootToPE 配置下次启动进入准备好的 PE。
func SetNextBootToPE(ctx *InstallContext) error {
	if ctx == nil || ctx.Plan == nil {
		return fmt.Errorf("install context is nil")
	}

	prepared, ok := preparedPEFromContext(ctx)
	if !ok || strings.TrimSpace(prepared.WIMPath) == "" || !utils.FileExists(prepared.WIMPath) {
		if err := PreparePEEnvironment(ctx); err != nil {
			return err
		}
		prepared, _ = preparedPEFromContext(ctx)
	}

	ui.UiSetStatus("正在设置下次启动进入PE...")

	var err error
	if strings.TrimSpace(prepared.SDIPath) == "" {
		_, _, _, err = pe.GoToPE(false)
	} else {
		_, _, _, err = pe.GoToPE(false, prepared.SDIPath, prepared.WIMPath)
	}
	if err != nil {
		log.LogWrite(0, "[SetNextBootToPE] GoToPE failed: %v", err)
		cleanupFailedPE(ctx, prepared)
		return fmt.Errorf("设置进入 PE 失败: %w", err)
	}

	return nil
}

// preparedPEFromContext 读取上下文中缓存的 PE 信息。
func preparedPEFromContext(ctx *InstallContext) (preparedPE, bool) {
	if ctx == nil || ctx.State == nil {
		return preparedPE{}, false
	}
	v, ok := ctx.State[statePreparedPE]
	if !ok {
		return preparedPE{}, false
	}
	prepared, ok := v.(preparedPE)
	return prepared, ok
}

// rememberPreparedPE 在上下文中缓存 PE 信息。
func rememberPreparedPE(ctx *InstallContext, prepared preparedPE) {
	if ctx == nil {
		return
	}
	if ctx.State == nil {
		ctx.State = map[string]any{}
	}
	ctx.State[statePreparedPE] = prepared
}

func persistPreparedPESelection(ctx *InstallContext, prepared preparedPE) error {
	if ctx == nil || ctx.Plan == nil {
		return nil
	}
	ctx.Plan.PreparedPEWIM = strings.TrimSpace(prepared.WIMPath)
	return SaveInstallPlan(ctx.Plan)
}

// forgetPreparedPE 清理上下文中的 PE 缓存。
func forgetPreparedPE(ctx *InstallContext) {
	if ctx == nil || ctx.State == nil {
		return
	}
	delete(ctx.State, statePreparedPE)
}

// failedPEImages 返回已标记失败的 PE 集合。
func failedPEImages(ctx *InstallContext) map[string]struct{} {
	if ctx == nil {
		return map[string]struct{}{}
	}
	if ctx.State == nil {
		ctx.State = map[string]any{}
	}
	if v, ok := ctx.State[stateFailedPEImages]; ok {
		if failed, ok := v.(map[string]struct{}); ok {
			return failed
		}
	}
	failed := map[string]struct{}{}
	ctx.State[stateFailedPEImages] = failed
	return failed
}

// shouldSkipLocalWePE 判断是否跳过本地微 PE 探测。
func shouldSkipLocalWePE(ctx *InstallContext) bool {
	if ctx == nil || ctx.State == nil {
		return false
	}
	v, ok := ctx.State[stateSkipLocalWePE]
	if !ok {
		return false
	}
	skip, ok := v.(bool)
	return ok && skip
}

// setSkipLocalWePE 更新本地微 PE 的跳过标记。
func setSkipLocalWePE(ctx *InstallContext, skip bool) {
	if ctx == nil {
		return
	}
	if ctx.State == nil {
		ctx.State = map[string]any{}
	}
	ctx.State[stateSkipLocalWePE] = skip
}

// cleanupFailedPE 清理失败的 PE 产物并更新重试状态。
func cleanupFailedPE(ctx *InstallContext, prepared preparedPE) {
	if prepared.ID != "" {
		markFailedPEImage(failedPEImages(ctx), prepared.ID)
	}
	if prepared.ID == "local-wepe" {
		setSkipLocalWePE(ctx, true)
	}
	if prepared.Temporary {
		removePEArtifacts(prepared.WIMPath, prepared.SDIPath)
	}
	forgetPreparedPE(ctx)
}

// markFailedPEImage 标记当前 PE 候选项不可再试。
func markFailedPEImage(failed map[string]struct{}, id string) {
	if id == "" {
		return
	}
	failed[id] = struct{}{}
}

// peImageID 生成 PE 候选镜像的稳定标识。
func peImageID(it data.WinPEImg) string {
	parts := []string{
		strings.TrimSpace(it.Grp),
		strings.TrimSpace(it.Ver),
		strings.TrimSpace(it.Arch),
		strings.TrimSpace(strings.Join(it.Links, "|")),
	}
	return strings.Join(parts, "|")
}

// downloadPE 按架构和失败记录选择并下载 PE。
func downloadPE(arch string, failedPEImages map[string]struct{}) (string, string, error) {
	arch = strings.TrimSpace(arch)
	if arch == "" {
		arch = "64"
	}
	if failedPEImages == nil {
		failedPEImages = map[string]struct{}{}
	}
	log.LogWrite(0, "[downloadPE] downloading PE, target arch=%s", arch)

	peList, err := data.GetWinPE()
	if err != nil {
		log.LogWrite(0, "[downloadPE] failed to load PE list: %v", err)
		return "", "", err
	}

	findByArch := func(list []data.WinPEImg, want string) []data.WinPEImg {
		var out []data.WinPEImg
		for _, it := range list {
			if strings.TrimSpace(it.Arch) == want {
				out = append(out, it)
			}
		}
		return out
	}

	tryDownload := func(it data.WinPEImg) (string, string, error) {
		id := peImageID(it)
		if id != "" {
			if _, ok := failedPEImages[id]; ok {
				return "", id, fmt.Errorf("PE marked failed: %s", id)
			}
		}
		if len(it.Links) == 0 {
			return "", id, fmt.Errorf("PE links are empty")
		}

		triedLink := false
		prevLink := ""
		switchReason := ""
		for _, link := range it.Links {
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
				log.LogWrite(0, "[downloadPE] PE link unavailable: %s", link)
				markFailedLink(link)
				prevLink = link
				switchReason = "链接预检查失败"
				continue
			}

			if prevLink != "" && switchReason != "" {
				logLinkSwitch("downloadPE", prevLink, link, switchReason)
				switchReason = ""
			}

			needBytes := int64(it.Sz * 1024 * 1024)
			root, err := ChoosePETempRoot(needBytes * 2)
			if err != nil {
				return "", id, err
			}
			peDir := filepath.Join(root, "PETEMP")
			if err := file.EnsureCleanDir(peDir); err != nil {
				return "", id, err
			}

			wimPath := filepath.Join(peDir, "boot.wim")
			pr := NewProgressReporter(
				70, 25,
				time.Second, time.Second,
				"正在下载PE... %.1f%% 速度: %.2f MB/s",
				"PE下载进度: %.1f%% 速度: %.2f MB/s",
				true,
			)

			if strings.HasSuffix(strings.ToLower(link), ".exe") && it.OffsetEnd > it.OffsetStart {
				exeName := download.GetlinkName(link)
				if exeName == "" {
					exeName = "wepe.exe"
				}
				exePath := filepath.Join(peDir, exeName)

				useExisting := false
				if utils.FileExists(exePath) {
					if strings.TrimSpace(it.MD5) != "" {
						ok, merr := tools.MatchMD5(exePath, it.MD5)
						if merr == nil && ok {
							log.LogWrite(0, "[downloadPE] reusing existing WEPE installer: %s", exePath)
							useExisting = true
						} else {
							log.LogWrite(0, "[downloadPE] existing WEPE installer MD5 mismatch, redownloading: %s", exePath)
							_ = file.Remove(exePath, false)
						}
					} else {
						log.LogWrite(0, "[downloadPE] reusing existing WEPE installer (without MD5): %s", exePath)
						useExisting = true
					}
				}

				if !useExisting {
					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
					err := download.DownloadFile(ctx, link, exePath, func(pct float64, speed int64) {
						pr.Update(pct, speed)
					})
					cancel()
					if err != nil {
						markFailedLink(link)
						log.LogWrite(0, "[downloadPE] PE download failed: %v", err)
						_ = file.Remove(exePath, false)
						prevLink = link
						switchReason = fmt.Sprintf("download error: %v", err)
						continue
					}

					if strings.TrimSpace(it.MD5) != "" {
						ok, merr := tools.MatchMD5(exePath, it.MD5)
						if merr != nil || !ok {
							markFailedLink(link)
							log.LogWrite(0, "[downloadPE] PE MD5 verification failed after download: %s", exePath)
							_ = file.Remove(exePath, false)
							prevLink = link
							switchReason = "download completed but MD5 verification failed"
							continue
						}
					}
				}

				if err := file.PeelFile(exePath, fmt.Sprintf("%d", it.OffsetStart), fmt.Sprintf("%d", it.OffsetEnd), wimPath); err != nil {
					markFailedLink(link)
					log.LogWrite(0, "[downloadPE] PE extraction failed: %v", err)
					prevLink = link
					switchReason = fmt.Sprintf("extraction failed: %v", err)
					continue
				}
			} else {
				if triedLink {
					_ = file.Remove(wimPath+".part", false)
				}
				triedLink = true

				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
				err := download.DownloadFile(ctx, link, wimPath, func(pct float64, speed int64) {
					pr.Update(pct, speed)
				})
				cancel()
				if err != nil {
					markFailedLink(link)
					log.LogWrite(0, "[downloadPE] PE download failed: %v", err)
					_ = file.Remove(wimPath, false)
					prevLink = link
					switchReason = fmt.Sprintf("download error: %v", err)
					continue
				}
			}

			if err := copySDIToPETEMP(peDir); err != nil {
				return "", id, err
			}
			return wimPath, id, nil
		}

		return "", id, fmt.Errorf("PE download failed")
	}

	for _, it := range findByArch(peList, arch) {
		if wim, id, err := tryDownload(it); err == nil {
			return wim, id, nil
		}
	}
	if arch == "32" {
		for _, it := range findByArch(peList, "64") {
			if wim, id, err := tryDownload(it); err == nil {
				return wim, id, nil
			}
		}
	}

	if name, size, links, err := data.PELnk(); err == nil {
		if _, ok := failedPEImages[peLinksID]; !ok {
			if wim, err := downloadPEUrls(name, size, arch, links); err == nil {
				return wim, peLinksID, nil
			}
		}
	}

	return "", "", fmt.Errorf("no available PE found")
}

// downloadPEUrls 从后备链接直接下载 PE，并尽量复用规则中的元数据。
func downloadPEUrls(name string, size float64, arch string, links []string) (string, error) {
	seen := map[string]bool{}
	var out []string
	for _, l := range links {
		l = strings.TrimSpace(l)
		if l == "" || seen[l] {
			continue
		}
		seen[l] = true
		out = append(out, l)
	}
	if len(out) == 0 {
		return "", fmt.Errorf("PE links are empty")
	}

	meta, hasMeta := matchPEMetaByLinks(name, arch, out)
	needBytes := int64(1024 * 1024 * 1024)
	if hasMeta && meta.Sz > 0 {
		needBytes = int64(meta.Sz * 1024 * 1024 * 2)
	} else if size > 0 {
		needBytes = int64(size * 1024 * 1024 * 2)
	}

	root, err := ChoosePETempRoot(needBytes)
	if err != nil {
		return "", err
	}
	peDir := filepath.Join(root, "PETEMP")
	if err := file.EnsureCleanDir(peDir); err != nil {
		return "", err
	}

	wimPath := filepath.Join(peDir, "boot.wim")
	pr := NewProgressReporter(
		70, 25,
		time.Second, time.Second,
		"正在下载PE... %.1f%% 速度: %.2f MB/s",
		"PE下载进度: %.1f%% 速度: %.2f MB/s",
		true,
	)

	triedLink := false
	prevLink := ""
	switchReason := ""
	for _, link := range out {
		link = strings.TrimSpace(link)
		if link == "" {
			continue
		}
		if !download.HttpStatus(link) {
			log.LogWrite(0, "[downloadPEUrls] PE link unavailable: %s", link)
			continue
		}
		log.LogWrite(0, "[downloadPEUrls] PE link: %s", link)

		if prevLink != "" && switchReason != "" {
			logLinkSwitch("downloadPEUrls", prevLink, link, switchReason)
			switchReason = ""
		}
		if triedLink {
			_ = file.Remove(wimPath+".part", false)
		}
		triedLink = true

		if strings.HasSuffix(strings.ToLower(link), ".exe") {
			if !hasMeta || meta.OffsetEnd <= meta.OffsetStart {
				log.LogWrite(0, "[downloadPEUrls] skip exe fallback without offset metadata: %s", link)
				prevLink = link
				switchReason = "缺少 EXE 剥离所需的 offset 元数据"
				continue
			}

			exeName := download.GetlinkName(link)
			if exeName == "" {
				exeName = "wepe.exe"
			}
			exePath := filepath.Join(peDir, exeName)

			useExisting := false
			if utils.FileExists(exePath) {
				if strings.TrimSpace(meta.MD5) != "" {
					ok, merr := tools.MatchMD5(exePath, meta.MD5)
					if merr == nil && ok {
						log.LogWrite(0, "[downloadPEUrls] reusing existing WEPE installer: %s", exePath)
						useExisting = true
					} else {
						_ = file.Remove(exePath, false)
					}
				} else {
					useExisting = true
				}
			}

			if !useExisting {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
				err := download.DownloadFile(ctx, link, exePath, func(pct float64, speed int64) {
					pr.Update(pct, speed)
				})
				cancel()
				if err != nil {
					markFailedLink(link)
					log.LogWrite(0, "[downloadPEUrls] PE installer download failed: %v, url:%s", err, link)
					_ = file.Remove(exePath, false)
					prevLink = link
					switchReason = fmt.Sprintf("download error: %v", err)
					continue
				}

				if strings.TrimSpace(meta.MD5) != "" {
					ok, merr := tools.MatchMD5(exePath, meta.MD5)
					if merr != nil || !ok {
						markFailedLink(link)
						log.LogWrite(0, "[downloadPEUrls] installer MD5 mismatch: %s", exePath)
						_ = file.Remove(exePath, false)
						prevLink = link
						switchReason = "download completed but MD5 verification failed"
						continue
					}
				}
			}

			if err := file.PeelFile(exePath, fmt.Sprintf("%d", meta.OffsetStart), fmt.Sprintf("%d", meta.OffsetEnd), wimPath); err != nil {
				markFailedLink(link)
				log.LogWrite(0, "[downloadPEUrls] PE extraction failed: %v", err)
				prevLink = link
				switchReason = fmt.Sprintf("extraction failed: %v", err)
				continue
			}
		} else {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
			err := download.DownloadFile(ctx, link, wimPath, func(pct float64, speed int64) {
				pr.Update(pct, speed)
			})
			cancel()
			if err != nil {
				markFailedLink(link)
				log.LogWrite(0, "[downloadPEUrls] PE download failed: %v, url:%s", err, link)
				_ = file.Remove(wimPath, false)
				prevLink = link
				switchReason = fmt.Sprintf("download error: %v", err)
				continue
			}
		}

		if err := copySDIToPETEMP(peDir); err != nil {
			return "", err
		}
		return wimPath, nil
	}

	return "", fmt.Errorf("PE download failed")
}

// matchPEMetaByLinks 根据名称、架构和链接回查规则元数据。
func matchPEMetaByLinks(name, arch string, links []string) (data.WinPEImg, bool) {
	list, err := data.GetWinPE()
	if err != nil {
		return data.WinPEImg{}, false
	}

	name = strings.TrimSpace(name)
	arch = strings.TrimSpace(arch)
	linkSet := make(map[string]struct{}, len(links))
	for _, link := range links {
		link = strings.TrimSpace(link)
		if link != "" {
			linkSet[link] = struct{}{}
		}
	}

	bestIdx := -1
	bestScore := -1
	for i := range list {
		it := list[i]
		score := 0
		if arch != "" && strings.TrimSpace(it.Arch) == arch {
			score += 100
		}
		if name != "" && strings.EqualFold(strings.TrimSpace(it.Name), name) {
			score += 50
		}
		for _, link := range it.Links {
			if _, ok := linkSet[strings.TrimSpace(link)]; ok {
				score += 10
			}
		}
		if score > bestScore {
			bestScore = score
			bestIdx = i
		}
	}

	if bestIdx < 0 || bestScore <= 0 {
		return data.WinPEImg{}, false
	}
	return list[bestIdx], true
}

// copySDIToPETEMP 将启动所需的 SDI 文件复制到 PETEMP。
func copySDIToPETEMP(peDir string) error {
	selfExe, err := os.Executable()
	if err != nil {
		return err
	}
	toolsDir := filepath.Join(filepath.Dir(selfExe), "tools")
	sdiFiles, _ := file.FindFile(toolsDir, "*.sdi|*.SDI", 1)
	if len(sdiFiles) == 0 {
		return fmt.Errorf("SDI files not found")
	}
	for _, sdi := range sdiFiles {
		dst := filepath.Join(peDir, filepath.Base(sdi))
		if err := file.Copy(sdi, dst, true, true); err != nil {
			return err
		}
	}
	log.LogWrite(0, "[copySDIToPETEMP] copied SDI files to PETEMP: %s", peDir)
	return nil
}

// resolveSdiPath 在 PE 目录中定位配套的 SDI 文件。
func resolveSdiPath(wimPath string) string {
	wimPath = strings.TrimSpace(wimPath)
	if wimPath == "" {
		return ""
	}
	dir := filepath.Dir(wimPath)
	if dir == "." || dir == "" {
		return ""
	}
	sdi := filepath.Join(dir, "boot.sdi")
	if utils.FileExists(sdi) {
		return sdi
	}
	if sdis, _ := file.FindFile(dir, "*.sdi|*.SDI", 1); len(sdis) > 0 {
		return sdis[0]
	}
	return ""
}

// removePEArtifacts 删除临时 PE 产物。
func removePEArtifacts(wimPath, sdiPath string) {
	if strings.TrimSpace(wimPath) != "" {
		_ = file.Remove(wimPath, false)
		if strings.Contains(strings.ToLower(wimPath), `\petemp\`) {
			_ = file.Remove(filepath.Dir(wimPath), true)
		}
	}
	if strings.TrimSpace(sdiPath) != "" {
		_ = file.Remove(sdiPath, false)
	}
}

func recoverPreparedPEPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if utils.FileExists(path) {
		return path
	}

	root, err := utils.NormalizeDrive(path, 2)
	if err != nil || root == "" {
		return ""
	}
	rel := strings.TrimPrefix(path, root)
	rel = strings.TrimPrefix(rel, `\`)
	if rel == "" {
		return ""
	}

	drives, err := disk.ListDrive()
	if err != nil {
		return ""
	}
	for _, d := range drives {
		drvRoot, derr := utils.NormalizeDrive(d, 0)
		if derr != nil || drvRoot == "" {
			continue
		}
		cand := filepath.Join(drvRoot, rel)
		if utils.FileExists(cand) {
			return cand
		}
	}
	return ""
}

func cleanupPreparedPEAfterInstall(ctx *InstallContext) error {
	if ctx == nil || ctx.Plan == nil {
		return nil
	}

	wimPath := recoverPreparedPEPath(ctx.Plan.PreparedPEWIM)
	if wimPath == "" {
		log.LogWrite(0, "[cleanupPreparedPEAfterInstall] prepared PE WIM not found, skip")
		return nil
	}

	targetRoot, err := utils.NormalizeDrive(ctx.Plan.TargetRoot, 0)
	if err != nil || targetRoot == "" {
		log.LogWrite(0, "[cleanupPreparedPEAfterInstall] invalid target root, skip: target=%s err=%v", ctx.Plan.TargetRoot, err)
		return nil
	}
	wimRoot, err := utils.NormalizeDrive(wimPath, 2)
	if err != nil || wimRoot == "" {
		log.LogWrite(0, "[cleanupPreparedPEAfterInstall] invalid prepared PE path, skip: wim=%s err=%v", wimPath, err)
		return nil
	}
	if strings.EqualFold(wimRoot, targetRoot) {
		log.LogWrite(0, "[cleanupPreparedPEAfterInstall] prepared PE is on target partition, skip cleanup: wim=%s target=%s", wimPath, targetRoot)
		return nil
	}

	if err := pe.Unpatwim(wimPath); err != nil {
		log.LogWrite(-2, "[cleanupPreparedPEAfterInstall] revert PE failed: wim=%s err=%v", wimPath, err)
		return nil
	}

	log.LogWrite(0, "[cleanupPreparedPEAfterInstall] reverted prepared PE: %s", wimPath)
	return nil
}

// ChoosePETempRoot 选择拥有足够剩余空间的 PETEMP 根分区。
func ChoosePETempRoot(needBytes int64) (string, error) {
	systemDrive := strings.ToUpper(os.Getenv("SystemDrive"))
	if systemDrive != "" {
		free, err := disk.GetFreeSize(systemDrive)
		if err == nil && int64(free) > needBytes {
			log.LogWrite(0, "[choosePETempRoot] PETEMP uses system drive: %s", systemDrive)
			return systemDrive + `\`, nil
		}
	}

	parts := disk.Findpart()
	for _, p := range parts {
		free, err := disk.GetFreeSize(p)
		if err == nil && int64(free) > needBytes {
			log.LogWrite(0, "[choosePETempRoot] PETEMP uses partition: %s", p)
			return p, nil
		}
	}

	if systemDrive != "" {
		return systemDrive + `\`, nil
	}
	return "", fmt.Errorf("未找到可用分区")
}

// extractWePE 从本地微 PE 安装包中提取 boot.wim。
func extractWePE(arch string) (string, error) {
	peList, err := data.GetWinPE()
	if err != nil {
		return "", err
	}

	for _, dir := range wepeDirs() {
		for _, name := range wepeNames(arch) {
			exePath := filepath.Join(dir, name)
			if !utils.FileExists(exePath) {
				continue
			}

			meta, ok := pickWePE(peList, exePath, name, arch)
			if !ok || meta.OffsetEnd <= meta.OffsetStart {
				continue
			}

			needBytes := int64(meta.Sz * 1024 * 1024)
			root, err := ChoosePETempRoot(needBytes * 2)
			if err != nil {
				return "", err
			}

			peDir := filepath.Join(root, "PETEMP")
			if err := file.EnsureCleanDir(peDir); err != nil {
				return "", err
			}

			wimPath := filepath.Join(peDir, "boot.wim")
			if err := file.PeelFile(
				exePath,
				fmt.Sprintf("%d", meta.OffsetStart),
				fmt.Sprintf("%d", meta.OffsetEnd),
				wimPath,
			); err != nil {
				_ = file.Remove(wimPath, false)
				continue
			}

			if err := copySDIToPETEMP(peDir); err != nil {
				return "", err
			}

			log.LogWrite(0, "[extractWePE] using local installer: %s", exePath)
			return wimPath, nil
		}
	}

	return "", fmt.Errorf("未找到本地可用的微PE安装包")
}

// wepeDirs 枚举可能存在微 PE 安装包的目录。
func wepeDirs() []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		key := strings.ToLower(p)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, p)
	}

	drives, _ := disk.ListDrive()
	for _, root := range drives {
		add(filepath.Join(root, "PETEMP"))
	}

	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		add(exeDir)
		add(filepath.Join(exeDir, "tools"))
	}

	if userProfile := strings.TrimSpace(os.Getenv("USERPROFILE")); userProfile != "" {
		add(filepath.Join(userProfile, "Downloads"))
	}

	return out
}

// wepeNames 返回指定架构常见的微 PE 文件名。
func wepeNames(arch string) []string {
	names := []string{"wepe.exe"}
	if strings.TrimSpace(arch) == "32" {
		return append(names,
			"WePE_32_V2.3.exe",
			"WePE_32_V1.3.exe",
		)
	}

	return append(names,
		"WePE_64_V2.3.exe",
		"WePE_64_V1.3.exe",
	)
}

// pickWePE 按文件名或 MD5 匹配本地微 PE 元数据。
func pickWePE(list []data.WinPEImg, exePath, exeName, arch string) (data.WinPEImg, bool) {
	exeName = strings.ToLower(strings.TrimSpace(exeName))
	if exeName == "wepe.exe" {
		return matchWePEMD5(list, exePath, arch)
	}

	meta, ok := matchWePEName(list, exeName, arch)
	if !ok {
		return data.WinPEImg{}, false
	}
	if strings.TrimSpace(meta.MD5) == "" {
		return meta, true
	}
	ok, err := tools.MatchMD5(exePath, meta.MD5)
	if err != nil || !ok {
		return data.WinPEImg{}, false
	}
	return meta, true
}

// matchWePEName 按文件名匹配微 PE 元数据。
func matchWePEName(list []data.WinPEImg, exeName, arch string) (data.WinPEImg, bool) {
	exeName = strings.ToLower(strings.TrimSpace(exeName))
	arch = strings.TrimSpace(arch)

	for _, it := range list {
		if strings.TrimSpace(it.Arch) != arch {
			continue
		}
		for _, link := range it.Links {
			base := strings.ToLower(filepath.Base(strings.Split(link, "?")[0]))
			if base == exeName {
				return it, true
			}
		}
	}

	return data.WinPEImg{}, false
}

// matchWePEMD5 按 MD5 匹配微 PE 元数据。
func matchWePEMD5(list []data.WinPEImg, exePath, arch string) (data.WinPEImg, bool) {
	arch = strings.TrimSpace(arch)
	for _, it := range list {
		if strings.TrimSpace(it.Arch) != arch || strings.TrimSpace(it.MD5) == "" {
			continue
		}
		ok, err := tools.MatchMD5(exePath, it.MD5)
		if err == nil && ok {
			return it, true
		}
	}
	return data.WinPEImg{}, false
}
