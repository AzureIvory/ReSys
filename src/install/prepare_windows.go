package install

import (
	"ReSys/src/data"
	"ReSys/src/disk"
	"ReSys/src/download"
	"ReSys/src/file"
	"ReSys/src/image"
	"ReSys/src/log"
	"ReSys/src/pe"
	"ReSys/src/tools"
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

// prepareImage 完成镜像定位与必要的安全迁移。
func prepareImage(target, imgArch string) (string, error) {
	imgPath, err := findImage(target, imgArch)
	if err != nil {
		return "", err
	}
	return relocateImage(imgPath)
}

// findImage 按“本地优先、微软直链次之、常规下载兜底”获取镜像。
func findImage(target, imgArch string) (string, error) {
	if local, err := image.FindLocalImage(target, imgArch); err == nil && strings.TrimSpace(local) != "" {
		return local, nil
	}

	if strings.EqualFold(target, TargetWin10) || strings.EqualFold(target, TargetWin11) {
		imgPath, err := downloadMSImage(target, imgArch)
		if err == nil && strings.TrimSpace(imgPath) != "" {
			return imgPath, nil
		}
		if err != nil {
			log.LogWrite(0, "[findImage] Microsoft direct download failed: %v", err)
		}
	}

	return DownloadImage(target, imgArch)
}

// downloadMSImage 使用微软官方直链下载 Win10/Win11 镜像。
func downloadMSImage(target, imgArch string) (string, error) {
	systemCode := ""
	switch strings.ToLower(strings.TrimSpace(target)) {
	case TargetWin10:
		systemCode = "10"
	case TargetWin11:
		systemCode = "11"
	default:
		return "", fmt.Errorf("不支持的微软镜像目标: %s", target)
	}

	urls, err := data.GetMSWinUrl(systemCode, "zh-cn", strings.TrimSpace(imgArch), "")
	log.LogWrite(0, "[downloadMSImage] url: %v,err:%v", urls,err)
	if err != nil {
		return "", err
	}
	if len(urls) == 0 {
		return "", fmt.Errorf("未找到微软官方镜像直链")
	}

	root := chooseDownloadRoot()
	log.LogWrite(0, "[downloadMSImage] chooseDownloadRoot: %v", root)
	if strings.TrimSpace(root) == "" {
		return "", fmt.Errorf("未找到可用下载分区")
	}

	dstDir := filepath.Join(root, "tempimg")
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return "", err
	}

	var errs []string
	for _, info := range urls {
		link := strings.TrimSpace(info.URL)
		if link == "" || isFailedLink(link) {
			continue
		}
		if !download.HttpStatus(link) {
			markFailedLink(link)
			errs = append(errs, fmt.Sprintf("微软直链不可用: %s", link))
			continue
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
			"镜像下载进度：%.1f%% 速度: %.2f MB/s",
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
			errs = append(errs, fmt.Sprintf("微软直链下载失败: %v", err))
			continue
		}

		if err := verifyMSImage(info, dstPath); err != nil {
			markFailedLink(link)
			_ = file.Remove(dstPath, false)
			errs = append(errs, fmt.Sprintf("微软镜像校验失败: %v", err))
			continue
		}

		ui.UiSetProgress(60)
		return dstPath, nil
	}

	if len(errs) > 0 {
		return "", fmt.Errorf("%s", strings.Join(errs, " | "))
	}
	return "", fmt.Errorf("微软直链下载失败")
}

// verifyMSImage 校验微软直链镜像，优先使用 SHA1。
func verifyMSImage(info data.MSWinURL, imagePath string) error {
	if strings.TrimSpace(info.SHA1) != "" {
		ok, got, err := download.CheckFileSHA1(imagePath, info.SHA1)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("SHA1 不匹配: %s", got)
		}
		return nil
	}

	_, err := image.DetectImageInfos(imagePath)
	return err
}

// relocateImage 确保镜像不会随着系统盘格式化一起被清掉。
func relocateImage(imgPath string) (string, error) {
	systemRoot, _ := utils.NormalizeDrive(windows.SystemDriveRoot(), 0)
	imageRoot, _ := utils.NormalizeDrive(imgPath, 2)
	if systemRoot == "" || imageRoot == "" || !strings.EqualFold(systemRoot, imageRoot) {
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

// writeInstallInfo 解析镜像并写入 PE 阶段需要的重装信息。
func writeInstallInfo(imgPath, target, imgArch string) (int, error) {
	ui.UiSetProgress(60)
	ui.UiSetStatus("正在写入重装信息...")

	preferIndex := 0
	if infos, err := image.DetectImageInfos(imgPath); err == nil {
		preferIndex = SelectInstallIndex(infos)
	}

	if err := WriteResFile(imgPath, target, imgArch, preferIndex); err != nil {
		return 0, err
	}
	return preferIndex, nil
}

// preparePEBoot 依次完成 PE 扫描、本地微PE提取、下载兜底和启动项写入。
func preparePEBoot(arch string) error {
	arch = strings.TrimSpace(arch)
	if arch == "" {
		arch = "64"
	}

	const maxAttempts = 3
	failedPEImages := map[string]struct{}{}
	skipLocal := false

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		var (
			wimPath string
			sdiPath string
			peID    string
			tempPE  bool
		)

		if attempt == 1 {
			found, wim, sdi, err := pe.GoToPE(true)
			if err != nil {
				log.LogWrite(0, "[preparePEBoot] PE scan failed: %v", err)
			} else if found && strings.TrimSpace(wim) != "" {
				wimPath = wim
				sdiPath = sdi
				log.LogWrite(0, "[preparePEBoot] using scanned PE: %s", wimPath)
			}
		}

		if wimPath == "" && !skipLocal {
			localWim, err := extractWePE(arch)
			if err != nil {
				log.LogWrite(0, "[preparePEBoot] local WePE unavailable: %v", err)
				skipLocal = true
			} else if strings.TrimSpace(localWim) != "" {
				wimPath = localWim
				sdiPath = resolveSdiPath(localWim)
				peID = "local-wepe"
				tempPE = true
				log.LogWrite(0, "[preparePEBoot] using local WePE installer: %s", wimPath)
			}
		}

		if wimPath == "" {
			log.LogWrite(0, "[preparePEBoot] no local PE found, downloading one")
			wp, id, err := downloadPE(arch, failedPEImages)
			if err != nil {
				log.LogWrite(0, "[preparePEBoot] downloadPE failed: %v", err)
				if attempt == maxAttempts {
					return fmt.Errorf("准备 PE 失败: %w", err)
				}
				continue
			}
			wimPath = wp
			sdiPath = resolveSdiPath(wimPath)
			peID = id
			tempPE = strings.Contains(strings.ToLower(wimPath), `\petemp\`)
		}

		if sdiPath == "" {
			sdiPath = resolveSdiPath(wimPath)
		}

		ui.UiSetStatus("正在写入自身到PE...")
		if err := pe.Patwim(wimPath); err != nil {
			log.LogWrite(0, "[preparePEBoot] Patwim failed: %v", err)
			markFailedPEImage(failedPEImages, peID)
			if tempPE {
				removePEArtifacts(wimPath, sdiPath)
			}
			if peID == "local-wepe" {
				skipLocal = true
			}
			if attempt == maxAttempts {
				return fmt.Errorf("写入 PE 失败: %w", err)
			}
			continue
		}

		ui.UiSetStatus("正在设置下次启动进入PE...")
		var err error
		if strings.TrimSpace(sdiPath) == "" {
			_, _, _, err = pe.GoToPE(false)
		} else {
			_, _, _, err = pe.GoToPE(false, sdiPath, wimPath)
		}
		if err != nil {
			log.LogWrite(0, "[preparePEBoot] GoToPE failed: %v", err)
			markFailedPEImage(failedPEImages, peID)
			if tempPE {
				removePEArtifacts(wimPath, sdiPath)
			}
			if peID == "local-wepe" {
				skipLocal = true
			}
			if attempt == maxAttempts {
				return fmt.Errorf("设置进入 PE 失败: %w", err)
			}
			continue
		}

		return nil
	}

	return fmt.Errorf("准备 PE 失败")
}

// extractWePE 按既定目录和文件名顺序查找并提取本地微PE。
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

// wepeDirs 返回微PE安装包的搜索目录，并自动去重。
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

// wepeNames 返回按架构筛过的微PE安装包候选名。
// 64 位系统只允许 64 位微PE，不做 32 位回退。
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

// pickWePE 为本地安装包挑出匹配的元数据和剥离区间。
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

// matchWePEName 按文件名和架构在 WinPE 列表中匹配安装包。
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

// matchWePEMD5 在通用文件名 wepe.exe 场景下通过 MD5 精确匹配。
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

// fileSize 返回普通文件大小，目录会被视为无效输入。
func fileSize(path string) (uint64, error) {
	st, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	if st.IsDir() {
		return 0, fmt.Errorf("镜像路径是目录: %s", path)
	}
	return uint64(st.Size()), nil
}

// moveImageToDisk 尝试把镜像迁移到空间足够的其他固定盘。
func moveImageToDisk(imgPath, systemRoot string, needBytes uint64) (string, bool, error) {
	const extraBytes uint64 = 512 * 1024 * 1024

	var (
		bestRoot string
		bestFree uint64
	)

	for _, root := range otherInstallVolumes(systemRoot) {
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

	ui.UiSetStatus("镜像位于系统盘，正在迁移到其他固定盘...")
	movedPath, err := moveImageFile(imgPath, bestRoot, "tempimg")
	if err != nil {
		return "", false, err
	}
	log.LogWrite(0, "[moveImageToDisk] image moved to %s", movedPath)
	return movedPath, true, nil
}

// moveImageToTemp 在没有可用固定盘时创建或复用 TEMP 分区。
func moveImageToTemp(imgPath string, needBytes uint64) (string, error) {
	ui.UiSetStatus("镜像位于系统盘，正在创建 TEMP 分区并迁移镜像...")

	tmpRoot, err := disk.EnsureTempVolumeForBytes(needBytes)
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

// moveImageFile 复制镜像到目标位置，并在成功后删除旧文件。
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
