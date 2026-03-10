package main

import (
	"ReSys/src/disk"
	"ReSys/src/download"
	"ReSys/src/file"
	"ReSys/src/log"
	"ReSys/src/pe"
	"ReSys/src/utils"
	"ReSys/src/windows"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// WinInstallPrepareResult 当前系统内准备重装
type WinInstallPrepareResult struct {
	ImagePath   string
	ImageArch   string
	PEArch      string
	PreferIndex int
	PEWimPath   string
	PESdiPath   string
}

// PrepareWindowsInstallForCompare 当前系统准备重装流程。
// 1) 查找/下载镜像（考虑目标系统与架构）；
// 2) 镜像若在系统盘，先迁移到其它固定盘，失败再迁移到 TEMP 分区；
// 3) 解析镜像并写入重装信息；
// 4) 扫描已有 PE（pe.GoToPE 扫描模式）；
// 5) 若未找到 PE，按架构在本地目录查找微PE安装包并提取；
// 6) 仍未找到则下载 PE。
func PrepareWindowsInstallForCompare(target string) (*WinInstallPrepareResult, error) {
	imgArch := windows.DesiredArch()
	peArch := systemArch()

	imgPath, ok := PrepareInstallImagePlanForCompare(target, imgArch)
	if !ok {
		return nil, fmt.Errorf("镜像准备失败")
	}

	preferIndex, ok := prepareResDataWithRetry(imgPath, target, imgArch)
	if !ok {
		return nil, fmt.Errorf("写入重装信息失败")
	}

	wimPath, sdiPath, ok := preparePEWithRetry(peArch)
	if !ok {
		return nil, fmt.Errorf("准备PE失败")
	}

	if !enterPEWithRetry(wimPath, sdiPath) {
		return nil, fmt.Errorf("设置进入PE失败")
	}

	uiSetProgress(100)
	uiSetStatus("即将重启进入PE...")
	log.LogWrite(0, "[install_win]准备完成，重启进入PE")
	Message("准备进入pe,测试模式", "请查看日志确定无误后手动重启")
	//Shutdown(true)

	return &WinInstallPrepareResult{
		ImagePath:   imgPath,
		ImageArch:   imgArch,
		PEArch:      peArch,
		PreferIndex: preferIndex,
		PEWimPath:   wimPath,
		PESdiPath:   sdiPath,
	}, nil
}

// prepareResDataWithRetry 重试执行解析镜像并写重装信息。
func prepareResDataWithRetry(imgPath, target, imgArch string) (int, bool) {
	return retryLoopWithResult("写入重装信息", func() (int, error) {
		return parseImageAndWriteResData(imgPath, target, imgArch)
	})
}

// preparePEWithRetry 重试执行扫描/准备PE文件。
func preparePEWithRetry(peArch string) (string, string, bool) {
	type peReady struct {
		wim string
		sdi string
	}
	v, ok := retryLoopWithResult("准备PE", func() (peReady, error) {
		wimPath, sdiPath, err := ensurePEReadyForCompare(peArch)
		if err != nil {
			return peReady{}, err
		}
		return peReady{wim: wimPath, sdi: sdiPath}, nil
	})
	if !ok {
		return "", "", false
	}
	return v.wim, v.sdi, true
}

// enterPEWithRetry 重试执行写入自身到PE + 设置下次启动进入PE。
func enterPEWithRetry(wimPath, sdiPath string) bool {
	if !retryLoop("写入自身到PE", func() error {
		uiSetStatus("正在写入自身到PE...")
		return pe.Patwim(wimPath)
	}) {
		return false
	}

	if strings.TrimSpace(sdiPath) == "" {
		sdiPath = resolveSdiPath(wimPath)
	}

	if !retryLoop("设置进入PE启动项", func() error {
		uiSetStatus("正在设置下次启动进入PE...")
		if strings.TrimSpace(sdiPath) == "" {
			_, _, _, err := pe.GoToPE(false)
			return err
		}
		_, _, _, err := pe.GoToPE(false, sdiPath, wimPath)
		return err
	}) {
		return false
	}

	return true
}

// PrepareInstallImagePlanForCompare 当前系统内准备重装镜像。
func PrepareInstallImagePlanForCompare(target, imgArch string) (string, bool) {
	uiSetStatus("正在寻找镜像...")
	return retryLoopWithResult("镜像准备", func() (string, error) {
		return prepareInstallImagePlanOnce(target, imgArch)
	})
}

// prepareInstallImagePlanOnce 执行一次镜像准备。
func prepareInstallImagePlanOnce(target, imgArch string) (string, error) {
	imgPath, err := findImageWithDownloadStrategy(target, imgArch)
	if err != nil {
		return "", err
	}
	return relocateImageIfOnSystemDrive(imgPath)
}

// findImageWithDownloadStrategy 获取镜像。
// 当目标系统为 win10/win11 且需要下载时，优先微软官方直链（GetMSWinUrl），失败再回退原有下载源。
func findImageWithDownloadStrategy(target, imgArch string) (string, error) {
	if local, err := findLocalImage(target, imgArch); err == nil && strings.TrimSpace(local) != "" {
		return local, nil
	}

	if strings.EqualFold(target, targetWin10) || strings.EqualFold(target, targetWin11) {
		if p, err := downloadImageFromMicrosoft(target, imgArch); err == nil && strings.TrimSpace(p) != "" {
			return p, nil
		}
	}

	return downloadImage(target, imgArch)
}

// downloadImageFromMicrosoft 使用微软官方直链下载 win10/win11 镜像。
// 失败时返回错误，由上层回退到原有下载源。
func downloadImageFromMicrosoft(target, imgArch string) (string, error) {
	systemCode := ""
	switch strings.ToLower(strings.TrimSpace(target)) {
	case targetWin10:
		systemCode = "10"
	case targetWin11:
		systemCode = "11"
	default:
		return "", fmt.Errorf("非微软直链目标系统: %s", target)
	}

	urls, err := GetMSWinUrl(systemCode, "zh-cn", strings.TrimSpace(imgArch), "")
	if err != nil {
		return "", err
	}
	if len(urls) == 0 {
		return "", fmt.Errorf("微软直链为空")
	}

	root := chooseDownloadRoot()
	if strings.TrimSpace(root) == "" {
		return "", fmt.Errorf("未找到可用下载分区")
	}
	dstDir := filepath.Join(root, "tempimg")
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return "", err
	}

	var errs []string
	for _, u := range urls {
		link := strings.TrimSpace(u.URL)
		if link == "" || isFailedLink(link) {
			continue
		}
		if !download.HttpStatus(link) {
			markFailedLink(link)
			errs = append(errs, fmt.Sprintf("微软直链不可用: %s", link))
			continue
		}

		name := strings.TrimSpace(u.FileName)
		if name == "" {
			name = filepath.Base(strings.Split(link, "?")[0])
		}
		if name == "" || name == "." || name == "/" {
			name = fmt.Sprintf("win%s_%s.iso", systemCode, strings.TrimSpace(imgArch))
		}
		dstPath := filepath.Join(dstDir, name)

		if st, err := os.Stat(dstPath); err == nil && !st.IsDir() && st.Size() > 0 {
			if err := validateMSImageFile(u, dstPath); err == nil {
				return dstPath, nil
			}
			_ = file.Remove(dstPath, false)
		}

		uiSetProgress(0)
		uiSetStatus("正在下载镜像... 0.0% 速度: 0.00 MB/s")
		pr := NewProgressReporter(
			0, 60,
			1*time.Second, 1*time.Second,
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

		if err := validateMSImageFile(u, dstPath); err != nil {
			markFailedLink(link)
			_ = file.Remove(dstPath, false)
			errs = append(errs, fmt.Sprintf("微软直链校验失败: %v", err))
			continue
		}

		uiSetProgress(60)
		return dstPath, nil
	}

	if len(errs) > 0 {
		return "", fmt.Errorf(strings.Join(errs, " | "))
	}
	return "", fmt.Errorf("微软直链下载失败")
}

// validateMSImageFile 校验微软直链镜像文件（优先 SHA1，回退镜像解析）。
func validateMSImageFile(info MSWinURL, imagePath string) error {
	if strings.TrimSpace(info.SHA1) != "" {
		ok, got, err := download.CheckFileSHA1(imagePath, info.SHA1)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("SHA1不匹配: %s", got)
		}
		return nil
	}
	if _, err := detectImageInfos(imagePath); err != nil {
		return err
	}
	return nil
}

// relocateImageIfOnSystemDrive 当镜像与系统盘同盘时进行安全迁移。
// 迁移顺序：其它固定盘 -> TEMP 分区。
func relocateImageIfOnSystemDrive(imgPath string) (string, error) {
	sysRoot, _ := utils.NormalizeDrive(systemDriveRoot(), 0)
	imgRoot, _ := utils.NormalizeDrive(imgPath, 2)
	if sysRoot == "" || imgRoot == "" || !strings.EqualFold(sysRoot, imgRoot) {
		return imgPath, nil
	}

	needBytes, err := fileSizeBytes(imgPath)
	if err != nil {
		return "", err
	}

	if movedPath, moved, err := moveImageToOtherFixedVolume(imgPath, sysRoot, needBytes); err != nil {
		return "", err
	} else if moved {
		return movedPath, nil
	}

	return moveImageToTempPartition(imgPath, needBytes)
}

// parseImageAndWriteResData 解析镜像并写入重装信息文件。
func parseImageAndWriteResData(imgPath, target, imgArch string) (int, error) {
	uiSetProgress(60)
	uiSetStatus("正在写入重装信息...")

	preferIndex := 0
	if infos, err := detectImageInfos(imgPath); err == nil {
		preferIndex = selectInstallIndex(infos)
	}
	if err := writeResFile(imgPath, target, imgArch, preferIndex); err != nil {
		return 0, err
	}
	return preferIndex, nil
}

// ensurePEReadyForCompare 确保存在可用 PE。
// 优先扫描已有 PE；再尝试本地微PE安装包；最后回退网络下载。
// 下载阶段沿用downloadPE：微PE失败会自动切换到其他 PE。
func ensurePEReadyForCompare(peArch string) (string, string, error) {
	uiSetStatus("正在扫描PE环境...")
	if found, wimPath, sdiPath, err := pe.GoToPE(true); err == nil && found && strings.TrimSpace(wimPath) != "" {
		if strings.TrimSpace(sdiPath) == "" {
			sdiPath = resolveSdiPath(wimPath)
		}
		log.LogWrite(0, "[install_win]扫描到已有PE：wim=%s sdi=%s", wimPath, sdiPath)
		return wimPath, sdiPath, nil
	}

	uiSetStatus("未找到PE，正在查找本地微PE安装包...")
	if wimPath, err := preparePEFromLocalWePEInstaller(peArch); err == nil {
		sdiPath := resolveSdiPath(wimPath)
		log.LogWrite(0, "[install_win]本地微PE安装包准备完成：wim=%s sdi=%s", wimPath, sdiPath)
		return wimPath, sdiPath, nil
	}

	uiSetStatus("本地未找到可用PE，正在下载PE...")
	wimPath, _, err := downloadPE(peArch, map[string]struct{}{})
	if err != nil {
		return "", "", err
	}
	sdiPath := resolveSdiPath(wimPath)
	return wimPath, sdiPath, nil
}

// preparePEFromLocalWePEInstaller 从本地目录查找微PE安装包并提取 WIM 到 PETEMP。
// 查找顺序：
// 1) 每个盘符的 PETEMP 目录（filepath.Join(root, "PETEMP")）；
// 2) 程序所在目录；
// 3) 程序所在目录的 tools 子目录；
// 4) 用户下载目录。
// 文件名顺序：先 wepe.exe，再按架构优先检查 WePE_* 版本文件。
func preparePEFromLocalWePEInstaller(arch string) (string, error) {
	peList, err := GetWinPE()
	if err != nil {
		return "", err
	}

	searchDirs := wepeSearchDirsForCompare()
	candidates := orderedWePEExeNames(arch)

	for _, dir := range searchDirs {
		for _, name := range candidates {
			path := filepath.Join(dir, name)
			if !utils.FileExists(path) {
				continue
			}

			meta, ok := matchWePEMetaByExeName(peList, name, arch)
			if !ok {
				continue
			}
			if meta.OffsetEnd <= meta.OffsetStart {
				continue
			}

			needBytes := int64(meta.Sz * 1024 * 1024)
			root, err := choosePETempRoot(needBytes * 2)
			if err != nil {
				return "", err
			}
			peDir := filepath.Join(root, "PETEMP")
			if err := ensureCleanDir(peDir); err != nil {
				return "", err
			}

			wimPath := filepath.Join(peDir, "boot.wim")
			if err := file.PeelFile(path, fmt.Sprintf("%d", meta.OffsetStart), fmt.Sprintf("%d", meta.OffsetEnd), wimPath); err != nil {
				continue
			}
			if err := copySDIToPETEMP(peDir); err != nil {
				return "", err
			}
			return wimPath, nil
		}
	}
	return "", fmt.Errorf("未找到本地可用微PE安装包")
}

// wepeSearchDirsForCompare 返回微PE安装包搜索目录。
func wepeSearchDirsForCompare() []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		if _, ok := seen[strings.ToLower(p)]; ok {
			return
		}
		seen[strings.ToLower(p)] = struct{}{}
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

// orderedWePEExeNames 返回按架构严格匹配的微PE安装包文件名候选。
// 约束：
// - arch=64 时只返回 64 位候选，不允许回退 32 位；
// - arch=32 时只返回 32 位候选；
// - wepe.exe 始终优先。
func orderedWePEExeNames(arch string) []string {
	names := []string{"wepe.exe"}
	if strings.TrimSpace(arch) == "32" {
		names = append(names,
			"WePE_32_V2.3.exe",
			"WePE_32_V1.3.exe",
		)
		return names
	}
	names = append(names,
		"WePE_64_V2.3.exe",
		"WePE_64_V1.3.exe",
	)
	return names
}

// matchWePEMetaByExeName 根据本地 exe 文件名在 WinPE 列表中匹配元数据。
// 约束：链接名与架构都必须匹配；不做跨架构回退。
func matchWePEMetaByExeName(list []WinPEImg, exeName, arch string) (WinPEImg, bool) {
	exeName = strings.ToLower(strings.TrimSpace(exeName))
	arch = strings.TrimSpace(arch)

	matchArch := func(it WinPEImg) bool {
		if arch == "" {
			return true
		}
		return strings.TrimSpace(it.Arch) == arch
	}
	matchName := func(it WinPEImg) bool {
		for _, link := range it.Links {
			base := strings.ToLower(filepath.Base(strings.Split(link, "?")[0]))
			if base == exeName {
				return true
			}
		}
		return false
	}

	for _, it := range list {
		if matchArch(it) && matchName(it) {
			return it, true
		}
	}
	return WinPEImg{}, false
}

// fileSizeBytes 返回文件大小（字节）。
func fileSizeBytes(path string) (uint64, error) {
	st, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	if st.IsDir() {
		return 0, fmt.Errorf("镜像路径是目录: %s", path)
	}
	return uint64(st.Size()), nil
}

// moveImageToOtherFixedVolume 尝试迁移镜像到其它固定盘卷。
// 仅当卷剩余空间 >= 镜像大小 + 512MB 缓冲 时才认为可用。
func moveImageToOtherFixedVolume(imgPath, systemRoot string, needBytes uint64) (string, bool, error) {
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

	uiSetStatus("镜像在系统盘：正在转移到其它分区...")
	movedPath, err := copyAndReplaceImage(imgPath, bestRoot, "tempimg")
	if err != nil {
		return "", false, err
	}
	log.LogWrite(0, "[install_win]镜像已转移到其它分区：%s", movedPath)
	return movedPath, true, nil
}

// moveImageToTempPartition 创建/复用 TEMP 分区并迁移镜像。
func moveImageToTempPartition(imgPath string, needBytes uint64) (string, error) {
	uiSetStatus("镜像在系统盘：正在创建TEMP分区并转移镜像...")
	tmpRoot, err := disk.EnsureTempVolumeForBytes(needBytes)
	if err != nil {
		return "", err
	}
	movedPath, err := copyAndReplaceImage(imgPath, tmpRoot, "tempimg")
	if err != nil {
		return "", err
	}
	log.LogWrite(0, "[install_win]镜像已转移到TEMP分区：%s", movedPath)
	return movedPath, nil
}

// copyAndReplaceImage 将镜像复制到目标盘的指定子目录，复制成功后删除原镜像并返回新路径。
func copyAndReplaceImage(srcPath, root, subDir string) (string, error) {
	dstDir := filepath.Join(root, subDir)
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return "", err
	}

	dstPath := filepath.Join(dstDir, filepath.Base(srcPath))
	log.LogWrite(0, "[install_win]转移镜像：%s -> %s", srcPath, dstPath)
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
