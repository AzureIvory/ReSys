package main

import (
	"ReSys/src/boot"
	"ReSys/src/disk"
	D "ReSys/src/dism"
	"ReSys/src/file"
	"ReSys/src/log"
	"ReSys/src/pe"
	"ReSys/src/tools"
	"ReSys/src/utils"
	"ReSys/src/windows"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	targetWin7  = "win7"
	targetWin10 = "win10"
	targetWin11 = "win11"
)

var (
	failedLinksMu sync.Mutex
	failedLinks   = map[string]struct{}{}
)

func markFailedLink(link string) {
	link = strings.TrimSpace(link)
	if link == "" {
		return
	}
	failedLinksMu.Lock()
	defer failedLinksMu.Unlock()
	failedLinks[link] = struct{}{}
}

func isFailedLink(link string) bool {
	link = strings.TrimSpace(link)
	if link == "" {
		return false
	}
	failedLinksMu.Lock()
	defer failedLinksMu.Unlock()
	_, ok := failedLinks[link]
	return ok
}

// 从 UI 入口启动安装流程。
// 搜索/下载镜像
// 写入 restall_win.dat / restall_img.dat
// 准备 PE 并重启进入 PE
func StartInstall(target string) {
	win2()
	imgArch := windows.DesiredArch()
	peArch := windows.SystemArch()
	log.LogWrite(0, "[StartInstall]开始重装流程，目标系统=%s，镜像期望架构=%s，PE架构=%s", target, imgArch, peArch)
	uiSetProgress(0)
	uiSetStatus("正在寻找镜像...")
	imgPath, ok := retryLoopWithResult("镜像准备", func() (string, error) {
		return findOrDownloadImage(target, imgArch)
	})
	if !ok {
		return
	}

	// 如果镜像在系统盘(C)，必须在进PE前把镜像移到 TEMP，否则PE格式化目标分区会丢镜像
	// 只要镜像在目标盘/系统盘上（通常是 C 盘），就优先搬到其它固定盘卷；
	// 如果不存在其它固定盘卷（或空间不足），再考虑创建 TEMP（未分配/拆分）来存放。
	if !retryLoop("准备镜像存放分区", func() error {
		sysRoot, _ := utils.NormalizeDrive(systemDriveRoot(), 0)
		imgRoot, _ := utils.NormalizeDrive(imgPath, 2)
		if sysRoot == "" || imgRoot == "" || !strings.EqualFold(sysRoot, imgRoot) {
			return nil
		}

		st, err := os.Stat(imgPath)
		if err != nil {
			return err
		}
		need := uint64(st.Size())

		// 1) 优先搬到其它“固定盘卷”（例如 D/E 盘）
		var (
			bestRoot string
			bestFree uint64
		)
		const extra uint64 = 512 * 1024 * 1024
		for _, r := range otherInstallVolumes(sysRoot) {
			freeBytes, err := disk.GetFreeSize(r)
			if err != nil {
				continue
			}
			if freeBytes >= need+extra && freeBytes > bestFree {
				bestFree = freeBytes
				bestRoot = r
			}
		}

		if bestRoot != "" {
			uiSetStatus("镜像在系统盘：正在转移到其它分区...")
			dstDir := filepath.Join(bestRoot, "tempimg")
			_ = os.MkdirAll(dstDir, 0o755)
			dstPath := filepath.Join(dstDir, filepath.Base(imgPath))

			log.LogWrite(0, "[StartInstall]转移镜像到其它分区：%s -> %s", imgPath, dstPath)
			if err := file.Copy(imgPath, dstPath, true, true); err != nil {
				file.Remove(dstPath, false)
				return err
			}
			if _, err := os.Stat(dstPath); err != nil {
				return err
			}
			if !strings.EqualFold(imgPath, dstPath) {
				if err := file.Remove(imgPath, false); err != nil {
					return err
				}
				log.LogWrite(0, "[StartInstall]已删除原镜像：%s", imgPath)
			}
			imgPath = dstPath
			log.LogWrite(0, "[StartInstall]镜像已转移到其它分区，更新路径：%s", imgPath)
			return nil
		}

		// 2) 没有其它固定盘卷（或空间不足）：创建 TEMP（未分配优先，最后才拆分 C）
		uiSetStatus("镜像在系统盘：正在创建TEMP分区并转移镜像...")
		tmpRoot, err := disk.EnsureTempVolumeForBytes(need)
		if err != nil {
			return err
		}
		dstDir := filepath.Join(tmpRoot, "tempimg")
		_ = os.MkdirAll(dstDir, 0o755)
		dstPath := filepath.Join(dstDir, filepath.Base(imgPath))
		log.LogWrite(0, "[StartInstall]转移镜像到TEMP：%s -> %s", imgPath, dstPath)
		if err := file.Copy(imgPath, dstPath, true, true); err != nil {
			file.Remove(dstPath, false)
			return err
		}
		if _, err := os.Stat(dstPath); err != nil {
			return err
		}
		if !strings.EqualFold(imgPath, dstPath) {
			if err := file.Remove(imgPath, false); err != nil {
				return err
			}
			log.LogWrite(0, "[StartInstall]已删除原镜像：%s", imgPath)
		}
		imgPath = dstPath
		log.LogWrite(0, "[StartInstall]镜像已转移到TEMP，更新路径：%s", imgPath)
		return nil
	}) {
		return
	}

	uiSetProgress(60)
	uiSetStatus("正在写入重装信息...")

	if !retryLoop("写入重装信息", func() error {
		preferIndex := 0
		if infos, err := detectImageInfos(imgPath); err == nil {
			preferIndex = selectInstallIndex(infos)
		}
		return writeResFile(imgPath, target, imgArch, preferIndex)
	}) {
		return
	}

	uiSetProgress(70)
	uiSetStatus("正在准备PE环境...")

	if !retryLoop("准备PE", func() error {

		return ensurePEAndReboot(peArch)
	}) {
		return
	}

	uiSetProgress(100)
	uiSetStatus("即将重启进入PE...")
	log.LogWrite(0, "[StartInstall]准备完成，重启进入PE")
	Message("准备进入pe,测试模式", "请查看日志确定无误后手动重启")
	//Shutdown(true)
}

// 扫描当前磁盘是否已存在可用 PE 引导文件。
func hasPEFiles(arch string) (bool, string, string) {
	drives, err := disk.ListDrive()
	if err != nil {
		log.LogWrite(0, "[hasPEFiles]枚举盘符失败：%v", err)
		return false, "", ""
	}

	for _, d := range drives {
		wims, _ := file.FindFile(d, `PETEMP\*.wim|PETEMP\*.WIM`, 1)
		sdis, _ := file.FindFile(d, `PETEMP\*.sdi|PETEMP\*.SDI`, 1)
		if len(wims) > 0 {
			wim := pe.ChooseBestWim(wims, arch)
			sdi := ""
			if len(sdis) > 0 {
				sdi = sdis[0]
			}
			log.LogWrite(0, "[hasPEFiles]发现PETEMP中的PE文件：wim=%s sdi=%s", wim, sdi)
			return true, wim, sdi
		}
	}

	type pair struct{ sdi, wim string }
	opts := []pair{
		{`FirPE\BOOT.SDI`, `FirPE\11PEX64.WIM`},
		{`FirPE\BOOT.SDI`, `FirPE\11PEX86.WIM`},
		{`WEPE\WEPE.SDI`, `WEPE\WEPE64.WIM`},
		{`WEPE\WEPE.SDI`, `WEPE\WEPE32.WIM`},
		{`HotPE\boot.sdi`, `HotPE\Boot.wim`},
		{`boot\boot.sdi`, `boot\11pex64.wim`},
		{`boot\boot.sdi`, `boot\11pex86.wim`},
	}

	var wimCands []string
	sdiMap := map[string]string{}

	for _, d := range drives {
		for _, o := range opts {
			wp := filepath.Join(d, o.wim)
			sp := filepath.Join(d, o.sdi)
			if utils.FileExists(wp) {
				wimCands = append(wimCands, wp)
				if utils.FileExists(sp) {
					sdiMap[wp] = sp
				} else {
					sdiMap[wp] = ""
				}
			}
		}
	}

	if len(wimCands) == 0 {
		return false, "", ""
	}

	bestWim := pe.ChooseBestWim(wimCands, arch)
	bestSdi := sdiMap[bestWim]
	log.LogWrite(0, "[hasPEFiles]发现已有PE文件：wim=%s sdi=%s", bestWim, bestSdi)
	return true, bestWim, bestSdi
}

// 优先在运行目录和用户下载目录中查找 WEPE 安装包。
func tryLocalWepe(wepe []WinPEImg, arch string) (string, error) {
	type cand struct {
		img  WinPEImg
		name string
	}
	var all []cand
	for _, it := range wepe {
		for _, link := range it.Links {
			base := filepath.Base(strings.Split(link, "?")[0])
			if base == "" || base == "." || base == "/" {
				continue
			}
			all = append(all, cand{img: it, name: base})
			break
		}
	}
	if len(all) == 0 {
		return "", fmt.Errorf("未找到可用WEPE列表")
	}

	preferredArch := arch
	order := func(list []cand) []cand {
		var a, b []cand
		for _, it := range list {
			if strings.TrimSpace(it.img.Arch) == preferredArch {
				a = append(a, it)
			} else {
				b = append(b, it)
			}
		}
		return append(a, b...)
	}
	all = order(all)

	searchDirs := localWepeSearchDirs()
	log.LogWrite(0, "[tryLocalWepe]本地WEPE搜索目录：%s", strings.Join(searchDirs, " | "))
	for _, dir := range searchDirs {
		if dir == "" {
			continue
		}
		for _, it := range all {
			candPath := filepath.Join(dir, it.name)
			if !utils.FileExists(candPath) {
				continue
			}
			if strings.TrimSpace(it.img.MD5) != "" {
				ok, err := tools.MatchMD5(candPath, it.img.MD5)
				if err != nil || !ok {
					log.LogWrite(0, "[tryLocalWepe]WEPE MD5 校验失败：%s", candPath)
					continue
				}
			}
			needBytes := int64(it.img.Sz * 1024 * 1024)
			root, err := choosePETempRoot(needBytes * 2)
			if err != nil {
				return "", err
			}
			peDir := filepath.Join(root, "PETEMP")
			if err := ensureCleanDir(peDir); err != nil {
				return "", err
			}
			wimPath := filepath.Join(peDir, "boot.wim")
			if it.img.OffsetEnd > it.img.OffsetStart {
				if err := file.PeelFile(candPath, fmt.Sprintf("%d", it.img.OffsetStart), fmt.Sprintf("%d", it.img.OffsetEnd), wimPath); err != nil {
					continue
				}
			} else {
				if err := file.Copy(candPath, wimPath, true, true); err != nil {
					continue
				}
			}
			if err := copySDIToPETEMP(peDir); err != nil {
				return "", err
			}
			log.LogWrite(0, "[tryLocalWepe]本地WEPE准备完成：%s", wimPath)
			return wimPath, nil
		}
	}
	return "", fmt.Errorf("未找到本地WEPE")
}

// 返回本地 WEPE 搜索目录
func localWepeSearchDirs() []string {
	var out []string
	exe, err := os.Executable()
	if err == nil {
		out = append(out, filepath.Dir(exe))
	}
	userProfile := strings.TrimSpace(os.Getenv("USERPROFILE"))
	if userProfile != "" {
		out = append(out, filepath.Join(userProfile, "Downloads"))
	}
	drives, _ := disk.ListDrive()
	for _, d := range drives {
		out = append(out, filepath.Join(d, "PETEMP"))
	}
	return out
}

// RunPEInstall：在 PE 模式执行安装流程。
// 1) 读取 restall_win.dat，定位镜像
// 2) 若失败则本地搜索镜像，再失败则下载 Win10
// 3) 处理镜像在 C 盘场景，必要时分区转移镜像
// 4) 格式化目标分区并应用镜像
// 5) 修复引导 + 安装后文件处理
// 6) 若创建临时分区，安装完成后合并回 C 盘
func RunPEInstall() error {
	uiSetProgress(0)
	uiSetStatus("正在读取重装信息...")
	log.LogWrite(0, "[RunPEInstall]进入PE安装流程")
	isWePE := pe.IsWePE()
	if isWePE {
		log.LogWrite(0, "[RunPEInstall]检测到微PE环境，使用非EX的分区工具调用")
	}
	//进度回调
	progressHandler := func(base, span int32, statusFmt, logFmt string) func(int) {
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

	targetRoot, diskPath, imagePath, volumeGuid, diskUniqueID, imageRel, savedTarget, savedArch, savedIndex, err := loadResData()
	if err != nil {
		log.LogWrite(0, "[RunPEInstall]读取重装信息失败：%v", err)
		targetRoot, diskPath, imagePath = "", "", ""
		os.Exit(0)
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
		log.LogWrite(0, "[RunPEInstall]尝试本地搜索镜像")
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
		log.LogWrite(0, "[RunPEInstall]本地无镜像，尝试下载Win10")
		if dl, derr := downloadImage(t, a); derr == nil {
			imagePath = dl
		} else {
			return fmt.Errorf("未找到镜像且下载失败: %w", derr)
		}
	}
	log.LogWrite(0, "[RunPEInstall]最终使用镜像：%s", imagePath)

	if targetRoot == "" {
		targetRoot = chooseInstallTargetRoot()
		if targetRoot == "" {
			return fmt.Errorf("未找到可用系统分区")
		}
	}
	log.LogWrite(0, "[RunPEInstall]目标分区：%s", targetRoot)

	uiSetProgress(10)
	uiSetStatus("正在准备分区...")

	tempVol := ""
	if nr, err := utils.NormalizeDrive(targetRoot, 0); err == nil {
		targetRoot = nr
	}
	imagePath = strings.TrimSpace(imagePath)

	imageRoot, _ := utils.NormalizeDrive(imagePath, 2)
	if strings.EqualFold(imageRoot, targetRoot) {
		fi, err := os.Stat(imagePath)
		if err != nil {
			return err
		}
		imageBytes := uint64(fi.Size())
		const extraBytes uint64 = 512 * 1024 * 1024
		needBytes := imageBytes + extraBytes

		var moved bool
		var moveErrs []string
		alts := otherInstallVolumes(targetRoot)

		for _, v := range alts {
			altRoot, _ := utils.NormalizeDrive(v, 0)
			if altRoot == "" {
				continue
			}
			if strings.EqualFold(altRoot, targetRoot) {
				continue
			}
			if strings.EqualFold(altRoot, "X:\\") || strings.EqualFold(strings.TrimRight(altRoot, `\`), "X:") {
				continue
			}
			if disk.GetDriveType(altRoot) != driveFixed {
				continue
			}

			freeBytes, ferr := disk.GetFreeSize(altRoot)
			if ferr != nil {
				moveErrs = append(moveErrs, fmt.Sprintf("%s GetFreeSize失败:%v", altRoot, ferr))
				continue
			}
			if freeBytes < needBytes {
				moveErrs = append(moveErrs, fmt.Sprintf("%s 空间不足: free=%d need=%d", altRoot, freeBytes, needBytes))
				continue
			}

			dstDir := filepath.Join(altRoot, "install_images")
			_ = os.MkdirAll(dstDir, 0755)
			dstPath := filepath.Join(dstDir, filepath.Base(imagePath))

			log.LogWrite(0, "[RunPEInstall]镜像在目标分区上，尝试复制到其它卷：%s -> %s", imagePath, dstPath)
			if err := file.Copy(imagePath, dstPath, true, true); err != nil {
				moveErrs = append(moveErrs, fmt.Sprintf("%s Copy失败:%v", altRoot, err))
				_ = file.Remove(dstPath, false)
				continue
			}

			if dfi, derr := os.Stat(dstPath); derr != nil || dfi.Size() <= 0 {
				moveErrs = append(moveErrs, fmt.Sprintf("%s 复制后校验失败:%v", altRoot, derr))
				_ = file.Remove(dstPath, false)
				continue
			}

			imagePath = dstPath
			moved = true
			log.LogWrite(0, "[RunPEInstall]已将镜像复制到其它卷并更新路径：%s", imagePath)
			break
		}

		if !moved {
			if len(moveErrs) > 0 {
				log.LogWrite(0, "[RunPEInstall]复制到其它卷失败/不可用，原因：%s", strings.Join(moveErrs, " | "))
			} else {
				log.LogWrite(0, "[RunPEInstall]无可用其它卷用于复制镜像，准备拆分TEMP分区")
			}

			sizeMB := int((int64(imageBytes) + 512*1024*1024) / (1024 * 1024))
			if sizeMB < 1024 {
				sizeMB = 1024
			}

			splitCb := progressHandler(10, 5, "正在拆分分区... %d%%", "拆分分区进度：%d%%")
			var newVol string
			splitCb(0)
			newVol, err = disk.SplitVolume(targetRoot, sizeMB, "ntfs", "TEMP")
			if err != nil {
				return err
			}
			splitCb(100)
			uiSetProgress(15)
			if nr, err := utils.NormalizeDrive(newVol, 0); err == nil {
				tempVol = nr
			}

			newPath := filepath.Join(tempVol, filepath.Base(imagePath))
			log.LogWrite(0, "[RunPEInstall]仅能拆分分区保存镜像：%s -> %s", imagePath, newPath)

			if err := file.Copy(imagePath, newPath, true, true); err != nil {
				return err
			}
			if _, err := os.Stat(newPath); err != nil {
				return err
			}
			imagePath = newPath
			log.LogWrite(0, "[RunPEInstall]已拆分TEMP并复制镜像，更新镜像路径：%s", imagePath)
		}
	}

	formatBase := int32(10)
	formatSpan := int32(10)
	if tempVol != "" {
		formatBase = 15
		formatSpan = 5
	}
	formatCb := progressHandler(formatBase, formatSpan, "正在格式化分区... %d%%", "格式化进度：%d%%")

	formatCb(0)
	err = disk.Format(strings.ReplaceAll(strings.ReplaceAll(targetRoot, "\\", ""), ":", ""), "ntfs", "Windows", true)
	if err == nil {
		formatCb(100)
	}
	if err != nil {
		log.LogWrite(0, "[RunPEInstall]格式化失败: %v", err)
	}
	log.LogWrite(0, "[RunPEInstall]格式化完成：%s", targetRoot)

	uiSetProgress(20)
	uiSetStatus("正在解析镜像...")
	infos, err := detectImageInfos(imagePath)
	index := 1
	if savedIndex > 0 {
		index = savedIndex
	} else if err == nil {
		index = selectInstallIndex(infos)
		log.LogWrite(0, "[RunPEInstall]镜像索引列表：%s", formatImageInfos(infos))
	}
	log.LogWrite(0, "[RunPEInstall]选择镜像索引：%d", index)

	uiSetStatus(fmt.Sprintf("正在应用镜像（索引 %d）...", index))

	// Apply 阶段20~85
	var lastUI time.Time
	var lastLog time.Time
	ImageProgress = func(phase string, pct float64, raw string) {
		if pct < 0 {
			return
		}
		now := time.Now()

		if lastUI.IsZero() || now.Sub(lastUI) >= 1*time.Second || pct >= 100 {
			uiSetStatus(fmt.Sprintf("正在应用镜像（%s）... %0.1f%%", phase, pct))
			uiSetProgress(mapPct(20, 65, pct))
			lastUI = now
		}
		if lastLog.IsZero() || now.Sub(lastLog) >= 1*time.Second || pct >= 100 {
			log.LogWrite(0, "[RunPEInstall]应用镜像进度：phase=%s pct=%.1f", phase, pct)
			lastLog = now
		}
	}

	switch strings.ToLower(filepath.Ext(imagePath)) {
	case ".esd":
		if err := ApplyEsdImage(imagePath, index, targetRoot); err != nil {
			log.LogWrite(0, "[RunPEInstall]flow ApplyEsdImage1失败"+err.Error())
		}
	case ".wim":
		if err := ApplyWimImage(imagePath, index, targetRoot); err != nil {
			log.LogWrite(0, "[RunPEInstall]flow ApplyWimImage2失败"+err.Error())
		}
	case ".iso":
		if err := ApplyISOImage(imagePath, index, targetRoot); err != nil {
			log.LogWrite(0, "[RunPEInstall]flow ApplyISOImage3失败"+err.Error())
		}
	default:
		return fmt.Errorf("不支持的镜像类型: %s", imagePath)
	}

	uiSetProgress(85)
	uiSetStatus("正在修复引导...")
	if err := boot.FixBoot(targetRoot, "", "zh-cn"); err != nil {
		return err
	}
	log.LogWrite(0, "[RunPEInstall]引导修复完成")

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
	log.LogWrite(0, "[RunPEInstall]安装后处理完成")

	// 如果不是 PE 内创建的 tempVol，尝试通过 marker 找到我们创建的 TEMP 分区
	if tempVol == "" {
		if mr := findTempRootByMarker(); mr != "" {
			if nr, err := utils.NormalizeDrive(mr, 0); err == nil {
				mr = nr
			}
			if mr != "" && !strings.EqualFold(mr, targetRoot) {
				tempVol = mr
				log.LogWrite(0, "[RunPEInstall]通过 marker 找到 TEMP 分区：%s", tempVol)
			}
		}
	}

	if tempVol != "" {
		deleteCb := progressHandler(85, 5, "正在删除临时分区... %d%%", "删除临时分区进度：%d%%")
		deleteCb(0)
		if err := disk.DeleteVolume(tempVol); err != nil {
			log.LogWrite(0, "[RunPEInstall]删除临时分区失败：%v", err)
		} else {
			deleteCb(100)
		}

		mergeCb := progressHandler(90, 5, "正在合并临时分区... %d%%", "合并临时分区进度：%d%%")
		mergeCb(0)
		if err := disk.MergeVolume(targetRoot, 0); err != nil {
			log.LogWrite(0, "[RunPEInstall]合并临时分区失败：%v", err)
		} else {
			mergeCb(100)
			log.LogWrite(0, "[RunPEInstall]已合并临时分区回系统分区：%s", targetRoot)
		}
	}

	uiSetStatus("安装完成，正在重启...")
	uiSetProgress(100)
	log.LogWrite(0, "[RunPEInstall]PE安装流程完成，准备重启")
	Message("安装完成,测试模式", "请查看日志确定无误后手动重启")
	//Shutdown(true)
	return nil
}

// 选择安装目标分区
func chooseInstallTargetRoot() string {
	parts := disk.Findpart()
	if len(parts) > 0 {
		log.LogWrite(0, "[chooseInstallTargetRoot]选择未装系统分区：%s", parts[0])
		if nr, err := utils.NormalizeDrive(parts[0], 0); err == nil {
			return nr
		}
		return ""
	}
	drives, _ := disk.ListDrive()
	for _, d := range drives {
		if strings.HasPrefix(strings.ToUpper(d), "X:") {
			continue
		}
		if disk.GetDriveType(d) == driveFixed {
			log.LogWrite(0, "[chooseInstallTargetRoot]回退选择固定盘分区：%s", d)
			if nr, err := utils.NormalizeDrive(d, 0); err == nil {
				return nr
			}
			return ""
		}
	}
	return ""
}

// 列出除目标分区外的其他固定磁盘分区。
func otherInstallVolumes(targetRoot string) []string {
	drives, _ := disk.ListDrive()
	var out []string
	for _, d := range drives {
		root, _ := utils.NormalizeDrive(d, 0)
		if root == "" || strings.EqualFold(root, targetRoot) {
			continue
		}
		if disk.GetDriveType(root) == driveFixed {
			out = append(out, root)
		}
	}
	return out
}

// 安装完成后的文件处理。
func postInstallTasks(targetRoot, targetOS string) error {
	selfExe, err := os.Executable()
	if err != nil {
		return err
	}
	baseDir := filepath.Dir(selfExe)

	unattend := filepath.Join(baseDir, "tools", "win10.xml")
	if targetOS == targetWin7 {
		unattend = filepath.Join(baseDir, "tools", "win7.xml")
	}
	_ = file.Copy(unattend, filepath.Join(targetRoot, "Windows", "Panther", "Unattend.xml"), true, true)
	_ = file.Copy(filepath.Join(baseDir, "tools", "HEU_KMS_Activator.exe"), filepath.Join(targetRoot, "HEU_KMS_Activator.exe"), true, true)
	_, _ = tools.CreateShortcut(filepath.Join(targetRoot, "Users", "Public", "Desktop")+`\\`, "应用商店", "https://store.ttraw.com")
	log.LogWrite(0, "[postInstallTasks]已写入应答文件/激活工具/快捷方式")

	driveExe := filepath.Join(baseDir, "tools", "drive.exe")

	if utils.FileExists(driveExe) {
		_ = file.Copy(driveExe, filepath.Join(targetRoot, "drive.exe"), true, true)
	}
	log.LogWrite(0, "[postInstallTasks]驱动安装工具准备完成")
	return nil
}

// 格式化镜像索引信息用于日志输出。
func formatImageInfos(infos []D.ImageMeta) string {
	var parts []string
	for _, info := range infos {
		parts = append(parts, fmt.Sprintf("Index=%d Name=%s Desc=%s Edition=%s Flags=%s Arch=%s",
			info.Index, info.Name, info.Description, info.Edition, info.Flags, info.Arch))
	}
	return strings.Join(parts, " | ")
}

// 把 0~100 的子进度映射到总进度
func mapPct(base, span int32, pct float64) int32 {
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	return base + int32(pct*float64(span)/100.0+0.5)
}

type ProgressReporter struct {
	base, span int32
	uiEvery    time.Duration
	logEvery   time.Duration
	lastUI     time.Time
	lastLog    time.Time
	statusFmt  string
	logFmt     string
	enableLog  bool
}

func NewProgressReporter(base, span int32, uiEvery, logEvery time.Duration, statusFmt, logFmt string, enableLog bool) *ProgressReporter {
	return &ProgressReporter{
		base:      base,
		span:      span,
		uiEvery:   uiEvery,
		logEvery:  logEvery,
		statusFmt: statusFmt,
		logFmt:    logFmt,
		enableLog: enableLog,
	}
}

func (p *ProgressReporter) Update(pct float64, speedBytes int64) {
	now := time.Now()

	if p.uiEvery <= 0 {
		p.uiEvery = 200 * time.Millisecond
	}
	if p.lastUI.IsZero() || now.Sub(p.lastUI) >= p.uiEvery || pct >= 100 {
		uiSetStatus(fmt.Sprintf(p.statusFmt, pct, float64(speedBytes)/1024.0/1024.0))
		uiSetProgress(mapPct(p.base, p.span, pct))
		p.lastUI = now
	}

	if !p.enableLog {
		return
	}
	if p.logEvery <= 0 {
		p.logEvery = 1 * time.Second
	}
	if p.lastLog.IsZero() || now.Sub(p.lastLog) >= p.logEvery || pct >= 100 {
		log.LogWrite(0, p.logFmt, pct, float64(speedBytes)/1024.0/1024.0)
		p.lastLog = now
	}
}

// 统一重试执行器
func retryLoop(title string, fn func() error) bool {
	for attempt := 0; ; attempt++ {
		if err := fn(); err == nil {
			return true
		} else {
			log.LogWrite(0, "[retryLoop]%s失败：%v", title, err)
			time.Sleep(2 * time.Second)
			if attempt == 0 {
				log.LogWrite(0, "[retryLoop]%s失败，自动重试一次", title)
				continue
			}
			uiShowError("错误", title+"失败："+err.Error())
			os.Exit(-1)
			return false
		}
	}
}

func retryLoopWithResult[T any](title string, fn func() (T, error)) (T, bool) {
	var zero T
	for attempt := 0; ; attempt++ {
		v, err := fn()
		if err == nil {
			return v, true
		}
		log.LogWrite(0, "[retryLoop]%s失败：%v", title, err)
		time.Sleep(2 * time.Second)
		if attempt == 0 {
			log.LogWrite(0, "[retryLoop]%s失败，自动重试一次", title)
			continue
		}
		uiShowError("错误", title+"失败："+err.Error())
		os.Exit(-1)
		return zero, false
	}
}
