package main

import (
	"context"
	"crypto/md5"
	"fmt"
	"io"
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

// 根据物理内存大小判断期望架构：
// - <4GB 使用 32 位
// - >=4GB 使用 64 位
// - 获取失败默认 64 位
// - win11 强制 64 位
func desiredArch() string {
	version, _, _ := GetCurrentWinVersion()
	if version == 11 {
		return "64"
	}
	if systemArch() == "64" {
		return "64"
	}
	return "32"
}

// 从 UI 入口启动安装流程。
// 搜索/下载镜像
// 写入 restall_win.dat / restall_img.dat
// 准备 PE 并重启进入 PE
func StartInstall(target string) {
	win2()
	imgArch := desiredArch()
	peArch := systemArch()
	logWrite("开始重装流程，目标系统=%s，镜像期望架构=%s，PE架构=%s", target, imgArch, peArch)
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
		sysRoot, _ := NormalizeDrive(systemDriveRoot(), 0)
		imgRoot, _ := NormalizeDrive(imgPath, 2)
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
			freeBytes, err := GetFreeSize(r)
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
			dstDir := filepath.Join(bestRoot, "镜像")
			_ = os.MkdirAll(dstDir, 0o755)
			dstPath := filepath.Join(dstDir, filepath.Base(imgPath))

			logWrite("转移镜像到其它分区：%s -> %s", imgPath, dstPath)
			if err := Copy(imgPath, dstPath, true, true); err != nil {
				return err
			}
			if _, err := os.Stat(dstPath); err != nil {
				return err
			}
			if !strings.EqualFold(imgPath, dstPath) {
				if err := Remove(imgPath, false); err != nil {
					return err
				}
				logWrite("已删除原镜像：%s", imgPath)
			}
			imgPath = dstPath
			logWrite("镜像已转移到其它分区，更新路径：%s", imgPath)
			return nil
		}

		// 2) 没有其它固定盘卷（或空间不足）：创建 TEMP（未分配优先，最后才拆分 C）
		uiSetStatus("镜像在系统盘：正在创建TEMP分区并转移镜像...")
		tmpRoot, err := ensureTempVolumeForBytes(need)
		if err != nil {
			return err
		}
		dstDir := filepath.Join(tmpRoot, "镜像")
		_ = os.MkdirAll(dstDir, 0o755)
		dstPath := filepath.Join(dstDir, filepath.Base(imgPath))
		logWrite("转移镜像到TEMP：%s -> %s", imgPath, dstPath)
		if err := Copy(imgPath, dstPath, true, true); err != nil {
			return err
		}
		if _, err := os.Stat(dstPath); err != nil {
			return err
		}
		if !strings.EqualFold(imgPath, dstPath) {
			if err := Remove(imgPath, false); err != nil {
				return err
			}
			logWrite("已删除原镜像：%s", imgPath)
		}
		imgPath = dstPath
		logWrite("镜像已转移到TEMP，更新路径：%s", imgPath)
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
	logWrite("准备完成，重启进入PE")
	Message("准备进入pe,测试模式", "请查看日志确定无误后手动重启")
	//Shutdown(true)
}

// 优先本地找镜像，找不到再下载。
func findOrDownloadImage(target, arch string) (string, error) {
	local, _ := findLocalImage(target, arch)
	if local != "" {
		return local, nil
	}
	return downloadImage(target, arch)
}

// 在全盘搜索镜像并按目标系统/架构筛选。
// 规则：
// - 优先匹配目标系统（win7/win10/win11）
// - 架构优先与期望一致（32/64）
// - 若仅有 64 位则直接使用 64 位
func findLocalImage(target, arch string) (string, error) {
	imgs, err := Findimg()
	if err != nil {
		logWrite("全盘搜索镜像失败：%v", err)
		return "", err
	}
	if len(imgs) == 0 {
		logWrite("全盘未找到镜像")
		return "", fmt.Errorf("未找到本地镜像")
	}
	logWrite("搜索到镜像：%s", strings.Join(imgs, " | "))

	var matchTarget []string
	for _, p := range imgs {
		if targetMatchesImage(p, target) {
			matchTarget = append(matchTarget, p)
		}
	}
	if len(matchTarget) == 0 {
		matchTarget = imgs
	}

	filterByArch := func(paths []string, want string) []string {
		var out []string
		for _, p := range paths {
			a := imageArchHint(p)
			if a == "" || a == want {
				out = append(out, p)
			}
		}
		return out
	}

	byArch := filterByArch(matchTarget, arch)
	if len(byArch) == 0 && arch == "32" {
		byArch = filterByArch(matchTarget, "64")
	}
	if len(byArch) == 0 {
		byArch = matchTarget
	}
	logWrite("本地镜像筛选结果：%s", strings.Join(byArch, " | "))
	return byArch[0], nil
}

// 选择镜像下载盘符。
func chooseDownloadRoot() string {
	systemDrive := strings.ToUpper(os.Getenv("SystemDrive")) // "C:"
	parts := Findpart()

	// 多分区：直接用 Findpart
	if len(parts) > 1 {
		for _, p := range parts {
			if systemDrive == "" || !strings.EqualFold(strings.TrimSuffix(p, `\`), systemDrive) {
				return p
			}
		}
		return parts[0]
	}

	// 单分区或 Findpart 为空：优先用系统盘 C
	root := ""
	if systemDrive != "" {
		root = systemDrive + `\`
	} else {
		root = systemDriveRoot()
	}
	if nr, err := NormalizeDrive(root, 0); err == nil {
		root = nr
	}

	// 先尝试直接用 C
	if root != "" {
		if free, err := GetFreeSize(root); err == nil && free >= minImageBytes {
			return root
		}
		// 不够 -> 清理 -> 再试
		_ = ClearPartition("C")
		if free, err := GetFreeSize(root); err == nil && free >= minImageBytes {
			return root
		}
	}

	// 还不够：用未分配创建 TEMP
	tmp, err := ensureTempVolumeForBytes(minImageBytes)
	if err == nil && tmp != "" {
		return tmp
	}

	// 兜底
	drives, _ := ListDrive()
	for _, d := range drives {
		if systemDrive != "" && strings.EqualFold(strings.TrimSuffix(d, `\`), systemDrive) {
			continue
		}
		if GetDriveType(d) == driveFixed {
			return d
		}
	}
	if systemDrive != "" {
		return systemDrive + `\`
	}
	return ""
}

// 根据目标系统/架构下载镜像。
func downloadImage(target, arch string) (string, error) {
	ent, err := GetWinImgs(target)
	if err != nil {
		logWrite("获取镜像列表失败：%v", err)
		return "", err
	}

	candidates := filterWinImgsByArch(ent, arch)
	if len(candidates) == 0 && arch == "32" {
		candidates = filterWinImgsByArch(ent, "64")
	}
	if len(candidates) == 0 {
		candidates = ent
	}
	logWrite("可用镜像数量：%d", len(candidates))

	root := chooseDownloadRoot()
	if root == "" {
		logWrite("未找到可用下载分区")
		return "", fmt.Errorf("未找到可用下载分区")
	}
	dstDir := filepath.Join(root, "镜像")
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return "", err
	}

	var errs []string

	// =========================
	// URL 下载
	// =========================
	for _, it := range candidates {
		if !strings.EqualFold(strings.TrimSpace(it.Type), "url") {
			continue
		}
		links := []string{strings.TrimSpace(it.Link), strings.TrimSpace(it.Link2)}
		triedLink := false

		for _, link := range links {
			if link == "" || isFailedLink(link) {
				continue
			}
			if !httpStatus(link) {
				logWrite("URL链接不可用：%s", link)
				markFailedLink(link)
				continue
			}

			name := ImgName(it, link)
			if strings.TrimSpace(it.File) != "" {
				name = strings.TrimSpace(it.File)
			}
			dstPath := filepath.Join(dstDir, name)

			// 已存在则校验
			if st, err := os.Stat(dstPath); err == nil && !st.IsDir() && st.Size() > 0 {
				if err := validateImageFile(it, dstPath); err != nil {
					logWrite("镜像校验失败，删除重下：%s err=%v", dstPath, err)
					_ = Remove(dstPath, false)
				} else {
					logWrite("镜像已存在：%s", dstPath)
					uiSetProgress(60)
					return dstPath, nil
				}
			}
			if triedLink {
				_ = Remove(dstPath+".part", false)
			}

			_ = Remove(dstPath, false)
			triedLink = true
			uiSetProgress(0)
			uiSetStatus("正在下载镜像... 0.0% 速度: 0.00 MB/s")

			logWrite("开始下载镜像(URL)：%s -> %s", link, dstPath)

			pr := NewProgressReporter(
				0, 60,
				1*time.Second, 1*time.Second,
				"正在下载镜像... %.1f%% 速度: %.2f MB/s",
				"镜像下载进度：%.1f%% 速度: %.2f MB/s",
				true,
			)

			ctx, cancel := context.WithCancel(context.Background())
			err := DownloadFile(ctx, link, dstPath, func(pct float64, speed int64) {
				pr.Update(pct, speed)
			})
			cancel()

			if err == nil {
				if vErr := validateImageFile(it, dstPath); vErr != nil {
					markFailedLink(link)
					_ = Remove(dstPath, false)
					logWrite("镜像校验失败，删除重下：%s err=%v", dstPath, vErr)
					errs = append(errs, fmt.Sprintf("URL校验失败 link=%s err=%v", link, vErr))
					continue
				}
				logWrite("镜像下载完成：%s", dstPath)
				uiSetProgress(60)
				return dstPath, nil
			}

			markFailedLink(link)
			_ = Remove(dstPath, false)
			logWrite("镜像下载失败(URL)：link=%s err=%v", link, err)
			errs = append(errs, fmt.Sprintf("URL失败 link=%s err=%v", link, err))
		}
	}

	// =========================
	// BT 下载（返回真实落盘路径 realPath）
	// =========================
	for _, it := range candidates {
		if strings.EqualFold(strings.TrimSpace(it.Type), "url") {
			continue
		}

		link, lerr := ImgLink(it)
		if lerr != nil {
			errs = append(errs, fmt.Sprintf("BT取链接失败 file=%s err=%v", it.File, lerr))
			continue
		}
		link = strings.TrimSpace(link)
		if link == "" || isFailedLink(link) {
			continue
		}

		// 期望落在 dstDir 的“规范文件名”
		name := ImgName(it, link)
		if strings.TrimSpace(it.File) != "" {
			name = strings.TrimSpace(it.File)
		}
		dstPath := filepath.Join(dstDir, name)

		// 已存在则校验
		if st, err := os.Stat(dstPath); err == nil && !st.IsDir() && st.Size() > 0 {
			if err := validateImageFile(it, dstPath); err != nil {
				logWrite("镜像校验失败，删除重下：%s err=%v", dstPath, err)
				_ = Remove(dstPath, false)
			} else {
				logWrite("镜像已存在：%s", dstPath)
				uiSetProgress(60)
				return dstPath, nil
			}
		}

		logWrite("开始下载镜像(BT)：%s -> %s", link, dstDir)

		lastLog := time.Time{}
		lastUI := time.Time{}

		realPath, err := DownloadBT(link, dstDir, func(pct int, speed, done, total int64) {
			now := time.Now()
			if lastUI.IsZero() || now.Sub(lastUI) >= 1*time.Second || pct >= 100 {
				uiSetStatus(fmt.Sprintf("正在下载镜像... %d%% 速度: %.2f MB/s", pct, float64(speed)/1024/1024))
				uiSetProgress(mapPct(0, 60, float64(pct)))
				lastUI = now
			}
			if lastLog.IsZero() || now.Sub(lastLog) >= 1*time.Second || pct >= 100 {
				logWrite("BT下载进度：%d%% 速度: %.2f MB/s", pct, float64(speed)/1024/1024)
				lastLog = now
			}
		})

		if err == nil {
			finalPath := realPath

			// 如果 BT 真实落盘不等于你期望的 dstPath，就整理到 dstPath（更利于后续统一处理）
			if realPath != "" && !strings.EqualFold(realPath, dstPath) {
				_ = Remove(dstPath, false)

				// 同卷优先 rename（快且不占双份空间）
				if rErr := os.Rename(realPath, dstPath); rErr == nil {
					finalPath = dstPath
				} else {
					// rename 失败再 copy（跨卷/权限等）
					if cErr := Copy(realPath, dstPath, true, true); cErr == nil {
						finalPath = dstPath
						// copy 成功后可选择删除 realPath（可留作断点或日志，此处默认删除避免占空间）
						_ = Remove(realPath, false)
					} else {
						// 整理失败：至少还能用 realPath
						logWrite("BT下载后整理路径失败：real=%s dst=%s err=%v", realPath, dstPath, cErr)
						finalPath = realPath
					}
				}
			}

			// 校验用最终路径（realPath 或 dstPath）
			if vErr := validateImageFile(it, finalPath); vErr != nil {
				markFailedLink(link)
				_ = Remove(finalPath, false)
				logWrite("镜像校验失败，删除重下：%s err=%v", finalPath, vErr)
				errs = append(errs, fmt.Sprintf("BT校验失败 link=%s err=%v", link, vErr))
				continue
			}

			logWrite("镜像下载完成(BT)：%s", finalPath)
			uiSetProgress(60)
			return finalPath, nil
		}

		markFailedLink(link)
		logWrite("镜像下载失败(BT)：link=%s err=%v", link, err)
		errs = append(errs, fmt.Sprintf("BT失败 link=%s err=%v", link, err))
	}

	if len(errs) > 0 {
		return "", fmt.Errorf("全部镜像链接下载失败：%s", strings.Join(errs, " | "))
	}
	return "", fmt.Errorf("未找到可用镜像下载链接")
}

func validateImageFile(it WinImg, imagePath string) error {
	if strings.TrimSpace(it.SHA1) != "" {
		ok, got, err := CheckFileSHA1(imagePath, it.SHA1)
		if err != nil {
			return fmt.Errorf("SHA1校验失败: %w", err)
		}
		if !ok {
			return fmt.Errorf("SHA1不匹配: %s", got)
		}
		return nil
	}

	switch strings.ToLower(filepath.Ext(imagePath)) {
	case ".iso", ".wim", ".esd":
		if _, err := detectImageInfos(imagePath); err != nil {
			return fmt.Errorf("镜像损坏: %w", err)
		}
	}
	return nil
}

// 按架构过滤镜像列表。
func filterWinImgsByArch(ent []WinImg, arch string) []WinImg {
	arch = strings.TrimSpace(arch)
	if arch == "" {
		return ent
	}
	var out []WinImg
	for _, it := range ent {
		if strings.TrimSpace(it.Arch) == arch {
			out = append(out, it)
		}
	}
	return out
}

// 选择下载镜像与链接。
func pickWinImg(ent []WinImg) (WinImg, string, error) {
	if len(ent) == 0 {
		return WinImg{}, "", fmt.Errorf("未找到可用镜像")
	}
	var urlList []WinImg
	var btList []WinImg
	for _, it := range ent {
		if strings.EqualFold(strings.TrimSpace(it.Type), "url") {
			urlList = append(urlList, it)
		} else {
			btList = append(btList, it)
		}
	}

	tryURL := func(it WinImg) []string {
		var links []string
		link := strings.TrimSpace(it.Link)
		if link != "" {
			links = append(links, link)
		}
		link = strings.TrimSpace(it.Link2)
		if link != "" {
			links = append(links, link)
		}
		return links
	}

	for _, it := range urlList {
		links := tryURL(it)
		for _, link := range links {
			if isFailedLink(link) {
				continue
			}
			if httpStatus(link) {
				return it, link, nil
			}
		}
	}
	if len(urlList) > 0 {
		it := urlList[0]
		link := strings.TrimSpace(it.Link)
		if link == "" {
			link = strings.TrimSpace(it.Link2)
		}
		if link != "" {
			return it, link, nil
		}
	}
	if len(btList) > 0 {
		link, err := ImgLink(btList[0])
		return btList[0], link, err
	}
	link, err := ImgLink(ent[0])
	return ent[0], link, err
}

// 确保有可用 PE 引导文件，若无则下载 PE。
func ensurePEAndReboot(arch string) error {
	arch = strings.TrimSpace(arch)
	if arch == "" {
		arch = "64"
	}
	const maxAttempts = 3
	failedPEImages := map[string]struct{}{}

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		var (
			wimPath string
			sdiPath string
			peID    string
		)

		if attempt == 1 {
			found, wim, sdi, _ := GoToPE(true)
			if found && strings.TrimSpace(wim) != "" {
				wimPath = wim
				sdiPath = sdi
				logWrite("使用已有PE：%s", wimPath)
			}
		}

		if wimPath == "" {
			logWrite("未检测到PE文件，开始下载/准备PE")
			wp, id, err := downloadPE(arch, failedPEImages)
			if err != nil {
				logWrite("下载PE失败：%v", err)
				if attempt == maxAttempts {
					uiShowError("错误", fmt.Sprintf("进入PE失败：%v", err))
					os.Exit(-1)
				}
				continue
			}
			wimPath = wp
			peID = id
			sdiPath = resolveSdiPath(wimPath)
			logWrite("PE镜像准备完成：%s", wimPath)
		}
		if sdiPath == "" {
			sdiPath = resolveSdiPath(wimPath)
		}

		uiSetStatus("正在写入自身到PE...")
		logWrite("准备Patwim：%s", wimPath)

		if err := Patwim(wimPath); err != nil {
			logWrite("ensurePEAndReboot Patwim失败：%v", err)
			markFailedPEImage(failedPEImages, peID)
			removePEArtifacts(wimPath, sdiPath)
			if attempt == maxAttempts {
				uiShowError("错误", fmt.Sprintf("进入PE失败：%v", err))
				os.Exit(-1)
			}
			continue
		}
		logWrite("ensurePEAndReboot Patwim成功：%s", wimPath)

		uiSetStatus("正在设置下次启动进入PE...")
		logWrite("进入PE")
		logWrite(sdiPath + "===" + wimPath)

		if sdiPath == "" {
			if _, _, _, err := GoToPE(false); err != nil {
				logWrite("进入PE失败：%v", err)
				markFailedPEImage(failedPEImages, peID)
				removePEArtifacts(wimPath, sdiPath)
				if attempt == maxAttempts {
					uiShowError("错误", fmt.Sprintf("进入PE失败：%v", err))
					os.Exit(-1)
				}
				continue
			}
			return nil
		}

		if _, _, _, err := GoToPE(false, sdiPath, wimPath); err != nil {
			logWrite("进入PE失败：%v", err)
			markFailedPEImage(failedPEImages, peID)
			removePEArtifacts(wimPath, sdiPath)
			if attempt == maxAttempts {
				uiShowError("错误", fmt.Sprintf("进入PE失败：%v", err))
				os.Exit(-1)
			}
			continue
		}
		return nil
	}
	return fmt.Errorf("进入PE失败")
}

// 根据wim路径推测sdi路径
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
	if fileExists(sdi) {
		return sdi
	}
	if sdis, _ := FindFile(dir, "*.sdi|*.SDI", 1); len(sdis) > 0 {
		return sdis[0]
	}
	return ""
}

// 扫描当前磁盘是否已存在可用 PE 引导文件。
func hasPEFiles(arch string) (bool, string, string) {
	drives, err := ListDrive()
	if err != nil {
		logWrite("枚举盘符失败：%v", err)
		return false, "", ""
	}

	for _, d := range drives {
		wims, _ := FindFile(d, `PETEMP\*.wim|PETEMP\*.WIM`, 1)
		sdis, _ := FindFile(d, `PETEMP\*.sdi|PETEMP\*.SDI`, 1)
		if len(wims) > 0 {
			wim := chooseBestWim(wims, arch)
			sdi := ""
			if len(sdis) > 0 {
				sdi = sdis[0]
			}
			logWrite("发现PETEMP中的PE文件：wim=%s sdi=%s", wim, sdi)
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
			if fileExists(wp) {
				wimCands = append(wimCands, wp)
				if fileExists(sp) {
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

	bestWim := chooseBestWim(wimCands, arch)
	bestSdi := sdiMap[bestWim]
	logWrite("发现已有PE文件：wim=%s sdi=%s", bestWim, bestSdi)
	return true, bestWim, bestSdi
}

// 文件存在且不是目录。
func fileExists(path string) bool {
	if st, err := os.Stat(path); err == nil && !st.IsDir() {
		return true
	}
	return false
}

func systemDriveRoot() string {
	drive := strings.TrimSpace(os.Getenv("SystemDrive"))
	if drive == "" {
		windir := os.Getenv("SystemRoot")
		if windir == "" {
			windir = os.Getenv("WINDIR")
		}
		if windir != "" {
			drive = filepath.VolumeName(windir)
		}
	}
	drive = strings.TrimSpace(drive)
	if drive == "" {
		return ""
	}
	drive = strings.TrimRight(drive, `\`)
	if strings.HasSuffix(drive, ":") {
		return drive + `\`
	}
	if len(drive) == 1 {
		return strings.ToUpper(drive) + `:\`
	}
	if vol := filepath.VolumeName(drive); vol != "" {
		return vol + `\`
	}
	return ""
}

// IsWePE 检测当前运行环境是否为微PE。
// 规则：系统盘的 Program Files 下存在 WepeGuide 目录则视为微PE。
func IsWePE() bool {
	root := systemDriveRoot()
	if root == "" {
		return false
	}
	wepeDir := filepath.Join(root, "Program Files", "WepeGuide")
	if st, err := os.Stat(wepeDir); err == nil && st.IsDir() {
		return true
	}
	return false
}

// 选择 PETEMP 所在盘符。
func choosePETempRoot(needBytes int64) (string, error) {
	systemDrive := strings.ToUpper(os.Getenv("SystemDrive"))
	if systemDrive != "" {
		free, err := GetFreeSize(systemDrive)
		if err == nil && int64(free) > needBytes {
			logWrite("PETEMP使用系统盘：%s", systemDrive)
			return systemDrive + `\`, nil
		}
	}
	parts := Findpart()
	if len(parts) > 0 {
		for _, p := range parts {
			free, err := GetFreeSize(p)
			if err == nil && int64(free) > needBytes {
				logWrite("PETEMP使用分区：%s", p)
				return p, nil
			}
		}
	}
	if systemDrive != "" {
		return systemDrive + `\`, nil
	}
	return "", fmt.Errorf("未找到可用分区")
}

// 创建指定目录
func ensureCleanDir(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	logWrite("准备PETEMP目录：%s", dir)
	return nil
}

// 下载 PE 镜像
const peLinksID = "pe_links"

func peImageID(it WinPEImg) string {
	parts := []string{
		strings.TrimSpace(it.Grp),
		strings.TrimSpace(it.Ver),
		strings.TrimSpace(it.Arch),
	}
	links := strings.Join(it.Links, "|")
	parts = append(parts, strings.TrimSpace(links))
	return strings.Join(parts, "|")
}

func markFailedPEImage(failed map[string]struct{}, id string) {
	if id == "" {
		return
	}
	failed[id] = struct{}{}
}

func removePEArtifacts(wimPath, sdiPath string) {
	if strings.TrimSpace(wimPath) != "" {
		_ = Remove(wimPath, false)
		if strings.Contains(strings.ToLower(wimPath), `\petemp\`) {
			_ = Remove(filepath.Dir(wimPath), true)
		}
	}
	if strings.TrimSpace(sdiPath) != "" {
		_ = Remove(sdiPath, false)
	}
}

func downloadPE(arch string, failedPEImages map[string]struct{}) (string, string, error) {
	arch = strings.TrimSpace(arch)
	if arch == "" {
		arch = "64"
	}
	if failedPEImages == nil {
		failedPEImages = map[string]struct{}{}
	}
	logWrite("下载PE，目标架构=%s", arch)

	peList, err := GetWinPE()
	if err != nil {
		logWrite("获取PE列表失败：%v", err)
		return "", "", err
	}

	var other []WinPEImg
	other = peList

	findByArch := func(list []WinPEImg, want string) []WinPEImg {
		var out []WinPEImg
		for _, it := range list {
			if strings.TrimSpace(it.Arch) == want {
				out = append(out, it)
			}
		}
		return out
	}

	// 尝试下载一个 PE 镜像
	tryDownload := func(it WinPEImg) (string, string, error) {
		id := peImageID(it)
		if id != "" {
			if _, ok := failedPEImages[id]; ok {
				return "", id, fmt.Errorf("PE已标记失败: %s", id)
			}
		}
		if len(it.Links) == 0 {
			return "", id, fmt.Errorf("PE链接为空")
		}

		triedLink := false
		for _, link := range it.Links {
			link = strings.TrimSpace(link)
			if link == "" {
				continue
			}
			if isFailedLink(link) {
				continue
			}
			if !httpStatus(link) {
				logWrite("PE链接不可用：%s", link)
				markFailedLink(link)
				continue
			}

			needBytes := int64(it.Sz * 1024 * 1024)
			root, err := choosePETempRoot(needBytes * 2)
			if err != nil {
				return "", id, err
			}
			peDir := filepath.Join(root, "PETEMP")
			if err := ensureCleanDir(peDir); err != nil {
				return "", id, err
			}

			wimPath := filepath.Join(peDir, "boot.wim")

			pr := NewProgressReporter(
				70, 25,
				1*time.Second, 1*time.Second,
				"正在下载PE... %.1f%% 速度: %.2f MB/s",
				"PE下载进度：%.1f%% 速度: %.2f MB/s",
				true,
			)

			if strings.HasSuffix(strings.ToLower(link), ".exe") && it.OffsetEnd > it.OffsetStart {
				exeName := linkBaseName(link)
				if exeName == "" {
					exeName = "wepe.exe"
				}
				exePath := filepath.Join(peDir, exeName)

				useExisting := false
				if fileExists(exePath) {
					if strings.TrimSpace(it.MD5) != "" {
						ok, merr := matchMD5(exePath, it.MD5)
						if merr == nil && ok {
							logWrite("复用已存在WEPE安装包：%s", exePath)
							useExisting = true
						} else {
							logWrite("已存在WEPE安装包MD5不匹配，删除重下：%s", exePath)
							_ = Remove(exePath, false)
						}
					} else {
						logWrite("复用已存在WEPE安装包(无MD5)：%s", exePath)
						useExisting = true
					}
				}

				// 下载
				if !useExisting {
					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
					err := DownloadFile(ctx, link, exePath, func(pct float64, speed int64) {
						pr.Update(pct, speed)
					})
					cancel()

					if err != nil {
						markFailedLink(link)
						logWrite("PE下载失败：%v", err)
						_ = Remove(exePath, false)
						continue
					}

					// 下载后校验 MD5
					if strings.TrimSpace(it.MD5) != "" {
						ok, merr := matchMD5(exePath, it.MD5)
						if merr != nil || !ok {
							markFailedLink(link)
							logWrite("PE下载后MD5校验失败：%s", exePath)
							_ = Remove(exePath, false)
							continue
						}
					}
				}

				// 从 exe 抽 WIM
				if err := PeelFile(exePath, fmt.Sprintf("%d", it.OffsetStart), fmt.Sprintf("%d", it.OffsetEnd), wimPath); err != nil {
					markFailedLink(link)
					logWrite("PE解包失败：%v", err)
					continue
				}

			} else {
				if triedLink {
					_ = Remove(wimPath+".part", false) // ✅切换链接清理
				}
				triedLink = true
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
				err := DownloadFile(ctx, link, wimPath, func(pct float64, speed int64) {
					pr.Update(pct, speed)
				})
				cancel()

				if err != nil {
					markFailedLink(link)
					logWrite("PE下载失败：%v", err)
					_ = Remove(wimPath, false)
					continue
				}
			}

			if err := copySDIToPETEMP(peDir); err != nil {
				return "", id, err
			}
			return wimPath, id, nil
		}

		return "", id, fmt.Errorf("PE下载失败")
	}
	//WinPE.json
	for _, it := range findByArch(other, arch) {
		if wim, id, err := tryDownload(it); err == nil {
			return wim, id, nil
		}
	}
	if arch == "32" {
		for _, it := range findByArch(other, "64") {
			if wim, id, err := tryDownload(it); err == nil {
				return wim, id, nil
			}
		}
	}
	// PEDownload.html
	if _, _, links, err := PELnk(); err == nil {
		if _, ok := failedPEImages[peLinksID]; !ok {
			if wim, err := downloadPEFromLinks(links); err == nil {
				return wim, peLinksID, nil
			}
		}
	}

	return "", "", fmt.Errorf("未找到可用PE")
}

// 使用 PEDownload.html 的链接下载 PE。
func downloadPEFromLinks(links []string) (string, error) {
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
		return "", fmt.Errorf("PE链接为空")
	}

	root, err := choosePETempRoot(1024 * 1024 * 1024)
	if err != nil {
		return "", err
	}
	peDir := filepath.Join(root, "PETEMP")
	if err := ensureCleanDir(peDir); err != nil {
		return "", err
	}

	wimPath := filepath.Join(peDir, "boot.wim")

	pr := NewProgressReporter(
		70, 25,
		1*time.Second, 1*time.Second,
		"正在下载PE... %.1f%% 速度: %.2f MB/s",
		"PE下载进度：%.1f%% 速度: %.2f MB/s",
		true,
	)

	triedLink := false
	for _, link := range out {
		if !httpStatus(link) {
			logWrite("PE链接不可用：%s", link)
			continue
		}
		logWrite("PE链接：%s\n", link)

		if triedLink {
			_ = Remove(wimPath+".part", false)
		}
		triedLink = true

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
		err := DownloadFile(ctx, link, wimPath, func(pct float64, speed int64) {
			pr.Update(pct, speed)
		})
		cancel()

		if err != nil {
			markFailedLink(link)
			logWrite("PE下载失败：%v,url:"+link, err)
			_ = Remove(wimPath, false)
			continue
		}

		if err := copySDIToPETEMP(peDir); err != nil {
			return "", err
		}
		return wimPath, nil
	}

	return "", fmt.Errorf("PE下载失败")
}

// 复制 tools 目录下的 SDI 文件到 PETEMP。
func copySDIToPETEMP(peDir string) error {
	selfExe, err := os.Executable()
	if err != nil {
		return err
	}
	toolsDir := filepath.Join(filepath.Dir(selfExe), "tools")
	sdiFiles, _ := FindFile(toolsDir, "*.sdi|*.SDI", 1)
	if len(sdiFiles) == 0 {
		return fmt.Errorf("未找到SDI文件")
	}
	for _, sdi := range sdiFiles {
		dst := filepath.Join(peDir, filepath.Base(sdi))
		if err := Copy(sdi, dst, true, true); err != nil {
			return err
		}
	}
	logWrite("已复制SDI文件到PETEMP：%s", peDir)
	return nil
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
	logWrite("本地WEPE搜索目录：%s", strings.Join(searchDirs, " | "))
	for _, dir := range searchDirs {
		if dir == "" {
			continue
		}
		for _, it := range all {
			candPath := filepath.Join(dir, it.name)
			if !fileExists(candPath) {
				continue
			}
			if strings.TrimSpace(it.img.MD5) != "" {
				ok, err := matchMD5(candPath, it.img.MD5)
				if err != nil || !ok {
					logWrite("WEPE MD5 校验失败：%s", candPath)
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
				if err := PeelFile(candPath, fmt.Sprintf("%d", it.img.OffsetStart), fmt.Sprintf("%d", it.img.OffsetEnd), wimPath); err != nil {
					continue
				}
			} else {
				if err := Copy(candPath, wimPath, true, true); err != nil {
					continue
				}
			}
			if err := copySDIToPETEMP(peDir); err != nil {
				return "", err
			}
			logWrite("本地WEPE准备完成：%s", wimPath)
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
	drives, _ := ListDrive()
	for _, d := range drives {
		out = append(out, filepath.Join(d, "PETEMP"))
	}
	return out
}

// 计算文件 MD5 并与期望值比较。
func matchMD5(path, expect string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return false, err
	}
	got := fmt.Sprintf("%x", h.Sum(nil))
	return strings.EqualFold(strings.TrimSpace(got), strings.TrimSpace(expect)), nil
}

// RunPEInstall：在 PE 模式执行安装流程。
// 1) 读取 restall_win.dat，定位镜像
// 2) 若失败则本地搜索镜像，再失败则下载 Win10
// 3) 处理“镜像在 C 盘”场景，必要时分区转移镜像
// 4) 格式化目标分区并应用镜像
// 5) 修复引导 + 安装后文件处理
// 6) 若创建临时分区，安装完成后合并回 C 盘
func RunPEInstall() error {
	uiSetProgress(0)
	uiSetStatus("正在读取重装信息...")
	logWrite("进入PE安装流程")
	isWePE := IsWePE()
	if isWePE {
		logWrite("检测到微PE环境，使用非EX的分区工具调用")
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
					logWrite(logFmt, v)
					lastLog = now
				}
			}
		}
	}

	targetRoot, diskPath, imagePath, volumeGuid, diskUniqueID, imageRel, savedTarget, savedArch, savedIndex, err := loadResData()
	if err != nil {
		logWrite("读取重装信息失败：%v", err)
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
		logWrite("尝试本地搜索镜像")
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
		logWrite("本地无镜像，尝试下载Win10")
		if dl, derr := downloadImage(t, a); derr == nil {
			imagePath = dl
		} else {
			return fmt.Errorf("未找到镜像且下载失败: %w", derr)
		}
	}
	logWrite("最终使用镜像：%s", imagePath)

	if targetRoot == "" {
		targetRoot = chooseInstallTargetRoot()
		if targetRoot == "" {
			return fmt.Errorf("未找到可用系统分区")
		}
	}
	logWrite("目标分区：%s", targetRoot)

	uiSetProgress(10)
	uiSetStatus("正在准备分区...")

	tempVol := ""
	if nr, err := NormalizeDrive(targetRoot, 0); err == nil {
		targetRoot = nr
	}
	imagePath = strings.TrimSpace(imagePath)

	imageRoot, _ := NormalizeDrive(imagePath, 2)
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
			altRoot, _ := NormalizeDrive(v, 0)
			if altRoot == "" {
				continue
			}
			if strings.EqualFold(altRoot, targetRoot) {
				continue
			}
			if strings.EqualFold(altRoot, "X:\\") || strings.EqualFold(strings.TrimRight(altRoot, `\`), "X:") {
				continue
			}
			if GetDriveType(altRoot) != driveFixed {
				continue
			}

			freeBytes, ferr := GetFreeSize(altRoot)
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

			logWrite("镜像在目标分区上，尝试复制到其它卷：%s -> %s", imagePath, dstPath)
			if err := Copy(imagePath, dstPath, true, true); err != nil {
				moveErrs = append(moveErrs, fmt.Sprintf("%s Copy失败:%v", altRoot, err))
				_ = Remove(dstPath, false)
				continue
			}

			if dfi, derr := os.Stat(dstPath); derr != nil || dfi.Size() <= 0 {
				moveErrs = append(moveErrs, fmt.Sprintf("%s 复制后校验失败:%v", altRoot, derr))
				_ = Remove(dstPath, false)
				continue
			}

			imagePath = dstPath
			moved = true
			logWrite("已将镜像复制到其它卷并更新路径：%s", imagePath)
			break
		}

		if !moved {
			if len(moveErrs) > 0 {
				logWrite("复制到其它卷失败/不可用，原因：%s", strings.Join(moveErrs, " | "))
			} else {
				logWrite("无可用其它卷用于复制镜像，准备拆分TEMP分区")
			}

			sizeMB := int((int64(imageBytes) + 512*1024*1024) / (1024 * 1024))
			if sizeMB < 1024 {
				sizeMB = 1024
			}

			splitCb := progressHandler(10, 5, "正在拆分分区... %d%%", "拆分分区进度：%d%%")
			var newVol string
			splitCb(0)
			newVol, err = SplitVolume(targetRoot, sizeMB, "ntfs", "TEMP")
			if err != nil {
				return err
			}
			splitCb(100)
			uiSetProgress(15)
			if nr, err := NormalizeDrive(newVol, 0); err == nil {
				tempVol = nr
			}

			newPath := filepath.Join(tempVol, filepath.Base(imagePath))
			logWrite("仅能拆分分区保存镜像：%s -> %s", imagePath, newPath)

			if err := Copy(imagePath, newPath, true, true); err != nil {
				return err
			}
			if _, err := os.Stat(newPath); err != nil {
				return err
			}
			imagePath = newPath
			logWrite("已拆分TEMP并复制镜像，更新镜像路径：%s", imagePath)
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
	err = Format(strings.ReplaceAll(strings.ReplaceAll(targetRoot, "\\", ""), ":", ""), "ntfs", "Windows", true)
	if err == nil {
		formatCb(100)
	}
	if err != nil {
		logWrite("格式化失败: %v", err)
	}
	logWrite("格式化完成：%s", targetRoot)

	uiSetProgress(20)
	uiSetStatus("正在解析镜像...")
	infos, err := detectImageInfos(imagePath)
	index := 1
	if savedIndex > 0 {
		index = savedIndex
	} else if err == nil {
		index = selectInstallIndex(infos)
		logWrite("镜像索引列表：%s", formatImageInfos(infos))
	}
	logWrite("选择镜像索引：%d", index)

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
			logWrite("应用镜像进度：phase=%s pct=%.1f", phase, pct)
			lastLog = now
		}
	}

	switch strings.ToLower(filepath.Ext(imagePath)) {
	case ".esd":
		if err := ApplyEsdImage(imagePath, index, targetRoot); err != nil {
			logWrite("flow ApplyEsdImage1失败" + err.Error())
		}
	case ".wim":
		if err := ApplyWimImage(imagePath, index, targetRoot); err != nil {
			logWrite("flow ApplyWimImage2失败" + err.Error())
		}
	case ".iso":
		if err := ApplyISOImage(imagePath, index, targetRoot); err != nil {
			logWrite("flow ApplyISOImage3失败" + err.Error())
		}
	default:
		return fmt.Errorf("不支持的镜像类型: %s", imagePath)
	}

	uiSetProgress(85)
	uiSetStatus("正在修复引导...")
	if err := FixBoot(targetRoot, "", "zh-cn"); err != nil {
		return err
	}
	logWrite("引导修复完成")

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
	logWrite("安装后处理完成")

	// 如果不是 PE 内创建的 tempVol，尝试通过 marker 找到我们创建的 TEMP 分区
	if tempVol == "" {
		if mr := findTempRootByMarker(); mr != "" {
			if nr, err := NormalizeDrive(mr, 0); err == nil {
				mr = nr
			}
			if mr != "" && !strings.EqualFold(mr, targetRoot) {
				tempVol = mr
				logWrite("通过 marker 找到 TEMP 分区：%s", tempVol)
			}
		}
	}

	if tempVol != "" {
		deleteCb := progressHandler(85, 5, "正在删除临时分区... %d%%", "删除临时分区进度：%d%%")
		deleteCb(0)
		if err := DeleteVolume(tempVol); err != nil {
			logWrite("删除临时分区失败：%v", err)
		} else {
			deleteCb(100)
		}

		mergeCb := progressHandler(90, 5, "正在合并临时分区... %d%%", "合并临时分区进度：%d%%")
		mergeCb(0)
		if err := MergeVolume(targetRoot, 0); err != nil {
			logWrite("合并临时分区失败：%v", err)
		} else {
			mergeCb(100)
			logWrite("已合并临时分区回系统分区：%s", targetRoot)
		}
	}

	uiSetStatus("安装完成，正在重启...")
	uiSetProgress(100)
	logWrite("PE安装流程完成，准备重启")
	Message("安装完成,测试模式", "请查看日志确定无误后手动重启")
	//Shutdown(true)
	return nil
}

// 选择安装目标分区
func chooseInstallTargetRoot() string {
	parts := Findpart()
	if len(parts) > 0 {
		logWrite("选择未装系统分区：%s", parts[0])
		if nr, err := NormalizeDrive(parts[0], 0); err == nil {
			return nr
		}
		return ""
	}
	drives, _ := ListDrive()
	for _, d := range drives {
		if strings.HasPrefix(strings.ToUpper(d), "X:") {
			continue
		}
		if GetDriveType(d) == driveFixed {
			logWrite("回退选择固定盘分区：%s", d)
			if nr, err := NormalizeDrive(d, 0); err == nil {
				return nr
			}
			return ""
		}
	}
	return ""
}

// 列出除目标分区外的其他固定磁盘分区。
func otherInstallVolumes(targetRoot string) []string {
	drives, _ := ListDrive()
	var out []string
	for _, d := range drives {
		root, _ := NormalizeDrive(d, 0)
		if root == "" || strings.EqualFold(root, targetRoot) {
			continue
		}
		if GetDriveType(root) == driveFixed {
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
	_ = Copy(unattend, filepath.Join(targetRoot, "Windows", "Panther", "Unattend.xml"), true, true)
	_ = Copy(filepath.Join(baseDir, "tools", "HEU_KMS_Activator.exe"), filepath.Join(targetRoot, "HEU_KMS_Activator.exe"), true, true)
	_, _ = CreateShortcut(filepath.Join(targetRoot, "Users", "Public", "Desktop")+`\\`, "应用商店", "https://store.ttraw.com")
	logWrite("已写入应答文件/激活工具/快捷方式")

	driveExe := filepath.Join(baseDir, "tools", "drive.exe")

	if fileExists(driveExe) {
		_ = Copy(driveExe, filepath.Join(targetRoot, "drive.exe"), true, true)
	}
	logWrite("驱动安装工具准备完成")
	return nil
}

// 格式化镜像索引信息用于日志输出。
func formatImageInfos(infos []ImageMeta) string {
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

// 取下载链接的文件名
func linkBaseName(link string) string {
	raw := strings.TrimSpace(link)
	if raw == "" {
		return ""
	}
	raw = strings.SplitN(raw, "?", 2)[0]
	base := filepath.Base(raw)
	if base == "" || base == "." || base == "/" {
		return ""
	}
	return base
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
		logWrite(p.logFmt, pct, float64(speedBytes)/1024.0/1024.0)
		p.lastLog = now
	}
}

// 统一重试执行器
func retryLoop(title string, fn func() error) bool {
	for attempt := 0; ; attempt++ {
		if err := fn(); err == nil {
			return true
		} else {
			logWrite("%s失败：%v", title, err)
			time.Sleep(2 * time.Second)
			if attempt == 0 {
				logWrite("%s失败，自动重试一次", title)
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
		logWrite("%s失败：%v", title, err)
		time.Sleep(2 * time.Second)
		if attempt == 0 {
			logWrite("%s失败，自动重试一次", title)
			continue
		}
		uiShowError("错误", title+"失败："+err.Error())
		os.Exit(-1)
		return zero, false
	}
}
