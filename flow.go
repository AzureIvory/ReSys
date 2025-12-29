package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/twgh/xcgui/app"
)

// 目标系统常量：用于按钮入口与镜像筛选的统一标识。
const (
	targetWin7  = "win7"
	targetWin10 = "win10"
	targetWin11 = "win11"
)

// UI：更新状态文本（线程安全，走 UI 线程）。
func uiSetStatus(text string) {
	if text_des == nil || w == nil {
		return
	}
	app.CallUT(func() {
		text_des.SetText(text)
		text_des.Redraw()
		w.Redraw(false)
	})
}

// UI：更新进度条（线程安全，走 UI 线程）。
func uiSetProgress(pos int32) {
	if progbar == nil || w == nil {
		return
	}
	app.CallUT(func() {
		progbar.SetPos(pos)
		progbar.Redraw(false)
		w.Redraw(false)
	})
}

// UI：显示错误消息框（线程安全，走 UI 线程）。
func uiShowError(title, text string) {
	if w == nil {
		return
	}
	app.CallUT(func() {
		Message(w, title, text)
	})
}

// 根据物理内存大小判断期望架构：
// - <4GB 使用 32 位
// - >=4GB 使用 64 位
// - 获取失败默认 64 位
func desiredArch() string {
	mem, err := GetMemory()
	if err != nil {
		return "64"
	}
	if mem < 4 {
		return "32"
	}
	return "64"
}

// StartInstall：从 UI 入口启动安装流程。
// 负责：
// 1) 搜索/下载镜像
// 2) 写入 restall_win.dat / restall_img.dat
// 3) 准备 PE 并重启进入 PE
func StartInstall(target string) {
	win2()

	arch := desiredArch()
	uiSetProgress(0)
	uiSetStatus("正在寻找镜像...")

	imgPath, err := findOrDownloadImage(target, arch)
	if err != nil {
		uiShowError("错误", "镜像准备失败："+err.Error())
		return
	}
	uiSetProgress(20)
	uiSetStatus("正在写入重装信息...")
	if err := writeResFile(imgPath); err != nil {
		uiShowError("错误", "写入重装信息失败："+err.Error())
		return
	}

	uiSetProgress(30)
	uiSetStatus("正在准备PE环境...")
	if err := ensurePEAndReboot(arch); err != nil {
		uiShowError("错误", "准备PE失败："+err.Error())
		return
	}
	uiSetProgress(100)
	uiSetStatus("即将重启进入PE...")
	Shutdown(true)
}

// findOrDownloadImage：优先本地找镜像，找不到再下载。
func findOrDownloadImage(target, arch string) (string, error) {
	local, _ := findLocalImage(target, arch)
	if local != "" {
		return local, nil
	}
	return downloadImage(target, arch)
}

// findLocalImage：在全盘搜索镜像并按目标系统/架构筛选。
// 规则：
// - 优先匹配目标系统（win7/win10/win11）
// - 架构优先与期望一致（32/64）
// - 若仅有 64 位则直接使用 64 位
func findLocalImage(target, arch string) (string, error) {
	imgs, err := Findimg()
	if err != nil {
		return "", err
	}
	if len(imgs) == 0 {
		return "", fmt.Errorf("未找到本地镜像")
	}

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
	return byArch[0], nil
}

// imageArchHint：尝试从镜像元数据推测架构，失败再从文件名推测。
func imageArchHint(imagePath string) string {
	infos, err := detectImageInfos(imagePath)
	if err == nil {
		for _, info := range infos {
			arch := strings.ToLower(info.Arch)
			switch {
			case strings.Contains(arch, "x64"), strings.Contains(arch, "amd64"), strings.Contains(arch, "64"):
				return "64"
			case strings.Contains(arch, "x86"), strings.Contains(arch, "32"):
				return "32"
			}
		}
	}
	name := strings.ToLower(imagePath)
	if strings.Contains(name, "x64") || strings.Contains(name, "amd64") || strings.Contains(name, "64") {
		return "64"
	}
	if strings.Contains(name, "x86") || strings.Contains(name, "32") {
		return "32"
	}
	return ""
}

// targetMatchesImage：判断镜像是否匹配目标系统（win7/win10/win11）。
func targetMatchesImage(imagePath, target string) bool {
	target = strings.ToLower(strings.TrimSpace(target))
	if target == "" {
		return true
	}
	infos, err := detectImageInfos(imagePath)
	if err == nil {
		if t := detectTargetFromInfos(infos); t != "" {
			return t == target
		}
	}
	name := strings.ToLower(imagePath)
	switch target {
	case targetWin7:
		return strings.Contains(name, "win7") || strings.Contains(name, "windows 7")
	case targetWin10:
		return strings.Contains(name, "win10") || strings.Contains(name, "windows 10")
	case targetWin11:
		return strings.Contains(name, "win11") || strings.Contains(name, "windows 11")
	default:
		return true
	}
}

// detectTargetFromInfos：从镜像元信息中推测目标系统类型。
func detectTargetFromInfos(infos []ImageMeta) string {
	if len(infos) == 0 {
		return ""
	}
	var b strings.Builder
	for _, info := range infos {
		b.WriteString(info.Name)
		b.WriteString(" ")
		b.WriteString(info.Description)
		b.WriteString(" ")
		b.WriteString(info.Edition)
		b.WriteString(" ")
		b.WriteString(info.Flags)
		b.WriteString(" ")
	}
	s := strings.ToLower(b.String())
	switch {
	case strings.Contains(s, "windows 7") || strings.Contains(s, "win7"):
		return targetWin7
	case strings.Contains(s, "windows 11") || strings.Contains(s, "win11"):
		return targetWin11
	case strings.Contains(s, "windows 10") || strings.Contains(s, "win10"):
		return targetWin10
	default:
		return ""
	}
}

// chooseDownloadRoot：选择镜像下载盘符。
// 优先使用 Findpart() 的盘符，并尽量避开 C 盘。
func chooseDownloadRoot() string {
	systemDrive := strings.ToUpper(os.Getenv("SystemDrive"))
	parts := Findpart()
	if len(parts) > 0 {
		for _, p := range parts {
			if systemDrive == "" || !strings.EqualFold(strings.TrimSuffix(p, `\`), systemDrive) {
				return p
			}
		}
		return parts[0]
	}
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

// downloadImage：根据目标系统/架构下载镜像。
// 优先 URL 直链，失败再用 BT。
func downloadImage(target, arch string) (string, error) {
	ent, err := GetWinImgs(target)
	if err != nil {
		return "", err
	}

	candidates := filterWinImgsByArch(ent, arch)
	if len(candidates) == 0 && arch == "32" {
		candidates = filterWinImgsByArch(ent, "64")
	}
	if len(candidates) == 0 {
		candidates = ent
	}

	it, link, err := pickWinImg(candidates)
	if err != nil {
		return "", err
	}

	root := chooseDownloadRoot()
	if root == "" {
		return "", fmt.Errorf("未找到可用下载分区")
	}
	dstDir := filepath.Join(root, "镜像")
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return "", err
	}
	name := ImgName(it, link)
	if strings.TrimSpace(it.File) != "" {
		name = strings.TrimSpace(it.File)
	}
	dstPath := filepath.Join(dstDir, name)

	if st, err := os.Stat(dstPath); err == nil && !st.IsDir() && st.Size() > 0 {
		return dstPath, nil
	}

	if strings.EqualFold(strings.TrimSpace(it.Type), "url") {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		err = DownloadFile(ctx, link, dstPath, func(pct float64) {
			uiSetStatus(fmt.Sprintf("正在下载镜像... %.1f%%", pct))
			uiSetProgress(int32(pct))
		})
	} else {
		err = DownloadBT(link, dstDir, func(pct int, speed, done, total int64) {
			uiSetStatus(fmt.Sprintf("正在下载镜像... %d%%", pct))
			uiSetProgress(int32(pct))
		})
	}
	if err != nil {
		return "", err
	}
	return dstPath, nil
}

// filterWinImgsByArch：按架构过滤镜像列表。
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

// pickWinImg：选择下载镜像与链接。
// 规则：
// - URL 直链优先（先 Link，再 Link2）
// - URL 不可用再退回 BT
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

	tryURL := func(it WinImg) (string, bool) {
		link := strings.TrimSpace(it.Link)
		if link != "" && httpStatus(link) {
			return link, true
		}
		link = strings.TrimSpace(it.Link2)
		if link != "" && httpStatus(link) {
			return link, true
		}
		return "", false
	}

	for _, it := range urlList {
		if link, ok := tryURL(it); ok {
			return it, link, nil
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

// ensurePEAndReboot：确保有可用 PE 引导文件，若无则下载 PE。
// 下载后会写入自身到 WIM 并修改 Pecmd.ini，最后设置下次启动进入 PE。
func ensurePEAndReboot(arch string) error {
	if hasPEFiles() {
		return GoToPE()
	}
	wimPath, err := downloadPE(arch)
	if err != nil {
		return err
	}
	if err := Patwim(wimPath); err != nil {
		return err
	}
	return GoToPE()
}

// hasPEFiles：扫描当前磁盘是否已存在可用 PE 引导文件。
func hasPEFiles() bool {
	drives, err := ListDrive()
	if err != nil {
		return false
	}
	type pair struct {
		sdi string
		wim string
	}
	opts := []pair{
		{`WEPE\WEPE.SDI`, `WEPE\WEPE64.WIM`},
		{`FirPE\BOOT.SDI`, `FirPE\11PEX64.WIM`},
		{`HotPE\boot.sdi`, `HotPE\Boot.wim`},
		{`boot\boot.sdi`, `boot\11pex64.wim`},
		{`PETEMP`, `PETEMP`},
	}
	for _, d := range drives {
		for _, o := range opts {
			if o.sdi == "PETEMP" && o.wim == "PETEMP" {
				sdi, _ := FindFile(d, `PETEMP\*.sdi|PETEMP\*.SDI`, 1)
				wim, _ := FindFile(d, `PETEMP\*.wim|PETEMP\*.WIM`, 1)
				if len(sdi) > 0 && len(wim) > 0 {
					return true
				}
				continue
			}
			if fileExists(filepath.Join(d, o.sdi)) && fileExists(filepath.Join(d, o.wim)) {
				return true
			}
		}
	}
	return false
}

// fileExists：文件存在且不是目录。
func fileExists(path string) bool {
	if st, err := os.Stat(path); err == nil && !st.IsDir() {
		return true
	}
	return false
}

// choosePETempRoot：选择 PETEMP 所在盘符。
// 优先 C 盘空间足够，否则选择 Findpart() 的盘符。
func choosePETempRoot(needBytes int64) (string, error) {
	systemDrive := strings.ToUpper(os.Getenv("SystemDrive"))
	if systemDrive != "" {
		free, err := GetFreeSize(systemDrive)
		if err == nil && int64(free) > needBytes {
			return systemDrive + `\`, nil
		}
	}
	parts := Findpart()
	if len(parts) > 0 {
		for _, p := range parts {
			free, err := GetFreeSize(p)
			if err == nil && int64(free) > needBytes {
				return p, nil
			}
		}
	}
	if systemDrive != "" {
		return systemDrive + `\`, nil
	}
	return "", fmt.Errorf("未找到可用分区")
}

// ensureCleanDir：创建并清空指定目录。
func ensureCleanDir(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, ent := range ents {
		_ = os.RemoveAll(filepath.Join(dir, ent.Name()))
	}
	return nil
}

// downloadPE：下载 PE 镜像（优先 WEPE，失败后用 PEDownload.html，再用其他 PE）。
// - WEPE exe 有 offset 则 PeelFile 抽出 WIM
// - 下载的 WIM 放到 PETEMP，并复制 SDI
func downloadPE(arch string) (string, error) {
	arch = strings.TrimSpace(arch)
	if arch == "" {
		arch = "64"
	}
	peList, err := GetWinPE()
	if err != nil {
		return "", err
	}

	var wepe []WinPEImg
	var other []WinPEImg
	for _, it := range peList {
		if strings.EqualFold(strings.TrimSpace(it.Grp), "WEPE") {
			wepe = append(wepe, it)
		} else {
			other = append(other, it)
		}
	}
	sort.Slice(wepe, func(i, j int) bool {
		return strings.TrimSpace(wepe[i].Ver) > strings.TrimSpace(wepe[j].Ver)
	})

	findByArch := func(list []WinPEImg, want string) []WinPEImg {
		var out []WinPEImg
		for _, it := range list {
			if strings.TrimSpace(it.Arch) == want {
				out = append(out, it)
			}
		}
		return out
	}

	// tryDownload：尝试下载一个 PE 镜像，并准备 PETEMP。
	tryDownload := func(it WinPEImg) (string, error) {
		if len(it.Links) == 0 {
			return "", fmt.Errorf("PE链接为空")
		}
		for _, link := range it.Links {
			if strings.TrimSpace(link) == "" {
				continue
			}
			if !httpStatus(link) {
				continue
			}
			needBytes := int64(it.Sz * 1024 * 1024)
			root, err := choosePETempRoot(needBytes * 2)
			if err != nil {
				return "", err
			}
			peDir := filepath.Join(root, "PETEMP")
			if err := ensureCleanDir(peDir); err != nil {
				return "", err
			}
			exePath := ""
			wimPath := filepath.Join(peDir, "boot.wim")
			if strings.HasSuffix(strings.ToLower(link), ".exe") && it.OffsetEnd > it.OffsetStart {
				exePath = filepath.Join(peDir, "wepe.exe")
			}
			if exePath != "" {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
				defer cancel()
				if err := DownloadFile(ctx, link, exePath, func(pct float64) {
					uiSetStatus(fmt.Sprintf("正在下载PE... %.1f%%", pct))
					uiSetProgress(int32(pct))
				}); err != nil {
					continue
				}
				if err := PeelFile(exePath, fmt.Sprintf("%d", it.OffsetStart), fmt.Sprintf("%d", it.OffsetEnd), wimPath); err != nil {
					continue
				}
			} else {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
				defer cancel()
				if err := DownloadFile(ctx, link, wimPath, func(pct float64) {
					uiSetStatus(fmt.Sprintf("正在下载PE... %.1f%%", pct))
					uiSetProgress(int32(pct))
				}); err != nil {
					continue
				}
			}
			if err := copySDIToPETEMP(peDir); err != nil {
				return "", err
			}
			return wimPath, nil
		}
		return "", fmt.Errorf("PE下载失败")
	}

	for _, it := range findByArch(wepe, arch) {
		if wim, err := tryDownload(it); err == nil {
			return wim, nil
		}
	}
	if arch == "32" {
		for _, it := range findByArch(wepe, "64") {
			if wim, err := tryDownload(it); err == nil {
				return wim, nil
			}
		}
	}

	if _, _, links, err := PELnk(); err == nil {
		if wim, err := downloadPEFromLinks(links); err == nil {
			return wim, nil
		}
	}

	for _, it := range findByArch(other, arch) {
		if wim, err := tryDownload(it); err == nil {
			return wim, nil
		}
	}
	if arch == "32" {
		for _, it := range findByArch(other, "64") {
			if wim, err := tryDownload(it); err == nil {
				return wim, nil
			}
		}
	}
	return "", fmt.Errorf("未找到可用PE")
}

// downloadPEFromLinks：使用 PEDownload.html 的链接下载 PE。
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
	for _, link := range out {
		if !httpStatus(link) {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
		defer cancel()
		if err := DownloadFile(ctx, link, wimPath, func(pct float64) {
			uiSetStatus(fmt.Sprintf("正在下载PE... %.1f%%", pct))
			uiSetProgress(int32(pct))
		}); err != nil {
			continue
		}
		if err := copySDIToPETEMP(peDir); err != nil {
			return "", err
		}
		return wimPath, nil
	}
	return "", fmt.Errorf("PE下载失败")
}

// copySDIToPETEMP：复制 tools 目录下的 SDI 文件到 PETEMP。
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
	return nil
}

// RunPEInstall：在 PE 模式执行安装流程。
// 主要步骤：
// 1) 读取 restall_win.dat，定位镜像
// 2) 若失败则本地搜索镜像，再失败则下载 Win10
// 3) 处理“镜像在 C 盘”场景，必要时分区转移镜像
// 4) 格式化目标分区并应用镜像
// 5) 修复引导 + 安装后文件处理
// 6) 若创建临时分区，安装完成后合并回 C 盘
func RunPEInstall() error {
	uiSetProgress(0)
	uiSetStatus("正在读取重装信息...")

	targetRoot, diskPath, imagePath, err := loadResData()
	if err != nil {
		targetRoot = ""
		diskPath = ""
		imagePath = ""
	}
	imagePath = strings.TrimSpace(imagePath)
	if imagePath != "" {
		if resolved, rerr := resolveImagePath(diskPath, imagePath); rerr == nil {
			imagePath = resolved
		}
	}

	if imagePath == "" {
		uiSetStatus("未找到重装镜像，尝试本地搜索...")
		if local, lerr := findLocalImage("", ""); lerr == nil {
			imagePath = local
		}
	}
	if imagePath == "" {
		uiSetStatus("未找到本地镜像，尝试下载Win10...")
		if dl, derr := downloadImage(targetWin10, "64"); derr == nil {
			imagePath = dl
		} else {
			return fmt.Errorf("未找到镜像且下载失败: %w", derr)
		}
	}

	if targetRoot == "" {
		targetRoot = chooseInstallTargetRoot()
		if targetRoot == "" {
			return fmt.Errorf("未找到可用系统分区")
		}
	}

	uiSetProgress(10)
	uiSetStatus("正在准备分区...")

	tempVol := ""
	imageRoot := volumeRootFromPath(imagePath)
	if strings.EqualFold(imageRoot, targetRoot) {
		alts := otherInstallVolumes(targetRoot)
		if len(alts) == 0 {
			fi, err := os.Stat(imagePath)
			if err != nil {
				return err
			}
			sizeMB := int((fi.Size() + 512*1024*1024) / (1024 * 1024))
			if sizeMB < 1024 {
				sizeMB = 1024
			}
			newVol, err := SplitVolume(targetRoot, sizeMB, "ntfs", "TEMP", "")
			if err != nil {
				return err
			}
			tempVol = normalizeRootPath(newVol)
			newPath := filepath.Join(tempVol, filepath.Base(imagePath))
			if err := Copy(imagePath, newPath, true, true); err != nil {
				return err
			}
			_ = os.Remove(imagePath)
			imagePath = newPath
		}
	}

	if err := Format(strings.ReplaceAll(strings.ReplaceAll(targetRoot, "\\", ""), ":", ""), "ntfs", "Windows", true); err != nil {
		return fmt.Errorf("格式化失败: %w", err)
	}

	uiSetProgress(20)
	uiSetStatus("正在解析镜像...")
	infos, err := detectImageInfos(imagePath)
	index := 1
	if err == nil {
		index = selectInstallIndex(infos)
	}

	uiSetStatus(fmt.Sprintf("正在应用镜像（索引 %d）...", index))
	ImageProgress = func(phase string, pct float64, raw string) {
		if pct < 0 {
			return
		}
		uiSetStatus(fmt.Sprintf("正在应用镜像（%s）... %0.1f%%", phase, pct))
		uiSetProgress(int32(pct))
	}

	switch strings.ToLower(filepath.Ext(imagePath)) {
	case ".esd":
		if err := ApplyEsdImage(imagePath, index, targetRoot); err != nil {
			return err
		}
	case ".wim":
		if err := ApplyWimImage(imagePath, index, targetRoot); err != nil {
			return err
		}
	case ".iso":
		if err := ApplyISOImage(imagePath, index, targetRoot); err != nil {
			return err
		}
	default:
		return fmt.Errorf("不支持的镜像类型: %s", imagePath)
	}

	uiSetStatus("正在修复引导...")
	if err := FixBoot(targetRoot, "", "zh-cn"); err != nil {
		return err
	}

	targetOS := detectTargetFromInfos(infos)
	if targetOS == "" {
		targetOS = targetWin10
	}
	if err := postInstallTasks(targetRoot, targetOS); err != nil {
		return err
	}

	if tempVol != "" {
		_, _ = DeleteVolume(tempVol)
		_, _ = MergeVolume(targetRoot, 0)
	}

	uiSetStatus("安装完成，正在重启...")
	uiSetProgress(100)
	Shutdown(true)
	return nil
}

// chooseInstallTargetRoot：选择安装目标分区（优先未装系统分区）。
func chooseInstallTargetRoot() string {
	parts := Findpart()
	if len(parts) > 0 {
		return normalizeRootPath(parts[0])
	}
	drives, _ := ListDrive()
	for _, d := range drives {
		if strings.HasPrefix(strings.ToUpper(d), "X:") {
			continue
		}
		if GetDriveType(d) == driveFixed {
			return normalizeRootPath(d)
		}
	}
	return ""
}

// otherInstallVolumes：列出除目标分区外的其他固定磁盘分区。
func otherInstallVolumes(targetRoot string) []string {
	drives, _ := ListDrive()
	var out []string
	for _, d := range drives {
		root := normalizeRootPath(d)
		if root == "" || strings.EqualFold(root, targetRoot) {
			continue
		}
		if GetDriveType(root) == driveFixed {
			out = append(out, root)
		}
	}
	return out
}

// postInstallTasks：安装完成后的文件处理。
// - 拷贝 Unattend.xml
// - 放置激活工具与驱动安装工具
// - 创建公共桌面快捷方式
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
	_, _ = CreateShortcut(filepath.Join(targetRoot, "Users", "Public", "Desktop")+`\\`, "百度", "https://www.baidu.com")

	driveExe := filepath.Join(baseDir, "tools", "drive10.exe")
	if targetOS == targetWin7 {
		driveExe = filepath.Join(baseDir, "tools", "drive7.exe")
	}
	if fileExists(driveExe) {
		_ = Copy(driveExe, filepath.Join(targetRoot, "drive.exe"), true, true)
	}
	return nil
}
