package main

import (
	"context"
	"crypto/md5"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
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

var (
	logOnce sync.Once
	logMu   sync.Mutex
	logPath string
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

// initLog：初始化日志文件（运行目录/log/yyyyMMdd_HHmmss.log）。
func initLog() {
	logOnce.Do(func() {
		exe, err := os.Executable()
		if err != nil {
			return
		}
		base := filepath.Dir(exe)
		logDir := filepath.Join(base, "log")
		_ = os.MkdirAll(logDir, 0o755)
		logPath = filepath.Join(logDir, time.Now().Format("20060102_150405")+".log")
	})
}

// logWrite：写入一行日志（中文）。
func logWrite(format string, args ...any) {
	initLog()
	if logPath == "" {
		return
	}
	logMu.Lock()
	defer logMu.Unlock()
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	msg := fmt.Sprintf(format, args...)
	line := fmt.Sprintf("[%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), msg)
	_, _ = f.WriteString(line)
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

	var imgPath string
	for {
		img, err := findOrDownloadImage(target, imgArch)
		if err == nil {
			imgPath = img
			break
		}
		logWrite("镜像准备失败：%v", err)
		if !MessageRetryExit(w, "错误", "镜像准备失败："+err.Error()) {
			return
		}
	}

	uiSetProgress(20)
	uiSetStatus("正在写入重装信息...")
	for {
		if err := writeResFile(imgPath); err != nil {
			logWrite("写入重装信息失败：%v", err)
			if !MessageRetryExit(w, "错误", "写入重装信息失败："+err.Error()) {
				return
			}
			continue
		}
		break
	}

	uiSetProgress(30)
	uiSetStatus("正在准备PE环境...")
	for {
		if err := ensurePEAndReboot(peArch); err != nil {
			logWrite("准备PE失败：%v", err)
			if !MessageRetryExit(w, "错误", "准备PE失败："+err.Error()) {
				return
			}
			continue
		}
		break
	}

	uiSetProgress(100)
	uiSetStatus("即将重启进入PE...")
	logWrite("准备完成，重启进入PE")
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
// 失败时自动切换备用链接/下一个镜像；全部失败才返回 error。
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

	// 先 URL 后 BT（符合你原来的优先级）
	// 第一轮：URL
	for _, it := range candidates {
		if !strings.EqualFold(strings.TrimSpace(it.Type), "url") {
			continue
		}
		links := []string{strings.TrimSpace(it.Link), strings.TrimSpace(it.Link2)}
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

			if st, err := os.Stat(dstPath); err == nil && !st.IsDir() && st.Size() > 0 {
				logWrite("镜像已存在：%s", dstPath)
				return dstPath, nil
			}

			// 若存在残留文件，先删掉，避免断点/脏文件导致后续判断混乱
			_ = os.Remove(dstPath)

			logWrite("开始下载镜像(URL)：%s -> %s", link, dstPath)
			ctx, cancel := context.WithCancel(context.Background())
			err := DownloadFile(ctx, link, dstPath, func(pct float64, speed int64) {
				uiSetStatus(fmt.Sprintf("正在下载镜像... %.1f%% 速度: %.2f MB/s", pct, float64(speed)/1024/1024))
				uiSetProgress(int32(pct))
				logWrite("镜像下载进度：%.1f%% 速度: %.2f MB/s", pct, float64(speed)/1024/1024)
			})
			cancel()

			if err == nil {
				logWrite("镜像下载完成：%s", dstPath)
				return dstPath, nil
			}

			// 失败：记录并换下一个 link / 下一个镜像
			markFailedLink(link)
			_ = os.Remove(dstPath)
			logWrite("镜像下载失败(URL)：link=%s err=%v", link, err)
			errs = append(errs, fmt.Sprintf("URL失败 link=%s err=%v", link, err))
		}
	}

	// 第二轮：BT
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

		name := ImgName(it, link)
		if strings.TrimSpace(it.File) != "" {
			name = strings.TrimSpace(it.File)
		}
		dstPath := filepath.Join(dstDir, name)

		if st, err := os.Stat(dstPath); err == nil && !st.IsDir() && st.Size() > 0 {
			logWrite("镜像已存在：%s", dstPath)
			return dstPath, nil
		}

		logWrite("开始下载镜像(BT)：%s -> %s", link, dstDir)
		err := DownloadBT(link, dstDir, func(pct int, speed, done, total int64) {
			uiSetStatus(fmt.Sprintf("正在下载镜像... %d%% 速度: %.2f MB/s", pct, float64(speed)/1024/1024))
			uiSetProgress(int32(pct))
			logWrite("BT下载进度：%d%% 速度: %.2f MB/s", pct, float64(speed)/1024/1024)
		})
		if err == nil {
			// BT 下载完成后一般就在 dstDir 里，按你原逻辑直接返回 dstPath
			// 如遇 BT 实际文件名不同，需要从 DownloadBT 返回值或目录扫描确认。
			logWrite("镜像下载完成(BT)：%s", dstPath)
			return dstPath, nil
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

// ensurePEAndReboot：确保有可用 PE 引导文件，若无则下载 PE。
// 下载后会写入自身到 WIM 并修改 Pecmd.ini，最后设置下次启动进入 PE。
func ensurePEAndReboot(arch string) error {
	if hasPEFiles() {
		logWrite("检测到已有PE文件，直接进入PE")
		return GoToPE()
	}
	logWrite("未检测到PE文件，开始下载/准备PE")
	wimPath, err := downloadPE(arch)
	if err != nil {
		logWrite("下载PE失败：%v", err)
		return err
	}
	logWrite("PE镜像准备完成：%s", wimPath)
	if err := Patwim(wimPath); err != nil {
		logWrite("写入自身到WIM失败：%v", err)
		return err
	}
	return GoToPE()
}

// hasPEFiles：扫描当前磁盘是否已存在可用 PE 引导文件。
func hasPEFiles() bool {
	drives, err := ListDrive()
	if err != nil {
		logWrite("枚举盘符失败：%v", err)
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
					logWrite("发现PETEMP中的PE文件：%s / %s", strings.Join(sdi, " | "), strings.Join(wim, " | "))
					return true
				}
				continue
			}
			if fileExists(filepath.Join(d, o.sdi)) && fileExists(filepath.Join(d, o.wim)) {
				logWrite("发现PE文件：%s %s", filepath.Join(d, o.sdi), filepath.Join(d, o.wim))
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

// ensureCleanDir：创建指定目录（不删除已有文件）。
func ensureCleanDir(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	logWrite("准备PETEMP目录：%s", dir)
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
	logWrite("下载PE，目标架构=%s", arch)
	peList, err := GetWinPE()
	if err != nil {
		logWrite("获取PE列表失败：%v", err)
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

	// 优先在本地查找已下载的 WEPE 安装包（exe），匹配 MD5 后直接使用。
	if wimPath, err := tryLocalWepe(wepe, arch); err == nil && wimPath != "" {
		logWrite("使用本地WEPE成功：%s", wimPath)
		return wimPath, nil
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
				logWrite("PE链接不可用：%s", link)
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
				if err := DownloadFile(ctx, link, exePath, func(pct float64, speed int64) {
					uiSetStatus(fmt.Sprintf("正在下载PE... %.1f%% 速度: %.2f MB/s", pct, float64(speed)/1024/1024))
					uiSetProgress(int32(pct))
					logWrite("PE下载进度：%.1f%% 速度: %.2f MB/s", pct, float64(speed)/1024/1024)
				}); err != nil {
					markFailedLink(link)
					logWrite("PE下载失败：%v", err)
					continue
				}
				if err := PeelFile(exePath, fmt.Sprintf("%d", it.OffsetStart), fmt.Sprintf("%d", it.OffsetEnd), wimPath); err != nil {
					markFailedLink(link)
					logWrite("PE解包失败：%v", err)
					continue
				}
			} else {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
				defer cancel()
				if err := DownloadFile(ctx, link, wimPath, func(pct float64, speed int64) {
					uiSetStatus(fmt.Sprintf("正在下载PE... %.1f%% 速度: %.2f MB/s", pct, float64(speed)/1024/1024))
					uiSetProgress(int32(pct))
					logWrite("PE下载进度：%.1f%% 速度: %.2f MB/s", pct, float64(speed)/1024/1024)
				}); err != nil {
					markFailedLink(link)
					logWrite("PE下载失败：%v", err)
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
			logWrite("PE链接不可用：%s", link)
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
		defer cancel()
		if err := DownloadFile(ctx, link, wimPath, func(pct float64, speed int64) {
			uiSetStatus(fmt.Sprintf("正在下载PE... %.1f%% 速度: %.2f MB/s", pct, float64(speed)/1024/1024))
			uiSetProgress(int32(pct))
			logWrite("PE下载进度：%.1f%% 速度: %.2f MB/s", pct, float64(speed)/1024/1024)
		}); err != nil {
			markFailedLink(link)
			logWrite("PE下载失败：%v", err)
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
	logWrite("已复制SDI文件到PETEMP：%s", peDir)
	return nil
}

// tryLocalWepe：优先在运行目录和用户下载目录中查找 WEPE 安装包。
// 要求：文件名与列表匹配，且 MD5 校验一致；若有 offset 则直接 PeelFile 抽出 WIM。
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

// localWepeSearchDirs：返回本地 WEPE 搜索目录（运行目录优先，其次下载目录）。
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

// matchMD5：计算文件 MD5 并与期望值比较。
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
	logWrite("进入PE安装流程")

	targetRoot, diskPath, imagePath, err := loadResData()
	if err != nil {
		logWrite("读取重装信息失败：%v", err)
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
		logWrite("尝试本地搜索镜像")
		if local, lerr := findLocalImage("", ""); lerr == nil {
			imagePath = local
		}
	}
	if imagePath == "" {
		uiSetStatus("未找到本地镜像，尝试下载Win10...")
		logWrite("本地无镜像，尝试下载Win10")
		if dl, derr := downloadImage(targetWin10, "64"); derr == nil {
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
	targetRoot = normalizeRootPath(targetRoot)
	imagePath = strings.TrimSpace(imagePath)

	imageRoot := normalizeRootPath(volumeRootFromPath(imagePath))
	if strings.EqualFold(imageRoot, targetRoot) {
		// 先拿到镜像大小，供空间判断/拆分使用
		fi, err := os.Stat(imagePath)
		if err != nil {
			return err
		}
		imageBytes := uint64(fi.Size())

		// 复制冗余
		const extraBytes uint64 = 512 * 1024 * 1024
		needBytes := imageBytes + extraBytes

		var moved bool
		var moveErrs []string

		alts := otherInstallVolumes(targetRoot)

		for _, v := range alts {
			altRoot := normalizeRootPath(v)
			if altRoot == "" {
				continue
			}
			// 跳过目标分区
			if strings.EqualFold(altRoot, targetRoot) {
				continue
			}
			// 跳过 X:\
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
				_ = os.Remove(dstPath)
				continue
			}

			// 复制后校验
			if dfi, derr := os.Stat(dstPath); derr != nil || dfi.Size() <= 0 {
				moveErrs = append(moveErrs, fmt.Sprintf("%s 复制后校验失败:%v", altRoot, derr))
				_ = os.Remove(dstPath)
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

			// 拆分大小：镜像大小+512MB，且至少1GB
			sizeMB := int((int64(imageBytes) + 512*1024*1024) / (1024 * 1024))
			if sizeMB < 1024 {
				sizeMB = 1024
			}

			newVol, err := SplitVolume(targetRoot, sizeMB, "ntfs", "TEMP", "")
			if err != nil {
				return err
			}
			tempVol = normalizeRootPath(newVol)

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

	if err := Format(strings.ReplaceAll(strings.ReplaceAll(targetRoot, "\\", ""), ":", ""), "ntfs", "Windows", true); err != nil {
		return fmt.Errorf("格式化失败: %w", err)
	}
	logWrite("格式化完成：%s", targetRoot)

	uiSetProgress(20)
	uiSetStatus("正在解析镜像...")
	infos, err := detectImageInfos(imagePath)
	index := 1
	if err == nil {
		index = selectInstallIndex(infos)
		logWrite("镜像索引列表：%s", formatImageInfos(infos))
	}
	logWrite("选择镜像索引：%d", index)

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
	logWrite("引导修复完成")

	targetOS := detectTargetFromInfos(infos)
	if targetOS == "" {
		targetOS = targetWin10
	}
	if err := postInstallTasks(targetRoot, targetOS); err != nil {
		return err
	}
	logWrite("安装后处理完成")

	if tempVol != "" {
		_, _ = DeleteVolume(tempVol)
		_, _ = MergeVolume(targetRoot, 0)
		logWrite("已合并临时分区回系统分区：%s", targetRoot)
	}

	uiSetStatus("安装完成，正在重启...")
	uiSetProgress(100)
	logWrite("PE安装流程完成，准备重启")
	Shutdown(true)
	return nil
}

// chooseInstallTargetRoot：选择安装目标分区（优先未装系统分区）。
func chooseInstallTargetRoot() string {
	parts := Findpart()
	if len(parts) > 0 {
		logWrite("选择未装系统分区：%s", parts[0])
		return normalizeRootPath(parts[0])
	}
	drives, _ := ListDrive()
	for _, d := range drives {
		if strings.HasPrefix(strings.ToUpper(d), "X:") {
			continue
		}
		if GetDriveType(d) == driveFixed {
			logWrite("回退选择固定盘分区：%s", d)
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
	logWrite("已写入应答文件/激活工具/快捷方式")

	driveExe := filepath.Join(baseDir, "tools", "drive10.exe")
	if targetOS == targetWin7 {
		driveExe = filepath.Join(baseDir, "tools", "drive7.exe")
	}
	if fileExists(driveExe) {
		_ = Copy(driveExe, filepath.Join(targetRoot, "drive.exe"), true, true)
	}
	logWrite("驱动安装工具准备完成")
	return nil
}

// formatImageInfos：格式化镜像索引信息用于日志输出。
func formatImageInfos(infos []ImageMeta) string {
	var parts []string
	for _, info := range infos {
		parts = append(parts, fmt.Sprintf("Index=%d Name=%s Desc=%s Edition=%s Flags=%s Arch=%s",
			info.Index, info.Name, info.Description, info.Edition, info.Flags, info.Arch))
	}
	return strings.Join(parts, " | ")
}
