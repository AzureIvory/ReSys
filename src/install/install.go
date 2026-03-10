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
	"ReSys/src/windows"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"ReSys/src/utils"
)

// 下载 PE 镜像
const peLinksID = "pe_links"

var (
	failedLinksMu sync.Mutex
	failedLinks   = map[string]struct{}{}
)

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

func (p *ProgressReporter) Update(pct float64, speedBytes int64) {
	now := time.Now()

	if p.uiEvery <= 0 {
		p.uiEvery = 200 * time.Millisecond
	}
	if p.lastUI.IsZero() || now.Sub(p.lastUI) >= p.uiEvery || pct >= 100 {
		ui.UiSetStatus(fmt.Sprintf(p.statusFmt, pct, float64(speedBytes)/1024.0/1024.0))
		ui.UiSetProgress(MapPct(p.base, p.span, pct))
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

// 把 0~100 的子进度映射到总进度
func MapPct(base, span int32, pct float64) int32 {
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	return base + int32(pct*float64(span)/100.0+0.5)
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

// markFailedLink 记录一个失败链接，供后续快速跳过或去重处理。
func markFailedLink(link string) {
	// 先去掉首尾空白，避免同一链接因格式差异重复记录。
	link = strings.TrimSpace(link)
	if link == "" {
		return
	}

	// 加锁保护共享 map，避免并发写冲突。
	failedLinksMu.Lock()
	defer failedLinksMu.Unlock()

	failedLinks[link] = struct{}{}
}

// isFailedLink 判断链接是否已被标记为失败。
func isFailedLink(link string) bool {
	// 统一清洗输入，保证查询口径一致。
	link = strings.TrimSpace(link)
	if link == "" {
		return false
	}

	// 加锁读取，避免并发访问 map 出现竞态。
	failedLinksMu.Lock()
	defer failedLinksMu.Unlock()

	_, ok := failedLinks[link]
	return ok
}

// 写入重装文件
func WriteResFile(imagePath string, target, arch string, index int) error {
	imagePath, _ = filepath.Abs(imagePath)
	imageRoot, _ := utils.NormalizeDrive(imagePath, 2)
	var (
		diskPath     string
		volumeGuid   string
		diskUniqueID string
		imageRel     string
	)
	if imageRoot != "" {
		imageRel = strings.TrimPrefix(imagePath, imageRoot)
		if imageRel != "" && !strings.HasPrefix(imageRel, `\`) {
			imageRel = `\` + imageRel
		}
		if diskNum, err := disk.GetDiskNum(imageRoot); err == nil {
			diskPath = fmt.Sprintf(`\\.\PhysicalDrive%d`, diskNum)
			if disks, derr := disk.ListPhysicalDisks(); derr == nil {
				for _, d := range disks {
					if d.DiskNumber == int(diskNum) {
						diskUniqueID = strings.TrimSpace(d.UniqueId)
						break
					}
				}
			}
		}
		if vols, verr := disk.ListVolumes(); verr == nil {
			for _, v := range vols {
				vRoot, _ := utils.NormalizeDrive(v.RootPath, 0)
				if strings.EqualFold(vRoot, imageRoot) {
					volumeGuid = strings.TrimSpace(v.VolumeGuidPath)
					break
				}
			}
		}
	}

	systemDrive := os.Getenv("SystemDrive")
	if systemDrive == "" {
		systemDrive = "C:"
	}
	sysRoot, _ := utils.NormalizeDrive(systemDrive, 0)
	restallPath := sysRoot + "restall_win.dat"
	content := fmt.Sprintf("disk=%s\nimage=%s\n", diskPath, imagePath)
	if volumeGuid != "" {
		content += fmt.Sprintf("volume_guid=%s\n", volumeGuid)
	}
	if diskUniqueID != "" {
		content += fmt.Sprintf("disk_unique_id=%s\n", diskUniqueID)
	}
	if imageRel != "" {
		content += fmt.Sprintf("image_rel=%s\n", imageRel)
	}

	if target != "" {
		content += fmt.Sprintf("target=%s\n", target)
	}
	if arch != "" {
		content += fmt.Sprintf("arch=%s\n", arch)
	}
	if index > 0 {
		content += fmt.Sprintf("index=%d\n", index)
	}
	if err := os.WriteFile(restallPath, []byte(content), 0o644); err != nil {
		return err
	}

	if diskPath == "" && imageRoot != "" {
		imgDat := filepath.Join(imageRoot, "restall_img.dat")
		_ = os.WriteFile(imgDat, []byte("image="+imagePath+"\n"), 0o644)
	}
	return nil
}

// 从所有盘符读取 restall_win.dat。
// 返回：目标盘符、物理磁盘路径、镜像路径、卷 GUID、磁盘唯一 ID、镜像相对路径。
func LoadResData() (targetRoot string, diskPath string, imagePath string, volumeGuid string, diskUniqueID string, imageRel string, targetOS string, arch string, index int, err error) {
	drives, err := disk.ListDrive()
	if err != nil {
		return "", "", "", "", "", "", "", "", 0, err
	}

	type hit struct {
		root  string
		path  string
		score int
	}

	var hits []hit
	for _, d := range drives {
		root, _ := utils.NormalizeDrive(d, 0)
		if root == "" {
			continue
		}
		if strings.HasPrefix(strings.ToUpper(root), "X:") {
			continue
		}

		cand := filepath.Join(root, "restall_win.dat")
		if _, err := os.Stat(cand); err != nil {
			continue
		}

		score := 0

		// 固定盘更可信
		if disk.GetDriveType(root) == 3 {
			score += 10
		}

		kind, _ := disk.GetDiskKind(root)
		if kind == "SSD" {
			score += 30
		} else if kind == "HDD" {
			score += 20
		} else if kind == "Removable" {
			score -= 50
		}

		// 有离线Windows说明这盘更可能就是要重装的系统盘
		if _, werr := windows.DetectWin(root); werr == nil {
			score += 100
		}

		hits = append(hits, hit{root: root, path: cand, score: score})
	}

	if len(hits) == 0 {
		return "", "", "", "", "", "", "", "", 0, fmt.Errorf("未找到 restall_win.dat")
	}

	// 选 score 最大的那个；如果读失败再尝试下一个
	for {
		bestIdx := -1
		bestScore := -1
		for i := range hits {
			if hits[i].score > bestScore {
				bestScore = hits[i].score
				bestIdx = i
			}
		}
		if bestIdx < 0 {
			break
		}
		h := hits[bestIdx]
		// 从列表移除，避免死循环
		hits = append(hits[:bestIdx], hits[bestIdx+1:]...)

		b, rerr := os.ReadFile(h.path)
		if rerr != nil {
			log.LogWrite(0, "[loadResData]读取 %s 失败：%v，尝试下一个", h.path, rerr)
			if len(hits) == 0 {
				return "", "", "", "", "", "", "", "", 0, rerr
			}
			continue
		}

		targetRoot = h.root

		for _, ln := range strings.Split(string(b), "\n") {
			ln = strings.TrimSpace(ln)
			if strings.HasPrefix(ln, "disk=") {
				diskPath = strings.TrimSpace(strings.TrimPrefix(ln, "disk="))
			} else if strings.HasPrefix(ln, "image=") {
				imagePath = strings.TrimSpace(strings.TrimPrefix(ln, "image="))
			} else if strings.HasPrefix(ln, "volume_guid=") {
				volumeGuid = strings.TrimSpace(strings.TrimPrefix(ln, "volume_guid="))
			} else if strings.HasPrefix(ln, "disk_unique_id=") {
				diskUniqueID = strings.TrimSpace(strings.TrimPrefix(ln, "disk_unique_id="))
			} else if strings.HasPrefix(ln, "image_rel=") {
				imageRel = strings.TrimSpace(strings.TrimPrefix(ln, "image_rel="))
			} else if strings.HasPrefix(ln, "target=") {
				targetOS = strings.TrimSpace(strings.TrimPrefix(ln, "target="))
			} else if strings.HasPrefix(ln, "arch=") {
				arch = strings.TrimSpace(strings.TrimPrefix(ln, "arch="))
			} else if strings.HasPrefix(ln, "index=") {
				if v, e := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(ln, "index="))); e == nil {
					index = v
				}
			}
		}

		return targetRoot, diskPath, imagePath, volumeGuid, diskUniqueID, imageRel, targetOS, arch, index, nil
	}

	return "", "", "", "", "", "", "", "", 0, fmt.Errorf("读取 restall_win.dat 失败")
}

// 根据 restall 信息定位镜像：
// 根据 restall 信息定位镜像：
func ResolveImagePath(diskPath, volumeGuid, diskUniqueID, imagePath, imageRel string) (string, error) {
	if imagePath != "" {
		if _, err := os.Stat(imagePath); err == nil {
			return imagePath, nil
		}
		log.LogWrite(0, "[resolveImagePath]restall镜像路径不可用：%s", imagePath)
	}

	base := filepath.Base(imagePath)
	if base == "" && imageRel != "" {
		base = filepath.Base(imageRel)
	}

	tryRoot := func(root string) (string, bool) {
		if nr, err := utils.NormalizeDrive(root, 0); err == nil {
			root = nr
		}
		if root == "" {
			return "", false
		}
		if imageRel != "" {
			rel := strings.TrimPrefix(imageRel, `\`)
			cand := filepath.Join(root, rel)
			if _, err := os.Stat(cand); err == nil {
				return cand, true
			}
		}
		if imageRel == "" && imagePath != "" && len(imagePath) > 2 {
			rel := strings.TrimPrefix(imagePath[2:], `\`)
			cand := filepath.Join(root, rel)
			if _, err := os.Stat(cand); err == nil {
				return cand, true
			}
		}
		if base != "" {
			found, _ := file.FindFile(root, base, 3)
			if len(found) > 0 {
				return found[0], true
			}
		}
		return "", false
	}

	volumeGuid = strings.TrimSpace(volumeGuid)
	if volumeGuid != "" {
		vols, err := disk.ListVolumes()
		if err != nil {
			log.LogWrite(0, "[resolveImagePath]读取卷GUID失败：%v", err)
		} else {
			for _, v := range vols {
				if strings.EqualFold(strings.TrimRight(v.VolumeGuidPath, `\`), strings.TrimRight(volumeGuid, `\`)) {
					root := v.RootPath
					if root == "" {
						root = v.VolumeGuidPath
					}
					if cand, ok := tryRoot(root); ok {
						return cand, nil
					}
					log.LogWrite(0, "[resolveImagePath]卷GUID匹配但未找到镜像：%s", volumeGuid)
					break
				}
			}
		}
	}

	diskUniqueID = strings.TrimSpace(diskUniqueID)
	if diskUniqueID != "" {

		disks, err := disk.ListPhysicalDisks()
		if err != nil {
			log.LogWrite(0, "[resolveImagePath]读取物理磁盘唯一ID失败：%v", err)
		} else {
			for _, d := range disks {
				if strings.EqualFold(strings.TrimSpace(d.UniqueId), diskUniqueID) {
					if _, roots, err := disk.GetDiskPartitions(fmt.Sprintf("%d", d.DiskNumber)); err == nil {
						for _, root := range roots {
							if cand, ok := tryRoot(root); ok {
								return cand, nil
							}
						}
						log.LogWrite(0, "[resolveImagePath]物理磁盘唯一ID匹配但未找到镜像：%s", diskUniqueID)
					} else {
						log.LogWrite(0, "[resolveImagePath]物理磁盘唯一ID匹配但分区读取失败：%s err=%v", diskUniqueID, err)
					}
					break
				}
			}
		}
	}

	if diskPath != "" {
		_, roots, err := disk.GetDiskPartitions(diskPath)
		if err == nil && len(roots) > 0 {
			for _, root := range roots {
				if cand, ok := tryRoot(root); ok {
					return cand, nil
				}
			}
			log.LogWrite(0, "[resolveImagePath]根据物理磁盘路径未找到镜像：%s", diskPath)
		} else if err != nil {
			log.LogWrite(0, "[resolveImagePath]读取物理磁盘路径失败：%s err=%v", diskPath, err)
		}
	}

	roots, _ := disk.ListDrive()
	for _, root := range roots {
		imgDat := filepath.Join(root, "restall_img.dat")
		if _, err := os.Stat(imgDat); err != nil {
			continue
		}
		b, err := os.ReadFile(imgDat)
		if err != nil {
			continue
		}
		for _, ln := range strings.Split(string(b), "\n") {
			ln = strings.TrimSpace(ln)
			if strings.HasPrefix(ln, "image=") {
				cand := strings.TrimSpace(strings.TrimPrefix(ln, "image="))
				if _, err := os.Stat(cand); err == nil {
					return cand, nil
				}
				base = filepath.Base(cand)
				found, _ := file.FindFile(root, base, 3)
				if len(found) > 0 {
					return found[0], nil
				}
			}
		}
	}
	return "", fmt.Errorf("未找到镜像文件")
}

const (
	minImageBytes uint64 = 7 * 1024 * 1024 * 1024
	tempMarkerRel        = `RESTALL\temp.marker`
)

// 清理指定分区
func ClearPartition(letter string) error {
	// TODO: your implementation
	return nil
}

// 扫描所有盘符找 marker，返回临时分区根路径（例如 "T:\\"）
func FindTempRootByMarker() string {
	drives, _ := disk.ListDrive()
	for _, d := range drives {
		root, _ := utils.NormalizeDrive(d, 0)
		if root == "" {
			continue
		}
		if strings.HasPrefix(strings.ToUpper(root), "X:") {
			continue
		}
		marker := filepath.Join(root, tempMarkerRel)
		if st, err := os.Stat(marker); err == nil && !st.IsDir() {
			return root
		}
	}
	return ""
}

// 优先本地找镜像，找不到再下载。
func findOrDownloadImage(target, arch string) (string, error) {
	local, _ := image.FindLocalImage(target, arch)
	if local != "" {
		return local, nil
	}
	return DownloadImage(target, arch)
}

// 校验镜像是否有效（先sha1，后解析镜像）
func validateImageFile(it data.WinImg, imagePath string) error {
	if strings.TrimSpace(it.SHA1) != "" {
		ok, got, err := download.CheckFileSHA1(imagePath, it.SHA1)
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
		if _, err := image.DetectImageInfos(imagePath); err != nil {
			return fmt.Errorf("镜像损坏: %w", err)
		}
	}
	return nil
}

// 根据目标系统/架构下载镜像。
func DownloadImage(target, arch string) (string, error) {
	ent, err := data.GetWinImgs(target)
	if err != nil {
		log.LogWrite(0, "[downloadImage]获取镜像列表失败：%v", err)
		return "", err
	}

	candidates := image.FilterWinImgsByArch(ent, arch)
	if len(candidates) == 0 && arch == "32" {
		candidates = image.FilterWinImgsByArch(ent, "64")
	}
	if len(candidates) == 0 {
		candidates = ent
	}
	log.LogWrite(0, "[downloadImage]可用镜像数量：%d", len(candidates))

	root := chooseDownloadRoot()
	if root == "" {
		log.LogWrite(0, "[downloadImage]未找到可用下载分区")
		return "", fmt.Errorf("未找到可用下载分区")
	}
	dstDir := filepath.Join(root, "tempimg")
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
			if !download.HttpStatus(link) {
				log.LogWrite(0, "[downloadImage]URL链接不可用：%s", link)
				markFailedLink(link)
				continue
			}

			name := data.ImgName(it, link)
			if strings.TrimSpace(it.File) != "" {
				name = strings.TrimSpace(it.File)
			}
			dstPath := filepath.Join(dstDir, name)

			// 已存在则校验
			if st, err := os.Stat(dstPath); err == nil && !st.IsDir() && st.Size() > 0 {
				if err := validateImageFile(it, dstPath); err != nil {
					log.LogWrite(0, "[downloadImage]镜像校验失败，删除重下：%s err=%v", dstPath, err)
					_ = file.Remove(dstPath, false)
				} else {
					log.LogWrite(0, "[downloadImage]镜像已存在：%s", dstPath)
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

			log.LogWrite(0, "[downloadImage]开始下载镜像(URL)：%s -> %s", link, dstPath)

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

			if err == nil {
				if vErr := validateImageFile(it, dstPath); vErr != nil {
					markFailedLink(link)
					_ = file.Remove(dstPath, false)
					log.LogWrite(0, "[downloadImage]镜像校验失败，删除重下：%s err=%v", dstPath, vErr)
					errs = append(errs, fmt.Sprintf("URL校验失败 link=%s err=%v", link, vErr))
					continue
				}
				log.LogWrite(0, "[downloadImage]镜像下载完成：%s", dstPath)
				ui.UiSetProgress(60)
				return dstPath, nil
			}

			markFailedLink(link)
			_ = file.Remove(dstPath, false)
			log.LogWrite(0, "[downloadImage]镜像下载失败(URL)：link=%s err=%v", link, err)
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

		link, lerr := data.ImgLink(it)
		if lerr != nil {
			errs = append(errs, fmt.Sprintf("BT取链接失败 file=%s err=%v", it.File, lerr))
			continue
		}
		link = strings.TrimSpace(link)
		if link == "" || isFailedLink(link) {
			continue
		}

		// 期望落在 dstDir 的文件名
		name := data.ImgName(it, link)
		if strings.TrimSpace(it.File) != "" {
			name = strings.TrimSpace(it.File)
		}
		dstPath := filepath.Join(dstDir, name)

		// 已存在则校验
		if st, err := os.Stat(dstPath); err == nil && !st.IsDir() && st.Size() > 0 {
			if err := validateImageFile(it, dstPath); err != nil {
				log.LogWrite(0, "[downloadImage]镜像校验失败，删除重下：%s err=%v", dstPath, err)
				_ = file.Remove(dstPath, false)
			} else {
				log.LogWrite(0, "[downloadImage]镜像已存在：%s", dstPath)
				ui.UiSetProgress(60)
				return dstPath, nil
			}
		}

		log.LogWrite(0, "[downloadImage]开始下载镜像(BT)：%s -> %s", link, dstDir)

		lastLog := time.Time{}
		lastUI := time.Time{}

		realPath, err := download.DownloadBT(link, dstDir, func(pct int, speed, done, total int64) {
			now := time.Now()
			if lastUI.IsZero() || now.Sub(lastUI) >= 1*time.Second || pct >= 100 {
				ui.UiSetStatus(fmt.Sprintf("正在下载镜像... %d%% 速度: %.2f MB/s", pct, float64(speed)/1024/1024))
				ui.UiSetProgress(MapPct(0, 60, float64(pct)))
				lastUI = now
			}
			if lastLog.IsZero() || now.Sub(lastLog) >= 1*time.Second || pct >= 100 {
				log.LogWrite(0, "[downloadImage]BT下载进度：%d%% 速度: %.2f MB/s", pct, float64(speed)/1024/1024)
				lastLog = now
			}
		})

		if err == nil {
			finalPath := realPath

			// 如果 BT 真实落盘不等于你期望的 dstPath，就整理到 dstPath（更利于后续统一处理）
			if realPath != "" && !strings.EqualFold(realPath, dstPath) {
				_ = file.Remove(dstPath, false)

				// 同卷优先 rename（快且不占双份空间）
				if rErr := os.Rename(realPath, dstPath); rErr == nil {
					finalPath = dstPath
				} else {
					// rename 失败再 copy（跨卷/权限等）
					if cErr := file.Copy(realPath, dstPath, true, true); cErr == nil {
						finalPath = dstPath
						// copy 成功后可选择删除 realPath（可留作断点或日志，此处默认删除避免占空间）
						_ = file.Remove(realPath, false)
					} else {
						// 整理失败：至少还能用 realPath
						log.LogWrite(0, "[downloadImage]BT下载后整理路径失败：real=%s dst=%s err=%v", realPath, dstPath, cErr)
						finalPath = realPath
					}
				}
			}

			// 校验用最终路径（realPath 或 dstPath）
			if vErr := validateImageFile(it, finalPath); vErr != nil {
				markFailedLink(link)
				_ = file.Remove(finalPath, false)
				log.LogWrite(0, "[downloadImage]镜像校验失败，删除重下：%s err=%v", finalPath, vErr)
				errs = append(errs, fmt.Sprintf("BT校验失败 link=%s err=%v", link, vErr))
				continue
			}

			log.LogWrite(0, "[downloadImage]镜像下载完成(BT)：%s", finalPath)
			ui.UiSetProgress(60)
			return finalPath, nil
		}

		markFailedLink(link)
		log.LogWrite(0, "[downloadImage]镜像下载失败(BT)：link=%s err=%v", link, err)
		errs = append(errs, fmt.Sprintf("BT失败 link=%s err=%v", link, err))
	}

	if len(errs) > 0 {
		return "", fmt.Errorf("全部镜像链接下载失败：%s", strings.Join(errs, " | "))
	}
	return "", fmt.Errorf("未找到可用镜像下载链接")
}

// 选择镜像下载盘符。
func chooseDownloadRoot() string {
	systemDrive := strings.ToUpper(os.Getenv("SystemDrive")) // "C:"
	parts := disk.Findpart()

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
		root = windows.SystemDriveRoot()
	}
	if nr, err := utils.NormalizeDrive(root, 0); err == nil {
		root = nr
	}

	// 先尝试直接用 C
	if root != "" {
		if free, err := disk.GetFreeSize(root); err == nil && free >= minImageBytes {
			return root
		}
		// 不够 -> 清理 -> 再试
		//_ = ClearPartition("C")
		if free, err := disk.GetFreeSize(root); err == nil && free >= minImageBytes {
			return root
		}
	}

	// 还不够：用未分配创建 TEMP
	tmp, err := disk.EnsureTempVolumeForBytes(minImageBytes)
	if err == nil && tmp != "" {
		return tmp
	}

	// 兜底
	drives, _ := disk.ListDrive()
	for _, d := range drives {
		if systemDrive != "" && strings.EqualFold(strings.TrimSuffix(d, `\`), systemDrive) {
			continue
		}
		if disk.GetDriveType(d) == 3 { //3=driveFixed固定盘
			return d
		}
	}
	if systemDrive != "" {
		return systemDrive + `\`
	}
	return ""
}

// 选择下载镜像与链接。
func pickWinImg(ent []data.WinImg) (data.WinImg, string, error) {
	if len(ent) == 0 {
		return data.WinImg{}, "", fmt.Errorf("未找到可用镜像")
	}
	var urlList []data.WinImg
	var btList []data.WinImg
	for _, it := range ent {
		if strings.EqualFold(strings.TrimSpace(it.Type), "url") {
			urlList = append(urlList, it)
		} else {
			btList = append(btList, it)
		}
	}

	tryURL := func(it data.WinImg) []string {
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
			if download.HttpStatus(link) {
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
		link, err := data.ImgLink(btList[0])
		return btList[0], link, err
	}
	link, err := data.ImgLink(ent[0])
	return ent[0], link, err
}

// 把某个镜像 ID 记到失败集合里。
func markFailedPEImage(failed map[string]struct{}, id string) {
	if id == "" {
		return
	}
	failed[id] = struct{}{}
}

// 将WinPEImg 的关键信息拼成一个字符串 ID
func peImageID(it data.WinPEImg) string {
	parts := []string{
		strings.TrimSpace(it.Grp),
		strings.TrimSpace(it.Ver),
		strings.TrimSpace(it.Arch),
	}
	links := strings.Join(it.Links, "|")
	parts = append(parts, strings.TrimSpace(links))
	return strings.Join(parts, "|")
}

func downloadPE(arch string, failedPEImages map[string]struct{}) (string, string, error) {
	arch = strings.TrimSpace(arch)
	if arch == "" {
		arch = "64"
	}
	if failedPEImages == nil {
		failedPEImages = map[string]struct{}{}
	}
	log.LogWrite(0, "[downloadPE]下载PE，目标架构=%s", arch)

	peList, err := data.GetWinPE()
	if err != nil {
		log.LogWrite(0, "[downloadPE]获取PE列表失败：%v", err)
		return "", "", err
	}

	var other []data.WinPEImg
	other = peList

	findByArch := func(list []data.WinPEImg, want string) []data.WinPEImg {
		var out []data.WinPEImg
		for _, it := range list {
			if strings.TrimSpace(it.Arch) == want {
				out = append(out, it)
			}
		}
		return out
	}

	// 尝试下载一个 PE 镜像
	tryDownload := func(it data.WinPEImg) (string, string, error) {
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
			if !download.HttpStatus(link) {
				log.LogWrite(0, "[downloadPE]PE链接不可用：%s", link)
				markFailedLink(link)
				continue
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
				1*time.Second, 1*time.Second,
				"正在下载PE... %.1f%% 速度: %.2f MB/s",
				"PE下载进度：%.1f%% 速度: %.2f MB/s",
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
							log.LogWrite(0, "[downloadPE]复用已存在WEPE安装包：%s", exePath)
							useExisting = true
						} else {
							log.LogWrite(0, "[downloadPE]已存在WEPE安装包MD5不匹配，删除重下：%s", exePath)
							_ = file.Remove(exePath, false)
						}
					} else {
						log.LogWrite(0, "[downloadPE]复用已存在WEPE安装包(无MD5)：%s", exePath)
						useExisting = true
					}
				}

				// 下载
				if !useExisting {
					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
					err := download.DownloadFile(ctx, link, exePath, func(pct float64, speed int64) {
						pr.Update(pct, speed)
					})
					cancel()

					if err != nil {
						markFailedLink(link)
						log.LogWrite(0, "[downloadPE]PE下载失败：%v", err)
						_ = file.Remove(exePath, false)
						continue
					}

					// 下载后校验 MD5
					if strings.TrimSpace(it.MD5) != "" {
						ok, merr := tools.MatchMD5(exePath, it.MD5)
						if merr != nil || !ok {
							markFailedLink(link)
							log.LogWrite(0, "[downloadPE]PE下载后MD5校验失败：%s", exePath)
							_ = file.Remove(exePath, false)
							continue
						}
					}
				}

				// 从 exe 抽 WIM
				if err := file.PeelFile(exePath, fmt.Sprintf("%d", it.OffsetStart), fmt.Sprintf("%d", it.OffsetEnd), wimPath); err != nil {
					markFailedLink(link)
					log.LogWrite(0, "[downloadPE]PE解包失败：%v", err)
					continue
				}

			} else {
				if triedLink {
					_ = file.Remove(wimPath+".part", false) // 切换链接清理
				}
				triedLink = true
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
				err := download.DownloadFile(ctx, link, wimPath, func(pct float64, speed int64) {
					pr.Update(pct, speed)
				})
				cancel()

				if err != nil {
					markFailedLink(link)
					log.LogWrite(0, "[downloadPE]PE下载失败：%v", err)
					_ = file.Remove(wimPath, false)
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
	if _, _, links, err := data.PELnk(); err == nil {
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

	root, err := ChoosePETempRoot(1024 * 1024 * 1024)
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
		1*time.Second, 1*time.Second,
		"正在下载PE... %.1f%% 速度: %.2f MB/s",
		"PE下载进度：%.1f%% 速度: %.2f MB/s",
		true,
	)

	triedLink := false
	for _, link := range out {
		if !download.HttpStatus(link) {
			log.LogWrite(0, "[downloadPEFromLinks]PE链接不可用：%s", link)
			continue
		}
		log.LogWrite(0, "[downloadPEFromLinks]PE链接：%s\n", link)

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
			log.LogWrite(0, "[downloadPEFromLinks]PE下载失败：%v,url:"+link, err)
			_ = file.Remove(wimPath, false)
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
	sdiFiles, _ := file.FindFile(toolsDir, "*.sdi|*.SDI", 1)
	if len(sdiFiles) == 0 {
		return fmt.Errorf("未找到SDI文件")
	}
	for _, sdi := range sdiFiles {
		dst := filepath.Join(peDir, filepath.Base(sdi))
		if err := file.Copy(sdi, dst, true, true); err != nil {
			return err
		}
	}
	log.LogWrite(0, "[copySDIToPETEMP]已复制SDI文件到PETEMP：%s", peDir)
	return nil
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
	if utils.FileExists(sdi) {
		return sdi
	}
	if sdis, _ := file.FindFile(dir, "*.sdi|*.SDI", 1); len(sdis) > 0 {
		return sdis[0]
	}
	return ""
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
			found, wim, sdi, _ := pe.GoToPE(true)
			if found && strings.TrimSpace(wim) != "" {
				wimPath = wim
				sdiPath = sdi
				log.LogWrite(0, "[ensurePEAndReboot]使用已有PE：%s", wimPath)
			}
		}

		if wimPath == "" {
			log.LogWrite(0, "[ensurePEAndReboot]未检测到PE文件，开始下载/准备PE")
			wp, id, err := downloadPE(arch, failedPEImages)
			if err != nil {
				log.LogWrite(0, "[ensurePEAndReboot]下载PE失败：%v", err)
				if attempt == maxAttempts {
					ui.UiShowError("错误", fmt.Sprintf("进入PE失败：%v", err))
					os.Exit(-1)
				}
				continue
			}
			wimPath = wp
			peID = id
			sdiPath = resolveSdiPath(wimPath)
			log.LogWrite(0, "[ensurePEAndReboot]PE镜像准备完成：%s", wimPath)
		}
		if sdiPath == "" {
			sdiPath = resolveSdiPath(wimPath)
		}

		ui.UiSetStatus("正在写入自身到PE...")
		log.LogWrite(0, "[ensurePEAndReboot]准备Patwim：%s", wimPath)

		if err := pe.Patwim(wimPath); err != nil {
			log.LogWrite(0, "[ensurePEAndReboot]ensurePEAndReboot Patwim失败：%v", err)
			markFailedPEImage(failedPEImages, peID)
			removePEArtifacts(wimPath, sdiPath)
			if attempt == maxAttempts {
				ui.UiShowError("错误", fmt.Sprintf("进入PE失败：%v", err))
				os.Exit(-1)
			}
			continue
		}
		log.LogWrite(0, "[ensurePEAndReboot]ensurePEAndReboot Patwim成功：%s", wimPath)

		ui.UiSetStatus("正在设置下次启动进入PE...")
		log.LogWrite(0, "[ensurePEAndReboot]进入PE")
		log.LogWrite(0, sdiPath+"==="+wimPath)

		if sdiPath == "" {
			if _, _, _, err := pe.GoToPE(false); err != nil {
				log.LogWrite(0, "[ensurePEAndReboot]进入PE失败：%v", err)
				markFailedPEImage(failedPEImages, peID)
				removePEArtifacts(wimPath, sdiPath)
				if attempt == maxAttempts {
					ui.UiShowError("错误", fmt.Sprintf("进入PE失败：%v", err))
					os.Exit(-1)
				}
				continue
			}
			return nil
		}

		if _, _, _, err := pe.GoToPE(false, sdiPath, wimPath); err != nil {
			log.LogWrite(0, "[ensurePEAndReboot]进入PE失败：%v", err)
			markFailedPEImage(failedPEImages, peID)
			removePEArtifacts(wimPath, sdiPath)
			if attempt == maxAttempts {
				ui.UiShowError("错误", fmt.Sprintf("进入PE失败：%v", err))
				os.Exit(-1)
			}
			continue
		}
		return nil
	}
	return fmt.Errorf("进入PE失败")
}

// 清理 PE 相关的产物文件，主要是：wimPath和sdiPath
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

// 选择 PETEMP 所在盘符。
func ChoosePETempRoot(needBytes int64) (string, error) {
	systemDrive := strings.ToUpper(os.Getenv("SystemDrive"))
	if systemDrive != "" {
		free, err := disk.GetFreeSize(systemDrive)
		if err == nil && int64(free) > needBytes {
			log.LogWrite(0, "[choosePETempRoot]PETEMP使用系统盘：%s", systemDrive)
			return systemDrive + `\`, nil
		}
	}
	parts := disk.Findpart()
	if len(parts) > 0 {
		for _, p := range parts {
			free, err := disk.GetFreeSize(p)
			if err == nil && int64(free) > needBytes {
				log.LogWrite(0, "[choosePETempRoot]PETEMP使用分区：%s", p)
				return p, nil
			}
		}
	}
	if systemDrive != "" {
		return systemDrive + `\`, nil
	}
	return "", fmt.Errorf("未找到可用分区")
}
