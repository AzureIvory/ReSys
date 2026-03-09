package main

import (
	"ReSys/src/disk"
	"ReSys/src/file"
	"ReSys/src/log"
	"ReSys/src/windows"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"

	"ReSys/src/registry"
	"ReSys/src/utils"

	"github.com/kdomanski/iso9660"
)

// 判断 Windows 的 HRESULT 是否失败。
func hresultFailed(hr uintptr) bool {
	return int32(hr) < 0
}

// 推测指定盘符的系统架构（32/64）
func detectArch(root string, hasPFx86, hasSysWOW, systemLoaded bool) string {
	if hasPFx86 || hasSysWOW {
		return "x64"
	}

	// SYSTEM hive 里的环境变量
	if systemLoaded {
		keyPath := `Offline_SYSTEM\ControlSet001\Control\Session Manager\Environment`
		if h, err := registry.RegOpenKey(HKEY_LOCAL_MACHINE, keyPath); err == nil {
			defer registry.RegCloseKey(h)
			if s, err := registry.RegGetString(h, "PROCESSOR_ARCHITECTURE"); err == nil && s != "" {
				up := strings.ToUpper(s)
				if strings.Contains(up, "64") || up == "AMD64" || up == "ARM64" {
					return "x64"
				}
				return "x86"
			}
		}
	}

	// 只有Program Files就32位
	if utils.DirExists(filepath.Join(root, "Program Files")) {
		return "x86"
	}
	return "x86"
}

// 返回当前系统架构（32/64）
func systemArch() string {
	arch := strings.ToLower(os.Getenv("PROCESSOR_ARCHITECTURE"))
	wow := strings.ToLower(os.Getenv("PROCESSOR_ARCHITEW6432"))
	if strings.Contains(arch, "64") || strings.Contains(wow, "64") || runtime.GOARCH == "amd64" {
		return "64"
	}
	return "32"
}

// 全盘寻找镜像,跳过小于1g
func Findimg() ([]string, error) {
	drives, err := disk.ListDrive()
	if err != nil {
		return nil, err
	}

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		files    []string
		firstErr error
	)

	patterns := []string{"*.iso", "*.esd", "*.wim"}
	const maxDepth = 2                            // 搜 2 层目录
	const minSize = int64(1) * 1024 * 1024 * 1024 //跳过小于1g

	skipNames := map[string]struct{}{
		"03pe.wim":    {},
		"11pex64.wim": {},
	}
	validateImage := func(imagePath string) bool {
		if _, err := t.ListImageInfos(imagePath); err != nil {
			return false
		}
		return true
	}
	validateISO := func(isoPath string) bool {
		f, err := os.Open(isoPath)
		if err != nil {
			return false
		}
		defer f.Close()

		format, err := detectISOFormat(f)
		if err != nil {
			return false
		}
		if format != "iso9660" {
			return false
		}
		img, err := iso9660.OpenImage(f)
		if err != nil {
			return false
		}

		root, err := img.RootDir()
		if err != nil {
			return false
		}

		return hasISOInstallImage(root, "")
	}

	for _, root := range drives {
		root := root
		if disk.GetDriveType(root) == driveCdrom {
			continue
		}
		for _, pattern := range patterns {
			pattern := pattern

			wg.Add(1)
			go func() {
				defer wg.Done()

				found, err := file.FindFile(root, pattern, maxDepth)
				if err != nil {
					mu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					mu.Unlock()
					return
				}

				if len(found) > 0 {
					mu.Lock()
					files = append(files, found...)
					mu.Unlock()
				}
			}()
		}
	}

	wg.Wait()

	// 去重 + 过滤
	if len(files) > 0 {
		seen := make(map[string]struct{}, len(files))
		dst := files[:0]

		for _, p := range files {
			lp := strings.ToLower(p)
			base := strings.ToLower(filepath.Base(lp))

			if _, ok := skipNames[base]; ok {
				continue
			}

			fi, err := os.Stat(p)
			if err != nil || fi.IsDir() || fi.Size() < minSize {
				continue
			}

			if _, ok := seen[lp]; ok {
				continue
			}
			ext := strings.ToLower(filepath.Ext(p))
			switch ext {
			case ".iso":
				if !validateISO(p) {
					continue
				}
			case ".wim", ".esd":
				if !validateImage(p) {
					continue
				}
			default:
				continue
			}
			seen[lp] = struct{}{}
			dst = append(dst, p)
		}

		files = dst
	}
	//排列
	sort.Slice(files, func(i, j int) bool {
		pri := func(p string) int {
			switch strings.ToLower(filepath.Ext(p)) {
			case ".esd":
				return 0
			case ".wim":
				return 1
			case ".iso":
				return 2
			default:
				return 3
			}
		}
		pi, pj := pri(files[i]), pri(files[j])
		if pi != pj {
			return pi < pj
		}
		return strings.ToLower(files[i]) < strings.ToLower(files[j])
	})

	if firstErr != nil && len(files) == 0 {
		return nil, firstErr
	}
	return files, firstErr
}

// detectISOFormat 函数。
func detectISOFormat(r io.ReaderAt) (string, error) {
	const sectorSize = 2048
	header := make([]byte, sectorSize)
	if _, err := r.ReadAt(header, int64(16*sectorSize)); err != nil {
		return "", err
	}

	identifier := string(header[1:6])
	switch identifier {
	case "CD001":
		return "iso9660", nil
	case "BEA01":
		return "udf", nil
	default:
		return "", fmt.Errorf("unknown iso format: %s", identifier)
	}
}

// hasISOInstallImage 函数。
func hasISOInstallImage(entry *iso9660.File, base string) bool {
	name := strings.ToLower(entry.Name())
	path := name
	if base != "" {
		path = base + "/" + name
	}

	if !entry.IsDir() {
		if path == "sources/install.wim" || path == "sources/install.esd" {
			return true
		}
		return false
	}

	children, err := entry.GetChildren()
	if err != nil {
		return false
	}
	for _, child := range children {
		if hasISOInstallImage(child, path) {
			return true
		}
	}
	return false
}

// 写入重装文件
func writeResFile(imagePath string, target, arch string, index int) error {
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
func loadResData() (targetRoot string, diskPath string, imagePath string, volumeGuid string, diskUniqueID string, imageRel string, targetOS string, arch string, index int, err error) {
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
		if disk.GetDriveType(root) == driveFixed {
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
func resolveImagePath(diskPath, volumeGuid, diskUniqueID, imagePath, imageRel string) (string, error) {
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
func findTempRootByMarker() string {
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

// boolToUintptr 函数。
func boolToUintptr(v bool) uintptr {
	if v {
		return 1
	}
	return 0
}
