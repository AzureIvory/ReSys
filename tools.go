package main

import (
	"ReSys/src/log"
	tools "ReSys/src/tools"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
	"unsafe"

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
	if dirExists(filepath.Join(root, "Program Files")) {
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

// 目录/文件是否存在
func dirExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// 搜索文件
// root：目录
// pattern：文件，支持通配符，支持*.esd|*.wim|*.iso
// maxDepth：搜索子目录的层数
func FindFile(root string, pattern string, maxDepth int) ([]string, error) {
	if maxDepth < 0 {
		maxDepth = 0
	}

	root = filepath.Clean(root)

	fi, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("stat root: %w", err)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("root is not directory: %s", root)
	}

	// 支持 "*.esd|*.wim|*.iso"
	rawPats := strings.Split(pattern, "|")
	pats := make([]string, 0, len(rawPats))
	for _, p := range rawPats {
		p = strings.TrimSpace(p)
		if p != "" {
			pats = append(pats, p)
		}
	}
	if len(pats) == 0 {
		return nil, fmt.Errorf("empty pattern")
	}

	// 不进入这些目录
	skipDirs := map[string]struct{}{
		"system volume information": {},
		"$recycle.bin":              {},
		"Windows":                   {},
		"Program Files":             {},
		"Program Files (x86)":       {},
		"ProgramData":               {},
		"AppData":                   {},
		"Music":                     {},
		"Pictures":                  {},
		"Videos":                    {},
		"Temp":                      {},
	}

	var matches []string
	var fatalErr error

	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		if fatalErr != nil {
			return
		}
		if depth > maxDepth {
			return
		}

		ents, err := os.ReadDir(dir)
		if err != nil {
			return
		}

		for _, ent := range ents {
			if fatalErr != nil {
				return
			}

			name := ent.Name()
			full := filepath.Join(dir, name)

			if ent.IsDir() {
				if _, ok := skipDirs[strings.ToLower(name)]; ok {
					continue
				}
				if depth < maxDepth {
					walk(full, depth+1)
				}
				continue
			}

			// 通配符匹配
			if ent.Type().IsRegular() {
				for _, pat := range pats {
					ok, err := filepath.Match(pat, name)
					if err != nil {
						fatalErr = fmt.Errorf("bad pattern %q: %w", pat, err)
						return
					}
					if ok {
						matches = append(matches, full)
						break
					}
				}
			}
		}
	}

	walk(root, 0)

	if fatalErr != nil {
		return nil, fatalErr
	}
	return matches, nil
}

// 全盘寻找镜像,跳过小于1g
func Findimg() ([]string, error) {
	drives, err := ListDrive()
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
		if _, err := ListImageInfos(imagePath); err != nil {
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
		if GetDriveType(root) == driveCdrom {
			continue
		}
		for _, pattern := range patterns {
			pattern := pattern

			wg.Add(1)
			go func() {
				defer wg.Done()

				found, err := FindFile(root, pattern, maxDepth)
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

// 在所有盘符下搜索指定文件
// pattern：文件名，支持通配符，支持*.esd|*.wim|*.iso
// maxDepth：搜索子目录的层数
func FindFileAll(pattern string, maxDepth int) []string {
	drives, err := ListDrive()
	if err != nil || len(drives) == 0 {
		return []string{}
	}

	limit := runtime.NumCPU()
	if limit < 2 {
		limit = 2
	}
	sem := make(chan struct{}, limit)

	var (
		wg  sync.WaitGroup
		mu  sync.Mutex
		out = make([]string, 0, 128)
	)

	for _, d := range drives {
		driveRoot := d
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			files, e := FindFile(driveRoot, pattern, maxDepth)
			if e != nil || len(files) == 0 {
				return
			}

			mu.Lock()
			out = append(out, files...)
			mu.Unlock()
		}()
	}
	wg.Wait()

	// 去重 + 排序
	if len(out) == 0 {
		return []string{}
	}
	seen := make(map[string]struct{}, len(out))
	dedup := make([]string, 0, len(out))
	for _, p := range out {
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		dedup = append(dedup, p)
	}
	sort.Strings(dedup)
	return dedup
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
		if diskNum, err := GetDiskNum(imageRoot); err == nil {
			diskPath = fmt.Sprintf(`\\.\PhysicalDrive%d`, diskNum)
			if disks, derr := ListPhysicalDisks(); derr == nil {
				for _, d := range disks {
					if d.DiskNumber == int(diskNum) {
						diskUniqueID = strings.TrimSpace(d.UniqueId)
						break
					}
				}
			}
		}
		if vols, verr := ListVolumes(); verr == nil {
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
	drives, err := ListDrive()
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
		if GetDriveType(root) == driveFixed {
			score += 10
		}

		kind, _ := GetDiskKind(root)
		if kind == "SSD" {
			score += 30
		} else if kind == "HDD" {
			score += 20
		} else if kind == "Removable" {
			score -= 50
		}

		// 有离线Windows说明这盘更可能就是要重装的系统盘
		if _, werr := DetectWin(root); werr == nil {
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
			found, _ := FindFile(root, base, 3)
			if len(found) > 0 {
				return found[0], true
			}
		}
		return "", false
	}

	volumeGuid = strings.TrimSpace(volumeGuid)
	if volumeGuid != "" {
		vols, err := ListVolumes()
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

		disks, err := ListPhysicalDisks()
		if err != nil {
			log.LogWrite(0, "[resolveImagePath]读取物理磁盘唯一ID失败：%v", err)
		} else {
			for _, d := range disks {
				if strings.EqualFold(strings.TrimSpace(d.UniqueId), diskUniqueID) {
					if _, roots, err := GetDiskPartitions(fmt.Sprintf("%d", d.DiskNumber)); err == nil {
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
		_, roots, err := GetDiskPartitions(diskPath)
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

	roots, _ := ListDrive()
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
				found, _ := FindFile(root, base, 3)
				if len(found) > 0 {
					return found[0], nil
				}
			}
		}
	}
	return "", fmt.Errorf("未找到镜像文件")
}

// 从多个候选里挑最合适的pe(一般不会用到)
func chooseBestWim(paths []string, arch string) string {
	if len(paths) == 0 {
		return ""
	}
	arch = strings.TrimSpace(strings.ToLower(arch))

	score := func(p string) int {
		s := 0
		lp := strings.ToLower(p)

		if strings.Contains(lp, `\petemp\boot.wim`) {
			s += 300
		}
		if strings.Contains(lp, `\petemp\`) {
			s += 100
		}
		if strings.Contains(lp, "wepe") {
			s += 50
		}
		if strings.Contains(lp, "firpe") || strings.Contains(lp, "hotpe") {
			s += 20
		}

		// 架构偏好
		if arch == "64" {
			if strings.Contains(lp, "64") || strings.Contains(lp, "x64") || strings.Contains(lp, "amd64") {
				s += 20
			}
			if strings.Contains(lp, "32") || strings.Contains(lp, "x86") {
				s -= 10
			}
		} else if arch == "32" {
			if strings.Contains(lp, "32") || strings.Contains(lp, "x86") {
				s += 20
			}
			if strings.Contains(lp, "64") || strings.Contains(lp, "x64") || strings.Contains(lp, "amd64") {
				s -= 10
			}
		}
		return s
	}

	best := paths[0]
	bestScore := score(best)
	for _, p := range paths[1:] {
		if sc := score(p); sc > bestScore {
			best, bestScore = p, sc
		}
	}
	return best
}

type peOpt struct {
	n, s, w, a string
}

type peCand struct {
	nm   string
	arch string // opts 的 a
	lt   string // 盘符字母，如 "C"
	root string // 如 "C:\"
	wAbs string
	wRel string
	sAbs string
	sRel string
	sPat string // opts.s（用于缺 SDI 时决定复制到哪里）
}

// parseGoToPEArgs 函数。
func parseGoToPEArgs(paths []string) (string, string, error) {
	if len(paths) == 0 {
		return "", "", nil
	}
	if len(paths) != 2 {
		return "", "", fmt.Errorf("参数数量错误：GoToPE(scan) 或 GoToPE(scan, sdiPath, wimPath)")
	}
	customSdi := strings.TrimSpace(paths[0])
	customWim := strings.TrimSpace(paths[1])
	if customSdi == "" || customWim == "" {
		return "", "", fmt.Errorf("自定义路径需要同时指定 sdi 和 wim（要么都传，要么都不传）")
	}
	return customSdi, customWim, nil
}

// collectPECands 函数。
func collectPECands(dvs []string, opts []peOpt, wantArch, customSdi, customWim string) (map[string]peCand, []string, error) {
	hasGlob := func(s string) bool { return strings.ContainsAny(s, "*?[") }
	hasDrivePrefix := func(p string) bool { return len(p) >= 2 && p[1] == ':' }

	// 把 abs 变成相对卷根 \xxx\yyy
	toRel := func(root, abs string) string {
		abs = strings.ReplaceAll(abs, "/", `\`)
		root = strings.ReplaceAll(root, "/", `\`)
		if len(abs) >= len(root) && strings.EqualFold(abs[:len(root)], root) {
			rest := abs[len(root):]
			rest = strings.TrimPrefix(rest, `\`)
			return `\` + rest
		}
		if len(abs) >= 3 && abs[1] == ':' && (abs[2] == '\\' || abs[2] == '/') {
			return `\` + strings.TrimPrefix(abs[3:], `\`)
		}
		return abs
	}

	// 返回所有匹配（大小写不敏感 + 支持通配符）
	allMatchesInsensitive := func(pattern string) ([]string, error) {
		pattern = strings.ReplaceAll(pattern, "/", `\`)

		if !hasGlob(pattern) {
			if dirExists(pattern) {
				return []string{pattern}, nil
			}
			return nil, nil
		}

		dir := filepath.Dir(pattern)
		base := filepath.Base(pattern)

		if hasGlob(dir) {
			ms, _ := filepath.Glob(pattern)
			var out []string
			for _, m := range ms {
				if dirExists(m) {
					out = append(out, m)
				}
			}
			return out, nil
		}

		entries, e := os.ReadDir(dir)
		if e != nil {
			ms, _ := filepath.Glob(pattern)
			var out []string
			for _, m := range ms {
				if dirExists(m) {
					out = append(out, m)
				}
			}
			return out, nil
		}

		patLower := strings.ToLower(base)
		var out []string
		for _, ent := range entries {
			if ent.IsDir() {
				continue
			}
			nameLower := strings.ToLower(ent.Name())
			ok, _ := filepath.Match(patLower, nameLower)
			if ok {
				out = append(out, filepath.Join(dir, ent.Name()))
			}
		}
		return out, nil
	}

	firstMatchInsensitive := func(pattern string) (string, bool) {
		ms, _ := allMatchesInsensitive(pattern)
		if len(ms) > 0 {
			return ms[0], true
		}
		return "", false
	}

	candByWim := map[string]peCand{}
	var allWims []string

	addCand := func(c peCand) {
		if old, ok := candByWim[c.wAbs]; ok {
			// 只做最小规则：优先保留“有 SDI”的
			if old.sAbs == "" && c.sAbs != "" {
				candByWim[c.wAbs] = c
			}
			return
		}
		candByWim[c.wAbs] = c
		allWims = append(allWims, c.wAbs)
	}

	if customSdi != "" && customWim != "" {
		sPat := strings.ReplaceAll(customSdi, "/", `\`)
		wPat := strings.ReplaceAll(customWim, "/", `\`)

		// 绝对路径
		if hasDrivePrefix(sPat) || hasDrivePrefix(wPat) {
			var vol string
			if hasDrivePrefix(sPat) {
				vol = strings.ToUpper(string(sPat[0]))
			}
			if hasDrivePrefix(wPat) {
				wVol := strings.ToUpper(string(wPat[0]))
				if vol != "" && vol != wVol {
					return nil, nil, fmt.Errorf("sdi 和 wim 不在同一盘：%s vs %s", vol, wVol)
				}
				if vol == "" {
					vol = wVol
				}
			}
			root := vol + `:\`

			// WIM 必须存在
			wAbs, ok := firstMatchInsensitive(wPat)
			if !ok {
				return nil, nil, fmt.Errorf("未找到WIM: %s", wPat)
			}

			sAbs, _ := firstMatchInsensitive(sPat)

			addCand(peCand{
				nm: "CUSTOM", arch: "",
				lt: vol, root: root,
				wAbs: wAbs, wRel: toRel(root, wAbs),
				sAbs: sAbs, sRel: func() string {
					if sAbs == "" {
						return ""
					}
					return toRel(root, sAbs)
				}(),
				sPat: sPat, // 直接用sPat，补 SDI 时会 materialize
			})
			return candByWim, allWims, nil
		}

		// 相对路径：遍历盘符
		for _, d := range dvs {
			if len(d) < 3 {
				continue
			}
			vol := strings.ToUpper(string(d[0]))
			root := vol + `:\`

			wAbs, okW := firstMatchInsensitive(d + strings.TrimPrefix(wPat, `\`))
			if !okW {
				continue
			}
			sAbs, _ := firstMatchInsensitive(d + strings.TrimPrefix(sPat, `\`))

			addCand(peCand{
				nm: "CUSTOM", arch: "",
				lt: vol, root: root,
				wAbs: wAbs, wRel: toRel(root, wAbs),
				sAbs: sAbs, sRel: func() string {
					if sAbs == "" {
						return ""
					}
					return toRel(root, sAbs)
				}(),
				sPat: `\` + strings.TrimPrefix(sPat, `\`),
			})
			return candByWim, allWims, nil
		}
		return nil, nil, fmt.Errorf("未找到匹配的SDI/WIM：SDI=%s WIM=%s", sPat, wPat)
	}

	// 按 opts 扫描所有盘符
	for _, o := range opts {
		if o.a != "" && utils.NormalizeArch(o.a) != utils.NormalizeArch(wantArch) {
			continue
		}

		for _, d := range dvs {
			if len(d) < 3 {
				continue
			}
			vol := strings.ToUpper(string(d[0]))
			root := vol + `:\`

			// SDI 可缺失（只取第一个匹配）
			sAbs := ""
			sMatches, _ := allMatchesInsensitive(d + strings.TrimPrefix(o.s, `\`))
			if len(sMatches) > 0 {
				sAbs = sMatches[0]
			}

			// WIM 收集全部
			wMatches, _ := allMatchesInsensitive(d + strings.TrimPrefix(o.w, `\`))
			for _, wAbs := range wMatches {
				c := peCand{
					nm:   o.n,
					arch: o.a,
					lt:   vol,
					root: root,
					wAbs: wAbs,
					wRel: toRel(root, wAbs),
					sAbs: sAbs,
					sRel: "",
					sPat: o.s,
				}
				if sAbs != "" {
					c.sRel = toRel(root, sAbs)
				}
				addCand(c)
			}
		}
	}
	return candByWim, allWims, nil
}

// 用 tools\boot.sdi 生成目标 SDI（只在缺 SDI 时调用）
func ensureSdiByCopy(root string, sPatRel string, wAbs string) (sAbs string, sRel string, err error) {
	findToolsBootSdi := func() (string, bool) {
		exe, e := os.Executable()
		if e != nil {
			return "", false
		}
		base := filepath.Dir(exe)
		cands := []string{
			filepath.Join(base, "tools", "boot.sdi"),
			filepath.Join(base, "tools", "BOOT.SDI"),
			filepath.Join(base, "tools", "Boot.sdi"),
		}
		for _, p := range cands {
			if dirExists(p) {
				return p, true
			}
		}
		return "", false
	}

	toRel := func(root, abs string) string {
		abs = strings.ReplaceAll(abs, "/", `\`)
		root = strings.ReplaceAll(root, "/", `\`)
		if len(abs) >= len(root) && strings.EqualFold(abs[:len(root)], root) {
			rest := abs[len(root):]
			rest = strings.TrimPrefix(rest, `\`)
			return `\` + rest
		}
		if len(abs) >= 3 && abs[1] == ':' && (abs[2] == '\\' || abs[2] == '/') {
			return `\` + strings.TrimPrefix(abs[3:], `\`)
		}
		return abs
	}

	materializeSdiRel := func(sPat string) string {
		sPat = strings.ReplaceAll(sPat, "/", `\`)
		if sPat == "" {
			return ""
		}
		if !strings.ContainsAny(sPat, "*?[") {
			return sPat
		}
		dir := filepath.Dir(sPat)
		dst := filepath.Join(dir, "boot.sdi")
		if !strings.HasPrefix(dst, `\`) {
			dst = `\` + dst
		}
		return dst
	}

	src, ok := findToolsBootSdi()
	if !ok {
		return "", "", fmt.Errorf("缺少SDI，且未找到 %s", `tools\boot.sdi`)
	}

	dstRel := materializeSdiRel(sPatRel)
	if dstRel == "" {
		dstAbs := filepath.Join(filepath.Dir(wAbs), "boot.sdi")
		if e := Copy(src, dstAbs, false, true); e != nil {
			return "", "", e
		}
		return dstAbs, toRel(root, dstAbs), nil
	}

	dstAbs := filepath.Join(root, strings.TrimPrefix(dstRel, `\`))
	if e := Copy(src, dstAbs, false, true); e != nil {
		return "", "", e
	}
	return dstAbs, toRel(root, dstAbs), nil
}

// applyPEBoot 函数。
func applyPEBoot(best peCand) error {
	lt, sdi, wim, nm := best.lt, best.sRel, best.wRel, best.nm
	log.LogWrite(0, "[applyPEBoot]PE:", nm, "DRV:", lt, "SDI:", sdi, "WIM:", wim)

	bcdeditPath := utils.GetSystemExe("bcdedit.exe")
	out, err := tools.RunCmd(bcdeditPath, nil, nil, "")
	if err != nil && (errors.Is(err, os.ErrNotExist) || errors.Is(err, exec.ErrNotFound)) {
		exe, e := os.Executable()
		if e == nil {
			bcdeditPath = filepath.Join(filepath.Dir(exe), "tools", "bcdedit.exe")
		}
	}

	// /device guid
	out, err = tools.RunCmd(bcdeditPath, nil, nil, "", "/create", "/d", "pe", "/device")
	if err != nil {
		return err
	}
	re := regexp.MustCompile(`(?i)\{([a-f0-9-]+)\}`)
	m1 := re.FindStringSubmatch(out)
	if len(m1) < 2 {
		return fmt.Errorf("guid1解析失败: %s", out)
	}
	gd1 := strings.ToLower(m1[1])

	// ramdisksdi*
	_, err = tools.RunCmd(bcdeditPath, nil, nil, "", "/set", "{"+gd1+"}", "ramdisksdidevice", "partition="+lt+":")
	if err != nil {
		return err
	}
	_, err = tools.RunCmd(bcdeditPath, nil, nil, "", "/set", "{"+gd1+"}", "ramdisksdipath", sdi)
	if err != nil {
		return err
	}

	// /application osloader guid2
	out, err = tools.RunCmd(bcdeditPath, nil, nil, "", "/create", "/d", "pe", "/application", "osloader")
	if err != nil {
		return err
	}
	m2 := re.FindStringSubmatch(out)
	if len(m2) < 2 {
		return fmt.Errorf("guid2解析失败: %s", out)
	}
	gd2 := strings.ToLower(m2[1])

	// device/osdevice
	dev := fmt.Sprintf("ramdisk=[%s:]%s,{%s}", lt, wim, gd1)
	_, err = tools.RunCmd(bcdeditPath, nil, nil, "", "/set", "{"+gd2+"}", "device", dev)
	if err != nil {
		return err
	}
	_, err = tools.RunCmd(bcdeditPath, nil, nil, "", "/set", "{"+gd2+"}", "osdevice", dev)
	if err != nil {
		return err
	}

	// BIOS/UEFI
	fw := 0 // 1=BIOS 2=UEFI

	if t, e := GetFwType(); e == nil {
		// 1=BIOS 2=UEFI 0=Unknown
		if t == 1 || t == 2 {
			fw = int(t)
		}
	} else {
		log.LogWrite(0, "[applyPEBoot]applyPEBoot: GetFwType 失败，走其他方案: %v", e)
	}

	// WinPE 注册表 PEFirmwareType（可能不存在；不存在时 reg 会 exit 1）
	if fw == 0 {
		regPath := utils.GetSystemExe("reg.exe")

		// 有些 WinPE 需要先 UpdateBootInfo 才会写出 PEFirmwareType
		wpeutilPath := utils.GetSystemExe("wpeutil.exe")
		if _, stErr := os.Stat(wpeutilPath); stErr == nil {
			_, _ = tools.RunCmd(wpeutilPath, nil, nil, "", "UpdateBootInfo")
		}

		regOut, er2 := tools.RunCmd(regPath, nil, nil, "", "query",
			`HKLM\SYSTEM\CurrentControlSet\Control`, "/v", "PEFirmwareType")

		if er2 == nil {
			r2 := regexp.MustCompile(`(?i)0x([0-9a-f]+)`)
			m3 := r2.FindStringSubmatch(regOut)
			if len(m3) >= 2 {
				if v, e3 := strconv.ParseInt(m3[1], 16, 32); e3 == nil {
					if v == 1 || v == 2 {
						fw = int(v)
					}
				}
			}
		} else {
			log.LogWrite(0, "[applyPEBoot]applyPEBoot: PEFirmwareType 不可用(忽略): %v", er2)
		}
	}

	// 用 bcdedit 判断 {fwbootmgr}（UEFI 通常存在）
	if fw == 0 {
		if _, e := tools.RunCmd(bcdeditPath, nil, nil, "", "/enum", "{fwbootmgr}"); e == nil {
			fw = 2
		} else {
			fw = 1
		}
	}

	p1 := `\windows\system32\boot\winload.efi`
	p2 := `\windows\system32\boot\winload.exe`
	if fw == 1 {
		p1, p2 = p2, p1
	}
	if _, err = tools.RunCmd(bcdeditPath, nil, nil, "", "/set", "{"+gd2+"}", "path", p1); err != nil {
		if _, err = tools.RunCmd(bcdeditPath, nil, nil, "", "/set", "{"+gd2+"}", "path", p2); err != nil {
			return err
		}
	}

	if _, err = tools.RunCmd(bcdeditPath, nil, nil, "", "/set", "{"+gd2+"}", "systemroot", `\windows`); err != nil {
		return err
	}
	if _, err = tools.RunCmd(bcdeditPath, nil, nil, "", "/set", "{"+gd2+"}", "detecthal", "YES"); err != nil {
		return err
	}
	if _, err = tools.RunCmd(bcdeditPath, nil, nil, "", "/set", "{"+gd2+"}", "winpe", "YES"); err != nil {
		return err
	}
	if _, err = tools.RunCmd(bcdeditPath, nil, nil, "", "/set", "{"+gd2+"}", "nx", "OptIn"); err != nil {
		return err
	}

	// 设置下次启动
	if _, err = tools.RunCmd(bcdeditPath, nil, nil, "", "/bootsequence", "{"+gd2+"}"); err != nil {
		return err
	}
	return nil
}

// 进入PE + 扫描模式：scan=true 时只返回最优 WIM/SDI
// 用法示例：
//
//	ok, wim, sdi, err := GoToPE(true)          // 扫描
//	_, _, _, err := GoToPE(false)             // 设置下次启动进PE
//	ok, wim, sdi, err := GoToPE(true, sdiPath, wimPath)   // 扫描/校验自定义
//	_, _, _, err := GoToPE(false, sdiPath, wimPath)       // 自定义设置启动
func GoToPE(scan bool, paths ...string) (bool, string, string, error) {
	customSdi, customWim, err := parseGoToPEArgs(paths)
	if err != nil {
		log.LogWrite(0, "[GoToPE]GoToPE 参数解析失败："+err.Error())
		return false, "", "", err
	}

	dvs, err := ListDrive()
	if err != nil {
		log.LogWrite(0, "[GoToPE]GoToPE ListDrive失败："+err.Error())
		return false, "", "", err
	}

	wantArch := utils.NormalizeArch(utils.SelfArch())
	if utils.IsWOW64() {
		wantArch = "64"
	}

	opts := []peOpt{
		{"WEPE", `\WEPE\WEPE.SDI`, `\WEPE\WEPE64.WIM`, "64"},    //64位微PE
		{"WEPE", `\WEPE\WEPE.SDI`, `\WEPE\WEPE32.WIM`, "32"},    //32位微PE
		{"FIR", `\FirPE\BOOT.SDI`, `\FirPE\11PEX64.WIM`, "64"},  //64位win11的FirPE
		{"FIR", `\FirPE\BOOT.SDI`, `\FirPE\11PEX86.WIM`, "32"},  //32位FirPE
		{"HOT", `\HotPE\boot.sdi`, `\HotPE\Boot.wim`, "64"},     //64位HOTPE
		{"FirPE1", `\boot\boot.sdi`, `\boot\11pex64.wim`, "64"}, //64位FirPE1
		{"FirPE1", `\boot\boot.sdi`, `\boot\11pex86.wim`, "32"}, //32位FirPE1
		{"PETEMP", `\PETEMP\*.sdi`, `\PETEMP\*.wim`, ""},        //不强制架构，交给 chooseBestWim
		{"PETEMP", `\PETEMP\*.SDI`, `\PETEMP\*.WIM`, ""},
	}

	candByWim, allWims, err := collectPECands(dvs, opts, wantArch, customSdi, customWim)
	if err != nil {
		log.LogWrite(0, "[GoToPE]GoToPE collectPECands失败: err=%v", err)
		if scan {
			return false, "", "", err
		}
		return false, "", "", err
	}

	if len(allWims) == 0 {
		if scan {
			return false, "", "", nil
		}
		log.LogWrite(0, "[GoToPE]GoToPE 未找到PE引导文件")
		return false, "", "", fmt.Errorf("未找到PE引导文件")
	}

	bestWim := chooseBestWim(allWims, wantArch)
	best, ok := candByWim[bestWim]
	if !ok || bestWim == "" {
		if scan {
			return false, "", "", nil
		}
		log.LogWrite(0, "[GoToPE]GoToPE 选优失败: bestWim=%s wantArch=%s", bestWim, wantArch)
		return false, "", "", fmt.Errorf("chooseBestWim 选优失败")
	}

	if best.sAbs == "" {
		sAbs, sRel, e := ensureSdiByCopy(best.root, best.sPat, best.wAbs)
		if e == nil {
			best.sAbs = sAbs
			best.sRel = sRel
			candByWim[best.wAbs] = best
		} else if !scan {
			log.LogWrite(0, "[GoToPE]GoToPE 自动补齐SDI失败: wim=%s err=%v", best.wAbs, e)
			return true, best.wAbs, "", e
		}
	}

	if scan {
		return true, best.wAbs, best.sAbs, nil
	}

	if best.sRel == "" {
		log.LogWrite(0, "[GoToPE]GoToPE 缺少SDI无法设置引导: wim=%s", best.wAbs)
		return true, best.wAbs, best.sAbs, fmt.Errorf("找到WIM但仍缺少SDI，无法设置ramdisk引导：WIM=%s", best.wAbs)
	}

	if err := applyPEBoot(best); err != nil {
		log.LogWrite(0, "[GoToPE]GoToPE 设置引导失败: wim=%s sdi=%s err=%v", best.wAbs, best.sAbs, err)
		return false, "", "", err
	}
	return false, "", "", nil
}

// 从指定的文件中，按偏移区间 [start, end) 抽取数据，写入到指定的文件中。
// 支持十进制和十六进制的偏移参数
func PeelFile(exePath, start, end, out string) error {
	if exePath == "" {
		return errors.New("exePath 不能为空")
	}
	if out == "" {
		return errors.New("out 不能为空")
	}

	startOffset, err := parseOffsetString(start)
	if err != nil {
		return fmt.Errorf("解析 startOffset 失败: %w", err)
	}
	endOffset, err := parseOffsetString(end)
	if err != nil {
		return fmt.Errorf("解析 endOffset 失败: %w", err)
	}

	if startOffset < 0 || endOffset < 0 {
		return errors.New("startOffset/endOffset 不能为负数")
	}
	if endOffset <= startOffset {
		return fmt.Errorf("endOffset 必须大于 startOffset（区间为 [start,end)），当前 start=%d end=%d", startOffset, endOffset)
	}

	// 输入文件
	in, err := os.Open(exePath)
	if err != nil {
		return fmt.Errorf("打开输入文件失败: %w", err)
	}
	defer in.Close()

	st, err := in.Stat()
	if err != nil {
		return fmt.Errorf("获取输入文件信息失败: %w", err)
	}
	size := st.Size()
	if startOffset >= size {
		return fmt.Errorf("startOffset 超出文件大小: start=%d size=%d", startOffset, size)
	}
	if endOffset > size {
		return fmt.Errorf("endOffset 超出文件大小: end=%d size=%d", endOffset, size)
	}

	if !filepath.IsAbs(out) {
		return fmt.Errorf("out 必须是绝对路径: %s", out)
	}

	outDir := filepath.Dir(out)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("创建输出目录失败: %w", err)
	}

	// 输出文件
	out1, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("创建输出文件失败: %w", err)
	}
	defer func() { _ = out1.Close() }()

	// 只读取指定区间
	length := endOffset - startOffset
	section := io.NewSectionReader(in, startOffset, length)

	// 拷贝
	buf := make([]byte, 1024*1024) // 1MB buffer
	written, err := io.CopyBuffer(out1, section, buf)
	if err != nil {
		return fmt.Errorf("写出失败: %w", err)
	}
	if written != length {
		return fmt.Errorf("写出字节数不一致: expect=%d got=%d", length, written)
	}

	if err := out1.Sync(); err != nil {
		return fmt.Errorf("输出文件 Sync 失败: %w", err)
	}
	return nil
}

// 解析偏移字符串：
func parseOffsetString(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("偏移字符串为空")
	}

	// 处理符号
	if strings.HasPrefix(s, "-") {
		return 0, fmt.Errorf("不允许负数偏移: %s", s)
	}
	s = strings.TrimPrefix(s, "+")

	// 判定进制
	base := 10
	ss := strings.ToLower(s)

	if strings.HasPrefix(ss, "0x") {
		base = 16
		ss = ss[2:]
		if ss == "" {
			return 0, fmt.Errorf("无效十六进制偏移: %s", s)
		}
	} else {
		// 不带 0x：如果包含 a-f，则认为是十六进制；否则十进制
		for _, r := range ss {
			if unicode.IsLetter(r) {
				base = 16
				break
			}
		}
	}

	// 用 uint64 解析
	u, err := strconv.ParseUint(ss, base, 64)
	if err != nil {
		return 0, fmt.Errorf("无法解析偏移 %q (base=%d): %w", s, base, err)
	}
	maxInt64u := ^uint64(0) >> 1 // 0x7FFF... = MaxInt64
	if u > maxInt64u {
		return 0, fmt.Errorf("偏移过大，超出 int64 范围: %d", u)
	}
	return int64(u), nil
}

// 返回本机物理内存总量
// 返回值GB
func GetMemory() (float64, error) {
	var m memoryStatusEx
	m.dwLength = uint32(unsafe.Sizeof(m))

	r1, _, e1 := procGlobalMemoryStatus.Call(uintptr(unsafe.Pointer(&m)))
	if r1 == 0 {
		if errno, ok := e1.(syscall.Errno); ok && errno != 0 {
			return 0, errno
		}
		return 0, syscall.EINVAL
	}

	const gib = 1024 * 1024 * 1024
	return float64(m.ullTotalPhys) / float64(gib), nil
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
	drives, _ := ListDrive()
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
