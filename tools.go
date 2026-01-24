package main

import (
	"bytes"
	"context"
	"encoding/binary"
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
	"unicode/utf16"
	"unsafe"
)

func hresultFailed(hr uintptr) bool {
	return int32(hr) < 0
}

// 返回 tools 目录下对应系统/架构的 dism.exe 绝对路径。
// tools/xp/dism.exe 或 tools/32/dism.exe 或 tools/64/dism.exe
func GetDism() (string, error) {
	baseDir := ""
	if exe, err := os.Executable(); err == nil {
		baseDir = filepath.Dir(exe)
	}
	if baseDir == "" {
		baseDir = "."
	}

	subDir := "32"
	if isWinXP() {
		subDir = "xp"
	} else if systemArch() == "64" {
		subDir = "64"
	}

	p := filepath.Join(baseDir, "tools", subDir, "dism.exe")
	if st, err := os.Stat(p); err != nil || st.IsDir() {
		if err != nil {
			return "", fmt.Errorf("dism.exe not found: %s: %w", p, err)
		}
		return "", fmt.Errorf("dism.exe not found: %s", p)
	}
	return p, nil
}

// 推测指定盘符的系统架构（32/64）
func detectArch(root string, hasPFx86, hasSysWOW, systemLoaded bool) string {
	if hasPFx86 || hasSysWOW {
		return "x64"
	}

	// SYSTEM hive 里的环境变量
	if systemLoaded {
		keyPath := `Offline_SYSTEM\ControlSet001\Control\Session Manager\Environment`
		if h, err := RegOpenKey(HKEY_LOCAL_MACHINE, keyPath); err == nil {
			defer RegCloseKey(h)
			if s, err := RegGetString(h, "PROCESSOR_ARCHITECTURE"); err == nil && s != "" {
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

// 规范化盘符为 "D:\" 这种格式
func normalizeRoot(drive string) (string, error) {
	s := strings.TrimSpace(drive)
	if s == "" {
		return "", fmt.Errorf("empty drive")
	}
	s = strings.ReplaceAll(s, "/", `\`)

	if len(s) == 1 { // "D"
		s = s + ":"
	}
	if len(s) == 2 && s[1] == ':' { // "D:"
		s = s + `\`
	}
	if len(s) != 3 || s[1] != ':' || s[2] != '\\' {
		return "", fmt.Errorf("invalid drive: %q", drive)
	}
	s = strings.ToUpper(s[:1]) + s[1:]
	return s, nil
}

// normalizeRootPath 统一盘符为类似 "C:\" 的格式。
func normalizeRootPath(root string) string {
	if root == "" {
		return root
	}
	root = strings.ReplaceAll(root, "/", `\`)
	if len(root) == 2 && root[1] == ':' {
		root += `\`
	}
	if len(root) == 1 {
		root += `:\`
	}
	return root
}

// volumeRootFromPath 从路径中提取盘符根（例如 C:\）。
func volumeRootFromPath(p string) string {
	if len(p) >= 3 && p[1] == ':' {
		return strings.ToUpper(p[:1]) + `:\`
	}
	return ""
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
		isoRoot, err := MountISO(isoPath, 30*time.Second)
		if err != nil {
			return false
		}
		found, err := FindFile(isoRoot, "install.wim|install.esd", 3)
		if err != nil || len(found) == 0 {
			return false
		}
		sort.Strings(found)
		for _, candidate := range found {
			fi, err := os.Stat(candidate)
			if err != nil || fi.IsDir() || fi.Size() < minSize {
				continue
			}
			if validateImage(candidate) {
				return true
			}
		}
		return false
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

// 写入重装文件
func writeResFile(imagePath string) error {
	imagePath, _ = filepath.Abs(imagePath)
	imageRoot := volumeRootFromPath(imagePath)
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
				if normalizeRootPath(v.RootPath) == normalizeRootPath(imageRoot) {
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
	restallPath := normalizeRootPath(systemDrive) + "restall_win.dat"
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
func loadResData() (targetRoot string, diskPath string, imagePath string, volumeGuid string, diskUniqueID string, imageRel string, err error) {
	drives, err := ListDrive()
	if err != nil {
		return "", "", "", "", "", "", err
	}
	for _, root := range drives {
		cand := filepath.Join(root, "restall_win.dat")
		if _, err := os.Stat(cand); err == nil {
			targetRoot = normalizeRootPath(root)
			b, err := os.ReadFile(cand)
			if err != nil {
				return targetRoot, "", "", "", "", "", err
			}
			lines := strings.Split(string(b), "\n")
			for _, ln := range lines {
				ln = strings.TrimSpace(ln)
				if strings.HasPrefix(ln, "disk=") {
					diskPath = strings.TrimSpace(strings.TrimPrefix(ln, "disk="))
				}
				if strings.HasPrefix(ln, "image=") {
					imagePath = strings.TrimSpace(strings.TrimPrefix(ln, "image="))
				}
				if strings.HasPrefix(ln, "volume_guid=") {
					volumeGuid = strings.TrimSpace(strings.TrimPrefix(ln, "volume_guid="))
				}
				if strings.HasPrefix(ln, "disk_unique_id=") {
					diskUniqueID = strings.TrimSpace(strings.TrimPrefix(ln, "disk_unique_id="))
				}
				if strings.HasPrefix(ln, "image_rel=") {
					imageRel = strings.TrimSpace(strings.TrimPrefix(ln, "image_rel="))
				}
			}
			return targetRoot, diskPath, imagePath, volumeGuid, diskUniqueID, imageRel, nil
		}
	}
	return "", "", "", "", "", "", fmt.Errorf("未找到 restall_win.dat")
}

// 根据 restall 信息定位镜像：
// 根据 restall 信息定位镜像：
func resolveImagePath(diskPath, volumeGuid, diskUniqueID, imagePath, imageRel string) (string, error) {
	if imagePath != "" {
		if _, err := os.Stat(imagePath); err == nil {
			return imagePath, nil
		}
		logWrite("restall镜像路径不可用：%s", imagePath)
	}

	base := filepath.Base(imagePath)
	if base == "" && imageRel != "" {
		base = filepath.Base(imageRel)
	}

	tryRoot := func(root string) (string, bool) {
		root = normalizeRootPath(root)
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
			logWrite("读取卷GUID失败：%v", err)
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
					logWrite("卷GUID匹配但未找到镜像：%s", volumeGuid)
					break
				}
			}
		}
	}

	diskUniqueID = strings.TrimSpace(diskUniqueID)
	if diskUniqueID != "" {

		disks, err := ListPhysicalDisks()
		if err != nil {
			logWrite("读取物理磁盘唯一ID失败：%v", err)
		} else {
			for _, d := range disks {
				if strings.EqualFold(strings.TrimSpace(d.UniqueId), diskUniqueID) {
					if _, roots, err := GetDiskPartitions(fmt.Sprintf("%d", d.DiskNumber)); err == nil {
						for _, root := range roots {
							if cand, ok := tryRoot(root); ok {
								return cand, nil
							}
						}
						logWrite("物理磁盘唯一ID匹配但未找到镜像：%s", diskUniqueID)
					} else {
						logWrite("物理磁盘唯一ID匹配但分区读取失败：%s err=%v", diskUniqueID, err)
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
			logWrite("根据物理磁盘路径未找到镜像：%s", diskPath)
		} else if err != nil {
			logWrite("读取物理磁盘路径失败：%s err=%v", diskPath, err)
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

// 返回有足够大小的分区数组
// SSD>HDD>USB
func Findpart() []string {
	D, err := ListDrive()
	if err != nil {
		return nil
	}

	type cand struct {
		path string
		kind string
		free uint64
		pri  int
	}

	var cs []cand

	for i := 0; i < len(D); i++ {
		root := D[i]

		freeBytes, err := GetFreeSize(root)
		if err != nil {
			continue
		}
		if freeBytes <= 7516192768 { // > 7g才算
			continue
		}

		// 磁盘类型
		kind, err := GetDiskKind(root)
		if err != nil {
			continue
		}
		if kind == "CDROM" || kind == "Unknown" {
			continue
		}

		pri := 0
		switch kind {
		case "SSD":
			pri = 3
		case "HDD":
			pri = 2
		case "Removable":
			pri = 1
		default:
			pri = 0
		}
		if pri == 0 {
			continue
		}

		cs = append(cs, cand{
			path: root,
			kind: kind,
			free: freeBytes,
			pri:  pri,
		})
	}

	// 排序
	if len(cs) == 0 {
		return nil
	}

	sort.Slice(cs, func(i, j int) bool {
		if cs[i].pri != cs[j].pri {
			return cs[i].pri > cs[j].pri // 类型优先级高的在前
		}
		if cs[i].free != cs[j].free {
			return cs[i].free > cs[j].free // 同一类型剩余空间大的在前
		}
		return cs[i].path < cs[j].path
	})

	part := make([]string, 0, len(cs))
	for _, c := range cs {
		part = append(part, c.path)
	}
	logWrite("Findpart: %v", part)
	return part
}

// 进入PE + 扫描模式：scan=true 时只返回最优 WIM/SDI
// 用法示例：
//
//	ok, wim, sdi, err := GoToPE(true)          // 扫描
//	_, _, _, err := GoToPE(false)             // 设置下次启动进PE
//	ok, wim, sdi, err := GoToPE(true, sdiPath, wimPath)   // 扫描/校验自定义
//	_, _, _, err := GoToPE(false, sdiPath, wimPath)       // 自定义设置启动
func GoToPE(scan bool, paths ...string) (bool, string, string, error) {
	var customSdi, customWim string
	if len(paths) == 0 {
	} else if len(paths) == 2 {
		customSdi = strings.TrimSpace(paths[0])
		customWim = strings.TrimSpace(paths[1])
		if customSdi == "" || customWim == "" {
			return false, "", "", fmt.Errorf("自定义路径需要同时指定 sdi 和 wim（要么都传，要么都不传）")
		}
	} else {
		return false, "", "", fmt.Errorf("参数数量错误：GoToPE(scan) 或 GoToPE(scan, sdiPath, wimPath)")
	}

	dvs, err := ListDrive()
	if err != nil {
		return false, "", "", err
	}

	wantArch := func() string {
		isWow64 := runtime.GOARCH == "386" && os.Getenv("PROCESSOR_ARCHITEW6432") != ""
		if isWow64 {
			return "64"
		}
		switch runtime.GOARCH {
		case "amd64", "arm64":
			return "64"
		default:
			return "32"
		}
	}()

	normArch := func(a string) string {
		a = strings.ToLower(strings.TrimSpace(a))
		switch a {
		case "64", "x64", "amd64", "arm64":
			return "64"
		case "32", "x86", "386":
			return "32"
		default:
			return a
		}
	}

	opts := []struct {
		n, s, w, a string
	}{
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

	hasGlob := func(s string) bool { return strings.ContainsAny(s, "*?[") }
	hasDrivePrefix := func(p string) bool { return len(p) >= 2 && p[1] == ':' }

	fileExists := func(p string) bool {
		fi, e := os.Stat(p)
		return e == nil && !fi.IsDir()
	}

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
			if fileExists(pattern) {
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
				if fileExists(m) {
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
				if fileExists(m) {
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

	// tools\boot.sdi 源文件定位
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
			if fileExists(p) {
				return p, true
			}
		}
		return "", false
	}

	// 把 opts.s转成一个具体 SDI 相对路径
	materializeSdiRel := func(sPat string) string {
		sPat = strings.ReplaceAll(sPat, "/", `\`)
		if sPat == "" {
			return ""
		}
		if !hasGlob(sPat) {
			return sPat
		}
		// \PETEMP\*.sdi -> \PETEMP\boot.sdi
		dir := filepath.Dir(sPat)
		dst := filepath.Join(dir, "boot.sdi")
		if !strings.HasPrefix(dst, `\`) {
			dst = `\` + dst
		}
		return dst
	}

	// 用 tools\boot.sdi 生成目标 SDI（只在缺 SDI 时调用）
	ensureSdiByCopy := func(root string, sPatRel string, wAbs string) (sAbs string, sRel string, copied bool, err error) {
		src, ok := findToolsBootSdi()
		if !ok {
			return "", "", false, fmt.Errorf("缺少SDI，且未找到 %s", `tools\boot.sdi`)
		}

		dstRel := materializeSdiRel(sPatRel)
		if dstRel == "" {
			// 没有可用的 sPat，就落到 WIM 同目录
			dstAbs := filepath.Join(filepath.Dir(wAbs), "boot.sdi")
			if e := Copy(src, dstAbs, false, true); e != nil {
				return "", "", false, e
			}
			return dstAbs, toRel(root, dstAbs), true, nil
		}

		// 拼绝对路径：root + 去掉开头 '\'
		dstAbs := filepath.Join(root, strings.TrimPrefix(dstRel, `\`))
		if e := Copy(src, dstAbs, false, true); e != nil {
			return "", "", false, e
		}
		return dstAbs, toRel(root, dstAbs), true, nil
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

	// wimAbs -> best cand
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

	collect := func() error {
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
						return fmt.Errorf("sdi 和 wim 不在同一盘：%s vs %s", vol, wVol)
					}
					if vol == "" {
						vol = wVol
					}
				}
				root := vol + `:\`

				// WIM 必须存在
				wAbs, ok := firstMatchInsensitive(wPat)
				if !ok {
					return fmt.Errorf("未找到WIM: %s", wPat)
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
				return nil
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
				return nil
			}
			return fmt.Errorf("未找到匹配的SDI/WIM：SDI=%s WIM=%s", sPat, wPat)
		}

		// 按 opts 扫描所有盘符
		for _, o := range opts {
			if o.a != "" && normArch(o.a) != normArch(wantArch) {
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
		return nil
	}

	if err := collect(); err != nil {
		if scan {
			// 扫描模式
			return false, "", "", err
		}
		return false, "", "", err
	}

	if len(allWims) == 0 {
		if scan {
			return false, "", "", nil
		}
		return false, "", "", fmt.Errorf("未找到PE引导文件")
	}

	bestWim := chooseBestWim(allWims, wantArch)
	best, ok := candByWim[bestWim]
	if !ok || bestWim == "" {
		if scan {
			return false, "", "", nil
		}
		return false, "", "", fmt.Errorf("chooseBestWim 选优失败")
	}

	// 缺 SDI时用 tools\boot.sdi 复制补齐
	if best.sAbs == "" {
		sAbs, sRel, _, e := ensureSdiByCopy(best.root, best.sPat, best.wAbs)
		if e == nil {
			best.sAbs = sAbs
			best.sRel = sRel
			candByWim[best.wAbs] = best
		} else {
			// scan 模式允许返回wim 有、sdi 仍空
			if !scan {
				return true, best.wAbs, "", e
			}
		}
	}

	// scan 模式：直接返回最优绝对路径
	if scan {
		return true, best.wAbs, best.sAbs, nil
	}

	lt, sdi, wim, nm := best.lt, best.sRel, best.wRel, best.nm

	// 执行模式：仍然必须有 SDI（ramdisk 引导要用）
	if best.sRel == "" {
		return true, best.wAbs, best.sAbs, fmt.Errorf("找到WIM但仍缺少SDI，无法设置ramdisk引导：WIM=%s", best.wAbs)
	}

	fmt.Println("PE:", nm, "DRV:", lt, "SDI:", sdi, "WIM:", wim)

	windir := os.Getenv("SystemRoot")
	if windir == "" {
		windir = os.Getenv("WINDIR")
	}
	isWow64 := runtime.GOARCH == "386" && os.Getenv("PROCESSOR_ARCHITEW6432") != ""
	bcdeditPath := filepath.Join(windir, "System32", "bcdedit.exe")
	if isWow64 {
		bcdeditPath = filepath.Join(windir, "Sysnative", "bcdedit.exe")
	}
	out, err := runCmd(bcdeditPath, nil, nil, "")
	if err != nil && (errors.Is(err, os.ErrNotExist) || errors.Is(err, exec.ErrNotFound)) {
		exe, e := os.Executable()
		if e == nil {
			bcdeditPath = filepath.Join(filepath.Dir(exe), "tools", "bcdedit.exe")
		}
	}

	// /device guid
	out, err = runCmd(bcdeditPath, nil, nil, "", "/create", "/d", "pe", "/device")
	if err != nil {
		return false, "", "", err
	}
	re := regexp.MustCompile(`(?i)\{([a-f0-9-]+)\}`)
	m1 := re.FindStringSubmatch(out)
	if len(m1) < 2 {
		return false, "", "", fmt.Errorf("guid1解析失败: %s", out)
	}
	gd1 := strings.ToLower(m1[1])

	// ramdisksdi*
	_, err = runCmd(bcdeditPath, nil, nil, "", "/set", "{"+gd1+"}", "ramdisksdidevice", "partition="+lt+":")
	if err != nil {
		return false, "", "", err
	}
	_, err = runCmd(bcdeditPath, nil, nil, "", "/set", "{"+gd1+"}", "ramdisksdipath", sdi)
	if err != nil {
		return false, "", "", err
	}

	// /application osloader guid2
	out, err = runCmd(bcdeditPath, nil, nil, "", "/create", "/d", "pe", "/application", "osloader")
	if err != nil {
		return false, "", "", err
	}
	m2 := re.FindStringSubmatch(out)
	if len(m2) < 2 {
		return false, "", "", fmt.Errorf("guid2解析失败: %s", out)
	}
	gd2 := strings.ToLower(m2[1])

	// device/osdevice
	dev := fmt.Sprintf("ramdisk=[%s:]%s,{%s}", lt, wim, gd1)
	_, err = runCmd(bcdeditPath, nil, nil, "", "/set", "{"+gd2+"}", "device", dev)
	if err != nil {
		return false, "", "", err
	}
	_, err = runCmd(bcdeditPath, nil, nil, "", "/set", "{"+gd2+"}", "osdevice", dev)
	if err != nil {
		return false, "", "", err
	}

	// BIOS/UEFI
	fw := 0
	windir = os.Getenv("SystemRoot")
	if windir == "" {
		windir = os.Getenv("WINDIR")
	}
	isWow64 = runtime.GOARCH == "386" && os.Getenv("PROCESSOR_ARCHITEW6432") != ""
	regPath := filepath.Join(windir, "System32", "reg.exe")
	if isWow64 {
		regPath = filepath.Join(windir, "Sysnative", "reg.exe")
	}
	out, er2 := runCmd(regPath, nil, nil, "", "query", `HKLM\SYSTEM\CurrentControlSet\Control`, "/v", "PEFirmwareType")
	if err != nil && (errors.Is(err, os.ErrNotExist) || errors.Is(err, exec.ErrNotFound)) {
		if exe, e := os.Executable(); e == nil {
			out, err = runCmd(filepath.Join(filepath.Dir(exe), "tools", "reg"), nil, nil, "", "query",
				`HKLM\SYSTEM\CurrentControlSet\Control`, "/v", "PEFirmwareType")
		}
	}
	if er2 == nil {
		r2 := regexp.MustCompile(`(?i)0x([0-9a-f]+)`)
		m3 := r2.FindStringSubmatch(out)
		if len(m3) >= 2 {
			if v, e3 := strconv.ParseInt(m3[1], 16, 32); e3 == nil {
				fw = int(v) // 1=BIOS 2=UEFI
			}
		}
	}

	p1 := `\windows\system32\boot\winload.efi`
	p2 := `\windows\system32\boot\winload.exe`
	if fw == 1 {
		p1, p2 = p2, p1
	}
	if _, err = runCmd(bcdeditPath, nil, nil, "", "/set", "{"+gd2+"}", "path", p1); err != nil {
		if _, err = runCmd(bcdeditPath, nil, nil, "", "/set", "{"+gd2+"}", "path", p2); err != nil {
			return false, "", "", err
		}
	}

	if _, err = runCmd(bcdeditPath, nil, nil, "", "/set", "{"+gd2+"}", "systemroot", `\windows`); err != nil {
		return false, "", "", err
	}
	if _, err = runCmd(bcdeditPath, nil, nil, "", "/set", "{"+gd2+"}", "detecthal", "YES"); err != nil {
		return false, "", "", err
	}
	if _, err = runCmd(bcdeditPath, nil, nil, "", "/set", "{"+gd2+"}", "winpe", "YES"); err != nil {
		return false, "", "", err
	}
	if _, err = runCmd(bcdeditPath, nil, nil, "", "/set", "{"+gd2+"}", "nx", "OptIn"); err != nil {
		return false, "", "", err
	}

	// 设置下次启动
	if _, err = runCmd(bcdeditPath, nil, nil, "", "/bootsequence", "{"+gd2+"}"); err != nil {
		return false, "", "", err
	}
	return false, "", "", nil
}

// 确保 WIM 文件可写
func ensureWimWritable(wim string) error {
	st, err := os.Stat(wim)
	if err != nil {
		return fmt.Errorf("WIM不存在或不可访问: %w", err)
	}
	if st.IsDir() {
		return fmt.Errorf("WIM路径是目录不是文件: %s", wim)
	}

	// 1) 尝试直接以读写方式打开
	tryOpenRW := func() error {
		f, e := os.OpenFile(wim, os.O_RDWR, 0)
		if e != nil {
			return e
		}
		_ = f.Close()
		return nil
	}

	if err := tryOpenRW(); err != nil {
		// 2) 如果打不开，尝试去只读（Windows 属性只读）
		if e2 := clearReadonly(wim); e2 != nil {
			return fmt.Errorf("WIM不可写(打开失败): %v；去只读失败: %v", err, e2)
		}
		// 3) 去只读后再试一次
		if err2 := tryOpenRW(); err2 != nil {
			return fmt.Errorf("WIM仍不可写(已去只读): %v", err2)
		}
	}

	// 4) 检查 WIM 所在目录是否可写（只读介质/无权限目录常见）
	dir := filepath.Dir(wim)
	tf, err := os.CreateTemp(dir, "wimwrite_*")
	if err != nil {
		return fmt.Errorf("WIM所在目录不可写: %s: %w", dir, err)
	}
	name := tf.Name()
	_ = tf.Close()
	_ = os.Remove(name)

	return nil
}

// 修改wim文件，将自身及对应文件写入到wim中，并修改ini
func Patwim(wim string) error {
	if wim == "" {
		return fmt.Errorf("wim为空")
	}
	wimAbs, err := filepath.Abs(wim)
	if err != nil {
		return err
	}
	wim = wimAbs
	if err := ensureWimWritable(wim); err != nil {
		return err
	}

	// 自身程序
	selfExe, err := os.Executable()
	if err != nil {
		return err
	}
	selfExe, _ = filepath.Abs(selfExe)
	selfName := filepath.Base(selfExe)

	dir := filepath.Dir(selfExe)

	resolveTool := func(name, fallback string) string {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
		if fallback != "" {
			if st, err := os.Stat(fallback); err == nil && !st.IsDir() {
				return fallback
			}
		}
		return ""
	}

	runWithTimeout := func(exe string, args []string, to time.Duration) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), to)
		defer cancel()
		cmd := exec.CommandContext(ctx, exe, args...)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		var buf bytes.Buffer
		cmd.Stdout = &buf
		cmd.Stderr = &buf
		err := cmd.Run()
		out := buf.String()
		if ctx.Err() == context.DeadlineExceeded {
			return out, fmt.Errorf("超时: %s %s", exe, strings.Join(args, " "))
		}
		return out, err
	}

	//把多条命令从 stdin 喂进去
	runUpdateWithStdin := func(exe string, args []string, stdinText string, to time.Duration) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), to)
		defer cancel()
		cmd := exec.CommandContext(ctx, exe, args...)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		cmd.Stdin = strings.NewReader(stdinText)
		var buf bytes.Buffer
		cmd.Stdout = &buf
		cmd.Stderr = &buf
		err := cmd.Run()
		out := buf.String()
		if ctx.Err() == context.DeadlineExceeded {
			return out, fmt.Errorf("超时: %s %s", exe, strings.Join(args, " "))
		}
		return out, err
	}

	qCmdArg := func(s string) string {
		if !strings.ContainsAny(s, " \t") && !strings.Contains(s, `"`) {
			return s
		}
		return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
	}

	// 插入启动项
	appendExecLine := func(b []byte, line string) ([]byte, error) {
		pickNLBytes := func(src []byte) []byte {
			if bytes.Contains(src, []byte("\r\n")) {
				return []byte("\r\n")
			}
			if bytes.Contains(src, []byte("\n")) {
				return []byte("\n")
			}
			return []byte("\r\n")
		}

		lowerASCII := func(c byte) byte {
			if c >= 'A' && c <= 'Z' {
				return c + 32
			}
			return c
		}
		isSpace := func(c byte) bool { return c == ' ' || c == '\t' }

		findEndfileLineStartBytes := func(src []byte) (int, bool) {
			i := 0
			for i < len(src) {
				lineStart := i
				j := bytes.IndexByte(src[i:], '\n')
				if j == -1 {
					i = len(src)
				} else {
					i += j + 1
				}
				lineBytes := src[lineStart:i]
				trimmed := bytes.TrimRight(lineBytes, "\r\n")
				trimmed = bytes.TrimLeft(trimmed, " \t")
				if len(trimmed) < len("_ENDFILE") {
					continue
				}
				ok := true
				for k := 0; k < len("_ENDFILE"); k++ {
					if lowerASCII(trimmed[k]) != lowerASCII("_ENDFILE"[k]) {
						ok = false
						break
					}
				}
				if !ok {
					continue
				}
				if len(trimmed) == len("_ENDFILE") {
					return lineStart, true
				}
				c := trimmed[len("_ENDFILE")]
				if isSpace(c) || c == '/' || c == ';' {
					return lineStart, true
				}
			}
			return 0, false
		}

		containsFoldASCII := func(hay, needle []byte) bool {
			if len(needle) == 0 {
				return true
			}
			for i := 0; i+len(needle) <= len(hay); i++ {
				ok := true
				for j := 0; j < len(needle); j++ {
					if lowerASCII(hay[i+j]) != lowerASCII(needle[j]) {
						ok = false
						break
					}
				}
				if ok {
					return true
				}
			}
			return false
		}

		applyOnBytes := func(src []byte) []byte {
			nl := pickNLBytes(src)
			insertPos := len(src)
			if p, ok := findEndfileLineStartBytes(src); ok {
				insertPos = p
			}
			head := src[:insertPos]
			tail := src[insertPos:]

			if containsFoldASCII(head, []byte(line)) {
				return src
			}

			out := make([]byte, 0, len(src)+len(line)+len(nl)+4)
			out = append(out, head...)
			if len(out) > 0 && out[len(out)-1] != '\n' {
				out = append(out, nl...)
			}
			out = append(out, []byte(line)...)
			out = append(out, nl...)
			out = append(out, tail...)
			return out
		}

		// UTF-16LE BOM：FF FE
		if len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE {
			raw := b[2:]
			if len(raw)%2 != 0 {
				raw = raw[:len(raw)-1]
			}

			u := make([]uint16, len(raw)/2)
			for i := 0; i < len(u); i++ {
				u[i] = binary.LittleEndian.Uint16(raw[i*2 : i*2+2])
			}
			s := string(utf16.Decode(u))

			nl := "\r\n"
			if strings.Contains(s, "\n") && !strings.Contains(s, "\r\n") {
				nl = "\n"
			}

			reEnd := regexp.MustCompile(`(?im)^[ \t]*_endfile\b.*(?:\r?\n|$)`)
			loc := reEnd.FindStringIndex(s)

			head := s
			tail := ""
			if loc != nil {
				head = s[:loc[0]]
				tail = s[loc[0]:]
			}

			if strings.Contains(strings.ToLower(head), strings.ToLower(line)) {
				return b, nil
			}

			if head != "" && !strings.HasSuffix(head, "\n") {
				head += nl
			}
			head += line + nl
			s2 := head + tail

			u2 := utf16.Encode([]rune(s2))
			o := make([]byte, 2+len(u2)*2)
			o[0], o[1] = 0xFF, 0xFE
			for i, v := range u2 {
				binary.LittleEndian.PutUint16(o[2+i*2:2+i*2+2], v)
			}
			return o, nil
		}

		return applyOnBytes(b), nil
	}

	wimlib := resolveTool("wimlib-imagex.exe", filepath.Join(dir, "tools", "wimlib-imagex.exe"))
	if wimlib == "" {
		return fmt.Errorf("找不到 wimlib-imagex.exe（PATH 或 %s）", filepath.Join(dir, "tools", "wimlib-imagex.exe"))
	}

	type wimRes struct {
		src   string
		dst   string
		isDir bool
	}
	resList := []wimRes{
		{src: selfExe, dst: `\Windows\` + selfName, isDir: false},
		{src: filepath.Join(dir, "Windows.json"), dst: `\Windows\Windows.json`, isDir: false},
		{src: filepath.Join(dir, "WinPE.json"), dst: `\Windows\WinPE.json`, isDir: false},
		{src: filepath.Join(dir, "disk.dll"), dst: `\Windows\disk.dll`, isDir: false},
		{src: filepath.Join(dir, "trackers.txt"), dst: `\Windows\trackers.txt`, isDir: false},
		{src: filepath.Join(dir, "tools"), dst: `\Windows\tools`, isDir: true},
	}

	// 资源存在性检查
	keep := make([]wimRes, 0, len(resList))
	for _, r := range resList {
		st, e := os.Stat(r.src)
		if e != nil {
			fmt.Fprintf(os.Stderr, "WARN: 跳过缺少资源: %s (%v)\n", r.src, e)
			continue
		}
		if r.isDir && !st.IsDir() {
			fmt.Fprintf(os.Stderr, "WARN: 跳过资源(应为目录但不是): %s\n", r.src)
			continue
		}
		if !r.isDir && st.IsDir() {
			fmt.Fprintf(os.Stderr, "WARN: 跳过资源(应为文件但却是目录): %s\n", r.src)
			continue
		}
		keep = append(keep, r)
	}
	resList = keep

	wimBase := func(p string) string {
		p = strings.TrimRight(p, `\/`)
		if i := strings.LastIndexAny(p, `\/`); i >= 0 {
			return p[i+1:]
		}
		return p
	}
	wimDir := func(p string) string {
		p = strings.TrimRight(p, `\/`)
		if i := strings.LastIndexAny(p, `\/`); i >= 0 {
			return p[:i]
		}
		return ""
	}
	wimJoin := func(a, b string) string {
		if a == "" {
			return `\` + b
		}
		if strings.HasSuffix(a, `\`) || strings.HasSuffix(a, `/`) {
			return a + b
		}
		return a + `\` + b
	}

	//获取 Index：info 文本 -> info --xml -> 默认 1
	getIdxs := func() ([]int, error) {
		out, err := runWithTimeout(wimlib, []string{"info", wim}, 2*time.Minute)
		if err != nil {
			return nil, fmt.Errorf("wimlib info失败: %w\n%s", err, out)
		}

		reIdx := regexp.MustCompile(`(?m)^\s*Image\s+(\d+)\s*:`)
		ms := reIdx.FindAllStringSubmatch(out, -1)

		seen := map[int]bool{}
		idxs := make([]int, 0, len(ms))
		for _, m := range ms {
			i, _ := strconv.Atoi(m[1])
			if i > 0 && !seen[i] {
				seen[i] = true
				idxs = append(idxs, i)
			}
		}
		if len(idxs) > 0 {
			return idxs, nil
		}

		xout, xerr := runWithTimeout(wimlib, []string{"info", wim, "--xml"}, 2*time.Minute)
		if xerr == nil && len(xout) > 0 {
			b := []byte(xout)
			if len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE {
				raw := b[2:]
				if len(raw)%2 != 0 {
					raw = raw[:len(raw)-1]
				}
				u := make([]uint16, len(raw)/2)
				for i := range u {
					u[i] = binary.LittleEndian.Uint16(raw[i*2 : i*2+2])
				}
				s := string(utf16.Decode(u))

				reXML := regexp.MustCompile(`(?i)<\s*image\b[^>]*\bindex\s*=\s*"(\d+)"`)
				ms2 := reXML.FindAllStringSubmatch(s, -1)

				seen2 := map[int]bool{}
				idxs2 := make([]int, 0, len(ms2))
				for _, m := range ms2 {
					i, _ := strconv.Atoi(m[1])
					if i > 0 && !seen2[i] {
						seen2[i] = true
						idxs2 = append(idxs2, i)
					}
				}
				if len(idxs2) > 0 {
					return idxs2, nil
				}
			} else {
				s := xout
				reXML := regexp.MustCompile(`(?i)<\s*image\b[^>]*\bindex\s*=\s*"(\d+)"`)
				ms2 := reXML.FindAllStringSubmatch(s, -1)

				seen2 := map[int]bool{}
				idxs2 := make([]int, 0, len(ms2))
				for _, m := range ms2 {
					i, _ := strconv.Atoi(m[1])
					if i > 0 && !seen2[i] {
						seen2[i] = true
						idxs2 = append(idxs2, i)
					}
				}
				if len(idxs2) > 0 {
					return idxs2, nil
				}
			}
		}

		return []int{1}, nil
	}

	idxs, err := getIdxs()
	if err != nil {
		return err
	}

	// 启动项
	line := "EXEC %WinDir%\\" + selfName

	for _, idx := range idxs {
		// 列出 \Windows 下的文件
		dout, de := runWithTimeout(wimlib, []string{"dir", wim, strconv.Itoa(idx), `--path=\Windows`}, 2*time.Minute)
		if de != nil {
			return fmt.Errorf("dir失败 idx=%d: %v\n%s", idx, de, dout)
		}

		actual := map[string]string{}
		pecmdActual := ""
		for _, ln := range strings.Split(dout, "\n") {
			f := strings.Fields(strings.TrimSpace(ln))
			if len(f) == 0 {
				continue
			}
			nm := strings.TrimRight(f[len(f)-1], `\/`)
			lm := strings.ToLower(nm)
			if _, ok := actual[lm]; !ok {
				actual[lm] = nm
			}
			if lm == "pecmd.ini" {
				pecmdActual = nm
			}
		}

		// 生成 update 命令脚本
		cmdLines := make([]string, 0, len(resList)*2)
		for _, r := range resList {
			baseLower := strings.ToLower(wimBase(r.dst))
			delPath := r.dst
			if act, ok := actual[baseLower]; ok && act != "" {
				delPath = wimJoin(wimDir(r.dst), act)
			}
			if r.isDir {
				cmdLines = append(cmdLines, "delete --recursive --force "+qCmdArg(delPath))
			} else {
				cmdLines = append(cmdLines, "delete --force "+qCmdArg(delPath))
			}

			cmdLines = append(cmdLines, "add "+qCmdArg(r.src)+" "+qCmdArg(r.dst))
		}
		script := strings.Join(cmdLines, "\n") + "\n"

		uout, ue := runUpdateWithStdin(
			wimlib,
			[]string{"update", wim, strconv.Itoa(idx)},
			script,
			10*time.Minute,
		)
		if ue != nil {
			return fmt.Errorf("写入资源失败 idx=%d: %v\n%s", idx, ue, uout)
		}

		// Pecmd.ini 文件名
		iniName := pecmdActual
		if iniName == "" {
			iniName = "Pecmd.ini"
		}

		// 抽取 Pecmd.ini
		tmp, _ := os.MkdirTemp("", "wim_")
		_, _ = runWithTimeout(wimlib,
			[]string{"extract", wim, strconv.Itoa(idx), `\Windows\` + iniName, "--dest-dir=" + tmp},
			5*time.Minute,
		)

		p1 := filepath.Join(tmp, "Windows", iniName)
		p2 := filepath.Join(tmp, iniName)
		inip := p1
		if _, e1 := os.Stat(p1); e1 != nil {
			inip = p2
		}
		if _, e2 := os.Stat(inip); e2 != nil {
			_ = os.MkdirAll(filepath.Dir(p1), 0o755)
			inip = p1
			_ = os.WriteFile(inip, []byte{}, 0o644)
		}

		b, _ := os.ReadFile(inip)
		updated, err := appendExecLine(b, line)
		if err != nil {
			_ = Remove(tmp, true)
			return fmt.Errorf("修改ini失败 idx=%d: %w", idx, err)
		}
		if err := os.WriteFile(inip, updated, 0o644); err != nil {
			_ = Remove(tmp, true)
			return fmt.Errorf("写入ini失败 idx=%d: %w", idx, err)
		}

		// 写回 Pecmd.ini
		iniDst := `\Windows\` + iniName
		iniScript := strings.Join([]string{
			"delete --force " + qCmdArg(iniDst),
			"add " + qCmdArg(inip) + " " + qCmdArg(iniDst),
		}, "\n") + "\n"

		iout, ie := runUpdateWithStdin(
			wimlib,
			[]string{"update", wim, strconv.Itoa(idx)},
			iniScript,
			10*time.Minute,
		)
		_ = Remove(tmp, true)
		if ie != nil {
			return fmt.Errorf("写ini失败 idx=%d: %v\n%s", idx, ie, iout)
		}
	}

	return nil
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
	tempLabel            = "TEMP"
	tempMarkerRel        = `RESTALL\temp.marker`
)

// 清理指定分区
func ClearPartition(letter string) error {
	// TODO: your implementation
	return nil
}

// 优先：用连续未分配空间创建 TEMP 分区；失败再最后 SplitVolume(C)
// needBytes：需要的空间
func ensureTempVolumeForBytes(needBytes uint64) (string, error) {
	// 给点余量
	const extra uint64 = 512 * 1024 * 1024
	if needBytes < minImageBytes {
		needBytes = minImageBytes
	}
	needBytes += extra

	// 1) 先用未分配空间（全盘扫描，支持“另一块盘全未分配”的情况）
	extent, err := PickFreeExtent(needBytes, ExtentPickPolicy{
		PreferNonSystemDisk: true,
		PreferLargestExtent: true,
	})
	if err == nil && extent.SizeBytes >= needBytes {
		letter, err2 := CreatePartitionFromFreeExtent(extent, needBytes, "ntfs", tempLabel)
		if err2 == nil {
			root := normalizeRootPath(letter) // 你项目里已有
			if root != "" {
				// 写 marker
				marker := filepath.Join(root, tempMarkerRel)
				_ = os.MkdirAll(filepath.Dir(marker), 0o755)
				_ = os.WriteFile(marker, []byte(time.Now().Format(time.RFC3339)), 0o644)
				logWrite("已使用未分配空间创建 TEMP 分区：%s", root)
				return root, nil
			}
		} else {
			logWrite("CreatePartitionFromFreeExtent失败：%v", err2)
		}
	} else {
		if err != nil {
			logWrite("PickFreeExtent未找到足够大的未分配段：%v", err)
		}
	}

	// 2) 最后兜底：拆分系统盘
	// 尝试先清理一下，增加 shrink 成功率
	_ = ClearPartition("C")

	sizeMB64 := (needBytes + 1024*1024 - 1) / (1024 * 1024)
	sizeMB := int(sizeMB64)
	if sizeMB < 1024 {
		sizeMB = 1024
	}

	newVol, err := SplitVolume("C", sizeMB, "ntfs", tempLabel)
	if err != nil {
		return "", err
	}
	root := normalizeRootPath(newVol)
	if root == "" {
		return "", fmt.Errorf("SplitVolume成功但未解析到新分区盘符: %v", newVol)
	}

	// 写 marker
	marker := filepath.Join(root, tempMarkerRel)
	_ = os.MkdirAll(filepath.Dir(marker), 0o755)
	_ = os.WriteFile(marker, []byte(time.Now().Format(time.RFC3339)), 0o644)

	logWrite("已通过拆分C盘创建 TEMP 分区：%s", root)
	return root, nil
}

// 扫描所有盘符找 marker，返回临时分区根路径（例如 "T:\\"）
func findTempRootByMarker() string {
	drives, _ := ListDrive()
	for _, d := range drives {
		root := normalizeRootPath(d)
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

func boolToUintptr(v bool) uintptr {
	if v {
		return 1
	}
	return 0
}

// 取自身架构
func GetSelfArch() string {
	switch runtime.GOARCH {
	case "amd64":
		return "64"
	case "386":
		return "32"
	case "arm", "arm64":
		return "arm"
	default:
		return "other"
	}
}
