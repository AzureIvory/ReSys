package image

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"ReSys/src/data"
	"ReSys/src/disk"
	"ReSys/src/dism"
	"ReSys/src/file"
	"ReSys/src/log"

	"github.com/kdomanski/iso9660"
)

const (
	targetWin7  = "win7"
	targetWin10 = "win10"
	targetWin11 = "win11"
)

var t = dism.NewDism()

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
		if disk.GetDriveType(root) == 5 { //5=driveCdrom光盘
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

// 在全盘搜索镜像并按目标系统/架构筛选。
// 规则：
// - 优先匹配目标系统（win7/win10/win11）
// - 架构优先与期望一致（32/64）
// - 若仅有 64 位则直接使用 64 位
func FindLocalImage(target, arch string) (string, error) {
	imgs, err := Findimg()
	if len(imgs) == 0 {
		if err != nil {
			log.LogWrite(0, "[findLocalImage] local image scan failed: %v", err)
			return "", err
		}
		log.LogWrite(0, "[findLocalImage] no local image found")
		return "", fmt.Errorf("no local image found")
	}
	if err != nil {
		log.LogWrite(0, "[findLocalImage] skipped inaccessible volume(s): %v", err)
		err = nil
	}
	if err != nil {
		log.LogWrite(0, "[findLocalImage]全盘搜索镜像失败：%v", err)
		return "", err
	}
	if len(imgs) == 0 {
		log.LogWrite(0, "[findLocalImage]全盘未找到镜像")
		return "", fmt.Errorf("未找到本地镜像")
	}
	log.LogWrite(0, "[findLocalImage]搜索到镜像：%s", strings.Join(imgs, " | "))

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
			a := DetectImageArchHint(p)
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
	log.LogWrite(0, "[findLocalImage] selected local image candidate(s): %s", strings.Join(byArch, " | "))
	return byArch[0], nil
	log.LogWrite(0, "[findLocalImage]本地镜像筛选结果：%s", strings.Join(byArch, " | "))
	return byArch[0], nil
}

// 从 WIM/ESD 或 ISO 中读取镜像元数据。
func DetectImageInfos(imagePath string) ([]dism.ImageMeta, error) {
	ext := strings.ToLower(filepath.Ext(imagePath))
	if ext != ".iso" {
		return t.ListImageInfos(imagePath)
	}
	isoRoot, err := MountISO(imagePath, 30*time.Second)
	if err != nil {
		return nil, err
	}
	installPath := filepath.Join(isoRoot, "sources", "install.wim")
	if _, err := os.Stat(installPath); err != nil {
		installPath = filepath.Join(isoRoot, "sources", "install.esd")
	}
	if _, err := os.Stat(installPath); err != nil {
		found, err := file.FindFile(isoRoot, "install.wim|install.esd", 3)
		if err != nil || len(found) == 0 {
			return nil, fmt.Errorf("ISO中未找到安装镜像")
		}
		sort.Strings(found)
		installPath = found[0]
	}
	return t.ListImageInfos(installPath)
}

// 从镜像元信息中推测目标系统类型。
func DetectTargetFromInfos(infos []dism.ImageMeta) string {
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

// 尝试从镜像元数据推测架构，失败再从文件名推测。
func DetectImageArchHint(imagePath string) string {
	infos, err := DetectImageInfos(imagePath)
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

// 判断镜像是否匹配目标系统（win7/win10/win11）。
func targetMatchesImage(imagePath, target string) bool {
	target = strings.ToLower(strings.TrimSpace(target))
	if target == "" {
		return true
	}
	infos, err := DetectImageInfos(imagePath)
	if err == nil {
		if t := DetectTargetFromInfos(infos); t != "" {
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

// 按架构过滤镜像列表。
func FilterWinImgsByArch(ent []data.WinImg, arch string) []data.WinImg {
	arch = strings.TrimSpace(arch)
	if arch == "" {
		return ent
	}
	var out []data.WinImg
	for _, it := range ent {
		if strings.TrimSpace(it.Arch) == arch {
			out = append(out, it)
		}
	}
	return out
}
