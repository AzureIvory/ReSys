package image

import (
	"errors"
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
	"ReSys/src/utils"

	"github.com/kdomanski/iso9660"
)

const (
	targetWin7  = "win7"
	targetWin10 = "win10"
	targetWin11 = "win11"
)

var (
	t = dism.NewDism()

	findImg   = Findimg
	hitTarget = targetMatchesImage
	hintArch  = DetectImageArchHint

	errNoHit = errors.New("no target image")
)

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
	const maxDepth = 2
	const minSize = int64(1) * 1024 * 1024 * 1024

	skipNames := map[string]struct{}{
		"03pe.wim":    {},
		"11pex64.wim": {},
	}

	validateImage := func(imagePath string) bool {
		_, err := t.ListImageInfos(imagePath)
		return err == nil
	}

	validateISO := func(isoPath string) bool {
		f, err := os.Open(isoPath)
		if err != nil {
			return false
		}
		defer f.Close()

		format, err := detectISOFormat(f)
		if err != nil || format != "iso9660" {
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
		if disk.GetDriveType(root) == 5 {
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

				if len(found) == 0 {
					return
				}

				mu.Lock()
				files = append(files, found...)
				mu.Unlock()
			}()
		}
	}

	wg.Wait()

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

			switch strings.ToLower(filepath.Ext(p)) {
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

	sort.Slice(files, func(i, j int) bool {
		priority := func(p string) int {
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

		pi := priority(files[i])
		pj := priority(files[j])
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
	}

	log.LogWrite(0, "[findLocalImage] candidates: %s", strings.Join(imgs, " | "))

	matchTarget := make([]string, 0, len(imgs))
	for _, p := range imgs {
		if targetMatchesImage(p, target) {
			matchTarget = append(matchTarget, p)
		}
	}
	if len(matchTarget) == 0 {
		matchTarget = imgs
	}

	filterByArch := func(paths []string, want string) []string {
		out := make([]string, 0, len(paths))
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
}

// FindLocalHit 只返回命中目标系统的本地镜像。
// 找不到命中项时返回 errNoHit，不再回退到其他系统镜像。
func FindLocalHit(target, arch string) (string, error) {
	imgs, err := findImg()
	if len(imgs) == 0 {
		if err != nil {
			log.LogWrite(0, "[findLocalHit] local image scan failed: %v", err)
			return "", err
		}

		log.LogWrite(0, "[findLocalHit] no local image found")
		return "", errNoHit
	}

	if err != nil {
		log.LogWrite(0, "[findLocalHit] skipped inaccessible volume(s): %v", err)
	}

	log.LogWrite(0, "[findLocalHit] candidates: %s", strings.Join(imgs, " | "))

	hits := make([]string, 0, len(imgs))
	for _, path := range imgs {
		if hitTarget(path, target) {
			hits = append(hits, path)
		}
	}
	if len(hits) == 0 {
		log.LogWrite(0, "[findLocalHit] no target image hit: target=%s", target)
		return "", errNoHit
	}

	base := hits
	hits = filterArch(base, arch)
	if len(hits) == 0 && arch == "32" {
		// 32 位镜像缺失时，允许回退到 64 位镜像。
		hits = filterArch(base, "64")
	}
	if len(hits) == 0 {
		log.LogWrite(0, "[findLocalHit] no arch image hit: target=%s arch=%s", target, arch)
		return "", errNoHit
	}

	log.LogWrite(0, "[findLocalHit] selected local image: %s", hits[0])
	return hits[0], nil
}

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
			return nil, fmt.Errorf("ISO does not contain install.wim or install.esd")
		}
		sort.Strings(found)
		installPath = found[0]
	}

	return t.ListImageInfos(installPath)
}

func DetectTargetFromInfos(infos []dism.ImageMeta) string {
	if len(infos) == 0 {
		return ""
	}

	values := make([]string, 0, len(infos)*4)
	for _, info := range infos {
		values = append(values, info.Name, info.Description, info.Edition, info.Flags)
	}

	return utils.DetectTarget(values...)
}

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

func filterArch(paths []string, want string) []string {
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		arch := hintArch(path)
		if arch == "" || arch == want {
			out = append(out, path)
		}
	}
	return out
}

func targetMatchesImage(imagePath, target string) bool {
	target = strings.ToLower(strings.TrimSpace(target))
	if target == "" {
		return true
	}

	infos, err := DetectImageInfos(imagePath)
	if err == nil {
		if detected := DetectTargetFromInfos(infos); detected != "" {
			return detected == target
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

func FilterRuleItemsByArch(items []data.RuleItem, arch string) []data.RuleItem {
	arch = strings.TrimSpace(arch)
	if arch == "" {
		return items
	}

	out := make([]data.RuleItem, 0, len(items))
	for _, it := range items {
		if strings.TrimSpace(it.Arch) == arch {
			out = append(out, it)
		}
	}

	return out
}
