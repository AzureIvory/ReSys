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
)

const (
	targetWin7  = "win7"
	targetWin10 = "win10"
	targetWin11 = "win11"
)

var (
	t = dism.Default()

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
	policy := currentImageScanPolicy()

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		files    []string
		firstErr error
	)

	patterns := []string{"*.iso", "*.esd", "*.wim"}

	validateImage := func(imagePath string) (bool, string) {
		infos, err := t.ListImageInfos(imagePath)
		if err != nil {
			return false, fmt.Sprintf("list image infos failed: %v", err)
		}
		if len(infos) == 0 {
			return false, "no image infos"
		}
		return true, ""
	}

	validateISO := func(isoPath string) (bool, string) {
		okay := func(msg string, args ...interface{}) (bool, string) {
			reason := fmt.Sprintf(msg, args...)
			log.LogWrite(0, "[validateISO] accept: path=%s reason=%s", isoPath, reason)
			return true, ""
		}
		fail := func(msg string, args ...interface{}) (bool, string) {
			reason := fmt.Sprintf(msg, args...)
			log.LogWrite(0, "[validateISO] reject: path=%s reason=%s", isoPath, reason)
			return false, reason
		}
		joinOrNone := func(items []string, max int) string {
			if len(items) == 0 {
				return "none"
			}
			if max > 0 && len(items) > max {
				items = append([]string(nil), items[:max]...)
				items = append(items, "...")
			}
			return strings.Join(items, ",")
		}

		if st, err := os.Stat(isoPath); err == nil {
			log.LogWrite(0, "[validateISO] check: path=%s size=%d", isoPath, st.Size())
		}

		meta, err := listISO7z(isoPath)
		if err != nil {
			return fail("7z list failed: %v", err)
		}
		if meta.hasWim || meta.hasEsd {
			return okay("found install image via 7z list: wim=%t esd=%t", meta.hasWim, meta.hasEsd)
		}
		if meta.hasSwm {
			return fail("found split swm only (%s), no install.wim/install.esd", joinOrNone(meta.ins, 20))
		}
		if !meta.hasSrc {
			return fail("sources dir missing; root entries=%s", joinOrNone(meta.root, 12))
		}
		if len(meta.ins) > 0 {
			return fail("install files found but unsupported by pre-scan (%s)", joinOrNone(meta.ins, 20))
		}
		return fail("install.wim/install.esd not found; sources entries=%s; root entries=%s", joinOrNone(meta.src, 20), joinOrNone(meta.root, 12))
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

				found, err := file.FindFile(root, pattern, policy.scanDepth)
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
	logAll := func(tag string, list []string) {
		if len(list) == 0 {
			log.LogWrite(0, "[Findimg] %s: none", tag)
			return
		}

		seen := make(map[string]struct{}, len(list))
		out := make([]string, 0, len(list))
		for _, item := range list {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			key := strings.ToLower(item)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, item)
		}
		sort.Slice(out, func(i, j int) bool {
			return strings.ToLower(out[i]) < strings.ToLower(out[j])
		})
		log.LogWrite(0, "[Findimg] %s (%d): %s", tag, len(out), strings.Join(out, " | "))
	}
	logDrop := func(path, reason string) {
		path = strings.TrimSpace(path)
		reason = strings.TrimSpace(reason)
		if path == "" {
			return
		}
		if reason == "" {
			reason = "unknown"
		}
		log.LogWrite(0, "[Findimg] reject image: path=%s reason=%s", path, reason)
	}

	// 记录搜索阶段扫到的全部镜像文件（未做格式/体积校验前）。
	logAll("scanned image files", files)

	if len(files) > 0 {
		seen := make(map[string]struct{}, len(files))
		dst := files[:0]

		for _, p := range files {
			lp := strings.ToLower(p)
			base := strings.ToLower(filepath.Base(lp))

			if _, ok := policy.skipNameSet[base]; ok {
				logDrop(p, "matched skip-name list")
				continue
			}

			fi, err := os.Stat(p)
			if err != nil {
				logDrop(p, fmt.Sprintf("stat failed: %v", err))
				continue
			}
			if fi.IsDir() {
				logDrop(p, "is directory")
				continue
			}
			if fi.Size() < policy.minLocalImageBytes {
				logDrop(p, fmt.Sprintf("file too small: size=%d min=%d", fi.Size(), policy.minLocalImageBytes))
				continue
			}

			if _, ok := seen[lp]; ok {
				logDrop(p, "duplicate path")
				continue
			}

			switch strings.ToLower(filepath.Ext(p)) {
			case ".iso":
				ok, why := validateISO(p)
				if !ok {
					if why == "" {
						why = "unknown"
					}
					logDrop(p, "iso validation failed: "+why)
					continue
				}
			case ".wim", ".esd":
				ok, why := validateImage(p)
				if !ok {
					if why == "" {
						why = "unknown"
					}
					logDrop(p, "wim/esd metadata parse failed: "+why)
					continue
				}
			default:
				logDrop(p, "unsupported extension")
				continue
			}

			seen[lp] = struct{}{}
			dst = append(dst, p)
		}

		files = dst
	}
	// 记录过滤后可用的本地镜像文件。
	logAll("accepted image files", files)

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

// targetMatchesImage 判断镜像文件是否匹配目标系统。
func targetMatchesImage(imagePath, target string) bool {
	target = normalizeTargetText(target)
	if target == "" {
		return true
	}

	infos, err := DetectImageInfos(imagePath)
	if err == nil {
		if detected := DetectTargetFromInfos(infos); detected != "" {
			return normalizeTargetText(detected) == target
		}
	}

	name := normalizeTargetText(imagePath)

	switch target {
	case normalizeTargetText(targetWin7):
		return strings.Contains(name, "win7") || strings.Contains(name, "windows7")
	case normalizeTargetText(targetWin10):
		return strings.Contains(name, "win10") || strings.Contains(name, "windows10")
	case normalizeTargetText(targetWin11):
		return strings.Contains(name, "win11") || strings.Contains(name, "windows11")
	default:
		return true
	}
}

// normalizeTargetText 将目标文本转换为小写并去除非字母数字字符。
func normalizeTargetText(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))

	var b strings.Builder
	b.Grow(len(s))

	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}

	return b.String()
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
