package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// 读取WIM/ESD中所有的信息（Index/Name/Description/Flags）。
func ListImageInfos(imagePath string) ([]ImageMeta, error) {
	if _, err := os.Stat(imagePath); err != nil {
		return nil, fmt.Errorf("image not found: %w", err)
	}

	// DISM
	if out, err := runCmd(
		dism,
		nil,
		nil,
		"",
		"/English",
		"/Get-WimInfo",
		"/WimFile:"+imagePath,
	); err == nil {
		if imgs, perr := parseImageInfoText(out); perr == nil && len(imgs) > 0 {
			fmt.Println("[ListImageInfos] use DISM result")
			return imgs, nil
		} else {
			fmt.Println("[ListImageInfos] DISM output parse failed, fallback to wimlib")
			fmt.Println(perr)
		}
	} else {
		fmt.Println("[ListImageInfos] DISM failed, fallback to wimlib:", err)
	}

	// wimlib-imagex
	exePath, _ := os.Executable()
	exePath = filepath.Join(filepath.Dir(exePath), "tools\\wimlib-imagex.exe")
	if out, err := runCmd(exePath, nil, nil, "", "info", imagePath); err == nil {
		if imgs, perr := parseImageInfoText(out); perr == nil && len(imgs) > 0 {
			fmt.Println("[ListImageInfos] use wimlib-imagex result")
			return imgs, nil
		} else {
			fmt.Println("[ListImageInfos] wimlib output parse failed:", perr)
			return nil, perr
		}
	} else {
		return nil, fmt.Errorf("both DISM and wimlib-imagex failed: %w", err)
	}
}

// 从一行输出中提取百分比,失败返回 -1
func extractPercent(line string) float64 {
	idx := strings.Index(line, "%")
	if idx == -1 {
		return -1
	}

	i := idx - 1
	for i >= 0 && ((line[i] >= '0' && line[i] <= '9') || line[i] == '.') {
		i--
	}
	if i == idx-1 {
		return -1
	}
	numStr := strings.TrimSpace(line[i+1 : idx])
	v, err := strconv.ParseFloat(numStr, 64)
	if err != nil {
		return -1
	}
	if v < 0 {
		v = 0
	}
	if v > 100 {
		v = 100
	}
	return v
}

// 会优先使用wimlib-imagex，失败后DISM
// imagePath:WIM 或 ESD 路径
// index:镜像索引（1 开始）
// targetVol:目标卷，如 "C:"、"C:\"
func ApplyImage(imagePath string, index int, targetVol string) error {
	if _, err := os.Stat(imagePath); err != nil {
		return fmt.Errorf("image not found: %w", err)
	}
	if index <= 0 {
		return fmt.Errorf("invalid image index: %d", index)
	}

	targetRoot := normRoot(targetVol)
	if targetRoot == "" {
		return fmt.Errorf("invalid target volume: %q", targetVol)
	}

	// 先用 wimlib-imagex
	wimArgs := []string{
		"apply",
		imagePath,
		fmt.Sprintf("%d", index),
		targetRoot,
	}

	exePath, _ := os.Executable()
	exePath = filepath.Join(filepath.Dir(exePath), "tools\\wimlib-imagex.exe")

	wimOnLine := func(line string) {
		if ImageProgress == nil {
			return
		}

		phase := ""
		lower := strings.ToLower(line)

		switch {
		case strings.HasPrefix(lower, "creating files"):
			phase = "Creating files"
		case strings.HasPrefix(lower, "extracting file data"):
			phase = "Extracting"
		case strings.HasPrefix(lower, "applying metadata"):
			phase = "Applying metadata"
		default:
		}

		pct := extractPercent(line)
		if pct >= 0 || phase != "" {
			ImageProgress(phase, pct, line)
		}
	}

	if out, err := runCmd(exePath, nil, wimOnLine, "", wimArgs...); err == nil {
		fmt.Println("[ApplyImage] wimlib-imagex ok")
		fmt.Println(out)
		if ImageProgress != nil {
			ImageProgress("wimlib", 100, "wimlib apply finished")
		}
		return nil
	} else {
		fmt.Println("[ApplyImage] wimlib-imagex failed, will try DISM")
		fmt.Println(out)
	}

	dismArgs := []string{
		"/Apply-Image",
		"/ImageFile:" + imagePath,
		fmt.Sprintf("/Index:%d", index),
		"/ApplyDir:" + targetRoot,
	}

	dismOnLine := func(line string) {
		if ImageProgress == nil {
			return
		}
		pct := extractPercent(line)
		if pct >= 0 {
			ImageProgress("DISM", pct, line)
		}
	}

	if out, err := runCmd(dism, nil, dismOnLine, "", dismArgs...); err == nil {
		fmt.Println("[ApplyImage] DISM ok")
		fmt.Println(out)
		if ImageProgress != nil {
			ImageProgress("DISM", 100, "DISM apply finished")
		}
		return nil
	} else {
		fmt.Println("[ApplyImage] DISM failed")
		fmt.Println(out)
		return err
	}
}

// 安装 WIM 镜像到指定卷。
// wimPath:wim路径
// index:要安装的索引
// targetVol:目标卷，如"C:"、"C:\"
func ApplyWimImage(wimPath string, index int, targetVol string) error {
	if !strings.EqualFold(strings.TrimSpace(
		wimPath[len(wimPath)-4:]), ".wim") && !strings.HasSuffix(strings.ToLower(wimPath), ".wim") {
	}
	return ApplyImage(wimPath, index, targetVol)
}

// 安装ESD镜像到指定卷
func ApplyEsdImage(esdPath string, index int, targetVol string) error {
	return ApplyImage(esdPath, index, targetVol)
}

// 安装ISO镜像到指定卷
func ApplyISOImage(isoPath string, index int, targetVol string) error {
	isoRoot, err := MountISO(isoPath, 30*time.Second)
	if err != nil {
		parts := Findpart()
		if len(parts) == 0 {
			return fmt.Errorf("未找到可用分区用于解包ISO！")
		}
		var lastErr error
		for _, part := range parts {
			tempDir := filepath.Join(part, "TEMPISO")
			if err := os.MkdirAll(tempDir, 0755); err != nil {
				lastErr = err
				continue
			}
			if err := UnpackISO(isoPath, tempDir); err != nil {
				lastErr = err
				continue
			}
			isoRoot = tempDir
			lastErr = nil
			break
		}
		if lastErr != nil || isoRoot == "" {
			return fmt.Errorf("解包ISO失败！")
		}
	}

	installPath := filepath.Join(isoRoot, "sources", "install.wim")
	if _, err := os.Stat(installPath); err != nil {
		installPath = filepath.Join(isoRoot, "sources", "install.esd")
	}
	if _, err := os.Stat(installPath); err != nil {
		found, findErr := FindFile(isoRoot, "install.wim|install.esd", 3)
		if findErr != nil || len(found) == 0 {
			return fmt.Errorf("ISO中未找到安装镜像！")
		}
		installPath = found[0]
	}

	if strings.EqualFold(filepath.Ext(installPath), ".esd") {
		if ApplyEsdImage(installPath, index, targetVol) != nil {
			return fmt.Errorf("应用镜像失败！")
		}
		return nil
	}
	if strings.EqualFold(filepath.Ext(installPath), ".wim") {
		if ApplyWimImage(installPath, index, targetVol) != nil {
			return fmt.Errorf("应用镜像失败！")
		}
		return nil
	}

	return fmt.Errorf("ISO安装镜像类型不支持！")
}

// 解析DISM/wimlib-imagex info输出信息
func parseImageInfoText(out string) ([]ImageMeta, error) {
	var (
		res []ImageMeta
		cur *ImageMeta
	)

	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}

		colon := strings.Index(line, ":")
		if colon <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:colon])
		val := strings.TrimSpace(line[colon+1:])

		switch {
		case key == "Index" || key == "Image Index":
			if cur != nil && cur.Index != 0 {
				finalizeImageMeta(cur)
				res = append(res, *cur)
			}
			cur = &ImageMeta{}
			if idx, err := strconv.Atoi(val); err == nil {
				cur.Index = idx
			}

		case key == "Name":
			if cur != nil {
				cur.Name = val
			}

		case key == "Description":
			if cur != nil {
				cur.Description = val
			}

		case key == "Flags":
			if cur != nil {
				cur.Flags = val
			}

		case strings.HasPrefix(key, "Size"):
			if cur != nil {
				cur.SizeBytes = parseSizeBytes(val)
			}

		case strings.HasPrefix(key, "Edition"):
			if cur != nil {
				cur.Edition = val
			}

		case strings.HasPrefix(key, "Installation"):
			if cur != nil {
				cur.Installation = val
			}

		case key == "Architecture" || key == "Arch":
			if cur != nil {
				cur.Arch = val
			}

		case strings.HasPrefix(key, "System Root"):
			if cur != nil {
				cur.SystemRoot = val
			}
		}
	}

	if cur != nil && cur.Index != 0 {
		finalizeImageMeta(cur)
		res = append(res, *cur)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(res) == 0 {
		return nil, errors.New("no image info parsed")
	}
	return res, nil
}

// 提取字节数
func parseSizeBytes(s string) uint64 {
	s = strings.ToLower(s)
	if idx := strings.Index(s, "bytes"); idx != -1 {
		s = s[:idx]
	} else if idx := strings.Index(s, "字节"); idx != -1 {
		s = s[:idx]
	}

	// 只保留数字
	var b []rune
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b = append(b, r)
		}
	}
	if len(b) == 0 {
		return 0
	}
	n, _ := strconv.ParseUint(string(b), 10, 64)
	return n
}

// 把字节转成MB/GB
func bytesToMBGBStr(size uint64) string {
	const (
		mb = 1024 * 1024
		gb = 1024 * 1024 * 1024
	)
	if size == 0 {
		return ""
	}
	if size < gb {
		v := float64(size) / float64(mb)
		return fmt.Sprintf("%.1f MB", v)
	}
	v := float64(size) / float64(gb)
	return fmt.Sprintf("%.2f GB", v)
}

// 结合 Installation / Edition / 名称 做系统索引判断 + Size
func finalizeImageMeta(m *ImageMeta) {
	m.Size = bytesToMBGBStr(m.SizeBytes)

	name := strings.ToLower(m.Name + " " + m.Description)
	inst := strings.ToLower(m.Installation)
	edition := strings.ToLower(m.Edition)

	isPEInstall := strings.Contains(inst, "windowspe") || strings.Contains(inst, "winpe")
	isPEEdition := strings.Contains(edition, "windowspe")

	isSetupName :=
		strings.Contains(name, "setup media") ||
			strings.Contains(name, "windows setup") ||
			strings.Contains(name, "windows pe") ||
			strings.Contains(name, "winpe") ||
			strings.Contains(name, "winre") ||
			strings.Contains(name, "recovery")
	isClientOrServer := strings.Contains(inst, "client") || strings.Contains(inst, "server")
	if inst == "" && !isPEInstall && !isPEEdition && !isSetupName {
		m.IsOS = true
		return
	}
	m.IsOS = isClientOrServer && !isPEInstall && !isPEEdition && !isSetupName
}

// 从 WIM/ESD 或 ISO 中读取镜像元数据。
func detectImageInfos(imagePath string) ([]ImageMeta, error) {
	ext := strings.ToLower(filepath.Ext(imagePath))
	if ext != ".iso" {
		return ListImageInfos(imagePath)
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
		found, err := FindFile(isoRoot, "install.wim|install.esd", 3)
		if err != nil || len(found) == 0 {
			return nil, fmt.Errorf("ISO中未找到安装镜像")
		}
		sort.Strings(found)
		installPath = found[0]
	}
	return ListImageInfos(installPath)
}

// 按优先级选择镜像索引
func selectInstallIndex(infos []ImageMeta) int {
	if len(infos) == 0 {
		return 1
	}
	preferred := []string{
		"旗舰版", "ultimate",
		"专业工作站", "professional workstation", "pro workstation",
		"专业教育", "professional education", "pro education",
		"专业版", "professional", "pro",
		"家庭版", "home",
		"企业版", "enterprise",
		"教育版", "education",
		"家庭高级版", "home premium",
		"家庭普通版", "home basic",
		"纯净版", "clean",
	}
	best := 0
	for _, key := range preferred {
		for _, info := range infos {
			if !info.IsOS {
				continue
			}
			text := strings.ToLower(info.Name + " " + info.Description + " " + info.Edition + " " + info.Flags)
			if strings.Contains(text, strings.ToLower(key)) {
				best = info.Index
				return best
			}
		}
	}
	return infos[len(infos)-1].Index
}

// 从镜像元信息中推测目标系统类型。
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

// 尝试从镜像元数据推测架构，失败再从文件名推测。
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

// 判断镜像是否匹配目标系统（win7/win10/win11）。
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
