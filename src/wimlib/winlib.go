package wimlib

import (
	"ReSys/src/disk"
	"ReSys/src/dism"
	"ReSys/src/file"
	"ReSys/src/image"
	"ReSys/src/utils"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	wbDeleteFlagForce     = 0x00000001
	wbDeleteFlagRecursive = 0x00000002
)

type wbPatwimRes struct {
	src   string
	dst   string
	isDir bool
}

type wbXMLRoot struct {
	Images []wbXMLImage `xml:"IMAGE"`
}

type wbXMLImage struct {
	Index       int    `xml:"INDEX,attr"`
	Name        string `xml:"NAME"`
	Description string `xml:"DESCRIPTION"`
	Flags       string `xml:"FLAGS"`
	TotalBytes  uint64 `xml:"TOTALBYTES"`
	Windows     struct {
		Arch             string `xml:"ARCH"`
		EditionID        string `xml:"EDITIONID"`
		InstallationType string `xml:"INSTALLATIONTYPE"`
		SystemRoot       string `xml:"SYSTEMROOT"`
	} `xml:"WINDOWS"`
}

func ListImageInfos(imagePath string) ([]dism.ImageMeta, error) {
	if _, err := os.Stat(imagePath); err != nil {
		return nil, fmt.Errorf("image not found: %w", err)
	}

	lib, err := LibwimLoad()
	if err != nil {
		return nil, err
	}
	defer lib.Close()

	w, err := lib.OpenWim(imagePath, 0)
	if err != nil {
		return nil, err
	}
	defer w.Free()

	xmlText, xmlErr := w.GetXML()
	if xmlErr == nil && strings.TrimSpace(xmlText) != "" {
		imgs, err := wbParseWIMXMLInfos(xmlText)
		if err == nil && len(imgs) > 0 {
			for i := range imgs {
				if imgs[i].Index <= 0 {
					imgs[i].Index = i + 1
				}
				if imgs[i].Name == "" {
					imgs[i].Name = strings.TrimSpace(w.GetImageName(imgs[i].Index))
				}
				if imgs[i].Description == "" {
					imgs[i].Description = strings.TrimSpace(w.GetImageDescription(imgs[i].Index))
				}
				wbFinalizeImageMeta(&imgs[i])
			}
			sort.Slice(imgs, func(i, j int) bool { return imgs[i].Index < imgs[j].Index })
			return imgs, nil
		}
	}

	info, err := w.GetWimInfo()
	if err != nil {
		return nil, err
	}
	if info.ImageCount == 0 {
		return nil, errors.New("no image info parsed")
	}

	out := make([]dism.ImageMeta, 0, info.ImageCount)
	for i := 1; i <= int(info.ImageCount); i++ {
		m := dism.ImageMeta{
			Index:       i,
			Name:        strings.TrimSpace(w.GetImageName(i)),
			Description: strings.TrimSpace(w.GetImageDescription(i)),
		}
		wbFinalizeImageMeta(&m)
		out = append(out, m)
	}
	return out, nil
}

func ApplyImage(imagePath string, index int, targetVol string) error {
	if _, err := os.Stat(imagePath); err != nil {
		return fmt.Errorf("image not found: %w", err)
	}
	if index <= 0 {
		return fmt.Errorf("invalid image index: %d", index)
	}

	targetRoot, _ := utils.NormalizeDrive(targetVol, 0)
	if targetRoot == "" {
		return fmt.Errorf("invalid target volume: %q", targetVol)
	}

	lib, err := LibwimLoad()
	if err != nil {
		return err
	}
	defer lib.Close()

	w, err := lib.OpenWim(imagePath, 0)
	if err != nil {
		return err
	}
	defer w.Free()

	return w.Apply(index, targetRoot, 0)
}

func verifyPatwimWrite(wim string, idx int, resList []wbPatwimRes, line string) error {
	lib, err := LibwimLoad()
	if err != nil {
		return err
	}
	defer lib.Close()

	h, err := lib.OpenWim(wim, 0)
	if err != nil {
		return err
	}
	defer h.Free()

	for _, r := range resList {
		ok, err := wbWimPathExists(h, idx, r.dst)
		if err != nil {
			return fmt.Errorf("校验资源失败: path=%s err=%w", r.dst, err)
		}
		if !ok {
			return fmt.Errorf("校验资源失败: path=%s 不存在", r.dst)
		}
	}

	tmp, err := os.MkdirTemp("", "wim_verify_")
	if err != nil {
		return fmt.Errorf("创建临时目录失败: %w", err)
	}
	defer func() {
		_ = file.Remove(tmp, true)
	}()

	inip, err := wbExtractSinglePath(h, idx, `\Windows\Pecmd.ini`, tmp)
	if err != nil {
		inip, err = wbExtractSinglePath(h, idx, `\Windows\pecmd.ini`, tmp)
		if err != nil {
			return fmt.Errorf("校验ini提取失败: %w", err)
		}
	}

	b, err := os.ReadFile(inip)
	if err != nil {
		return fmt.Errorf("校验ini读取失败: %w", err)
	}
	if !strings.Contains(strings.ToLower(string(b)), strings.ToLower(line)) {
		return fmt.Errorf("校验ini失败: 启动项未写入")
	}
	return nil
}

func ApplyWimImage(wimPath string, index int, targetVol string) error {
	p := strings.TrimSpace(wimPath)
	if len(p) < 4 || !strings.EqualFold(strings.ToLower(filepath.Ext(p)), ".wim") {
		return fmt.Errorf("不是WIM镜像: %s", wimPath)
	}
	return ApplyImage(wimPath, index, targetVol)
}

func ApplyEsdImage(esdPath string, index int, targetVol string) error {
	return ApplyImage(esdPath, index, targetVol)
}

func ApplyISOImage(isoPath string, index int, targetVol string) error {
	isoRoot, err := image.MountISO(isoPath, 30*time.Second)
	if err != nil {
		parts := disk.Findpart()
		if len(parts) == 0 {
			return fmt.Errorf("未找到可用分区用于解包ISO")
		}

		var lastErr error
		for _, part := range parts {
			tempDir := filepath.Join(part, "TEMPISO")
			if err := os.MkdirAll(tempDir, 0o755); err != nil {
				lastErr = err
				continue
			}
			if err := image.UnpackISO(isoPath, tempDir); err != nil {
				lastErr = err
				continue
			}
			isoRoot = tempDir
			lastErr = nil
			break
		}
		if lastErr != nil || isoRoot == "" {
			return fmt.Errorf("解包ISO失败")
		}
	}

	installPath := filepath.Join(isoRoot, "sources", "install.wim")
	if _, err := os.Stat(installPath); err != nil {
		installPath = filepath.Join(isoRoot, "sources", "install.esd")
	}
	if _, err := os.Stat(installPath); err != nil {
		found, findErr := file.FindFile(isoRoot, "install.wim|install.esd", 3)
		if findErr != nil || len(found) == 0 {
			return fmt.Errorf("ISO中未找到安装镜像")
		}
		installPath = found[0]
	}

	if strings.EqualFold(filepath.Ext(installPath), ".esd") {
		return ApplyEsdImage(installPath, index, targetVol)
	}
	if strings.EqualFold(filepath.Ext(installPath), ".wim") {
		return ApplyWimImage(installPath, index, targetVol)
	}
	return fmt.Errorf("ISO安装镜像类型不支持")
}

func detectImageInfos(imagePath string) ([]dism.ImageMeta, error) {
	ext := strings.ToLower(filepath.Ext(imagePath))
	if ext != ".iso" {
		return ListImageInfos(imagePath)
	}

	isoRoot, err := image.MountISO(imagePath, 30*time.Second)
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
	return ListImageInfos(installPath)
}

func selectInstallIndex(infos []dism.ImageMeta) int {
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
	for _, key := range preferred {
		for _, info := range infos {
			if !info.IsOS {
				continue
			}
			text := strings.ToLower(info.Name + " " + info.Description + " " + info.Edition + " " + info.Flags)
			if strings.Contains(text, strings.ToLower(key)) {
				return info.Index
			}
		}
	}
	return infos[len(infos)-1].Index
}

func detectTargetFromInfos(infos []dism.ImageMeta) string {
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
		return "win7"
	case strings.Contains(s, "windows 11") || strings.Contains(s, "win11"):
		return "win10"
	case strings.Contains(s, "windows 10") || strings.Contains(s, "win10"):
		return "win11"
	default:
		return ""
	}
}

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
	case "win7":
		return strings.Contains(name, "win7") || strings.Contains(name, "windows 7")
	case "win10":
		return strings.Contains(name, "win10") || strings.Contains(name, "windows 10")
	case "win11":
		return strings.Contains(name, "win11") || strings.Contains(name, "windows 11")
	default:
		return true
	}
}

// ---------------- private helpers ----------------

func wbParseWIMXMLInfos(xmlText string) ([]dism.ImageMeta, error) {
	var root wbXMLRoot
	if err := xml.Unmarshal([]byte(xmlText), &root); err != nil {
		return nil, err
	}
	if len(root.Images) == 0 {
		return nil, errors.New("no image info parsed")
	}

	out := make([]dism.ImageMeta, 0, len(root.Images))
	for i, img := range root.Images {
		m := dism.ImageMeta{
			Index:        img.Index,
			Name:         strings.TrimSpace(img.Name),
			Description:  strings.TrimSpace(img.Description),
			Flags:        strings.TrimSpace(img.Flags),
			SizeBytes:    img.TotalBytes,
			Edition:      strings.TrimSpace(img.Windows.EditionID),
			Installation: strings.TrimSpace(img.Windows.InstallationType),
			Arch:         wbNormalizeArch(img.Windows.Arch),
			SystemRoot:   strings.TrimSpace(img.Windows.SystemRoot),
		}
		if m.Index <= 0 {
			m.Index = i + 1
		}
		m.Size = wbBytesToMBGBStr(m.SizeBytes)
		out = append(out, m)
	}
	return out, nil
}

func wbNormalizeArch(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}

	if n, err := strconv.Atoi(s); err == nil {
		switch n {
		case 0:
			return "x86"
		case 5:
			return "ARM"
		case 6:
			return "IA64"
		case 9:
			return "x64"
		case 12:
			return "ARM64"
		default:
			return s
		}
	}

	ls := strings.ToLower(s)
	switch {
	case strings.Contains(ls, "amd64"), strings.Contains(ls, "x64"):
		return "x64"
	case strings.Contains(ls, "x86"):
		return "x86"
	case strings.Contains(ls, "arm64"):
		return "ARM64"
	case strings.Contains(ls, "arm"):
		return "ARM"
	default:
		return s
	}
}

func wbBytesToMBGBStr(size uint64) string {
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

func wbFinalizeImageMeta(m *dism.ImageMeta) {
	m.Size = wbBytesToMBGBStr(m.SizeBytes)

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

func wbCollectImageIndexes(infos []dism.ImageMeta) []int {
	seen := map[int]bool{}
	out := make([]int, 0, len(infos))
	for _, info := range infos {
		if info.Index > 0 && !seen[info.Index] {
			seen[info.Index] = true
			out = append(out, info.Index)
		}
	}
	sort.Ints(out)
	return out
}

func wbListWindowsEntries(w *WIM, idx int) (map[string]string, string, error) {
	entries, err := w.ListPaths(idx, `\Windows`, IterateChildren)
	if err != nil {
		return nil, "", err
	}

	actual := map[string]string{}
	pecmdActual := ""

	for _, e := range entries {
		full := strings.TrimRight(strings.TrimSpace(e.FullPath), `\/`)
		if full == "" {
			continue
		}
		if strings.EqualFold(full, `\Windows`) {
			continue
		}
		base := wbWimBase(full)
		if base == "" {
			continue
		}
		lb := strings.ToLower(base)
		if _, ok := actual[lb]; !ok {
			actual[lb] = base
		}
		if lb == "pecmd.ini" {
			pecmdActual = base
		}
	}

	return actual, pecmdActual, nil
}

func wbExtractSinglePath(w *WIM, idx int, wimPath, destDir string) (string, error) {
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return "", err
	}

	listFile := filepath.Join(destDir, "__wim_pathlist.txt")
	if err := os.WriteFile(listFile, []byte(wimPath+"\n"), 0o644); err != nil {
		return "", err
	}
	defer os.Remove(listFile)

	if err := w.ExtractByPathList(idx, destDir, listFile, ExtractFlagNoACLs); err != nil {
		return "", err
	}

	rel := strings.TrimLeft(wimPath, `\/`)
	rel = strings.ReplaceAll(rel, `\`, string(os.PathSeparator))
	rel = strings.ReplaceAll(rel, `/`, string(os.PathSeparator))

	candidates := []string{
		filepath.Join(destDir, rel),
		filepath.Join(destDir, filepath.Base(rel)),
	}

	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}

	return "", fmt.Errorf("extracted file not found: %s", wimPath)
}

func wbWimPathExists(w *WIM, idx int, wimPath string) (bool, error) {
	entries, err := w.ListPaths(idx, wimPath, 0)
	if err == nil && len(entries) > 0 {
		return true, nil
	}
	entries, err = w.ListPaths(idx, wimPath, IterateChildren)
	if err == nil && len(entries) > 0 {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return false, nil
}

func wbWimBase(p string) string {
	p = strings.TrimRight(p, `\/`)
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}

func wbWimDir(p string) string {
	p = strings.TrimRight(p, `\/`)
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[:i]
	}
	return ""
}

func wbWimJoin(a, b string) string {
	if a == "" {
		return `\` + b
	}
	if strings.HasSuffix(a, `\`) || strings.HasSuffix(a, `/`) {
		return a + b
	}
	return a + `\` + b
}
