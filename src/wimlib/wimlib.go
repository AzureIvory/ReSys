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
	"strings"
	"time"
)

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
	fmt.Println(w, err)
	fmt.Println(w.GetXML())
	if err != nil {
		return nil, err
	}
	defer w.Free()

	xmlText, xmlErr := w.GetXML()
	fmt.Println(xmlErr, xmlText)
	if xmlErr == nil && strings.TrimSpace(xmlText) != "" {
		imgs, err := wbParseWIMXMLInfos(xmlText)
		fmt.Println(imgs)
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
				dism.FinalizeImageMeta(&imgs[i])
			}
			sort.Slice(imgs, func(i, j int) bool { return imgs[i].Index < imgs[j].Index })
			return imgs, nil
		}
	}

	info, err := w.GetWimInfo()
	fmt.Println(info)
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
		dism.FinalizeImageMeta(&m)
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
			Arch:         utils.NormalizeArch(img.Windows.Arch),
			SystemRoot:   strings.TrimSpace(img.Windows.SystemRoot),
		}
		if m.Index <= 0 {
			m.Index = i + 1
		}
		m.Size = dism.BytesToMBGBStr(m.SizeBytes)
		out = append(out, m)
	}
	return out, nil
}
