package wimlib

import (
	"ReSys/src/disk"
	"ReSys/src/dism"
	"ReSys/src/file"
	"ReSys/src/image"
	"ReSys/src/log"
	"ReSys/src/tools"
	"ReSys/src/utils"
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func ListImageInfos(imagePath string) ([]dism.ImageMeta, error) {
	if _, err := os.Stat(imagePath); err != nil {
		return nil, fmt.Errorf("image not found: %w", err)
	}
	wimlib := findWimlibImagex()
	if wimlib == "" {
		return nil, errors.New("wimlib-imagex.exe not found")
	}
	out, err := tools.RunCmd(wimlib, nil, nil, "", "info", imagePath)
	if err != nil {
		return nil, fmt.Errorf("wimlib-imagex info failed: %w", err)
	}
	return parseImageInfoText(out)
}

func findWimlibImagex() string {
	if exe, err := os.Executable(); err == nil {
		local := filepath.Join(filepath.Dir(exe), "tools", "wimlib-imagex.exe")
		if utils.FileExists(local) {
			return local
		}
	}
	if p, err := exec.LookPath("wimlib-imagex.exe"); err == nil {
		return p
	}
	return ""
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
	wimlib := findWimlibImagex()
	if wimlib == "" {
		return errors.New("wimlib-imagex.exe not found")
	}

	args := []string{"apply", imagePath, fmt.Sprintf("%d", index), targetRoot}
	if _, err := tools.RunCmd(wimlib, nil, nil, "", args...); err != nil {
		log.LogWrite(0, "[wimlib.ApplyImage] wimlib-imagex apply failed: %v", err)
		return err
	}
	return nil
}
func parseImageInfoText(out string) ([]dism.ImageMeta, error) {
	var (
		res []dism.ImageMeta
		cur *dism.ImageMeta
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
				dism.FinalizeImageMeta(cur)
				res = append(res, *cur)
			}
			cur = &dism.ImageMeta{}
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
		dism.FinalizeImageMeta(cur)
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
func parseSizeBytes(s string) uint64 {
	s = strings.ToLower(s)
	if idx := strings.Index(s, "bytes"); idx != -1 {
		s = s[:idx]
	} else if idx := strings.Index(s, "字节"); idx != -1 {
		s = s[:idx]
	}

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
