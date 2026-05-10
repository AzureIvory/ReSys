package wimlib

import (
	"ReSys/src/dism"
	"ReSys/src/log"
	"ReSys/src/tools"
	"ReSys/src/utils"
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var (
	findImagex = findWimlibImagex
	runCmd     = tools.RunCmd
	reApplyPct = regexp.MustCompile(`\((\d{1,3})%\)`)
)

func ListImageInfos(imagePath string) ([]dism.ImageMeta, error) {
	if _, err := os.Stat(imagePath); err != nil {
		return nil, fmt.Errorf("image not found: %w", err)
	}
	wimlib := findImagex()
	if wimlib == "" {
		return nil, errors.New("wimlib-imagex.exe not found")
	}
	out, err := runCmd(wimlib, nil, nil, "", "info", imagePath)
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
	return ApplyImageProgress(imagePath, index, targetVol, nil)
}

// ApplyImageProgress 应用镜像并解析 wimlib-imagex 的文本进度。
func ApplyImageProgress(imagePath string, index int, targetVol string, progress func(uint8, string)) error {
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
	wimlib := findImagex()
	if wimlib == "" {
		return errors.New("wimlib-imagex.exe not found")
	}

	last := int16(-1)
	emit := func(pct uint8, status string) {
		if progress == nil {
			return
		}
		if int16(pct) == last {
			return
		}
		last = int16(pct)
		progress(pct, strings.TrimSpace(status))
	}

	args := []string{"apply", imagePath, fmt.Sprintf("%d", index), targetRoot}
	emit(0, "Applying image")
	onLine := func(line string) {
		for _, part := range splitApplyLines(line) {
			if pct, ok := parseApplyProgressLine(part); ok {
				emit(pct, part)
			}
		}
	}

	if _, err := runCmd(wimlib, nil, onLine, "", args...); err != nil {
		log.LogWrite(0, "[wimlib.ApplyImage] wimlib-imagex apply failed: %v", err)
		return err
	}
	emit(100, "Done")
	return nil
}

func splitApplyLines(line string) []string {
	parts := strings.FieldsFunc(line, func(r rune) bool {
		return r == '\r' || r == '\n'
	})
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func parseApplyProgressLine(line string) (uint8, bool) {
	match := reApplyPct.FindStringSubmatch(line)
	if len(match) != 2 {
		return 0, false
	}
	n, err := strconv.Atoi(match[1])
	if err != nil || n < 0 {
		return 0, false
	}
	if n > 100 {
		n = 100
	}
	return uint8(n), true
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
