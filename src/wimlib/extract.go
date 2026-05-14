package wimlib

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ExtractPath 用 wimlib-imagex 从镜像中提取指定目录树到目标目录。
func ExtractPath(imagePath string, index int, targetDir string, wimPath string) error {
	if _, err := os.Stat(imagePath); err != nil {
		return fmt.Errorf("image not found: %w", err)
	}
	if index <= 0 {
		return fmt.Errorf("invalid image index: %d", index)
	}
	if strings.TrimSpace(targetDir) == "" {
		return fmt.Errorf("target dir is empty")
	}
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return err
	}

	wimlib := findImagex()
	if wimlib == "" {
		return fmt.Errorf("wimlib-imagex.exe not found")
	}

	wimPath = strings.TrimSpace(strings.ReplaceAll(wimPath, "/", `\`))
	if wimPath == "" {
		return fmt.Errorf("wim path is empty")
	}
	if !strings.HasPrefix(wimPath, `\`) {
		wimPath = `\` + wimPath
	}

	args := []string{
		"extract",
		imagePath,
		strconv.Itoa(index),
		wimPath,
		"--dest-dir=" + filepath.Clean(targetDir),
		"--preserve-dir-structure",
		"--no-globs",
	}
	if _, err := runProg(wimlib, args, nil); err != nil {
		return fmt.Errorf("wimlib-imagex extract failed: %w", err)
	}
	return nil
}
