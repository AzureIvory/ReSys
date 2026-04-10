package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ProjectFile 在当前工作目录和可执行文件目录附近向上查找目标文件。
func ProjectFile(relativePath string) (string, error) {
	return projectPath(relativePath, false)
}

// ProjectDir 在当前工作目录和可执行文件目录附近向上查找目标目录。
func ProjectDir(parts ...string) (string, error) {
	return projectPath(filepath.Join(parts...), true)
}

func projectPath(relativePath string, wantDir bool) (string, error) {
	suffix := filepath.Clean(filepath.FromSlash(relativePath))
	candidates := make([]string, 0, 12)

	if wd, err := os.Getwd(); err == nil && strings.TrimSpace(wd) != "" {
		candidates = appendProjectRoots(candidates, wd, suffix)
	}
	if exe, err := os.Executable(); err == nil && strings.TrimSpace(exe) != "" {
		candidates = appendProjectRoots(candidates, filepath.Dir(exe), suffix)
	}

	seen := map[string]struct{}{}
	for _, candidate := range candidates {
		candidate = filepath.Clean(candidate)
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}

		info, err := os.Stat(candidate)
		if err != nil {
			continue
		}
		if wantDir {
			if info.IsDir() {
				return candidate, nil
			}
			continue
		}
		if !info.IsDir() {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("%w: %s", os.ErrNotExist, suffix)
}

func appendProjectRoots(candidates []string, root, suffix string) []string {
	root = filepath.Clean(root)
	for range 5 {
		candidates = append(candidates, filepath.Join(root, suffix))
		parent := filepath.Dir(root)
		if parent == root {
			break
		}
		root = parent
	}
	return candidates
}
