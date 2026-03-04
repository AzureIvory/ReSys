package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
)

type CabinetExtractor struct {
	expandPath string
}

func NewCab() (*CabinetExtractor, error) {
	p, err := findExpandExecutable()
	if err != nil {
		return nil, err
	}
	return &CabinetExtractor{expandPath: p}, nil
}

func (e *CabinetExtractor) ExpandPath() string { return e.expandPath }

// Extract 解压 cab 到 destDir，返回解压出的文件路径列表（递归扫描 destDir）。
func (e *CabinetExtractor) Extract(cabPath, destDir string) ([]string, error) {
	if cabPath == "" || destDir == "" {
		return nil, fmt.Errorf("cabPath/destDir 不能为空")
	}
	if !fileExists(cabPath) {
		return nil, fmt.Errorf("CAB 文件不存在: %s", cabPath)
	}

	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return nil, fmt.Errorf("创建目标目录失败: %w", err)
	}

	// expand.exe -F:* <cab> <dest>
	out, err := runHidden(e.expandPath, "-F:*", cabPath, destDir)
	if err != nil {
		msg := strings.TrimSpace(bestEffortText(out))
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("expand.exe 解压失败: %s", msg)
	}

	files, err := scanFilesRecursive(destDir)
	if err != nil {
		return nil, err
	}
	return files, nil
}

// ListContents 列出 CAB 内容（尽力解析；不同语言/版本输出格式可能不同）。
// 如果你业务不强依赖“列内容”，建议只用 Extract 后扫描目录的方式。
func (e *CabinetExtractor) ListContents(cabPath string) ([]string, error) {
	if !fileExists(cabPath) {
		return nil, fmt.Errorf("CAB 文件不存在: %s", cabPath)
	}

	out, err := runHidden(e.expandPath, "-D", cabPath)
	if err != nil {
		msg := strings.TrimSpace(bestEffortText(out))
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("expand.exe -D 失败: %s", msg)
	}

	// best-effort：取每行第一个字段当作候选文件名，过滤掉明显的非文件行
	var res []string
	seen := map[string]struct{}{}
	for _, line := range strings.Split(bestEffortText(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		first := strings.TrimSpace(fields[0])

		// 过滤常见表头/噪声（不同语言可能不同，只做轻量过滤）
		lower := strings.ToLower(first)
		if strings.Contains(lower, "microsoft") || strings.Contains(lower, "expansion") || strings.Contains(lower, "utility") {
			continue
		}
		// 过滤 "正在展开:" / "Expanding:" 这类（如果输出里出现）
		if strings.HasSuffix(first, ":") {
			continue
		}
		// 作为“文件名”至少要含一个可见字符且不含路径分隔符
		if first == "" || strings.ContainsAny(first, `\/`) {
			continue
		}

		// 放宽：不强制必须包含点号（CAB 内也可能有无扩展名文件）
		if _, ok := seen[first]; !ok {
			seen[first] = struct{}{}
			res = append(res, first)
		}
	}
	return res, nil
}

func IsCabFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".cab"
}

// IsValidCabFile 通过魔数判断是否 CAB："MSCF"
func IsValidCabFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	var magic [4]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		return false
	}
	return bytes.Equal(magic[:], []byte("MSCF"))
}

// ExtractCab 便捷函数
func ExtractCab(cabPath, destDir string) ([]string, error) {
	ex, err := NewCab()
	if err != nil {
		return nil, err
	}
	return ex.Extract(cabPath, destDir)
}

type CabExtractFailure struct {
	CabPath string
	Err     error
}

// ExtractAllCabs 解压 sourceDir 下所有 .cab 到 destDir/<cabname>/
// 返回：成功数量、失败列表、致命错误（如无法读目录/无法创建目标目录）。
func ExtractAllCabs(sourceDir, destDir string) (int, []CabExtractFailure, error) {
	ex, err := NewCab()
	if err != nil {
		return 0, nil, err
	}
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return 0, nil, fmt.Errorf("创建目标目录失败: %w", err)
	}

	entries, err := os.ReadDir(sourceDir)
	if err != nil {
		return 0, nil, fmt.Errorf("读取源目录失败: %w", err)
	}

	var okCount int
	var fails []CabExtractFailure

	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		name := ent.Name()
		if !IsCabFile(name) {
			continue
		}
		cabPath := filepath.Join(sourceDir, name)
		cabName := strings.TrimSuffix(name, filepath.Ext(name))
		subDest := filepath.Join(destDir, cabName)

		_, e := ex.Extract(cabPath, subDest)
		if e != nil {
			fails = append(fails, CabExtractFailure{CabPath: cabPath, Err: e})
			continue
		}
		okCount++
	}

	return okCount, fails, nil
}

func FindCabFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var res []string
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		if IsCabFile(ent.Name()) {
			res = append(res, filepath.Join(dir, ent.Name()))
		}
	}
	return res, nil
}

func FindCabFilesRecursive(dir string) ([]string, error) {
	var res []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !d.IsDir() && IsCabFile(path) {
			res = append(res, path)
		}
		return nil
	})
	return res, err
}

// ---------------- internal helpers ----------------

func findExpandExecutable() (string, error) {
	windir := os.Getenv("WINDIR")
	var candidates []string

	if windir != "" {
		// 关键：32 位进程在 64 位系统上访问 System32 会被重定向到 SysWOW64；
		// Sysnative 是“虚拟目录”，用于从 32 位进程访问真实的 64 位 System32（Win7/Win10 都支持）。
		if is32bitProcessOn64bitWindows() {
			candidates = append(candidates, filepath.Join(windir, "Sysnative", "expand.exe"))
		}
		candidates = append(candidates,
			filepath.Join(windir, "System32", "expand.exe"),
			filepath.Join(windir, "SysWOW64", "expand.exe"),
		)
	}

	for _, p := range candidates {
		if fileExists(p) && verifyExpandAvailable(p) {
			return p, nil
		}
	}

	// 最后尝试 PATH
	if p, err := exec.LookPath("expand.exe"); err == nil && verifyExpandAvailable(p) {
		return p, nil
	}

	return "", fmt.Errorf("未找到 expand.exe（请确认系统完整，或 expand.exe 在 PATH 中）")
}

func verifyExpandAvailable(path string) bool {
	// 有些版本/环境下 -? 可能返回非 0，但只要能启动就视为可用
	_, err := runHidden(path, "-?")
	if err == nil {
		return true
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		// 进程启动了，只是返回码非 0
		return true
	}
	// 例如找不到文件、权限问题等
	return false
}

func runHidden(exe string, args ...string) ([]byte, error) {
	cmd := exec.Command(exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.CombinedOutput()
}

func scanFilesRecursive(root string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("扫描解压文件失败: %w", err)
	}
	return files, nil
}

func is32bitProcessOn64bitWindows() bool {
	if runtime.GOARCH != "386" {
		return false
	}
	// 32-bit 进程跑在 64-bit Windows 时通常会有该环境变量
	if os.Getenv("PROCESSOR_ARCHITEW6432") != "" {
		return true
	}
	return false
}

// bestEffortText：expand.exe 输出可能不是 UTF-8，这里仅做“尽力”转换。
// 如需中文不乱码，可考虑按系统代码页做解码（可用 x/text 等库）。
func bestEffortText(b []byte) string {
	// 如果是合法 UTF-8，直接转；否则也直接转（可能乱码，但不崩）
	return string(b)
}
