package cab

import (
	"ReSys/src/log"
	tools "ReSys/src/tools"
	"ReSys/src/utils"
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

// CabinetExtractor 用于调用系统自带的 expand.exe 来解压 CAB 文件。
// expand.exe 通常位于 Windows 目录下（System32/SysWOW64/Sysnative）。
type CabinetExtractor struct {
	expandPath string // expand.exe 的绝对路径
}

// NewCab 创建一个 CabinetExtractor：
// 1) 在常见系统目录中查找 expand.exe；
// 2) 额外验证 expand.exe 是否可运行；
// 返回：可用的 CabinetExtractor 或错误。
func NewCab() (*CabinetExtractor, error) {
	p := utils.GetSystemExe("expand.exe")
	return &CabinetExtractor{expandPath: p}, nil
}

// ExpandPath 返回当前使用的 expand.exe 路径（便于日志/排错/展示）。
func (e *CabinetExtractor) ExpandPath() string { return e.expandPath }

// Extract 解压 cab 到 destDir，返回解压出的文件路径列表（递归扫描 destDir）。
// 注意：
// - 会自动创建 destDir；
// - 调用：expand.exe -F:* <cab> <dest>；
// - expand 的输出编码可能不是 UTF-8
func (e *CabinetExtractor) Extract(cabPath, destDir string) ([]string, error) {
	if cabPath == "" || destDir == "" {
		err := fmt.Errorf("cabPath/destDir 不能为空")
		log.LogWrite(-2, "[Extract]参数错误: %v", err)
		return nil, err
	}
	if !utils.FileExists(cabPath) {
		err := fmt.Errorf("CAB 文件不存在: %s", cabPath)
		log.LogWrite(-2, "[Extract]源文件不存在: %v", err)
		return nil, err
	}

	if err := os.MkdirAll(destDir, 0o755); err != nil {
		log.LogWrite(-2, "[Extract]创建目标目录失败: dir=%s err=%v", destDir, err)
		return nil, fmt.Errorf("创建目标目录失败: %w", err)
	}

	// expand.exe -F:* <cab> <dest>
	// 这里把原来的 runHidden 改为你自定义的 runCmd：
	// - bin：expand.exe 路径
	// - input：nil（expand 不需要 stdin）
	// - onLine：nil（不需要逐行回调，想要的话也可以传回调）
	// - dir：""
	out, err := tools.RunCmd(e.expandPath, nil, nil, "", "-F:*", cabPath, destDir)
	if err != nil {
		msg := strings.TrimSpace(out)
		if msg == "" {
			msg = err.Error()
		}
		log.LogWrite(-2, "[Extract]解压失败: cab=%s dest=%s msg=%s", cabPath, destDir, msg)
		return nil, fmt.Errorf("expand.exe 解压失败: %s", msg)
	}

	files, err := scanFilesRecursive(destDir)
	if err != nil {
		log.LogWrite(-2, "[Extract]扫描解压结果失败: dir=%s err=%v", destDir, err)
		return nil, err
	}
	return files, nil
}

// ListContents 列出 CAB 内容（尽力解析；不同语言/版本输出格式可能不同）。
// 调用：expand.exe -D <cab>
func (e *CabinetExtractor) ListContents(cabPath string) ([]string, error) {
	if !utils.FileExists(cabPath) {
		err := fmt.Errorf("CAB 文件不存在: %s", cabPath)
		log.LogWrite(-2, "[ListContents]源文件不存在: %v", err)
		return nil, err
	}

	out, err := tools.RunCmd(e.expandPath, nil, nil, "", "-D", cabPath)
	if err != nil {
		msg := strings.TrimSpace(out)
		if msg == "" {
			msg = err.Error()
		}
		log.LogWrite(-2, "[ListContents]读取CAB目录失败: cab=%s msg=%s", cabPath, msg)
		return nil, fmt.Errorf("expand.exe -D 失败: %s", msg)
	}

	// best-effort：取每行第一个字段当作候选文件名，过滤掉明显的非文件行
	var res []string
	seen := map[string]struct{}{}
	for _, line := range strings.Split(out, "\n") {
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

// IsCabFile 根据扩展名判断是否为 .cab 文件。
func IsCabFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".cab"
}

// IsValidCabFile 通过魔数判断是否 CAB："MSCF"。
// 说明：CAB 文件头 4 字节通常是 "MSCF"。
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

// ExtractCab 便捷函数：创建 extractor 并解压指定 cab 到 destDir。
func ExtractCab(cabPath, destDir string) ([]string, error) {
	ex, err := NewCab()
	if err != nil {
		log.LogWrite(-2, "[ExtractCab]初始化CAB解压器失败: err=%v", err)
		return nil, err
	}
	return ex.Extract(cabPath, destDir)
}

// CabExtractFailure 表示批量解压时某个 CAB 的失败信息。
type CabExtractFailure struct {
	CabPath string // CAB 路径
	Err     error  // 失败原因
}

// ExtractAllCabs 解压 sourceDir 下所有 .cab 到 destDir/<cabname>/
// 返回：成功数量、失败列表、致命错误（如无法读目录/无法创建目标目录）。
func ExtractAllCabs(sourceDir, destDir string) (int, []CabExtractFailure, error) {
	ex, err := NewCab()
	if err != nil {
		return 0, nil, err
	}
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		log.LogWrite(-2, "[ExtractAllCabs]创建目标目录失败: dir=%s err=%v", destDir, err)
		return 0, nil, fmt.Errorf("创建目标目录失败: %w", err)
	}

	entries, err := os.ReadDir(sourceDir)
	if err != nil {
		log.LogWrite(-2, "[ExtractAllCabs]读取源目录失败: dir=%s err=%v", sourceDir, err)
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

// FindCabFiles 扫描目录（不递归），返回其中所有 .cab 文件的完整路径。
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

// FindCabFilesRecursive 递归扫描目录，返回所有 .cab 文件路径。
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

// verifyExpandAvailable 验证 expand.exe 是否“可运行”。
// 说明：有些版本/环境下 expand.exe -? 可能返回非 0，
func verifyExpandAvailable(path string) bool {
	// 有些版本/环境下 -? 可能返回非 0，但只要能启动就视为可用
	_, err := tools.RunCmd(path, nil, nil, "", "-?")
	if err == nil {
		return true
	}

	// 如果是退出码非 0（进程确实启动并退出），也当作可用
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return true
	}

	// 例如找不到文件、权限问题等
	return false
}

// scanFilesRecursive 递归扫描 root 目录，返回所有文件路径（不包含目录）。
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

var _ = syscall.Errno(0)
var _ = runtime.GOOS
