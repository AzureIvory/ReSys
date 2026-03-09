package file

import (
	"ReSys/src/boot"
	"ReSys/src/disk"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unicode"
	"unsafe"
)

var (
	//文件操作相关
	Kernel32              = syscall.NewLazyDLL("kernel32.dll")
	modShell32            = syscall.NewLazyDLL("shell32.dll")
	procShellExecuteW     = modShell32.NewProc("ShellExecuteW")
	procCopyFileW         = Kernel32.NewProc("CopyFileW")
	procDeleteFileW       = Kernel32.NewProc("DeleteFileW")
	procRemoveDirectoryW  = Kernel32.NewProc("RemoveDirectoryW")
	procSetFileAttributes = Kernel32.NewProc("SetFileAttributesW")
	procFindFirstFileW    = Kernel32.NewProc("FindFirstFileW")
	procFindNextFileW     = Kernel32.NewProc("FindNextFileW")
	procFindClose         = Kernel32.NewProc("FindClose")
	procSetFileAttrsW     = Kernel32.NewProc("SetFileAttributesW")
	procSHFileOperationW  = modShell32.NewProc("SHFileOperationW")
)

const (
	FILE_ATTRIBUTE_NORMAL = 0x00000080
	FO_DELETE             = 0x0003
	FOF_SILENT            = 0x0004
	FOF_NOCONFIRMATION    = 0x0010
	FOF_NOERRORUI         = 0x0400
	FOF_NOCONFIRMMKDIR    = 0x0200
)

// SHFILEOPSTRUCTW 结构体（文件操作）
type shFileOpStructW struct {
	hwnd                  uintptr
	wFunc                 uint32
	pFrom                 *uint16
	pTo                   *uint16
	fFlags                uint16
	fAnyOperationsAborted int32
	hNameMappings         uintptr
	lpszProgressTitle     *uint16
}

// 尝试把src拷贝到dst。
// overwrite=true：覆盖；false：跳过
// createDir=true：目标目录不存在就创建；false：报错
func Copy(src, dst string, overwrite, createDir bool) error {
	si, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("Copy: src not found: %w", err)
	}

	copyOneFile := func(srcFile, dstFile string, overwrite, createDir bool) error {
		fi, err := os.Stat(srcFile)
		if err != nil {
			return fmt.Errorf("Copy: src not found: %w", err)
		}
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("Copy: src is not a regular file: %s", srcFile)
		}

		// 目标存在
		if dfi, err := os.Stat(dstFile); err == nil {
			if dfi.IsDir() {
				return fmt.Errorf("Copy: dst is a directory: %s", dstFile)
			}
			if !overwrite {
				// 跳过
				fmt.Println("[Copy] dst exists, skip file:", dstFile)
				return nil
			}
		}

		// 确保目标目录存在
		if dir := filepath.Dir(dstFile); dir != "" && dir != "." {
			if dfi, err := os.Stat(dir); err != nil {
				if os.IsNotExist(err) {
					if !createDir {
						return fmt.Errorf("Copy: dest dir not exist and createDir=false: %s", dir)
					}
					if err := os.MkdirAll(dir, 0755); err != nil {
						return fmt.Errorf("Copy: MkdirAll(%s) failed: %w", dir, err)
					}
				} else {
					return fmt.Errorf("Copy: stat dest dir failed: %w", err)
				}
			} else if !dfi.IsDir() {
				return fmt.Errorf("Copy: dest parent is not dir: %s", dir)
			}
		}

		// io.Copy
		if err := func() error {
			in, err := os.Open(srcFile)
			if err != nil {
				return err
			}
			defer in.Close()

			out, err := os.OpenFile(dstFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, fi.Mode().Perm())
			if err != nil {
				return err
			}
			defer out.Close()

			if _, err := io.Copy(out, in); err != nil {
				return err
			}
			return nil
		}(); err == nil {
			return nil
		} else {
			fmt.Println("[Copy] std copy failed, try cmd.exe:", err)
		}

		// cmd.exe
		if err := func() error {
			srcQ := `"` + srcFile + `"`
			dstQ := `"` + dstFile + `"`

			args := []string{"/C", "copy"}
			if overwrite {
				args = append(args, "/Y")
			} else {
				args = append(args, "/-Y")
			}
			args = append(args, srcQ, dstQ)

			cmd := exec.Command("cmd.exe", args...)
			cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			return cmd.Run()
		}(); err == nil {
			return nil
		} else {
			fmt.Println("[Copy] cmd copy failed, try CopyFileW:", err)
		}

		// WinAPI CopyFileW
		srcW, err := syscall.UTF16PtrFromString(srcFile)
		if err != nil {
			return fmt.Errorf("Copy: src UTF16 failed: %w", err)
		}
		dstW, err := syscall.UTF16PtrFromString(dstFile)
		if err != nil {
			return fmt.Errorf("Copy: dst UTF16 failed: %w", err)
		}

		var failIfExists uintptr = 0
		if !overwrite {
			failIfExists = 1
		}

		r, _, e := procCopyFileW.Call(
			uintptr(unsafe.Pointer(srcW)),
			uintptr(unsafe.Pointer(dstW)),
			failIfExists,
		)
		if r == 0 {
			if !overwrite {
				if errno, ok := e.(syscall.Errno); ok &&
					(errno == syscall.ERROR_FILE_EXISTS || errno == syscall.ERROR_ALREADY_EXISTS) {
					fmt.Println("[Copy] dst exists (CopyFileW), skip:", dstFile)
					return nil
				}
			}
			return fmt.Errorf("Copy: CopyFileW failed: %v", e)
		}
		return nil
	}

	// 目录分支
	if si.IsDir() {
		if dfi, err := os.Stat(dst); err == nil {
			if !dfi.IsDir() {
				return fmt.Errorf("Copy: dst exists and is not directory: %s", dst)
			}
		} else if os.IsNotExist(err) {
			if !createDir {
				return fmt.Errorf("Copy: dst dir not exist and createDir=false: %s", dst)
			}
			if err := os.MkdirAll(dst, si.Mode().Perm()); err != nil {
				return fmt.Errorf("Copy: MkdirAll root dst failed: %w", err)
			}
		} else {
			return fmt.Errorf("Copy: stat dst failed: %w", err)
		}

		// 递归遍历整个目录树
		return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if path == src {
				return nil
			}

			rel, err := filepath.Rel(src, path)
			if err != nil {
				return err
			}
			targetPath := filepath.Join(dst, rel)

			if info.IsDir() {
				if err := os.MkdirAll(targetPath, info.Mode().Perm()); err != nil {
					return err
				}
				return nil
			}

			return copyOneFile(path, targetPath, overwrite, true) // 子目录内部总是需要创建
		})
	}

	return copyOneFile(src, dst, overwrite, createDir)
}

// Remove 删除文件/目录。
// recursive=true：递归删除；false：仅删除文件或空目录
func Remove(path string, recursive bool) error {
	if _, err := os.Lstat(path); err != nil {
		return fmt.Errorf("Remove: stat failed: %w", err)
	}

	// os
	if recursive {
		if err := os.RemoveAll(path); err == nil {
			return nil
		}
	} else {
		if err := os.Remove(path); err == nil {
			return nil
		}
	}
	//winapi
	if pW, err := syscall.UTF16PtrFromString(path); err == nil {
		_, _, _ = procSetFileAttrsW.Call(uintptr(unsafe.Pointer(pW)), uintptr(FILE_ATTRIBUTE_NORMAL))
	}
	if recursive {
		// SHFileOperation 需要 double-null terminated 的 pFrom
		from := syscall.StringToUTF16(path)
		from = append(from, 0) // 再补一个 0，形成双 0 结尾

		op := shFileOpStructW{
			wFunc:  FO_DELETE,
			pFrom:  &from[0],
			fFlags: FOF_SILENT | FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_NOCONFIRMMKDIR,
		}
		r, _, _ := procSHFileOperationW.Call(uintptr(unsafe.Pointer(&op)))
		if r == 0 && op.fAnyOperationsAborted == 0 {
			return nil
		}
	} else {
		if pW, err := syscall.UTF16PtrFromString(path); err == nil {
			if rr, _, _ := procDeleteFileW.Call(uintptr(unsafe.Pointer(pW))); rr != 0 {
				return nil
			}
			if rr, _, _ := procRemoveDirectoryW.Call(uintptr(unsafe.Pointer(pW))); rr != 0 {
				return nil
			}
		}
	}

	// cmd.exe
	pQ := `"` + path + `"`
	if recursive {
		if err := exec.Command("cmd.exe", "/C", "rmdir", "/S", "/Q", pQ).Run(); err == nil {
			return nil
		} else {
			return fmt.Errorf("Remove: cmd rmdir failed: %w", err)
		}
	}

	_ = exec.Command("cmd.exe", "/C", "del", "/F", "/Q", pQ).Run()
	if err := exec.Command("cmd.exe", "/C", "rmdir", pQ).Run(); err == nil {
		return nil
	}
	return fmt.Errorf("Remove: failed (os/winapi/cmd): %s", path)
}

// 清除文件只读属性
func ClearReadonly(path string) error {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attrs, err := syscall.GetFileAttributes(p)
	if err != nil {
		return err
	}

	// 已经不是只读，直接返回
	if attrs&syscall.FILE_ATTRIBUTE_READONLY == 0 {
		return nil
	}

	attrs &^= syscall.FILE_ATTRIBUTE_READONLY
	return syscall.SetFileAttributes(p, attrs)
}

// 从指定的文件中，按偏移区间 [start, end) 抽取数据，写入到指定的文件中。
// 支持十进制和十六进制的偏移参数
func PeelFile(exePath, start, end, out string) error {
	boot.GetFwType()
	if exePath == "" {
		return errors.New("exePath 不能为空")
	}
	if out == "" {
		return errors.New("out 不能为空")
	}

	startOffset, err := parseOffsetString(start)
	if err != nil {
		return fmt.Errorf("解析 startOffset 失败: %w", err)
	}
	endOffset, err := parseOffsetString(end)
	if err != nil {
		return fmt.Errorf("解析 endOffset 失败: %w", err)
	}

	if startOffset < 0 || endOffset < 0 {
		return errors.New("startOffset/endOffset 不能为负数")
	}
	if endOffset <= startOffset {
		return fmt.Errorf("endOffset 必须大于 startOffset（区间为 [start,end)），当前 start=%d end=%d", startOffset, endOffset)
	}

	// 输入文件
	in, err := os.Open(exePath)
	if err != nil {
		return fmt.Errorf("打开输入文件失败: %w", err)
	}
	defer in.Close()

	st, err := in.Stat()
	if err != nil {
		return fmt.Errorf("获取输入文件信息失败: %w", err)
	}
	size := st.Size()
	if startOffset >= size {
		return fmt.Errorf("startOffset 超出文件大小: start=%d size=%d", startOffset, size)
	}
	if endOffset > size {
		return fmt.Errorf("endOffset 超出文件大小: end=%d size=%d", endOffset, size)
	}

	if !filepath.IsAbs(out) {
		return fmt.Errorf("out 必须是绝对路径: %s", out)
	}

	outDir := filepath.Dir(out)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("创建输出目录失败: %w", err)
	}

	// 输出文件
	out1, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("创建输出文件失败: %w", err)
	}
	defer func() { _ = out1.Close() }()

	// 只读取指定区间
	length := endOffset - startOffset
	section := io.NewSectionReader(in, startOffset, length)

	// 拷贝
	buf := make([]byte, 1024*1024) // 1MB buffer
	written, err := io.CopyBuffer(out1, section, buf)
	if err != nil {
		return fmt.Errorf("写出失败: %w", err)
	}
	if written != length {
		return fmt.Errorf("写出字节数不一致: expect=%d got=%d", length, written)
	}

	if err := out1.Sync(); err != nil {
		return fmt.Errorf("输出文件 Sync 失败: %w", err)
	}
	return nil
}

// 解析偏移字符串：
func parseOffsetString(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("偏移字符串为空")
	}

	// 处理符号
	if strings.HasPrefix(s, "-") {
		return 0, fmt.Errorf("不允许负数偏移: %s", s)
	}
	s = strings.TrimPrefix(s, "+")

	// 判定进制
	base := 10
	ss := strings.ToLower(s)

	if strings.HasPrefix(ss, "0x") {
		base = 16
		ss = ss[2:]
		if ss == "" {
			return 0, fmt.Errorf("无效十六进制偏移: %s", s)
		}
	} else {
		// 不带 0x：如果包含 a-f，则认为是十六进制；否则十进制
		for _, r := range ss {
			if unicode.IsLetter(r) {
				base = 16
				break
			}
		}
	}

	// 用 uint64 解析
	u, err := strconv.ParseUint(ss, base, 64)
	if err != nil {
		return 0, fmt.Errorf("无法解析偏移 %q (base=%d): %w", s, base, err)
	}
	maxInt64u := ^uint64(0) >> 1 // 0x7FFF... = MaxInt64
	if u > maxInt64u {
		return 0, fmt.Errorf("偏移过大，超出 int64 范围: %d", u)
	}
	return int64(u), nil
}

// 搜索文件
// root：目录
// pattern：文件，支持通配符，支持*.esd|*.wim|*.iso
// maxDepth：搜索子目录的层数
func FindFile(root string, pattern string, maxDepth int) ([]string, error) {
	if maxDepth < 0 {
		maxDepth = 0
	}

	root = filepath.Clean(root)

	fi, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("stat root: %w", err)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("root is not directory: %s", root)
	}

	// 支持 "*.esd|*.wim|*.iso"
	rawPats := strings.Split(pattern, "|")
	pats := make([]string, 0, len(rawPats))
	for _, p := range rawPats {
		p = strings.TrimSpace(p)
		if p != "" {
			pats = append(pats, p)
		}
	}
	if len(pats) == 0 {
		return nil, fmt.Errorf("empty pattern")
	}

	// 不进入这些目录
	skipDirs := map[string]struct{}{
		"system volume information": {},
		"$recycle.bin":              {},
		"Windows":                   {},
		"Program Files":             {},
		"Program Files (x86)":       {},
		"ProgramData":               {},
		"AppData":                   {},
		"Music":                     {},
		"Pictures":                  {},
		"Videos":                    {},
		"Temp":                      {},
	}

	var matches []string
	var fatalErr error

	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		if fatalErr != nil {
			return
		}
		if depth > maxDepth {
			return
		}

		ents, err := os.ReadDir(dir)
		if err != nil {
			return
		}

		for _, ent := range ents {
			if fatalErr != nil {
				return
			}

			name := ent.Name()
			full := filepath.Join(dir, name)

			if ent.IsDir() {
				if _, ok := skipDirs[strings.ToLower(name)]; ok {
					continue
				}
				if depth < maxDepth {
					walk(full, depth+1)
				}
				continue
			}

			// 通配符匹配
			if ent.Type().IsRegular() {
				for _, pat := range pats {
					ok, err := filepath.Match(pat, name)
					if err != nil {
						fatalErr = fmt.Errorf("bad pattern %q: %w", pat, err)
						return
					}
					if ok {
						matches = append(matches, full)
						break
					}
				}
			}
		}
	}

	walk(root, 0)

	if fatalErr != nil {
		return nil, fatalErr
	}
	return matches, nil
}

// 在所有盘符下搜索指定文件
// pattern：文件名，支持通配符，支持*.esd|*.wim|*.iso
// maxDepth：搜索子目录的层数
func FindFileAll(pattern string, maxDepth int) []string {
	drives, err := disk.ListDrive()
	if err != nil || len(drives) == 0 {
		return []string{}
	}

	limit := runtime.NumCPU()
	if limit < 2 {
		limit = 2
	}
	sem := make(chan struct{}, limit)

	var (
		wg  sync.WaitGroup
		mu  sync.Mutex
		out = make([]string, 0, 128)
	)

	for _, d := range drives {
		driveRoot := d
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			files, e := FindFile(driveRoot, pattern, maxDepth)
			if e != nil || len(files) == 0 {
				return
			}

			mu.Lock()
			out = append(out, files...)
			mu.Unlock()
		}()
	}
	wg.Wait()

	// 去重 + 排序
	if len(out) == 0 {
		return []string{}
	}
	seen := make(map[string]struct{}, len(out))
	dedup := make([]string, 0, len(out))
	for _, p := range out {
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		dedup = append(dedup, p)
	}
	sort.Strings(dedup)
	return dedup
}
