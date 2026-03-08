package main

import (
	"ReSys/src/disk"
	D "ReSys/src/dism"
	"ReSys/src/log"
	"ReSys/src/tools"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
)

var Dism = D.NewDism()

// ensureWimWritable 确保 WIM 文件可写。
func ensureWimWritable(wim string) error {
	st, err := os.Stat(wim)
	if err != nil {
		log.LogWrite(0, "[ensureWimWritable]ensureWimWritable Stat失败: wim=%s err=%v", wim, err)
		return fmt.Errorf("WIM不存在或不可访问: %w", err)
	}
	if st.IsDir() {
		return fmt.Errorf("WIM路径是目录不是文件: %s", wim)
	}

	tryOpenRW := func() error {
		f, e := os.OpenFile(wim, os.O_RDWR, 0)
		if e != nil {
			return e
		}
		_ = f.Close()
		return nil
	}

	if err := tryOpenRW(); err != nil {
		if e2 := tools.ClearReadonly(wim); e2 != nil {
			log.LogWrite(0, "[ensureWimWritable]ensureWimWritable 去只读失败: wim=%s err=%v", wim, e2)
			return fmt.Errorf("WIM不可写(打开失败): %v；去只读失败: %v", err, e2)
		}
		if err2 := tryOpenRW(); err2 != nil {
			log.LogWrite(0, "[ensureWimWritable]ensureWimWritable 仍不可写: wim=%s err=%v", wim, err2)
			return fmt.Errorf("WIM仍不可写(已去只读): %v", err2)
		}
	}

	dir := filepath.Dir(wim)
	tf, err := os.CreateTemp(dir, "wimwrite_*")
	if err != nil {
		log.LogWrite(0, "[ensureWimWritable]ensureWimWritable 创建临时文件失败: dir=%s err=%v", dir, err)
		return fmt.Errorf("WIM所在目录不可写: %s: %w", dir, err)
	}
	name := tf.Name()
	_ = tf.Close()
	_ = tools.Remove(name, false)

	return nil
}

// findTool 查找工具路径（优先 PATH，失败使用 fallback）。
func findTool(name, fallback string) string {
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	if fallback != "" {
		if st, err := os.Stat(fallback); err == nil && !st.IsDir() {
			return fallback
		}
	}
	return ""
}

// runCmdWithTimeout 执行命令并设置超时。
func runCmdWithTimeout(exe string, args []string, stdinText string, to time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), to)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if stdinText != "" {
		cmd.Stdin = strings.NewReader(stdinText)
	}
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	out := buf.String()
	if ctx.Err() == context.DeadlineExceeded {
		log.LogWrite(0, "[runCmdWithTimeout]runCmdWithTimeout 超时: exe=%s args=%v", exe, args)
		return out, fmt.Errorf("超时: %s %s", exe, strings.Join(args, " "))
	}
	return out, err
}

// 插入启动项
// appendExecLine 向 Pecmd.ini 追加启动项。
func appendExecLine(b []byte, line string) ([]byte, error) {
	pickNLBytes := func(src []byte) []byte {
		if bytes.Contains(src, []byte("\r\n")) {
			return []byte("\r\n")
		}
		if bytes.Contains(src, []byte("\n")) {
			return []byte("\n")
		}
		return []byte("\r\n")
	}

	lowerASCII := func(c byte) byte {
		if c >= 'A' && c <= 'Z' {
			return c + 32
		}
		return c
	}
	isSpace := func(c byte) bool { return c == ' ' || c == '\t' }

	findEndfileLineStartBytes := func(src []byte) (int, bool) {
		i := 0
		for i < len(src) {
			lineStart := i
			j := bytes.IndexByte(src[i:], '\n')
			if j == -1 {
				i = len(src)
			} else {
				i += j + 1
			}
			lineBytes := src[lineStart:i]
			trimmed := bytes.TrimRight(lineBytes, "\r\n")
			trimmed = bytes.TrimLeft(trimmed, " \t")
			if len(trimmed) < len("_ENDFILE") {
				continue
			}
			ok := true
			for k := 0; k < len("_ENDFILE"); k++ {
				if lowerASCII(trimmed[k]) != lowerASCII("_ENDFILE"[k]) {
					ok = false
					break
				}
			}
			if !ok {
				continue
			}
			if len(trimmed) == len("_ENDFILE") {
				return lineStart, true
			}
			c := trimmed[len("_ENDFILE")]
			if isSpace(c) || c == '/' || c == ';' {
				return lineStart, true
			}
		}
		return 0, false
	}

	containsFoldASCII := func(hay, needle []byte) bool {
		if len(needle) == 0 {
			return true
		}
		for i := 0; i+len(needle) <= len(hay); i++ {
			ok := true
			for j := 0; j < len(needle); j++ {
				if lowerASCII(hay[i+j]) != lowerASCII(needle[j]) {
					ok = false
					break
				}
			}
			if ok {
				return true
			}
		}
		return false
	}

	applyOnBytes := func(src []byte) []byte {
		nl := pickNLBytes(src)
		insertPos := len(src)
		if p, ok := findEndfileLineStartBytes(src); ok {
			insertPos = p
		}
		head := src[:insertPos]
		tail := src[insertPos:]

		if containsFoldASCII(head, []byte(line)) {
			return src
		}

		out := make([]byte, 0, len(src)+len(line)+len(nl)+4)
		out = append(out, head...)
		if len(out) > 0 && out[len(out)-1] != '\n' {
			out = append(out, nl...)
		}
		out = append(out, []byte(line)...)
		out = append(out, nl...)
		out = append(out, tail...)
		return out
	}

	// UTF-16LE BOM：FF FE
	if len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE {
		raw := b[2:]
		if len(raw)%2 != 0 {
			raw = raw[:len(raw)-1]
		}

		u := make([]uint16, len(raw)/2)
		for i := 0; i < len(u); i++ {
			u[i] = binary.LittleEndian.Uint16(raw[i*2 : i*2+2])
		}
		s := string(utf16.Decode(u))

		nl := "\r\n"
		if strings.Contains(s, "\n") && !strings.Contains(s, "\r\n") {
			nl = "\n"
		}

		reEnd := regexp.MustCompile(`(?im)^[ \t]*_endfile\b.*(?:\r?\n|$)`)
		loc := reEnd.FindStringIndex(s)

		head := s
		tail := ""
		if loc != nil {
			head = s[:loc[0]]
			tail = s[loc[0]:]
		}

		if strings.Contains(strings.ToLower(head), strings.ToLower(line)) {
			return b, nil
		}

		if head != "" && !strings.HasSuffix(head, "\n") {
			head += nl
		}
		head += line + nl
		s2 := head + tail

		u2 := utf16.Encode([]rune(s2))
		o := make([]byte, 2+len(u2)*2)
		o[0], o[1] = 0xFF, 0xFE
		for i, v := range u2 {
			binary.LittleEndian.PutUint16(o[2+i*2:2+i*2+2], v)
		}
		return o, nil
	}

	return applyOnBytes(b), nil
}

// wimRes 记录需要写入 WIM 的资源。
type wimRes struct {
	src   string
	dst   string
	isDir bool
}

// Patwim 修改wim文件，将自身及对应文件写入到wim中，并修改ini。
func Patwim(wim string) error {
	if wim == "" {
		return fmt.Errorf("wim为空")
	}
	wimAbs, err := filepath.Abs(wim)
	if err != nil {
		log.LogWrite(0, "[Patwim]Patwim 获取绝对路径失败: wim=%s err=%v", wim, err)
		return err
	}
	wim = wimAbs
	if err := ensureWimWritable(wim); err != nil {
		log.LogWrite(0, "[Patwim]Patwim ensureWimWritable失败: wim=%s err=%v", wim, err)
		return err
	}

	selfExe, err := os.Executable()
	if err != nil {
		log.LogWrite(0, "[Patwim]Patwim 获取自身路径失败: err=%v", err)
		return err
	}
	selfExe, _ = filepath.Abs(selfExe)
	selfName := filepath.Base(selfExe)

	dir := filepath.Dir(selfExe)

	qCmdArg := func(s string) string {
		if !strings.ContainsAny(s, " \t") && !strings.Contains(s, `"`) {
			return s
		}
		return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
	}

	wimlib := findTool("wimlib-imagex.exe", filepath.Join(dir, "tools", "wimlib-imagex.exe"))
	if wimlib == "" {
		log.LogWrite(0, "[Patwim]Patwim 未找到 wimlib-imagex.exe: dir=%s", dir)
		return fmt.Errorf("找不到 wimlib-imagex.exe（PATH 或 %s）", filepath.Join(dir, "tools", "wimlib-imagex.exe"))
	}

	resList := []wimRes{
		{src: selfExe, dst: `\Windows\` + selfName, isDir: false},
		{src: filepath.Join(dir, "Windows.json"), dst: `\Windows\Windows.json`, isDir: false},
		{src: filepath.Join(dir, "WinPE.json"), dst: `\Windows\WinPE.json`, isDir: false},
		{src: filepath.Join(dir, "disk.dll"), dst: `\Windows\disk.dll`, isDir: false},
		{src: filepath.Join(dir, "trackers.txt"), dst: `\Windows\trackers.txt`, isDir: false},
		{src: filepath.Join(dir, "tools"), dst: `\Windows\tools`, isDir: true},
	}

	keep := make([]wimRes, 0, len(resList))
	for _, r := range resList {
		st, e := os.Stat(r.src)
		if e != nil {
			log.LogWrite(0, "[Patwim]Patwim 资源缺失，跳过: %s err=%v", r.src, e)
			continue
		}
		if r.isDir && !st.IsDir() {
			log.LogWrite(0, "[Patwim]Patwim 资源类型错误(应为目录): %s", r.src)
			continue
		}
		if !r.isDir && st.IsDir() {
			log.LogWrite(0, "[Patwim]Patwim 资源类型错误(应为文件): %s", r.src)
			continue
		}
		keep = append(keep, r)
	}
	resList = keep

	wimBase := func(p string) string {
		p = strings.TrimRight(p, `\/`)
		if i := strings.LastIndexAny(p, `\/`); i >= 0 {
			return p[i+1:]
		}
		return p
	}
	wimDir := func(p string) string {
		p = strings.TrimRight(p, `\/`)
		if i := strings.LastIndexAny(p, `\/`); i >= 0 {
			return p[:i]
		}
		return ""
	}
	wimJoin := func(a, b string) string {
		if a == "" {
			return `\` + b
		}
		if strings.HasSuffix(a, `\`) || strings.HasSuffix(a, `/`) {
			return a + b
		}
		return a + `\` + b
	}

	getIdxs := func() ([]int, error) {
		out, err := runCmdWithTimeout(wimlib, []string{"info", wim}, "", 2*time.Minute)
		if err != nil {
			log.LogWrite(0, "[Patwim]Patwim wimlib info失败: wim=%s err=%v", wim, err)
			return nil, fmt.Errorf("wimlib info失败: %w\n%s", err, out)
		}

		reIdx := regexp.MustCompile(`(?m)^\s*Image\s+(\d+)\s*:`)
		ms := reIdx.FindAllStringSubmatch(out, -1)

		seen := map[int]bool{}
		idxs := make([]int, 0, len(ms))
		for _, m := range ms {
			i, _ := strconv.Atoi(m[1])
			if i > 0 && !seen[i] {
				seen[i] = true
				idxs = append(idxs, i)
			}
		}
		if len(idxs) > 0 {
			return idxs, nil
		}

		xout, xerr := runCmdWithTimeout(wimlib, []string{"info", wim, "--xml"}, "", 2*time.Minute)
		if xerr == nil && len(xout) > 0 {
			b := []byte(xout)
			if len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE {
				raw := b[2:]
				if len(raw)%2 != 0 {
					raw = raw[:len(raw)-1]
				}
				u := make([]uint16, len(raw)/2)
				for i := range u {
					u[i] = binary.LittleEndian.Uint16(raw[i*2 : i*2+2])
				}
				s := string(utf16.Decode(u))

				reXML := regexp.MustCompile(`(?i)<\s*image\b[^>]*\bindex\s*=\s*"(\d+)"`)
				ms2 := reXML.FindAllStringSubmatch(s, -1)

				seen2 := map[int]bool{}
				idxs2 := make([]int, 0, len(ms2))
				for _, m := range ms2 {
					i, _ := strconv.Atoi(m[1])
					if i > 0 && !seen2[i] {
						seen2[i] = true
						idxs2 = append(idxs2, i)
					}
				}
				if len(idxs2) > 0 {
					return idxs2, nil
				}
			} else {
				s := xout
				reXML := regexp.MustCompile(`(?i)<\s*image\b[^>]*\bindex\s*=\s*"(\d+)"`)
				ms2 := reXML.FindAllStringSubmatch(s, -1)

				seen2 := map[int]bool{}
				idxs2 := make([]int, 0, len(ms2))
				for _, m := range ms2 {
					i, _ := strconv.Atoi(m[1])
					if i > 0 && !seen2[i] {
						seen2[i] = true
						idxs2 = append(idxs2, i)
					}
				}
				if len(idxs2) > 0 {
					return idxs2, nil
				}
			}
		}

		return []int{1}, nil
	}

	idxs, err := getIdxs()
	if err != nil {
		return err
	}

	line := "EXEC %WinDir%\\" + selfName

	for _, idx := range idxs {
		dout, de := runCmdWithTimeout(wimlib, []string{"dir", wim, strconv.Itoa(idx), `--path=\Windows`}, "", 2*time.Minute)
		if de != nil {
			log.LogWrite(0, "[Patwim]Patwim dir失败: wim=%s idx=%d err=%v", wim, idx, de)
			return fmt.Errorf("dir失败 idx=%d: %v\n%s", idx, de, dout)
		}

		actual := map[string]string{}
		pecmdActual := ""
		for _, ln := range strings.Split(dout, "\n") {
			f := strings.Fields(strings.TrimSpace(ln))
			if len(f) == 0 {
				continue
			}
			nm := strings.TrimRight(f[len(f)-1], `\/`)
			lm := strings.ToLower(nm)
			if _, ok := actual[lm]; !ok {
				actual[lm] = nm
			}
			if lm == "pecmd.ini" {
				pecmdActual = nm
			}
		}

		cmdLines := make([]string, 0, len(resList)*2)
		for _, r := range resList {
			baseLower := strings.ToLower(wimBase(r.dst))
			delPath := r.dst
			if act, ok := actual[baseLower]; ok && act != "" {
				delPath = wimJoin(wimDir(r.dst), act)
			}
			if r.isDir {
				cmdLines = append(cmdLines, "delete --recursive --force "+qCmdArg(delPath))
			} else {
				cmdLines = append(cmdLines, "delete --force "+qCmdArg(delPath))
			}

			cmdLines = append(cmdLines, "add "+qCmdArg(r.src)+" "+qCmdArg(r.dst))
		}
		script := strings.Join(cmdLines, "\n") + "\n"

		uout, ue := runCmdWithTimeout(wimlib, []string{"update", wim, strconv.Itoa(idx)}, script, 10*time.Minute)
		if ue != nil {
			log.LogWrite(0, "[Patwim]Patwim update失败: wim=%s idx=%d err=%v", wim, idx, ue)
			return fmt.Errorf("写入资源失败 idx=%d: %v\n%s", idx, ue, uout)
		}

		iniName := pecmdActual
		if iniName == "" {
			iniName = "Pecmd.ini"
		}

		tmp, _ := os.MkdirTemp("", "wim_")
		_, err = runCmdWithTimeout(wimlib,
			[]string{"extract", wim, strconv.Itoa(idx), `\Windows\` + iniName, "--dest-dir=" + tmp},
			"",
			5*time.Minute,
		)
		if err != nil {
			log.LogWrite(0, "[Patwim]Patwim extract失败: wim=%s idx=%d err=%v", wim, idx, err)
		}

		p1 := filepath.Join(tmp, "Windows", iniName)
		p2 := filepath.Join(tmp, iniName)
		inip := p1
		if _, e1 := os.Stat(p1); e1 != nil {
			inip = p2
		}
		if _, e2 := os.Stat(inip); e2 != nil {
			_ = os.MkdirAll(filepath.Dir(p1), 0o755)
			inip = p1
			_ = os.WriteFile(inip, []byte{}, 0o644)
		}

		b, _ := os.ReadFile(inip)
		updated, err := appendExecLine(b, line)
		if err != nil {
			log.LogWrite(0, "[Patwim]Patwim appendExecLine失败: idx=%d err=%v", idx, err)
			_ = tools.Remove(tmp, true)
			return fmt.Errorf("修改ini失败 idx=%d: %w", idx, err)
		}
		if err := os.WriteFile(inip, updated, 0o644); err != nil {
			log.LogWrite(0, "[Patwim]Patwim 写入ini失败: idx=%d err=%v", idx, err)
			_ = tools.Remove(tmp, true)
			return fmt.Errorf("写入ini失败 idx=%d: %w", idx, err)
		}

		iniDst := `\Windows\` + iniName
		iniScript := strings.Join([]string{
			"delete --force " + qCmdArg(iniDst),
			"add " + qCmdArg(inip) + " " + qCmdArg(iniDst),
		}, "\n") + "\n"

		iout, ie := runCmdWithTimeout(wimlib, []string{"update", wim, strconv.Itoa(idx)}, iniScript, 10*time.Minute)
		_ = tools.Remove(tmp, true)
		if ie != nil {
			log.LogWrite(0, "[Patwim]Patwim update ini失败: wim=%s idx=%d err=%v", wim, idx, ie)
			return fmt.Errorf("写ini失败 idx=%d: %v\n%s", idx, ie, iout)
		}
		if err := verifyPatwimWrite(wimlib, wim, idx, resList, line); err != nil {
			log.LogWrite(0, "[Patwim]Patwim 校验失败: wim=%s idx=%d err=%v", wim, idx, err)
			return err
		}
	}

	return nil
}

// verifyPatwimWrite 校验写入成功。
func verifyPatwimWrite(wimlib, wim string, idx int, resList []wimRes, line string) error {
	if wimlib == "" || wim == "" {
		return fmt.Errorf("wimlib/wim 不能为空")
	}
	for _, r := range resList {
		out, err := runCmdWithTimeout(wimlib, []string{"dir", wim, strconv.Itoa(idx), "--path=" + r.dst}, "", 2*time.Minute)
		if err != nil {
			return fmt.Errorf("校验资源失败: path=%s err=%w\n%s", r.dst, err, out)
		}
	}

	tmp, err := os.MkdirTemp("", "wim_verify_")
	if err != nil {
		return fmt.Errorf("创建临时目录失败: %w", err)
	}
	defer func() {
		_ = tools.Remove(tmp, true)
	}()

	iniPath := `\Windows\Pecmd.ini`
	if _, err := runCmdWithTimeout(wimlib, []string{"extract", wim, strconv.Itoa(idx), iniPath, "--dest-dir=" + tmp}, "", 3*time.Minute); err != nil {
		return fmt.Errorf("校验ini提取失败: %w", err)
	}
	cand := filepath.Join(tmp, "Windows", "Pecmd.ini")
	if _, err := os.Stat(cand); err != nil {
		cand = filepath.Join(tmp, "Pecmd.ini")
	}
	b, err := os.ReadFile(cand)
	if err != nil {
		return fmt.Errorf("校验ini读取失败: %w", err)
	}
	if !strings.Contains(strings.ToLower(string(b)), strings.ToLower(line)) {
		return fmt.Errorf("校验ini失败: 启动项未写入")
	}
	return nil
}

// 安装 WIM 镜像到指定卷。
// wimPath:wim路径
// index:要安装的索引
// targetVol:目标卷，如"C:"、"C:\"
func ApplyWimImage(wimPath string, index int, targetVol string) error {
	p := strings.TrimSpace(wimPath)
	if len(p) < 4 || !strings.EqualFold(strings.ToLower(filepath.Ext(p)), ".wim") {
		return fmt.Errorf("不是WIM镜像: %s", wimPath)
	}

	return Dism.ApplyImageCmd(wimPath, targetVol, uint32(index), nil)
}

// 安装ESD镜像到指定卷
func ApplyEsdImage(esdPath string, index int, targetVol string) error {
	return Dism.ApplyImageCmd(esdPath, targetVol, uint32(index), nil)
}

// 安装ISO镜像到指定卷
func ApplyISOImage(isoPath string, index int, targetVol string) error {
	isoRoot, err := MountISO(isoPath, 30*time.Second)
	if err != nil {
		parts := disk.Findpart()
		if len(parts) == 0 {
			log.LogWrite(0, "[ApplyISOImage]ApplyISOImage 未找到可用分区用于解包ISO")
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
			log.LogWrite(0, "[ApplyISOImage]ApplyISOImage 解包ISO失败:"+err.Error())
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
			log.LogWrite(0, "[ApplyISOImage]ApplyISOImage ISO中未找到安装镜像！")
			return fmt.Errorf("ISO中未找到安装镜像！")
		}
		installPath = found[0]
	}

	if strings.EqualFold(filepath.Ext(installPath), ".esd") {
		if ApplyEsdImage(installPath, index, targetVol) != nil {
			log.LogWrite(0, "[ApplyISOImage]ApplyISOImage 应用镜像失败！")
			return fmt.Errorf("应用镜像失败！")
		}
		return nil
	}
	if strings.EqualFold(filepath.Ext(installPath), ".wim") {
		if ApplyWimImage(installPath, index, targetVol) != nil {
			log.LogWrite(0, "[ApplyISOImage]ApplyISOImage 应用镜像失败！")
			return fmt.Errorf("应用镜像失败！")
		}
		return nil
	}
	log.LogWrite(0, "[ApplyISOImage]ApplyISOImage 不支持的镜像")

	return fmt.Errorf("ISO安装镜像类型不支持！")
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
func finalizeImageMeta(m *D.ImageMeta) {
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
func detectImageInfos(imagePath string) ([]D.ImageMeta, error) {
	ext := strings.ToLower(filepath.Ext(imagePath))
	if ext != ".iso" {
		return Dism.ListImageInfos(imagePath)
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
	return Dism.ListImageInfos(installPath)
}

// 按优先级选择镜像索引
func selectInstallIndex(infos []D.ImageMeta) int {
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
func detectTargetFromInfos(infos []D.ImageMeta) string {
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
