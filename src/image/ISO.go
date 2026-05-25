package image

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"ReSys/src/disk"
	"ReSys/src/log"
	"ReSys/src/tools"
)

var (
	Shell32           = syscall.NewLazyDLL("shell32.dll")
	procShellExecuteW = Shell32.NewProc("ShellExecuteW")
)

const (
	swHide = 0
)

// shellExecuteVerb 调用 ShellExecuteW 执行指定动词。
func shellExecuteVerb(path string, verb string) error {
	pPath, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		log.LogWrite(0, "[shellExecuteVerb] encode path failed: path=%s err=%v", path, err)
		return err
	}
	pVerb, err := syscall.UTF16PtrFromString(verb)
	if err != nil {
		log.LogWrite(0, "[shellExecuteVerb] encode verb failed: verb=%s err=%v", verb, err)
		return err
	}

	r, _, callErr := procShellExecuteW.Call(
		0,
		uintptr(unsafe.Pointer(pVerb)),
		uintptr(unsafe.Pointer(pPath)),
		0,
		0,
		uintptr(swHide),
	)
	if r <= 32 {
		if callErr != nil && callErr != syscall.Errno(0) {
			log.LogWrite(0, "[shellExecuteVerb] call failed: path=%s verb=%s ret=%d err=%v", path, verb, r, callErr)
			return fmt.Errorf("ShellExecuteW failed: ret=%d err=%w", r, callErr)
		}
		log.LogWrite(0, "[shellExecuteVerb] call failed: path=%s verb=%s ret=%d", path, verb, r)
		return fmt.Errorf("ShellExecuteW failed: ret=%d", r)
	}
	return nil
}

// MountISO 通过 shell 动作挂载 ISO，返回新出现的 CD 盘符。
func MountISO(isoPath string, wait time.Duration) (string, error) {
	if _, err := os.Stat(isoPath); err != nil {
		log.LogWrite(0, "[MountISO] iso not found: path=%s err=%v", isoPath, err)
		return "", fmt.Errorf("iso not found: %w", err)
	}

	before, err := disk.ListCD()
	if err != nil {
		log.LogWrite(0, "[MountISO] list cdrom before mount failed: err=%v", err)
		return "", fmt.Errorf("list cdrom before mount: %w", err)
	}
	beforeSet := make(map[string]struct{}, len(before))
	for _, d := range before {
		beforeSet[d] = struct{}{}
	}

	if err := shellExecuteVerb(isoPath, "mount"); err != nil {
		if err2 := shellExecuteVerb(isoPath, "open"); err2 != nil {
			log.LogWrite(0, "[MountISO] mount failed: mountErr=%v openErr=%v", err, err2)
			return "", fmt.Errorf("mount/open iso failed: %v / %v", err, err2)
		}
	}

	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		time.Sleep(500 * time.Millisecond)

		now, err := disk.ListCD()
		if err != nil {
			log.LogWrite(0, "[MountISO] list cdrom after mount failed: err=%v", err)
			continue
		}
		for _, d := range now {
			if _, ok := beforeSet[d]; !ok {
				return d, nil
			}
		}
	}

	return "", errors.New("timeout: iso mounted but no new cdrom drive detected")
}

// UnpackISO 使用 7z.exe 解包 ISO 到目标目录。
// 先强制按 UDF 解包，失败后再走自动识别格式。
func UnpackISO(isoPath, dstDir string) error {
	if err := os.MkdirAll(dstDir, 0755); err != nil {
		log.LogWrite(0, "[UnpackISO] create dir failed: dir=%s err=%v", dstDir, err)
		return fmt.Errorf("create dst dir: %w", err)
	}
	if _, err := os.Stat(isoPath); err != nil {
		log.LogWrite(0, "[UnpackISO] open iso failed: path=%s err=%v", isoPath, err)
		return fmt.Errorf("open iso: %w", err)
	}

	bin, err := path7z()
	if err != nil {
		log.LogWrite(0, "[UnpackISO] find 7z failed: err=%v", err)
		return err
	}
	work := filepath.Dir(bin)
	log.LogWrite(0, "[UnpackISO] use 7z: bin=%s iso=%s dir=%s", bin, isoPath, dstDir)

	argsUDF := []string{"x", "-tudf", "-y", "-aoa", "-o" + dstDir, isoPath}
	outUDF, errUDF := tools.RunCmd(bin, nil, nil, work, argsUDF...)
	if errUDF == nil {
		return nil
	}

	argsAuto := []string{"x", "-y", "-aoa", "-o" + dstDir, isoPath}
	outAuto, errAuto := tools.RunCmd(bin, nil, nil, work, argsAuto...)
	if errAuto == nil {
		return nil
	}

	log.LogWrite(0, "[UnpackISO] 7z extract failed: iso=%s dir=%s udfErr=%v autoErr=%v", isoPath, dstDir, errUDF, errAuto)
	return fmt.Errorf("extract iso by 7z failed: udf=%v auto=%v\nudfOut=%s\nautoOut=%s", errUDF, errAuto, outUDF, outAuto)
}

// path7z 从程序目录向上查找 tools\7z.exe。
func path7z() (string, error) {
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		for i := 0; i < 4; i++ {
			p := filepath.Join(dir, "tools", "7z.exe")
			if st, e := os.Stat(p); e == nil && !st.IsDir() {
				return p, nil
			}
			next := filepath.Dir(dir)
			if next == dir {
				break
			}
			dir = next
		}
	}
	return "", fmt.Errorf("7z.exe not found in tools directory")
}

type isoList struct {
	root   []string
	src    []string
	ins    []string
	hasSrc bool
	hasWim bool
	hasEsd bool
	hasSwm bool
}

// listISO7z 使用 7z 列表模式读取 ISO 文件条目。
func listISO7z(isoPath string) (*isoList, error) {
	bin, err := path7z()
	if err != nil {
		return nil, err
	}
	work := filepath.Dir(bin)
	out, err := tools.RunCmd(bin, nil, func(string) {}, work, "l", "-slt", isoPath)
	if err != nil {
		return nil, fmt.Errorf("7z list failed: %w, out=%s", err, strings.TrimSpace(out))
	}
	return parseISOList(isoPath, out), nil
}

func parseISOList(isoPath, out string) *isoList {
	res := &isoList{
		root: make([]string, 0, 16),
		src:  make([]string, 0, 64),
		ins:  make([]string, 0, 16),
	}
	isoAbs := cleanISOPath(isoPath)
	isoBase := strings.ToLower(filepath.Base(isoAbs))

	lines := strings.Split(strings.ReplaceAll(out, "\r", ""), "\n")
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if len(line) < 7 {
			continue
		}
		if !strings.HasPrefix(strings.ToLower(line), "path = ") {
			continue
		}

		item := strings.TrimSpace(line[7:])
		item = strings.ReplaceAll(item, "\\", "/")
		item = strings.TrimSpace(item)
		item = strings.TrimLeft(item, "/")
		item = strings.TrimSuffix(item, "/")
		if item == "" {
			continue
		}

		low := strings.ToLower(item)
		if low == isoAbs || low == isoBase {
			continue
		}

		parts := strings.Split(low, "/")
		if len(parts) > 0 && parts[0] != "" {
			res.root = addISOItem(res.root, parts[0])
		}
		if !strings.HasPrefix(low, "sources/") {
			continue
		}

		res.hasSrc = true
		sub := strings.TrimPrefix(low, "sources/")
		if sub == "" {
			continue
		}
		res.src = addISOItem(res.src, sub)
		if strings.HasPrefix(sub, "install") {
			res.ins = addISOItem(res.ins, sub)
		}
		switch sub {
		case "install.wim":
			res.hasWim = true
		case "install.esd":
			res.hasEsd = true
		default:
			if strings.HasPrefix(sub, "install") && strings.HasSuffix(sub, ".swm") {
				res.hasSwm = true
			}
		}
	}

	sort.Strings(res.root)
	sort.Strings(res.src)
	sort.Strings(res.ins)
	return res
}

func addISOItem(dst []string, item string) []string {
	for _, old := range dst {
		if old == item {
			return dst
		}
	}
	return append(dst, item)
}

func cleanISOPath(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	abs = strings.ReplaceAll(abs, "\\", "/")
	return strings.ToLower(strings.TrimSpace(abs))
}
