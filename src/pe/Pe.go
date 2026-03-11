package pe

import (
	"ReSys/src/boot"
	"ReSys/src/disk"
	"ReSys/src/file"
	"ReSys/src/log"
	"ReSys/src/tools"
	"ReSys/src/windows"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"

	"ReSys/src/utils"
)

// 从多个候选里挑最合适的pe(一般不会用到)
func ChooseBestWim(paths []string, arch string) string {
	if len(paths) == 0 {
		return ""
	}
	arch = strings.TrimSpace(strings.ToLower(arch))

	score := func(p string) int {
		s := 0
		lp := strings.ToLower(p)

		if strings.Contains(lp, `\petemp\boot.wim`) {
			s += 300
		}
		if strings.Contains(lp, `\petemp\`) {
			s += 100
		}
		if strings.Contains(lp, "wepe") {
			s += 50
		}
		if strings.Contains(lp, "firpe") || strings.Contains(lp, "hotpe") {
			s += 20
		}

		// 架构偏好
		if arch == "64" {
			if strings.Contains(lp, "64") || strings.Contains(lp, "x64") || strings.Contains(lp, "amd64") {
				s += 20
			}
			if strings.Contains(lp, "32") || strings.Contains(lp, "x86") {
				s -= 10
			}
		} else if arch == "32" {
			if strings.Contains(lp, "32") || strings.Contains(lp, "x86") {
				s += 20
			}
			if strings.Contains(lp, "64") || strings.Contains(lp, "x64") || strings.Contains(lp, "amd64") {
				s -= 10
			}
		}
		return s
	}

	best := paths[0]
	bestScore := score(best)
	for _, p := range paths[1:] {
		if sc := score(p); sc > bestScore {
			best, bestScore = p, sc
		}
	}
	return best
}

type peOpt struct {
	n, s, w, a string
}

type peCand struct {
	nm   string
	arch string // opts 的 a
	lt   string // 盘符字母，如 "C"
	root string // 如 "C:\"
	wAbs string
	wRel string
	sAbs string
	sRel string
	sPat string // opts.s（用于缺 SDI 时决定复制到哪里）
}

// parseGoToPEArgs 函数。
func parseGoToPEArgs(paths []string) (string, string, error) {
	if len(paths) == 0 {
		return "", "", nil
	}
	if len(paths) != 2 {
		return "", "", fmt.Errorf("参数数量错误：GoToPE(scan) 或 GoToPE(scan, sdiPath, wimPath)")
	}
	customSdi := strings.TrimSpace(paths[0])
	customWim := strings.TrimSpace(paths[1])
	if customSdi == "" || customWim == "" {
		return "", "", fmt.Errorf("自定义路径需要同时指定 sdi 和 wim（要么都传，要么都不传）")
	}
	return customSdi, customWim, nil
}

// collectPECands 函数。
func collectPECands(dvs []string, opts []peOpt, wantArch, customSdi, customWim string) (map[string]peCand, []string, error) {
	hasGlob := func(s string) bool { return strings.ContainsAny(s, "*?[") }
	hasDrivePrefix := func(p string) bool { return len(p) >= 2 && p[1] == ':' }

	// 把 abs 变成相对卷根 \xxx\yyy
	toRel := func(root, abs string) string {
		abs = strings.ReplaceAll(abs, "/", `\`)
		root = strings.ReplaceAll(root, "/", `\`)
		if len(abs) >= len(root) && strings.EqualFold(abs[:len(root)], root) {
			rest := abs[len(root):]
			rest = strings.TrimPrefix(rest, `\`)
			return `\` + rest
		}
		if len(abs) >= 3 && abs[1] == ':' && (abs[2] == '\\' || abs[2] == '/') {
			return `\` + strings.TrimPrefix(abs[3:], `\`)
		}
		return abs
	}

	// 返回所有匹配（大小写不敏感 + 支持通配符）
	allMatchesInsensitive := func(pattern string) ([]string, error) {
		pattern = strings.ReplaceAll(pattern, "/", `\`)

		if !hasGlob(pattern) {
			if utils.DirExists(pattern) {
				return []string{pattern}, nil
			}
			return nil, nil
		}

		dir := filepath.Dir(pattern)
		base := filepath.Base(pattern)

		if hasGlob(dir) {
			ms, _ := filepath.Glob(pattern)
			var out []string
			for _, m := range ms {
				if utils.DirExists(m) {
					out = append(out, m)
				}
			}
			return out, nil
		}

		entries, e := os.ReadDir(dir)
		if e != nil {
			ms, _ := filepath.Glob(pattern)
			var out []string
			for _, m := range ms {
				if utils.DirExists(m) {
					out = append(out, m)
				}
			}
			return out, nil
		}

		patLower := strings.ToLower(base)
		var out []string
		for _, ent := range entries {
			if ent.IsDir() {
				continue
			}
			nameLower := strings.ToLower(ent.Name())
			ok, _ := filepath.Match(patLower, nameLower)
			if ok {
				out = append(out, filepath.Join(dir, ent.Name()))
			}
		}
		return out, nil
	}

	firstMatchInsensitive := func(pattern string) (string, bool) {
		ms, _ := allMatchesInsensitive(pattern)
		if len(ms) > 0 {
			return ms[0], true
		}
		return "", false
	}

	candByWim := map[string]peCand{}
	var allWims []string

	addCand := func(c peCand) {
		if old, ok := candByWim[c.wAbs]; ok {
			// 只做最小规则：优先保留“有 SDI”的
			if old.sAbs == "" && c.sAbs != "" {
				candByWim[c.wAbs] = c
			}
			return
		}
		candByWim[c.wAbs] = c
		allWims = append(allWims, c.wAbs)
	}

	if customSdi != "" && customWim != "" {
		sPat := strings.ReplaceAll(customSdi, "/", `\`)
		wPat := strings.ReplaceAll(customWim, "/", `\`)

		// 绝对路径
		if hasDrivePrefix(sPat) || hasDrivePrefix(wPat) {
			var vol string
			if hasDrivePrefix(sPat) {
				vol = strings.ToUpper(string(sPat[0]))
			}
			if hasDrivePrefix(wPat) {
				wVol := strings.ToUpper(string(wPat[0]))
				if vol != "" && vol != wVol {
					return nil, nil, fmt.Errorf("sdi 和 wim 不在同一盘：%s vs %s", vol, wVol)
				}
				if vol == "" {
					vol = wVol
				}
			}
			root := vol + `:\`

			// WIM 必须存在
			wAbs, ok := firstMatchInsensitive(wPat)
			if !ok {
				return nil, nil, fmt.Errorf("未找到WIM: %s", wPat)
			}

			sAbs, _ := firstMatchInsensitive(sPat)

			addCand(peCand{
				nm: "CUSTOM", arch: "",
				lt: vol, root: root,
				wAbs: wAbs, wRel: toRel(root, wAbs),
				sAbs: sAbs, sRel: func() string {
					if sAbs == "" {
						return ""
					}
					return toRel(root, sAbs)
				}(),
				sPat: sPat, // 直接用sPat，补 SDI 时会 materialize
			})
			return candByWim, allWims, nil
		}

		// 相对路径：遍历盘符
		for _, d := range dvs {
			if len(d) < 3 {
				continue
			}
			vol := strings.ToUpper(string(d[0]))
			root := vol + `:\`

			wAbs, okW := firstMatchInsensitive(d + strings.TrimPrefix(wPat, `\`))
			if !okW {
				continue
			}
			sAbs, _ := firstMatchInsensitive(d + strings.TrimPrefix(sPat, `\`))

			addCand(peCand{
				nm: "CUSTOM", arch: "",
				lt: vol, root: root,
				wAbs: wAbs, wRel: toRel(root, wAbs),
				sAbs: sAbs, sRel: func() string {
					if sAbs == "" {
						return ""
					}
					return toRel(root, sAbs)
				}(),
				sPat: `\` + strings.TrimPrefix(sPat, `\`),
			})
			return candByWim, allWims, nil
		}
		return nil, nil, fmt.Errorf("未找到匹配的SDI/WIM：SDI=%s WIM=%s", sPat, wPat)
	}

	// 按 opts 扫描所有盘符
	for _, o := range opts {
		if o.a != "" && utils.NormalizeArch(o.a) != utils.NormalizeArch(wantArch) {
			continue
		}

		for _, d := range dvs {
			if len(d) < 3 {
				continue
			}
			vol := strings.ToUpper(string(d[0]))
			root := vol + `:\`

			// SDI 可缺失（只取第一个匹配）
			sAbs := ""
			sMatches, _ := allMatchesInsensitive(d + strings.TrimPrefix(o.s, `\`))
			if len(sMatches) > 0 {
				sAbs = sMatches[0]
			}

			// WIM 收集全部
			wMatches, _ := allMatchesInsensitive(d + strings.TrimPrefix(o.w, `\`))
			for _, wAbs := range wMatches {
				c := peCand{
					nm:   o.n,
					arch: o.a,
					lt:   vol,
					root: root,
					wAbs: wAbs,
					wRel: toRel(root, wAbs),
					sAbs: sAbs,
					sRel: "",
					sPat: o.s,
				}
				if sAbs != "" {
					c.sRel = toRel(root, sAbs)
				}
				addCand(c)
			}
		}
	}
	return candByWim, allWims, nil
}

// 用 tools\boot.sdi 生成目标 SDI（只在缺 SDI 时调用）
func ensureSdiByCopy(root string, sPatRel string, wAbs string) (sAbs string, sRel string, err error) {
	findToolsBootSdi := func() (string, bool) {
		exe, e := os.Executable()
		if e != nil {
			return "", false
		}
		base := filepath.Dir(exe)
		cands := []string{
			filepath.Join(base, "tools", "boot.sdi"),
			filepath.Join(base, "tools", "BOOT.SDI"),
			filepath.Join(base, "tools", "Boot.sdi"),
		}
		for _, p := range cands {
			if utils.DirExists(p) {
				return p, true
			}
		}
		return "", false
	}

	toRel := func(root, abs string) string {
		abs = strings.ReplaceAll(abs, "/", `\`)
		root = strings.ReplaceAll(root, "/", `\`)
		if len(abs) >= len(root) && strings.EqualFold(abs[:len(root)], root) {
			rest := abs[len(root):]
			rest = strings.TrimPrefix(rest, `\`)
			return `\` + rest
		}
		if len(abs) >= 3 && abs[1] == ':' && (abs[2] == '\\' || abs[2] == '/') {
			return `\` + strings.TrimPrefix(abs[3:], `\`)
		}
		return abs
	}

	materializeSdiRel := func(sPat string) string {
		sPat = strings.ReplaceAll(sPat, "/", `\`)
		if sPat == "" {
			return ""
		}
		if !strings.ContainsAny(sPat, "*?[") {
			return sPat
		}
		dir := filepath.Dir(sPat)
		dst := filepath.Join(dir, "boot.sdi")
		if !strings.HasPrefix(dst, `\`) {
			dst = `\` + dst
		}
		return dst
	}

	src, ok := findToolsBootSdi()
	if !ok {
		return "", "", fmt.Errorf("缺少SDI，且未找到 %s", `tools\boot.sdi`)
	}

	dstRel := materializeSdiRel(sPatRel)
	if dstRel == "" {
		dstAbs := filepath.Join(filepath.Dir(wAbs), "boot.sdi")
		if e := file.Copy(src, dstAbs, false, true); e != nil {
			return "", "", e
		}
		return dstAbs, toRel(root, dstAbs), nil
	}

	dstAbs := filepath.Join(root, strings.TrimPrefix(dstRel, `\`))
	if e := file.Copy(src, dstAbs, false, true); e != nil {
		return "", "", e
	}
	return dstAbs, toRel(root, dstAbs), nil
}

// applyPEBoot 函数。
func applyPEBoot(best peCand) error {
	lt, sdi, wim, nm := best.lt, best.sRel, best.wRel, best.nm
	log.LogWrite(0, "[applyPEBoot]PE:", nm, "DRV:", lt, "SDI:", sdi, "WIM:", wim)

	bcdeditPath := utils.GetSystemExe("bcdedit.exe")
	out, err := tools.RunCmd(bcdeditPath, nil, nil, "")
	if err != nil && (errors.Is(err, os.ErrNotExist) || errors.Is(err, exec.ErrNotFound)) {
		exe, e := os.Executable()
		if e == nil {
			bcdeditPath = filepath.Join(filepath.Dir(exe), "tools", "bcdedit.exe")
		}
	}

	// /device guid
	out, err = tools.RunCmd(bcdeditPath, nil, nil, "", "/create", "/d", "pe", "/device")
	if err != nil {
		return err
	}
	re := regexp.MustCompile(`(?i)\{([a-f0-9-]+)\}`)
	m1 := re.FindStringSubmatch(out)
	if len(m1) < 2 {
		return fmt.Errorf("guid1解析失败: %s", out)
	}
	gd1 := strings.ToLower(m1[1])

	// ramdisksdi*
	_, err = tools.RunCmd(bcdeditPath, nil, nil, "", "/set", "{"+gd1+"}", "ramdisksdidevice", "partition="+lt+":")
	if err != nil {
		return err
	}
	_, err = tools.RunCmd(bcdeditPath, nil, nil, "", "/set", "{"+gd1+"}", "ramdisksdipath", sdi)
	if err != nil {
		return err
	}

	// /application osloader guid2
	out, err = tools.RunCmd(bcdeditPath, nil, nil, "", "/create", "/d", "pe", "/application", "osloader")
	if err != nil {
		return err
	}
	m2 := re.FindStringSubmatch(out)
	if len(m2) < 2 {
		return fmt.Errorf("guid2解析失败: %s", out)
	}
	gd2 := strings.ToLower(m2[1])

	// device/osdevice
	dev := fmt.Sprintf("ramdisk=[%s:]%s,{%s}", lt, wim, gd1)
	_, err = tools.RunCmd(bcdeditPath, nil, nil, "", "/set", "{"+gd2+"}", "device", dev)
	if err != nil {
		return err
	}
	_, err = tools.RunCmd(bcdeditPath, nil, nil, "", "/set", "{"+gd2+"}", "osdevice", dev)
	if err != nil {
		return err
	}

	// BIOS/UEFI
	fw := 0 // 1=BIOS 2=UEFI

	if t, e := boot.GetFwType(); e == nil {
		// 1=BIOS 2=UEFI 0=Unknown
		if t == 1 || t == 2 {
			fw = int(t)
		}
	} else {
		log.LogWrite(0, "[applyPEBoot]applyPEBoot: GetFwType 失败，走其他方案: %v", e)
	}

	// WinPE 注册表 PEFirmwareType（可能不存在；不存在时 reg 会 exit 1）
	if fw == 0 {
		regPath := utils.GetSystemExe("reg.exe")

		// 有些 WinPE 需要先 UpdateBootInfo 才会写出 PEFirmwareType
		wpeutilPath := utils.GetSystemExe("wpeutil.exe")
		if _, stErr := os.Stat(wpeutilPath); stErr == nil {
			_, _ = tools.RunCmd(wpeutilPath, nil, nil, "", "UpdateBootInfo")
		}

		regOut, er2 := tools.RunCmd(regPath, nil, nil, "", "query",
			`HKLM\SYSTEM\CurrentControlSet\Control`, "/v", "PEFirmwareType")

		if er2 == nil {
			r2 := regexp.MustCompile(`(?i)0x([0-9a-f]+)`)
			m3 := r2.FindStringSubmatch(regOut)
			if len(m3) >= 2 {
				if v, e3 := strconv.ParseInt(m3[1], 16, 32); e3 == nil {
					if v == 1 || v == 2 {
						fw = int(v)
					}
				}
			}
		} else {
			log.LogWrite(0, "[applyPEBoot]applyPEBoot: PEFirmwareType 不可用(忽略): %v", er2)
		}
	}

	// 用 bcdedit 判断 {fwbootmgr}（UEFI 通常存在）
	if fw == 0 {
		if _, e := tools.RunCmd(bcdeditPath, nil, nil, "", "/enum", "{fwbootmgr}"); e == nil {
			fw = 2
		} else {
			fw = 1
		}
	}

	p1 := `\windows\system32\boot\winload.efi`
	p2 := `\windows\system32\boot\winload.exe`
	if fw == 1 {
		p1, p2 = p2, p1
	}
	if _, err = tools.RunCmd(bcdeditPath, nil, nil, "", "/set", "{"+gd2+"}", "path", p1); err != nil {
		if _, err = tools.RunCmd(bcdeditPath, nil, nil, "", "/set", "{"+gd2+"}", "path", p2); err != nil {
			return err
		}
	}

	if _, err = tools.RunCmd(bcdeditPath, nil, nil, "", "/set", "{"+gd2+"}", "systemroot", `\windows`); err != nil {
		return err
	}
	if _, err = tools.RunCmd(bcdeditPath, nil, nil, "", "/set", "{"+gd2+"}", "detecthal", "YES"); err != nil {
		return err
	}
	if _, err = tools.RunCmd(bcdeditPath, nil, nil, "", "/set", "{"+gd2+"}", "winpe", "YES"); err != nil {
		return err
	}
	if _, err = tools.RunCmd(bcdeditPath, nil, nil, "", "/set", "{"+gd2+"}", "nx", "OptIn"); err != nil {
		return err
	}

	// 设置下次启动
	if _, err = tools.RunCmd(bcdeditPath, nil, nil, "", "/bootsequence", "{"+gd2+"}"); err != nil {
		return err
	}
	return nil
}

// 进入PE + 扫描模式：scan=true 时只返回最优 WIM/SDI
// 用法示例：
//
//	ok, wim, sdi, err := GoToPE(true)          // 扫描
//	_, _, _, err := GoToPE(false)             // 设置下次启动进PE
//	ok, wim, sdi, err := GoToPE(true, sdiPath, wimPath)   // 扫描/校验自定义
//	_, _, _, err := GoToPE(false, sdiPath, wimPath)       // 自定义设置启动
func GoToPE(scan bool, paths ...string) (bool, string, string, error) {
	customSdi, customWim, err := parseGoToPEArgs(paths)
	if err != nil {
		log.LogWrite(0, "[GoToPE]GoToPE 参数解析失败："+err.Error())
		return false, "", "", err
	}

	dvs, err := disk.ListDrive()
	if err != nil {
		log.LogWrite(0, "[GoToPE]GoToPE ListDrive失败："+err.Error())
		return false, "", "", err
	}

	wantArch := utils.NormalizeArch(utils.SelfArch())
	if utils.IsWOW64() {
		wantArch = "64"
	}

	opts := []peOpt{
		{"WEPE", `\WEPE\WEPE.SDI`, `\WEPE\WEPE64.WIM`, "64"},    //64位微PE
		{"WEPE", `\WEPE\WEPE.SDI`, `\WEPE\WEPE32.WIM`, "32"},    //32位微PE
		{"FIR", `\FirPE\BOOT.SDI`, `\FirPE\11PEX64.WIM`, "64"},  //64位win11的FirPE
		{"FIR", `\FirPE\BOOT.SDI`, `\FirPE\11PEX86.WIM`, "32"},  //32位FirPE
		{"HOT", `\HotPE\boot.sdi`, `\HotPE\Boot.wim`, "64"},     //64位HOTPE
		{"FirPE1", `\boot\boot.sdi`, `\boot\11pex64.wim`, "64"}, //64位FirPE1
		{"FirPE1", `\boot\boot.sdi`, `\boot\11pex86.wim`, "32"}, //32位FirPE1
		{"PETEMP", `\PETEMP\*.sdi`, `\PETEMP\*.wim`, ""},        //不强制架构，交给 ChooseBestWim
		{"PETEMP", `\PETEMP\*.SDI`, `\PETEMP\*.WIM`, ""},
	}

	candByWim, allWims, err := collectPECands(dvs, opts, wantArch, customSdi, customWim)
	if err != nil {
		log.LogWrite(0, "[GoToPE]GoToPE collectPECands失败: err=%v", err)
		if scan {
			return false, "", "", err
		}
		return false, "", "", err
	}

	if len(allWims) == 0 {
		if scan {
			return false, "", "", nil
		}
		log.LogWrite(0, "[GoToPE]GoToPE 未找到PE引导文件")
		return false, "", "", fmt.Errorf("未找到PE引导文件")
	}

	bestWim := ChooseBestWim(allWims, wantArch)
	best, ok := candByWim[bestWim]
	if !ok || bestWim == "" {
		if scan {
			return false, "", "", nil
		}
		log.LogWrite(0, "[GoToPE]GoToPE 选优失败: bestWim=%s wantArch=%s", bestWim, wantArch)
		return false, "", "", fmt.Errorf("ChooseBestWim 选优失败")
	}

	if best.sAbs == "" {
		sAbs, sRel, e := ensureSdiByCopy(best.root, best.sPat, best.wAbs)
		if e == nil {
			best.sAbs = sAbs
			best.sRel = sRel
			candByWim[best.wAbs] = best
		} else if !scan {
			log.LogWrite(0, "[GoToPE]GoToPE 自动补齐SDI失败: wim=%s err=%v", best.wAbs, e)
			return true, best.wAbs, "", e
		}
	}

	if scan {
		return true, best.wAbs, best.sAbs, nil
	}

	if best.sRel == "" {
		log.LogWrite(0, "[GoToPE]GoToPE 缺少SDI无法设置引导: wim=%s", best.wAbs)
		return true, best.wAbs, best.sAbs, fmt.Errorf("找到WIM但仍缺少SDI，无法设置ramdisk引导：WIM=%s", best.wAbs)
	}

	if err := applyPEBoot(best); err != nil {
		log.LogWrite(0, "[GoToPE]GoToPE 设置引导失败: wim=%s sdi=%s err=%v", best.wAbs, best.sAbs, err)
		return false, "", "", err
	}
	return false, "", "", nil
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
		if e2 := file.ClearReadonly(wim); e2 != nil {
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
	_ = file.Remove(name, false)

	return nil
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
			_ = file.Remove(tmp, true)
			return fmt.Errorf("修改ini失败 idx=%d: %w", idx, err)
		}
		if err := os.WriteFile(inip, updated, 0o644); err != nil {
			log.LogWrite(0, "[Patwim]Patwim 写入ini失败: idx=%d err=%v", idx, err)
			_ = file.Remove(tmp, true)
			return fmt.Errorf("写入ini失败 idx=%d: %w", idx, err)
		}

		iniDst := `\Windows\` + iniName
		iniScript := strings.Join([]string{
			"delete --force " + qCmdArg(iniDst),
			"add " + qCmdArg(inip) + " " + qCmdArg(iniDst),
		}, "\n") + "\n"

		iout, ie := runCmdWithTimeout(wimlib, []string{"update", wim, strconv.Itoa(idx)}, iniScript, 10*time.Minute)
		_ = file.Remove(tmp, true)
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
		_ = file.Remove(tmp, true)
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

// IsWePE 检测当前运行环境是否为微PE。
// 规则：系统盘的 Program Files 下存在 WepeGuide 目录则视为微PE。
func IsWePE() bool {
	root := windows.SystemDriveRoot()
	if root == "" {
		return false
	}
	wepeDir := filepath.Join(root, "Program Files", "WepeGuide")
	if st, err := os.Stat(wepeDir); err == nil && st.IsDir() {
		return true
	}
	return false
}
