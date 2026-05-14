package boot

import (
	"ReSys/src/disk"
	"ReSys/src/dism"
	"ReSys/src/log"
	"ReSys/src/tools"
	"ReSys/src/utils"
	"ReSys/src/wimlib"
	"ReSys/src/windows"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var (
	prepWin     = prepWinDir
	prepFlat    = prepWinFlatDir
	mountWim    = mountWin
	applyWim    = applyWin
	extWin      = extWinDir
	runBCDboot  = runUEFIBoot
	getVolInfo  = disk.GetVolumeInfo
	findIdx     = firstWinIdx
	listInfo    = listWimInfo
	findWBIdx   = firstWinIdxWB
	getCurVer   = windows.GetCurrentWinVersion
	findBCDBoot = bcdBootPath
	runCmdBoot  = tools.RunCmd
	mkTmp       = os.MkdirTemp
)

// WimToEFI 从 boot.wim 中准备 Windows 目录，然后执行 bcdboot。
// 返回值为最终实际使用的镜像索引。
func WimToEFI(wimPath string, idx int, espRoot string) (int, error) {
	wimPath = strings.TrimSpace(wimPath)
	if wimPath == "" {
		return 0, fmt.Errorf("wim path is empty")
	}
	if !utils.FileExists(wimPath) {
		return 0, fmt.Errorf("wim not found: %s", wimPath)
	}
	if idx <= 0 {
		autoIdx, err := findIdx(wimPath)
		if err != nil {
			return 0, err
		}
		idx = autoIdx
	}

	if strings.TrimSpace(espRoot) == "" {
		espRoot = wimPath
	}
	root, err := utils.NormalizeDrive(espRoot, 0)
	if err != nil {
		return 0, fmt.Errorf("invalid esp root: %w", err)
	}
	fs, _, err := getVolInfo(root)
	if err != nil {
		return 0, fmt.Errorf("GetVolumeInfo failed: %w", err)
	}
	if !strings.EqualFold(fs, "FAT32") {
		return 0, fmt.Errorf("esp is not FAT32: %s (%s)", root, fs)
	}

	winDir, clean, err := prepWin(wimPath, idx)
	if err != nil {
		return 0, err
	}

	out, err := runBCDboot(winDir, root)
	log.LogWrite(0, "[WimToEFI] wim=%s idx=%d esp=%s win=%s out=%s err=%v", wimPath, idx, root, winDir, out, err)
	if err == nil {
		defer clean()
		return idx, nil
	}

	// 某些系统上的 bcdboot 无法直接读取目录挂载的 WIM，失败时回退到真实解包目录再试。
	if !isMountWinDir(winDir) {
		defer clean()
		return 0, err
	}

	clean()
	winDir, clean, err = prepFlat(wimPath, idx)
	if err != nil {
		return 0, err
	}
	defer clean()

	out, err = runBCDboot(winDir, root)
	log.LogWrite(0, "[WimToEFI] retry flat: wim=%s idx=%d esp=%s win=%s out=%s err=%v", wimPath, idx, root, winDir, out, err)
	if err != nil {
		return 0, err
	}
	return idx, nil
}

// prepWinDir 优先目录挂载，失败后回退到解包和提取。
func prepWinDir(wimPath string, idx int) (string, func(), error) {
	tmp, err := workDir(wimPath)
	if err != nil {
		return "", nil, err
	}
	return prepWinIn(tmp, wimPath, idx, true)
}

// prepWinFlatDir 只走真实文件目录，不使用目录挂载。
func prepWinFlatDir(wimPath string, idx int) (string, func(), error) {
	tmp, err := workDir(wimPath)
	if err != nil {
		return "", nil, err
	}
	return prepWinIn(tmp, wimPath, idx, false)
}

func prepWinIn(tmp, wimPath string, idx int, tryMount bool) (string, func(), error) {
	if err := os.MkdirAll(tmp, 0755); err != nil {
		return "", nil, err
	}

	cleanBase := func() { _ = os.RemoveAll(tmp) }
	fail := func(err error) (string, func(), error) {
		cleanBase()
		return "", nil, err
	}

	if tryMount {
		mntDir := filepath.Join(tmp, "mnt")
		clean, err := mountWim(wimPath, idx, mntDir)
		if err == nil {
			winDir := filepath.Join(mntDir, "Windows")
			if isDir(winDir) {
				return winDir, func() {
					if clean != nil {
						clean()
					}
					cleanBase()
				}, nil
			}
			if clean != nil {
				clean()
			}
		}
		log.LogWrite(0, "[prepWinIn] mount failed: wim=%s idx=%d err=%v", wimPath, idx, err)
	}

	flatDir := filepath.Join(tmp, "flat")
	if err := applyWim(wimPath, idx, flatDir); err == nil {
		winDir := filepath.Join(flatDir, "Windows")
		if isDir(winDir) {
			return winDir, cleanBase, nil
		}
		log.LogWrite(0, "[prepWinIn] apply missing Windows: wim=%s idx=%d dir=%s", wimPath, idx, flatDir)
	} else {
		log.LogWrite(0, "[prepWinIn] apply failed: wim=%s idx=%d err=%v", wimPath, idx, err)
	}

	extDir := filepath.Join(tmp, "ext")
	if err := extWin(wimPath, idx, extDir); err == nil {
		winDir := filepath.Join(extDir, "Windows")
		if isDir(winDir) {
			return winDir, cleanBase, nil
		}
		log.LogWrite(0, "[prepWinIn] extract missing Windows: wim=%s idx=%d dir=%s", wimPath, idx, extDir)
	} else {
		log.LogWrite(0, "[prepWinIn] extract failed: wim=%s idx=%d err=%v", wimPath, idx, err)
	}

	return fail(fmt.Errorf("prepare Windows dir failed: %s", wimPath))
}

func workDir(wimPath string) (string, error) {
	base := filepath.Dir(strings.TrimSpace(wimPath))
	if !isDir(base) {
		return "", fmt.Errorf("wim dir not found: %s", base)
	}
	return mkTmp(base, "wim2efi-")
}

func mountWin(wimPath string, idx int, dir string) (func(), error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

	api, err := dism.NewWimg("")
	if err != nil {
		return nil, err
	}
	if err := api.MountImage(dir, wimPath, uint32(idx), nil); err != nil {
		return nil, err
	}

	return func() {
		if err := api.UnmountImage(dir, wimPath, uint32(idx), false); err != nil {
			log.LogWrite(0, "[mountWin] unmount failed: wim=%s idx=%d dir=%s err=%v", wimPath, idx, dir, err)
		}
	}, nil
}

func applyWin(wimPath string, idx int, dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	d := dism.Default()
	if err := d.ApplyImageCmd(wimPath, dir, uint32(idx), nil); err == nil {
		return nil
	}
	return d.ApplyImageApi(wimPath, dir, uint32(idx), nil)
}

func extWinDir(wimPath string, idx int, dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return wimlib.ExtractPath(wimPath, idx, dir, "/Windows")
}

func runUEFIBoot(winDir, espRoot string) (string, error) {
	bin, isLocal := findBCDBoot()
	if strings.TrimSpace(bin) == "" {
		bin = "bcdboot.exe"
	}
	espArg, err := utils.NormalizeDrive(espRoot, 3)
	if err != nil {
		return "", err
	}

	args := []string{winDir, "/s", espArg}

	// Win7 自带 bcdboot 不支持 /f 参数，传入会直接报参数错误。
	ver, _, err := getCurVer()
	if isLocal || (err == nil && ver != 7) {
		args = append(args, "/f", "UEFI")
	}

	// bcdboot 的 /s 需要盘符形式，如 D:，不能传 D:\
	return runCmdBoot(bin, nil, nil, "", args...)
}

func bcdBootPath() (string, bool) {
	exe, err := os.Executable()
	if err == nil {
		if local := toolPathFrom(filepath.Dir(exe), "bcdboot.exe"); local != "" {
			return local, true
		}
	}
	return utils.GetSystemExe("bcdboot.exe"), false
}

func toolPathFrom(base, name string) string {
	base = strings.TrimSpace(base)
	if base == "" {
		return ""
	}
	dir := filepath.Clean(base)
	for i := 0; i < 4; i++ {
		path := filepath.Join(dir, "tools", name)
		if utils.FileExists(path) {
			return path
		}
		next := filepath.Dir(dir)
		if next == dir {
			break
		}
		dir = next
	}
	return ""
}

// firstWinIdx 先用镜像元信息判断，必要时再回退到 wimlib 直接探测 \Windows。
func firstWinIdx(wimPath string) (int, error) {
	if imgs, err := listInfo(wimPath); err == nil {
		if idx := pickWinIdx(imgs); idx > 0 {
			return idx, nil
		}
		log.LogWrite(0, "[firstWinIdx] no Windows image from meta: wim=%s", wimPath)
	} else {
		log.LogWrite(0, "[firstWinIdx] list meta failed: wim=%s err=%v", wimPath, err)
	}

	return findWBIdx(wimPath)
}

func listWimInfo(wimPath string) ([]dism.ImageMeta, error) {
	return dism.Default().ListImageInfos(wimPath)
}

func pickWinIdx(imgs []dism.ImageMeta) int {
	for _, img := range imgs {
		if isWinMeta(img) {
			return img.Index
		}
	}
	return 0
}

func isWinMeta(img dism.ImageMeta) bool {
	root := strings.TrimSpace(strings.ToLower(img.SystemRoot))
	if root == "windows" || strings.HasSuffix(root, `\windows`) || strings.HasSuffix(root, `/windows`) {
		return true
	}
	if img.IsOS {
		return true
	}
	inst := strings.ToLower(strings.TrimSpace(img.Installation))
	return strings.Contains(inst, "windowspe") || strings.Contains(inst, "winpe")
}

func firstWinIdxWB(wimPath string) (idx int, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("wimlib probe panic: %v", r)
		}
	}()

	lib, err := wimlib.LibwimLoad()
	if err != nil {
		return 0, fmt.Errorf("load wimlib failed: %w", err)
	}
	defer lib.Close()

	w, err := lib.OpenWim(wimPath, 0)
	if err != nil {
		return 0, fmt.Errorf("open wim failed: %w", err)
	}
	defer w.Free()

	info, err := w.GetWimInfo()
	if err != nil {
		return 0, fmt.Errorf("get wim info failed: %w", err)
	}
	for i := 1; i <= int(info.ImageCount); i++ {
		items, err := w.ListPaths(i, `\Windows`, 0)
		if err != nil {
			log.LogWrite(0, "[firstWinIdx] check index=%d failed: wim=%s err=%v", i, wimPath, err)
			continue
		}
		if len(items) > 0 {
			return i, nil
		}
	}
	return 0, fmt.Errorf("no image contains \\Windows: %s", wimPath)
}

func isDir(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.IsDir()
}

func isMountWinDir(path string) bool {
	path = strings.ToLower(filepath.Clean(path))
	return strings.Contains(path, strings.ToLower(filepath.Join("mnt", "Windows")))
}
