package install

import (
	"ReSys/src/disk"
	"ReSys/src/file"
	imgsvc "ReSys/src/image"
	"ReSys/src/log"
	"ReSys/src/utils"
	"ReSys/src/windows"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var mtISO = imgsvc.MountISO
var upISO = imgsvc.UnpackISO
var cpISO = file.Copy
var fdISO = file.FindFile
var stISO = os.Stat
var mkTmp = disk.NewTempVolume
var volISO = getotherVolumes
var freeISO = disk.GetFreeSize
var infoISO = imgsvc.DetectImageInfos

// prepISO 在进入 PE 前把 ISO 中的 install.wim/install.esd 复制到可持久化的位置。
func prepISO(plan *InstallPlan) error {
	if plan == nil {
		return fmt.Errorf("install plan is nil")
	}

	iso := strings.TrimSpace(plan.ImagePath)
	if !strings.EqualFold(filepath.Ext(iso), ".iso") {
		return nil
	}

	src, err := isoSrcByISO(iso)
	if err != nil {
		return err
	}

	st, err := stISO(src)
	if err != nil {
		return err
	}
	if st.IsDir() {
		return fmt.Errorf("ISO install image is a directory: %s", src)
	}

	root, err := pickRoot(isoExcl(plan), uint64(st.Size()))
	if err != nil {
		return err
	}

	dst := isoDst(root, iso, src)
	if reuseISO(dst, st.Size()) {
		plan.ImagePath = dst
		log.LogWrite(0, "[prepISO] reuse extracted install image: iso=%s dst=%s", iso, dst)
		return nil
	}

	log.LogWrite(0, "[prepISO] copy install image from iso: iso=%s src=%s dst=%s", iso, src, dst)
	if err := cpISO(src, dst, true, true); err != nil {
		return fmt.Errorf("copy ISO install image failed: %w", err)
	}

	plan.ImagePath = dst
	return nil
}

func isoSrcByISO(iso string) (string, error) {
	root, err := mtISO(iso, 30*time.Second)
	if err == nil {
		return isoSrc(root)
	}

	// Win7 等环境可能不支持直接挂载 ISO，失败时回退到解包后提取 install.wim/esd。
	log.LogWrite(0, "[isoSrcByISO] mount iso failed, fallback to unpack: iso=%s err=%v", iso, err)
	dir, derr := isoUnpackDir(iso)
	if derr != nil {
		return "", fmt.Errorf("mount iso failed: %v; build unpack dir failed: %w", err, derr)
	}

	// 已解包过时优先复用，避免重复解包。
	if src, ferr := isoSrc(dir); ferr == nil {
		log.LogWrite(0, "[isoSrcByISO] reuse unpacked iso: iso=%s dir=%s", iso, dir)
		return src, nil
	}

	_ = os.RemoveAll(dir)
	if uerr := upISO(iso, dir); uerr != nil {
		return "", fmt.Errorf("mount iso failed: %v; unpack iso failed: %w", err, uerr)
	}

	src, serr := isoSrc(dir)
	if serr != nil {
		return "", fmt.Errorf("iso unpacked but install image not found: %w", serr)
	}
	log.LogWrite(0, "[isoSrcByISO] unpack iso success: iso=%s dir=%s src=%s", iso, dir, src)
	return src, nil
}

func isoUnpackDir(iso string) (string, error) {
	abs, err := filepath.Abs(strings.TrimSpace(iso))
	if err != nil {
		return "", err
	}
	name := strings.TrimSuffix(filepath.Base(abs), filepath.Ext(abs))
	if name == "" {
		name = "iso"
	}
	return filepath.Join(filepath.Dir(abs), ".resys_iso", name), nil
}

func isoSrc(root string) (string, error) {
	wim := filepath.Join(root, "sources", "install.wim")
	if st, err := stISO(wim); err == nil && !st.IsDir() {
		return wim, nil
	}

	esd := filepath.Join(root, "sources", "install.esd")
	if st, err := stISO(esd); err == nil && !st.IsDir() {
		return esd, nil
	}

	found, err := fdISO(root, "install.wim|install.esd", 3)
	if err != nil || len(found) == 0 {
		return "", fmt.Errorf("ISO中未找到安装镜像")
	}
	return found[0], nil
}

func isoExcl(plan *InstallPlan) string {
	if plan != nil {
		if root, err := utils.NormalizeDrive(plan.TargetRoot, 0); err == nil && root != "" {
			return root
		}
	}

	root := strings.TrimSpace(windows.SystemDriveRoot())
	if root != "" {
		return root
	}

	if drv := strings.TrimSpace(os.Getenv("SystemDrive")); drv != "" {
		if root, err := utils.NormalizeDrive(drv, 0); err == nil {
			return root
		}
	}
	return ""
}

func pickRoot(excl string, need uint64) (string, error) {
	need += uint64(512*1024*1024) + driverBackupWorkspaceReserveBytes()
	if root := pickVol(excl, need); root != "" {
		return root, nil
	}
	return mkTmp(need)
}

func pickVol(excl string, need uint64) string {
	var (
		best string
		free uint64
	)

	for _, root := range volISO(excl) {
		got, err := freeISO(root)
		if err != nil {
			continue
		}
		if got >= need && got > free {
			best = root
			free = got
		}
	}
	return best
}

func isoDst(root, iso, src string) string {
	base := strings.TrimSuffix(filepath.Base(iso), filepath.Ext(iso))
	if base == "" {
		base = filepath.Base(src)
	}
	return filepath.Join(downloadWorkspaceDir(root), base+strings.ToLower(filepath.Ext(src)))
}

func reuseISO(path string, size int64) bool {
	st, err := stISO(path)
	if err != nil || st.IsDir() || st.Size() != size {
		return false
	}
	_, err = infoISO(path)
	return err == nil
}
