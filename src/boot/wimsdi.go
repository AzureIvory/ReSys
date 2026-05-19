package boot

import (
	"ReSys/src/log"
	"ReSys/src/tools"
	"ReSys/src/utils"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	runBcd = tools.RunCmd
)

// WimSdiToBCD 根据 wim+sdi 创建一次性 WinPE 启动项，并设置为下次启动进入。
func WimSdiToBCD(wimPath, sdiPath string) error {
	wimAbs, err := absArg(wimPath)
	if err != nil {
		return err
	}
	sdiAbs, err := absArg(sdiPath)
	if err != nil {
		return err
	}
	if !utils.FileExists(wimAbs) {
		return fmt.Errorf("wim not found: %s", wimAbs)
	}
	if !utils.FileExists(sdiAbs) {
		return fmt.Errorf("sdi not found: %s", sdiAbs)
	}

	drvW, relW, err := splitDrv(wimAbs)
	if err != nil {
		return err
	}
	drvS, relS, err := splitDrv(sdiAbs)
	if err != nil {
		return err
	}
	if !strings.EqualFold(drvW, drvS) {
		return fmt.Errorf("wim and sdi must be on same volume: %s <> %s", drvW, drvS)
	}

	bcd := bcdEditPath()
	log.LogWrite(0, "[WimSdiToBCD] start: bcd=%s wim=%s sdi=%s", bcd, wimAbs, sdiAbs)

	devID, err := createID(bcd, "/create", "/d", "pe", "/device")
	if err != nil {
		return err
	}
	if _, err = runBcdCmd(bcd, "/set", devID, "ramdisksdidevice", "partition="+drvW); err != nil {
		return err
	}
	if _, err = runBcdCmd(bcd, "/set", devID, "ramdisksdipath", relS); err != nil {
		return err
	}

	ldrID, err := createID(bcd, "/create", "/d", "pe", "/application", "osloader")
	if err != nil {
		return err
	}
	dev := fmt.Sprintf("ramdisk=[%s]%s,%s", drvW, relW, devID)
	if _, err = runBcdCmd(bcd, "/set", ldrID, "device", dev); err != nil {
		return err
	}
	if _, err = runBcdCmd(bcd, "/set", ldrID, "osdevice", dev); err != nil {
		return err
	}
	if err = setLoadPath(bcd, ldrID); err != nil {
		return err
	}
	if _, err = runBcdCmd(bcd, "/set", ldrID, "systemroot", `\windows`); err != nil {
		return err
	}
	if _, err = runBcdCmd(bcd, "/set", ldrID, "detecthal", "YES"); err != nil {
		return err
	}
	if _, err = runBcdCmd(bcd, "/set", ldrID, "winpe", "YES"); err != nil {
		return err
	}
	if _, err = runBcdCmd(bcd, "/set", ldrID, "nx", "OptIn"); err != nil {
		return err
	}
	if _, err = runBcdCmd(bcd, "/bootsequence", ldrID); err != nil {
		return err
	}

	log.LogWrite(0, "[WimSdiToBCD] done: loader=%s dev=%s", ldrID, devID)
	return nil
}

func absArg(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("path is empty")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("abs path failed: %w", err)
	}
	return filepath.Clean(abs), nil
}

func splitDrv(abs string) (string, string, error) {
	drv := filepath.VolumeName(abs)
	if drv == "" {
		return "", "", fmt.Errorf("invalid volume path: %s", abs)
	}
	drv = strings.ToUpper(strings.TrimRight(drv, `\`))
	if !strings.HasSuffix(drv, ":") {
		return "", "", fmt.Errorf("invalid drive: %s", drv)
	}
	rel := strings.TrimPrefix(abs[len(drv):], `\`)
	if rel == "" {
		return "", "", fmt.Errorf("path points to volume root: %s", abs)
	}
	return drv, `\` + rel, nil
}

// toolPathFrom 从 base 开始向上查找 tools\name，最多向上 4 层。
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

func bcdEditPath() string {
	if exe, err := os.Executable(); err == nil {
		if local := toolPathFrom(filepath.Dir(exe), "bcdedit.exe"); local != "" {
			return local
		}
	}
	return utils.GetSystemExe("bcdedit.exe")
}

func runBcdCmd(bin string, args ...string) (string, error) {
	out, err := runBcd(bin, nil, nil, "", args...)
	if err != nil {
		return out, fmt.Errorf("%s %v failed: %w\n%s", bin, args, err, out)
	}
	return out, nil
}

func createID(bin string, args ...string) (string, error) {
	out, err := runBcdCmd(bin, args...)
	if err != nil {
		return "", err
	}
	re := regexp.MustCompile(`(?i)\{[a-f0-9-]+\}`)
	id := re.FindString(out)
	if id == "" {
		return "", fmt.Errorf("parse guid failed: %s", out)
	}
	return strings.ToLower(id), nil
}

func setLoadPath(bin, ldrID string) error {
	fw, err := GetFwType()
	p1 := `\windows\system32\boot\winload.efi`
	p2 := `\windows\system32\boot\winload.exe`
	if err == nil && fw == fwTypeBios {
		p1, p2 = p2, p1
	}
	if _, e1 := runBcdCmd(bin, "/set", ldrID, "path", p1); e1 == nil {
		return nil
	}
	if _, e2 := runBcdCmd(bin, "/set", ldrID, "path", p2); e2 == nil {
		return nil
	}
	return fmt.Errorf("set loader path failed")
}
