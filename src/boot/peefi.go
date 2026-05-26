package boot

import (
	"ReSys/src/disk"
	"ReSys/src/file"
	"ReSys/src/log"
	"ReSys/src/tools"
	"ReSys/src/utils"
	"ReSys/src/windows"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var (
	listVol   = disk.ListVolumes
	getType   = disk.GetDriveType
	getKind   = disk.GetDiskKind
	pickExt   = disk.PickFreeExtent
	mkPart    = disk.CreatePartitionFromFreeExtent
	splitVol  = disk.SplitVolume
	cpFile    = file.Copy
	rmPath    = file.Remove
	isDir     = utils.DirExists
	prepStore = prepPEStore
	winRoot   = windows.SystemDriveRoot
	runCmd    = tools.RunCmd
	bcdPathFn = bcdEditPath
	bcdBootFn = bcdBootPath
)

const (
	minFAT         uint64 = 2 * 1024 * 1024 * 1024
	fatPad         uint64 = 256 * 1024 * 1024
	fatMax         uint64 = 4*1024*1024*1024 - 1
	peLabel               = "RESYSPE"
	peDir                 = "ReSysPE"
	uefiName              = "My UEFI"
	legacyUEFIName        = "TEMP PE UEFI RESYS"

	efiBootMgrPath   = `\EFI\Microsoft\Boot\bootmgfw.efi`
	efiFallbackPath  = `\EFI\BOOT\BOOTX64.EFI`
	ramdiskOptionsID = "{ramdiskoptions}"
)

// SetPEEFI 为 Win7+UEFI 准备独立 FAT32 启动分区，并设置下次从该 EFI 条目启动。
func SetPEEFI(wimPath, sdiPath string) error {
	wimAbs, err := absArg(wimPath)
	if err != nil {
		return err
	}
	sdiAbs, err := absArg(sdiPath)
	if err != nil {
		return err
	}

	wimSt, err := os.Stat(wimAbs)
	if err != nil {
		return fmt.Errorf("stat wim failed: %w", err)
	}
	sdiSt, err := os.Stat(sdiAbs)
	if err != nil {
		return fmt.Errorf("stat sdi failed: %w", err)
	}
	if wimSt.IsDir() || sdiSt.IsDir() {
		return fmt.Errorf("wim/sdi must be files")
	}
	if uint64(wimSt.Size()) > fatMax {
		return fmt.Errorf("wim too large for FAT32: %s", wimAbs)
	}
	if uint64(sdiSt.Size()) > fatMax {
		return fmt.Errorf("sdi too large for FAT32: %s", sdiAbs)
	}

	need := uint64(wimSt.Size()) + uint64(sdiSt.Size()) + fatPad
	if need < minFAT {
		need = minFAT
	}

	root, reuse, err := pickFAT(need)
	if err != nil {
		return err
	}
	log.LogWrite(0, "[SetPEEFI] use fat root: %s", root)

	wDst, sDst, err := writePE(root, wimAbs, sdiAbs)
	if err != nil {
		if !reuse {
			return err
		}
		// 命中 RESYSPE 复用分区但写入失败时，回退为新建 FAT32 分区后重试。
		oldErr := err
		log.LogWrite(0, "[SetPEEFI] write to reused fat failed, create new fat: %v", oldErr)
		root, err = makeFAT(need)
		if err != nil {
			return fmt.Errorf("write reused fat failed: %v; create new fat failed: %w", oldErr, err)
		}
		log.LogWrite(0, "[SetPEEFI] fallback new fat root: %s", root)
		wDst, sDst, err = writePE(root, wimAbs, sdiAbs)
		if err != nil {
			return err
		}
	}

	sysRoot := strings.TrimSpace(winRoot())
	if sysRoot == "" {
		return fmt.Errorf("system drive root is empty")
	}
	winDir := filepath.Join(sysRoot, "Windows")
	drv, err := driveArg(root)
	if err != nil {
		return err
	}

	store := filepath.Join(root, "EFI", "Microsoft", "Boot", "BCD")
	bcdboot := bcdBootFn()
	if err := runBCDBootFresh(bcdboot, winDir, drv, store); err != nil {
		return err
	}
	// bcdboot 生成基础引导后，注入自定义 UEFI 启动程序和配置。
	// 注入通用 EFI 文件与 grubfm 配置，确保不同机器引导行为一致。
	if err := putUEFIRes(root); err != nil {
		return err
	}

	if err := prepStore(store, wDst, sDst); err != nil {
		return err
	}

	bcd := bcdPathFn()
	if out, err := runBcdStoreCmd(bcd, store, "/enum", "all", "/v"); err == nil {
		log.LogWrite(0, "[SetPEEFI] pe bcd store:\n%s", out)
	} else {
		return fmt.Errorf("verify pe bcd store failed: %w", err)
	}

	fwID, err := ensurePEFirmwareEntry(bcd, drv)
	if err != nil {
		return err
	}
	// 设置一次性下次启动进入该项。
	if _, err := runBcdCmd(bcd, "/set", "{fwbootmgr}", "bootsequence", fwID); err != nil {
		return err
	}
	if out, err := runBcdCmd(bcd, "/enum", "firmware", "/v"); err == nil {
		log.LogWrite(0, "[SetPEEFI] firmware list:\n%s", out)
	}
	log.LogWrite(0, "[SetPEEFI] done: root=%s fw=%s store=%s", root, fwID, store)
	return nil
}

// writePE 清空并重写目标分区上的 ReSysPE 目录。
func writePE(root, wimAbs, sdiAbs string) (string, string, error) {
	dstDir := filepath.Join(root, peDir)
	if isDir(dstDir) {
		if err := rmPath(dstDir, true, false); err != nil {
			return "", "", fmt.Errorf("remove old %s failed: %w", peDir, err)
		}
	}
	wDst := filepath.Join(dstDir, "boot.wim")
	sDst := filepath.Join(dstDir, "boot.sdi")
	if err := cpFile(wimAbs, wDst, true, true); err != nil {
		return "", "", fmt.Errorf("copy wim failed: %w", err)
	}
	if err := cpFile(sdiAbs, sDst, true, true); err != nil {
		return "", "", fmt.Errorf("copy sdi failed: %w", err)
	}
	return wDst, sDst, nil
}

func runBCDBootFresh(bin, winDir, drv, store string) error {
	if _, err := runCmd(bin, nil, nil, "", winDir, "/s", drv, "/f", "UEFI", "/c"); err == nil {
		return nil
	} else {
		log.LogWrite(0, "[SetPEEFI] bcdboot /c failed, retry with clean store: %v", err)
		bak, bakErr := backupBCDStore(store)
		if bakErr != nil {
			log.LogWrite(0, "[SetPEEFI] backup old BCD store failed: %v", bakErr)
		}
		if _, err2 := runCmd(bin, nil, nil, "", winDir, "/s", drv, "/f", "UEFI"); err2 != nil {
			if bak != "" {
				if restoreErr := restoreBCDStore(store, bak); restoreErr != nil {
					log.LogWrite(0, "[SetPEEFI] restore old BCD store failed: %v", restoreErr)
				}
			}
			return fmt.Errorf("bcdboot failed: with /c: %v; fallback: %w", err, err2)
		}
		return nil
	}
}

func backupBCDStore(store string) (string, error) {
	if !utils.FileExists(store) {
		return "", nil
	}
	bak := store + ".ReSysPE.bak"
	_ = os.Remove(bak)
	if err := os.Rename(store, bak); err != nil {
		return "", err
	}
	for _, name := range []string{"BCD.LOG", "BCD.LOG1", "BCD.LOG2"} {
		_ = os.Remove(filepath.Join(filepath.Dir(store), name))
	}
	log.LogWrite(0, "[SetPEEFI] old BCD store backup: %s", bak)
	return bak, nil
}

func restoreBCDStore(store, bak string) error {
	if strings.TrimSpace(bak) == "" || !utils.FileExists(bak) {
		return nil
	}
	_ = os.Remove(store)
	return os.Rename(bak, store)
}

type firmwareEntry struct {
	id          string
	device      string
	path        string
	description string
}

func ensurePEFirmwareEntry(bcd, drv string) (string, error) {
	entries, err := enumFirmwareEntries(bcd)
	if err != nil {
		log.LogWrite(0, "[SetPEEFI] enum firmware before update failed: %v", err)
	}

	// 先清理历史残留项，避免同名启动项不断累积。
	for _, ent := range entries {
		if !isOurFirmwareDescription(ent.description) {
			continue
		}
		path := normBCDValue(ent.path)
		if path != normBCDValue(efiBootMgrPath) && path != normBCDValue(efiFallbackPath) {
			continue
		}
		if _, err := runBcdCmd(bcd, "/delete", ent.id, "/f"); err != nil {
			log.LogWrite(0, "[SetPEEFI] delete duplicate firmware entry failed: id=%s err=%v", ent.id, err)
		} else {
			log.LogWrite(0, "[SetPEEFI] deleted old firmware entry: id=%s desc=%s", ent.id, ent.description)
		}
	}

	// 按 bcdedit /copy {bootmgr} 的方式创建固件启动项。
	fwID, err := createID(bcd, "/copy", "{bootmgr}", "/d", uefiName)
	if err != nil {
		return "", err
	}
	if _, err := runBcdCmd(bcd, "/set", fwID, "device", "partition="+drv); err != nil {
		return "", err
	}
	if _, err := runBcdCmd(bcd, "/set", fwID, "path", efiFallbackPath); err != nil {
		return "", err
	}

	return fwID, nil
}

func enumFirmwareEntries(bcd string) ([]firmwareEntry, error) {
	out, err := runBcdCmd(bcd, "/enum", "firmware", "/v")
	if err != nil {
		return nil, err
	}
	var entries []firmwareEntry
	cur := firmwareEntry{}
	flush := func() {
		if cur.id != "" {
			entries = append(entries, cur)
		}
		cur = firmwareEntry{}
	}
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if line == "" {
			flush()
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := fields[0]
		val := strings.TrimSpace(line[len(key):])
		switch strings.ToLower(key) {
		case "identifier", "标识符":
			cur.id = strings.ToLower(val)
		case "device", "设备":
			cur.device = val
		case "path", "路径":
			cur.path = val
		case "description", "描述":
			cur.description = val
		}
	}
	flush()
	return entries, nil
}

func isOurFirmwareDescription(desc string) bool {
	desc = strings.TrimSpace(desc)
	return strings.EqualFold(desc, uefiName) || strings.EqualFold(desc, legacyUEFIName)
}

func normBCDValue(v string) string {
	v = strings.TrimSpace(strings.ReplaceAll(v, "/", `\`))
	return strings.ToLower(v)
}

func pickFAT(need uint64) (string, bool, error) {
	vols, err := listVol()
	if err != nil {
		return "", false, err
	}
	type item struct {
		root string
		free uint64
	}
	tagged := make([]item, 0, 4)
	cands := make([]item, 0, len(vols))
	for _, vol := range vols {
		root, ok := normRoot(vol.RootPath)
		if !ok {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(vol.FileSystem), "FAT32") {
			continue
		}
		if getType(root) != 3 {
			continue
		}
		kind, err := getKind(root)
		if err != nil || strings.EqualFold(kind, "Removable") || strings.EqualFold(kind, "CDROM") {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(vol.Label), peLabel) {
			tagged = append(tagged, item{root: root, free: vol.FreeBytes})
		}
		if vol.SizeBytes < minFAT || vol.FreeBytes < need {
			continue
		}
		cands = append(cands, item{root: root, free: vol.FreeBytes})
	}
	if len(tagged) > 0 {
		sort.Slice(tagged, func(i, j int) bool {
			if tagged[i].free != tagged[j].free {
				return tagged[i].free > tagged[j].free
			}
			return strings.ToLower(tagged[i].root) < strings.ToLower(tagged[j].root)
		})
		log.LogWrite(0, "[pickFAT] reuse label=%s root=%s", peLabel, tagged[0].root)
		return tagged[0].root, true, nil
	}
	if len(cands) > 0 {
		sort.Slice(cands, func(i, j int) bool {
			if cands[i].free != cands[j].free {
				return cands[i].free > cands[j].free
			}
			return strings.ToLower(cands[i].root) < strings.ToLower(cands[j].root)
		})
		return cands[0].root, false, nil
	}
	root, err := makeFAT(need)
	return root, false, err
}

func makeFAT(need uint64) (string, error) {
	ext, err := pickExt(need, disk.ExtentPickPolicy{
		PreferNonSystemDisk: true,
		PreferLargestExtent: true,
	})
	if err == nil && ext.SizeBytes >= need {
		letter, err := mkPart(ext, need, "fat32", peLabel)
		if err == nil {
			if root, ok := normRoot(letter); ok {
				return root, nil
			}
		}
		log.LogWrite(0, "[makeFAT] create from free extent failed: %v", err)
	}

	root, err := pickNTFS(need)
	if err != nil {
		return "", err
	}
	sizeMB := int((need + 1024*1024 - 1) / (1024 * 1024))
	letter, err := splitVol(root, sizeMB, "fat32", peLabel)
	if err != nil {
		return "", err
	}
	out, ok := normRoot(letter)
	if !ok {
		return "", fmt.Errorf("split volume returned invalid root: %s", letter)
	}
	return out, nil
}

func pickNTFS(need uint64) (string, error) {
	vols, err := listVol()
	if err != nil {
		return "", err
	}
	type item struct {
		root string
		free uint64
	}
	cands := make([]item, 0, len(vols))
	for _, vol := range vols {
		root, ok := normRoot(vol.RootPath)
		if !ok {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(vol.FileSystem), "NTFS") {
			continue
		}
		if vol.FreeBytes < need+fatPad {
			continue
		}
		if getType(root) != 3 {
			continue
		}
		kind, err := getKind(root)
		if err != nil || strings.EqualFold(kind, "Removable") || strings.EqualFold(kind, "CDROM") {
			continue
		}
		cands = append(cands, item{root: root, free: vol.FreeBytes})
	}
	if len(cands) == 0 {
		return "", fmt.Errorf("no local ntfs volume can be split for fat32")
	}
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].free != cands[j].free {
			return cands[i].free > cands[j].free
		}
		return strings.ToLower(cands[i].root) < strings.ToLower(cands[j].root)
	})
	return cands[0].root, nil
}

func normRoot(path string) (string, bool) {
	root, err := utils.NormalizeDrive(path, 0)
	if err != nil || root == "" {
		return "", false
	}
	return root, true
}

func driveArg(root string) (string, error) {
	root, ok := normRoot(root)
	if !ok {
		return "", fmt.Errorf("invalid root: %s", root)
	}
	return strings.TrimRight(root, `\`), nil
}

func bcdBootPath() string {
	if exe, err := os.Executable(); err == nil {
		if local := toolPathFrom(filepath.Dir(exe), "bcdboot.exe"); local != "" {
			return local
		}
	}
	return utils.GetSystemExe("bcdboot.exe")
}

// putUEFIRes 将 tools\uefi 下的通用引导程序和配置复制到目标 FAT32 根目录。
func putUEFIRes(root string) error {
	// 先取通用 EFI 启动程序，目标是覆盖到 \EFI\BOOT\BOOTX64.EFI。
	bootSrc, err := findUEFIRes("bootx64.efi")
	if err != nil {
		return err
	}
	bootDst := filepath.Join(root, "EFI", "BOOT", "BOOTX64.EFI")
	// 覆盖 bcdboot 生成的 BOOTX64.EFI，统一引导行为。
	if err := cpFile(bootSrc, bootDst, true, true); err != nil {
		return fmt.Errorf("copy custom bootx64.efi failed: %w", err)
	}

	// 再写 grubfm 配置到 \boot\grubfm\config（无后缀）。
	cfgSrc, err := findUEFIRes("config")
	if err != nil {
		return err
	}
	cfgDst := filepath.Join(root, "boot", "grubfm", "config")
	if err := cpFile(cfgSrc, cfgDst, true, true); err != nil {
		return fmt.Errorf("copy grubfm config failed: %w", err)
	}
	log.LogWrite(0, "[SetPEEFI] uefi resources copied: boot=%s cfg=%s", bootDst, cfgDst)
	return nil
}

// findUEFIRes 查找 UEFI 资源文件，未命中直接返回错误。
func findUEFIRes(name string) (string, error) {
	if exe, err := os.Executable(); err == nil {
		base := filepath.Dir(exe)
		// 优先读 tools\uefi 下的资源，找不到再回退到 tools 根目录。
		cands := []string{
			filepath.Join("uefi", name),
			name,
		}
		for _, rel := range cands {
			if p := toolPathFrom(base, rel); p != "" {
				return p, nil
			}
		}
	}
	return "", fmt.Errorf("missing uefi resource: tools\\uefi\\%s", name)
}

func prepPEStore(store, wimPath, sdiPath string) error {
	if !utils.FileExists(store) {
		return fmt.Errorf("bcd store not found: %s", store)
	}

	bcd := bcdEditPath()

	wimAbs, err := absArg(wimPath)
	if err != nil {
		return err
	}
	sdiAbs, err := absArg(sdiPath)
	if err != nil {
		return err
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

	if _, err := runBcdStoreCmd(bcd, store, "/set", "{bootmgr}", "device", "partition="+drvW); err != nil {
		return err
	}
	if _, err := runBcdStoreCmd(bcd, store, "/set", "{bootmgr}", "path", efiBootMgrPath); err != nil {
		return err
	}
	if _, err := runBcdStoreCmd(bcd, store, "/set", "{bootmgr}", "description", uefiName); err != nil {
		log.LogWrite(0, "[prepPEStore] set bootmgr description failed: %v", err)
	}

	devID := ramdiskOptionsID
	if _, err := runBcdStoreCmd(bcd, store, "/create", devID, "/d", "ReSys Ramdisk"); err != nil && !isExistsErr(err) {
		return err
	}
	ldrID, err := createIDStore(bcd, store, "/create", "/d", "ReSys PE", "/application", "osloader")
	if err != nil {
		return err
	}

	if _, err := runBcdStoreCmd(bcd, store, "/set", devID, "ramdisksdidevice", "partition="+drvW); err != nil {
		return err
	}
	if _, err := runBcdStoreCmd(bcd, store, "/set", devID, "ramdisksdipath", relS); err != nil {
		return err
	}

	dev := fmt.Sprintf("ramdisk=[%s]%s,%s", drvW, relW, devID)
	if _, err := runBcdStoreCmd(bcd, store, "/set", ldrID, "device", dev); err != nil {
		return err
	}
	if _, err := runBcdStoreCmd(bcd, store, "/set", ldrID, "osdevice", dev); err != nil {
		return err
	}
	if err := setLoadPathStore(bcd, store, ldrID); err != nil {
		return err
	}
	if _, err := runBcdStoreCmd(bcd, store, "/set", ldrID, "systemroot", `\windows`); err != nil {
		return err
	}
	if _, err := runBcdStoreCmd(bcd, store, "/set", ldrID, "detecthal", "YES"); err != nil {
		return err
	}
	if _, err := runBcdStoreCmd(bcd, store, "/set", ldrID, "winpe", "YES"); err != nil {
		return err
	}
	if _, err := runBcdStoreCmd(bcd, store, "/set", ldrID, "nx", "OptIn"); err != nil {
		return err
	}
	if _, err := runBcdStoreCmd(bcd, store, "/set", "{bootmgr}", "default", ldrID); err != nil {
		return err
	}
	if _, err := runBcdStoreCmd(bcd, store, "/displayorder", ldrID, "/addfirst"); err != nil {
		return err
	}
	if _, err := runBcdStoreCmd(bcd, store, "/timeout", "0"); err != nil {
		return err
	}
	return nil
}

func isExistsErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "already exists") || strings.Contains(msg, "已存在")
}

func runBcdStoreCmd(bin, store string, args ...string) (string, error) {
	if strings.TrimSpace(store) != "" {
		args = append([]string{"/store", store}, args...)
	}
	return runBcdCmd(bin, args...)
}

func createIDStore(bin, store string, args ...string) (string, error) {
	if strings.TrimSpace(store) != "" {
		args = append([]string{"/store", store}, args...)
	}
	return createID(bin, args...)
}

func setLoadPathStore(bin, store, ldrID string) error {
	fw, err := GetFwType()
	p1 := `\windows\system32\boot\winload.efi`
	p2 := `\windows\system32\boot\winload.exe`
	if err == nil && fw == fwTypeBios {
		p1, p2 = p2, p1
	}
	if _, e1 := runBcdStoreCmd(bin, store, "/set", ldrID, "path", p1); e1 == nil {
		return nil
	}
	if _, e2 := runBcdStoreCmd(bin, store, "/set", ldrID, "path", p2); e2 == nil {
		return nil
	}
	return fmt.Errorf("set loader path failed")
}
