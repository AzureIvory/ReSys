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
	listDisk  = disk.ListPhysicalDisks
	listPart  = disk.ListDiskPartitions
	listFree  = disk.GetDiskFreeExtents
	mkESP     = disk.CreateESPFromExtent
	getType   = disk.GetDriveType
	getKind   = disk.GetDiskKind
	getDInfo  = disk.GetDiskInfo
	shrinkVol = disk.ShrinkVolume
	findExt   = disk.FindESPFreeExtentAfterShrink
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
	minESP         uint64 = 2 * 1024 * 1024 * 1024
	espPad         uint64 = 256 * 1024 * 1024
	fatMax         uint64 = 4*1024*1024*1024 - 1
	extProbe       uint64 = 64 * 1024 * 1024
	peLabel               = "RESYSPE"
	peDir                 = "ReSysPE"
	uefiName              = "TEMP PE UEFI RESYS"
	legacyUEFIName        = "My UEFI"

	efiBootMgrPath   = `\EFI\Microsoft\Boot\bootmgfw.efi`
	efiFallbackPath  = `\EFI\BOOT\BOOTX64.EFI`
	ramdiskOptionsID = "{ramdiskoptions}"
)

// SetPEEFI 在 Win7+UEFI 下准备独立 ESP，并设置下次从该 EFI 条目启动。
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

	need := uint64(wimSt.Size()) + uint64(sdiSt.Size()) + espPad
	if need < minESP {
		need = minESP
	}

	root, err := pickESP(need)
	if err != nil {
		return err
	}
	log.LogWrite(0, "[SetPEEFI] use esp root: %s", root)

	dstDir := filepath.Join(root, peDir)
	if isDir(dstDir) {
		if err := rmPath(dstDir, true, false); err != nil {
			return fmt.Errorf("remove old %s failed: %w", peDir, err)
		}
	}
	wDst := filepath.Join(dstDir, "boot.wim")
	sDst := filepath.Join(dstDir, "boot.sdi")
	if err := cpFile(wimAbs, wDst, true, true); err != nil {
		return fmt.Errorf("copy wim failed: %w", err)
	}
	if err := cpFile(sdiAbs, sDst, true, true); err != nil {
		return fmt.Errorf("copy sdi failed: %w", err)
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
	efiSrc := filepath.Join(root, "EFI", "Microsoft", "Boot", "bootmgfw.efi")
	efiDst := filepath.Join(root, "EFI", "BOOT", "BOOTX64.EFI")
	if err := cpFile(efiSrc, efiDst, true, true); err != nil {
		return fmt.Errorf("prepare bootx64.efi failed: %w", err)
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
	if _, err := runBcdCmd(bcd, "/set", "{fwbootmgr}", "bootsequence", fwID); err != nil {
		return err
	}
	if out, err := runBcdCmd(bcd, "/enum", "firmware", "/v"); err == nil {
		log.LogWrite(0, "[SetPEEFI] firmware list:\n%s", out)
	}
	log.LogWrite(0, "[SetPEEFI] done: root=%s fw=%s store=%s", root, fwID, store)
	return nil
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

	fwID := ""
	for _, ent := range entries {
		if isOurFirmwareEntry(ent, drv) && strings.EqualFold(strings.TrimSpace(ent.description), uefiName) {
			fwID = ent.id
			break
		}
	}
	if fwID == "" {
		for _, ent := range entries {
			if isOurFirmwareEntry(ent, drv) && strings.EqualFold(strings.TrimSpace(ent.description), legacyUEFIName) {
				fwID = ent.id
				break
			}
		}
	}
	if fwID == "" {
		fwID, err = createID(bcd, "/copy", "{bootmgr}", "/d", uefiName)
		if err != nil {
			return "", err
		}
	}

	if _, err := runBcdCmd(bcd, "/set", fwID, "description", uefiName); err != nil {
		return "", err
	}
	if _, err := runBcdCmd(bcd, "/set", fwID, "device", "partition="+drv); err != nil {
		return "", err
	}
	if _, err := runBcdCmd(bcd, "/set", fwID, "path", efiBootMgrPath); err != nil {
		return "", err
	}

	for _, ent := range entries {
		if strings.EqualFold(ent.id, fwID) || !isOurFirmwareEntry(ent, drv) {
			continue
		}
		if _, err := runBcdCmd(bcd, "/delete", ent.id, "/f"); err != nil {
			log.LogWrite(0, "[SetPEEFI] delete duplicate firmware entry failed: id=%s err=%v", ent.id, err)
		} else {
			log.LogWrite(0, "[SetPEEFI] deleted duplicate firmware entry: id=%s desc=%s", ent.id, ent.description)
		}
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

func isOurFirmwareEntry(ent firmwareEntry, drv string) bool {
	if ent.id == "" || !samePartitionDevice(ent.device, drv) || !isOurFirmwareDescription(ent.description) {
		return false
	}
	path := normBCDValue(ent.path)
	return path == normBCDValue(efiBootMgrPath) || path == normBCDValue(efiFallbackPath)
}

func isOurFirmwareDescription(desc string) bool {
	desc = strings.TrimSpace(desc)
	return strings.EqualFold(desc, uefiName) || strings.EqualFold(desc, legacyUEFIName)
}

func samePartitionDevice(device, drv string) bool {
	device = normBCDValue(strings.ReplaceAll(device, " ", ""))
	drv = strings.TrimRight(strings.ToLower(strings.TrimSpace(drv)), `\`)
	return strings.Contains(device, "partition="+drv)
}

func normBCDValue(v string) string {
	v = strings.TrimSpace(strings.ReplaceAll(v, "/", `\`))
	return strings.ToLower(v)
}

func pickESP(need uint64) (string, error) {
	vols, err := listVol()
	if err != nil {
		return "", err
	}
	pmap := map[int][]disk.PartitionInfo{}
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
		if !strings.EqualFold(strings.TrimSpace(vol.FileSystem), "FAT32") {
			continue
		}
		if vol.SizeBytes < minESP || vol.FreeBytes < need {
			continue
		}
		if getType(root) != 3 {
			continue
		}
		kind, err := getKind(root)
		if err != nil || strings.EqualFold(kind, "Removable") || strings.EqualFold(kind, "CDROM") {
			continue
		}
		if !isESPVol(vol, pmap) {
			continue
		}
		cands = append(cands, item{root: root, free: vol.FreeBytes})
	}
	if len(cands) > 0 {
		sort.Slice(cands, func(i, j int) bool {
			if cands[i].free != cands[j].free {
				return cands[i].free > cands[j].free
			}
			return strings.ToLower(cands[i].root) < strings.ToLower(cands[j].root)
		})
		return cands[0].root, nil
	}
	return makeESP(need)
}

func makeESP(need uint64) (string, error) {
	sizeMB, err := toMB(need)
	if err != nil {
		return "", err
	}

	// 1) 优先直接在 GPT 未分配空间创建真实 ESP。
	if root, err := makeESPFree(need, sizeMB); err == nil {
		return root, nil
	} else {
		log.LogWrite(0, "[makeESP] create from free extent failed: %v", err)
	}

	// 2) 再尝试收缩 GPT+NTFS 卷后创建真实 ESP。
	root, err := pickNTFS(need)
	if err != nil {
		return "", err
	}
	_, dnum, err := getDInfo(root)
	if err != nil {
		return "", err
	}
	if _, err := shrinkVol(root, sizeMB); err != nil {
		return "", err
	}
	ext, err := findExt(root, int(dnum), need, extProbe)
	if err != nil {
		return "", err
	}
	eroot, _, err := mkESP(ext, sizeMB, peLabel)
	if err != nil {
		return "", err
	}
	return normRootOrErr(eroot)
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
		if vol.FreeBytes < need+espPad {
			continue
		}
		if getType(root) != 3 {
			continue
		}
		kind, err := getKind(root)
		if err != nil || strings.EqualFold(kind, "Removable") || strings.EqualFold(kind, "CDROM") {
			continue
		}
		style, _, err := getDInfo(root)
		if err != nil || !strings.EqualFold(strings.TrimSpace(style), "GPT") {
			continue
		}
		cands = append(cands, item{root: root, free: vol.FreeBytes})
	}
	if len(cands) == 0 {
		return "", fmt.Errorf("no local gpt ntfs volume can be shrinked for esp")
	}
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].free != cands[j].free {
			return cands[i].free > cands[j].free
		}
		return strings.ToLower(cands[i].root) < strings.ToLower(cands[j].root)
	})
	return cands[0].root, nil
}

func makeESPFree(need uint64, sizeMB int) (string, error) {
	disks, err := listDisk()
	if err != nil {
		return "", err
	}
	type cand struct {
		ext   disk.FreeExtent
		sys   bool
		size  uint64
		diskn int
	}
	cs := make([]cand, 0, 8)
	for _, d := range disks {
		if !strings.EqualFold(strings.TrimSpace(d.PartitionStyle), "GPT") {
			continue
		}
		exts, err := listFree(d.DiskNumber)
		if err != nil {
			continue
		}
		for _, ex := range exts {
			if ex.SizeBytes < need {
				continue
			}
			cs = append(cs, cand{
				ext:   ex,
				sys:   d.IsSystemDisk,
				size:  ex.SizeBytes,
				diskn: d.DiskNumber,
			})
		}
	}
	if len(cs) == 0 {
		return "", fmt.Errorf("no gpt free extent large enough for esp")
	}
	sort.Slice(cs, func(i, j int) bool {
		if cs[i].sys != cs[j].sys {
			return !cs[i].sys
		}
		if cs[i].size != cs[j].size {
			return cs[i].size > cs[j].size
		}
		if cs[i].diskn != cs[j].diskn {
			return cs[i].diskn < cs[j].diskn
		}
		return cs[i].ext.OffsetBytes < cs[j].ext.OffsetBytes
	})
	for _, c := range cs {
		root, _, err := mkESP(c.ext, sizeMB, peLabel)
		if err != nil {
			log.LogWrite(0, "[makeESPFree] create esp failed: disk=%d off=%d size=%d err=%v", c.diskn, c.ext.OffsetBytes, c.ext.SizeBytes, err)
			continue
		}
		return normRootOrErr(root)
	}
	return "", fmt.Errorf("create esp from all candidates failed")
}

func isESPVol(vol disk.VolumeInfo, pmap map[int][]disk.PartitionInfo) bool {
	if vol.DiskNumber < 0 {
		return false
	}
	parts, ok := pmap[vol.DiskNumber]
	if !ok {
		ps, err := listPart(vol.DiskNumber)
		if err != nil {
			return false
		}
		parts = ps
		pmap[vol.DiskNumber] = parts
	}
	for _, p := range parts {
		if vol.OffsetBytes < p.OffsetBytes || vol.OffsetBytes >= p.OffsetBytes+p.SizeBytes {
			continue
		}
		return strings.EqualFold(strings.TrimSpace(p.Type), "EFI")
	}
	return false
}

func toMB(size uint64) (int, error) {
	mb := (size + 1024*1024 - 1) / (1024 * 1024)
	if mb == 0 {
		mb = 1
	}
	max := uint64(^uint(0) >> 1)
	if mb > max {
		return 0, fmt.Errorf("size too large")
	}
	return int(mb), nil
}

func normRootOrErr(path string) (string, error) {
	root, ok := normRoot(path)
	if !ok {
		return "", fmt.Errorf("invalid root: %s", path)
	}
	return root, nil
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
