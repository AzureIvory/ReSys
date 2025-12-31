package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// HRESULT helpers
func failed(hr uintptr) bool { return int32(hr) < 0 }

func hresultErr(hr uintptr, what string) error {
	if !failed(hr) {
		return nil
	}
	return fmt.Errorf("%s failed: HRESULT=0x%08X", what, uint32(hr))
}

func utf16Ptr(s string) (*uint16, error) {
	return syscall.UTF16PtrFromString(s)
}

// 分割卷，创建新分区并格式化。
// vol: 源卷盘符，如 "C"。
// sizeMB: 新分区大小，单位 MB。
// fs: 文件系统，如 "ntfs"。
// label: 分区标签。
// letter: 指定盘符，如 "E"。为空则自动分配。
// 返回新分区盘符，如 "E:"。
func SplitVolume(vol string, sizeMB int, fs, label, letter string) (string, error) {
	pVol, err := utf16Ptr(vol)
	if err != nil {
		return "", err
	}
	pFs, err := utf16Ptr(fs)
	if err != nil {
		return "", err
	}
	pLabel, err := utf16Ptr(label)
	if err != nil {
		return "", err
	}
	// desired letter can be "" => auto
	pDesired, err := utf16Ptr(letter)
	if err != nil {
		return "", err
	}

	// out buffer for "X:" + NUL
	out := make([]uint16, 8)

	hr, _, _ := procSplitW.Call(
		uintptr(unsafe.Pointer(pVol)),
		uintptr(int32(sizeMB)),
		uintptr(unsafe.Pointer(pFs)),
		uintptr(unsafe.Pointer(pLabel)),
		uintptr(unsafe.Pointer(pDesired)),
		uintptr(unsafe.Pointer(&out[0])),
		uintptr(int32(len(out))),
	)
	if err := hresultErr(hr, "SplitVolumeW"); err != nil {
		return "", err
	}

	return syscall.UTF16ToString(out), nil
	vol = strings.TrimSpace(vol)
	if vol == "" {
		return "", fmt.Errorf("vol 不能为空（请输入盘符，如 C / C: / C:\\）")
	}

	volUp := strings.ToUpper(vol)
	if len(volUp) >= 2 && volUp[1] == ':' {
		volUp = volUp[:1]
	} else if len(volUp) >= 3 && volUp[1] == ':' && (volUp[2] == '\\' || volUp[2] == '/') {
		volUp = volUp[:1]
	} else if len(volUp) == 1 {
	} else {
		return "", fmt.Errorf("vol 格式不支持：%q（请用盘符如 C 或 C:）", vol)
	}
	if volUp[0] < 'A' || volUp[0] > 'Z' {
		return "", fmt.Errorf("vol 不是有效盘符：%q", vol)
	}
	volForGetInfo := volUp + ":" // 传给 GetDiskInfo 用

	if sizeMB <= 0 {
		return "", fmt.Errorf("sizeMB 必须大于 0")
	}

	fs = strings.ToLower(strings.TrimSpace(fs))
	if fs == "" {
		return "", fmt.Errorf("fs 不能为空")
	}
	switch fs {
	case "ntfs", "exfat", "fat32", "refs":
	default:
		return "", fmt.Errorf("不支持的 fs：%q（建议 ntfs/exfat/fat32）", fs)
	}

	label = strings.TrimSpace(label)
	if strings.ContainsAny(label, "\r\n\t") {
		return "", fmt.Errorf("label 含非法控制字符")
	}

	letter = strings.TrimSpace(letter)
	if len(letter) >= 2 && letter[1] == ':' {
		letter = letter[:1]
	}
	letter = strings.ToUpper(letter)
	if letter != "" {
		if len(letter) != 1 || letter[0] < 'A' || letter[0] > 'Z' {
			return "", fmt.Errorf("letter 非法：%q（应为 A-Z 或空）", letter)
		}
	}
	//获取物理磁盘号
	style, diskNo, err := GetDiskInfo(volForGetInfo)
	if err != nil {
		return "", fmt.Errorf("GetDiskInfo(%q) 失败: %w", volForGetInfo, err)
	}

	beforeCount, beforeRoots, err := GetDiskPartitions(fmt.Sprintf("%d", diskNo))
	if err != nil {
		return "", fmt.Errorf("GetDiskPartitions(disk=%d) 失败: %w", diskNo, err)
	}
	beforeLetters := make(map[string]struct{}, len(beforeRoots))
	for _, r := range beforeRoots {
		r = strings.TrimSpace(r)
		if len(r) >= 1 {
			ch := strings.ToUpper(string(r[0]))
			if ch[0] >= 'A' && ch[0] <= 'Z' {
				beforeLetters[ch] = struct{}{}
			}
		}
	}

	// MBR 主分区数量限制
	if strings.EqualFold(style, "MBR") && beforeCount >= 4 {
		return "", fmt.Errorf("磁盘为 MBR 且当前分区数=%d，可能已达主分区上限（4）。需改用扩展/逻辑分区策略或先调整现有分区", beforeCount)
	}

	if letter != "" {
		if _, ok := beforeLetters[letter]; ok {
			return "", fmt.Errorf("指定盘符 %s 已被占用", letter+":")
		}
		if letter == volUp {
			return "", fmt.Errorf("指定盘符不能与源卷相同：%s", volUp+":")
		}
	}

	lines := []string{
		"select volume=" + volUp,
		fmt.Sprintf("shrink desired=%d minimum=%d", sizeMB, sizeMB),
		fmt.Sprintf("select disk %d", diskNo),
		fmt.Sprintf("create partition primary size=%d", sizeMB),
	}

	formatLine := "format fs=" + fs + " quick"
	if label != "" {
		formatLine += " label=" + label
	}
	lines = append(lines, formatLine)

	if letter != "" {
		lines = append(lines, "assign letter="+letter)
	} else {
		lines = append(lines, "assign")
	}

	_, err = RunDiskpart(lines)
	if err != nil {
		return "", fmt.Errorf("diskpart 执行失败: %w\n输出:\n%s", err, out)
	}

	if letter != "" {
		return letter + ":", nil
	}

	// 再次枚举磁盘盘符，取差集
	_, afterRoots, err := GetDiskPartitions(fmt.Sprintf("%d", diskNo))
	if err != nil {
		return "", fmt.Errorf("GetDiskPartitions(disk=%d) 获取新分区盘符失败: %w\n输出:\n%s", diskNo, err, out)
	}
	newLetters := make([]string, 0, 2)
	seen := make(map[string]struct{}, len(afterRoots))
	for _, r := range afterRoots {
		r = strings.TrimSpace(r)
		if len(r) < 1 {
			continue
		}
		ch := strings.ToUpper(string(r[0]))
		if ch[0] < 'A' || ch[0] > 'Z' {
			continue
		}
		if _, ok := seen[ch]; ok {
			continue
		}
		seen[ch] = struct{}{}
		if _, existed := beforeLetters[ch]; !existed {
			newLetters = append(newLetters, ch)
		}
	}

	if len(newLetters) == 1 {
		return newLetters[0] + ":", nil
	}
	if len(newLetters) == 0 {
		return "", fmt.Errorf("diskpart 执行成功但未检测到新盘符（可能未分配盘符或枚举未刷新）\n输出:\n%s", out)
	}
	return "", fmt.Errorf("检测到多个可能的新盘符：%v（无法唯一确定）\n输出:\n%s", newLetters, out)
}

// 根据物理磁盘号或盘符获取分区数量和盘符列表。
// diskID: 可传 "0"/"1" 或 "PhysicalDrive0"，也可传 "C"/"C:"/"C:\"。
// 返回：盘符数量、盘符数组（如 "C:"）。
func GetDiskPartitions(diskID string) (int, []string, error) {
	diskID = strings.TrimSpace(diskID)
	if diskID == "" {
		return 0, nil, fmt.Errorf("diskID 为空")
	}

	isColon := func(b byte) bool { return b == ':' } // ASCII
	diskID = strings.ReplaceAll(diskID, "：", ":")

	var diskNum uint32
	switch {
	case len(diskID) >= 2 && isColon(diskID[1]) &&
		((diskID[0] >= 'A' && diskID[0] <= 'Z') || (diskID[0] >= 'a' && diskID[0] <= 'z')):
		root := strings.ToUpper(diskID[:1]) + `:\`
		dn, err := GetDiskNum(root)
		if err != nil {
			return 0, nil, err
		}
		diskNum = dn

	case len(diskID) == 1 &&
		((diskID[0] >= 'A' && diskID[0] <= 'Z') || (diskID[0] >= 'a' && diskID[0] <= 'z')):
		root := strings.ToUpper(diskID) + `:\`
		dn, err := GetDiskNum(root)
		if err != nil {
			return 0, nil, err
		}
		diskNum = dn

	default:
		re := regexp.MustCompile(`(?i)physicaldrive(\d+)`)
		if m := re.FindStringSubmatch(diskID); len(m) == 2 {
			n, err := strconv.ParseUint(m[1], 10, 32)
			if err != nil {
				return 0, nil, fmt.Errorf("解析磁盘号失败: %w", err)
			}
			diskNum = uint32(n)
		} else {
			n, err := strconv.ParseUint(diskID, 10, 32)
			if err != nil {
				return 0, nil, fmt.Errorf("解析磁盘号失败: %w", err)
			}
			diskNum = uint32(n)
		}
	}

	drives, err := ListDrive()
	if err != nil {
		return 0, nil, err
	}

	letters := make([]string, 0, len(drives))
	for _, root := range drives {
		n, err := GetDiskNum(root)
		if err != nil {
			continue
		}
		if n == diskNum {
			r := strings.TrimSpace(root)
			if len(r) > 0 {
				ch := strings.ToUpper(string(r[0]))
				if ch[0] >= 'A' && ch[0] <= 'Z' {
					letters = append(letters, ch+":")
				}
			}
		}
	}

	return len(letters), letters, nil
}

// 合并分区：将目标卷卷尾紧邻的未分配空间扩展到指定卷。
// vol: 例如 "C" / "C:" / "C:\"
// sizeMB: 扩展大小（MB），<=0 表示使用全部
func MergeVolume(vol string, sizeMB int) error {
	pVol, err := utf16Ptr(vol)
	if err != nil {
		return err
	}
	hr, _, _ := procMergeW.Call(
		uintptr(unsafe.Pointer(pVol)),
		uintptr(int32(sizeMB)),
	)
	return hresultErr(hr, "MergeVolumeW")

	vol = strings.TrimSpace(vol)
	if vol == "" {
		return fmt.Errorf("vol 不能为空（请输入盘符，如 C / C: / C:\\）")
	}

	volUp := strings.ToUpper(vol)
	if len(volUp) >= 2 && volUp[1] == ':' {
		volUp = volUp[:1]
	} else if len(volUp) == 1 {
		// ok
	} else {
		return fmt.Errorf("vol 格式不支持：%q（请用盘符如 C 或 C:）", vol)
	}
	if volUp[0] < 'A' || volUp[0] > 'Z' {
		return fmt.Errorf("vol 不是有效盘符：%q", vol)
	}

	lines := []string{"select volume=" + volUp}
	if sizeMB > 0 {
		lines = append(lines, fmt.Sprintf("extend size=%d", sizeMB))
	} else {
		lines = append(lines, "extend")
	}

	_, err = RunDiskpart(lines)
	if err != nil {
		return fmt.Errorf("diskpart 执行失败: %w", err)
	}
	return nil
}

// 删除指定卷（转为未分配空间）。
// vol: 例如 "C" / "C:" / "C:\\"
func DeleteVolume(vol string) error {
	pVol, err := utf16Ptr(vol) // "E:"
	if err != nil {
		return err
	}
	hr, _, _ := procDeleteW.Call(uintptr(unsafe.Pointer(pVol)))
	return hresultErr(hr, "DeleteVolumeW")

	vol = strings.TrimSpace(vol)
	if vol == "" {
		return fmt.Errorf("卷标为空")
	}
	if len(vol) >= 2 && vol[1] == ':' {
		vol = vol[:2]
	}
	if len(vol) == 1 {
		vol = strings.ToUpper(vol) + ":"
	}

	lines := []string{
		"select volume " + vol,
		"delete volume",
	}

	_, err = RunDiskpart(lines)
	if err != nil {
		return fmt.Errorf("diskpart 执行失败: %w", err)
	}
	return nil
}

// 获取卷的文件系统类型和总大小（字节）
func GetVolumeInfo(root string) (fsType string, totalBytes uint64, err error) {
	root = normRoot(root)
	if root == "" {
		return "", 0, fmt.Errorf("empty root")
	}
	pRoot, e := syscall.UTF16PtrFromString(root)
	if e != nil {
		return "", 0, e
	}

	volName := make([]uint16, 256)
	fsName := make([]uint16, 256)
	var serial, maxCompLen, flags uint32

	r1, _, e1 := procGetVolumeInformationW.Call(
		uintptr(unsafe.Pointer(pRoot)),
		uintptr(unsafe.Pointer(&volName[0])),
		uintptr(len(volName)),
		uintptr(unsafe.Pointer(&serial)),
		uintptr(unsafe.Pointer(&maxCompLen)),
		uintptr(unsafe.Pointer(&flags)),
		uintptr(unsafe.Pointer(&fsName[0])),
		uintptr(len(fsName)),
	)
	if r1 == 0 {
		if e1 != nil && e1 != syscall.Errno(0) {
			return "", 0, fmt.Errorf("GetVolumeInformationW: %w", e1)
		}
		return "", 0, fmt.Errorf("GetVolumeInformationW failed")
	}
	fsType = strings.ToUpper(syscall.UTF16ToString(fsName))

	var freeBytes, total, freeTotal uint64
	r2, _, e2 := procGetDiskFreeSpaceExW.Call(
		uintptr(unsafe.Pointer(pRoot)),
		uintptr(unsafe.Pointer(&freeBytes)),
		uintptr(unsafe.Pointer(&total)),
		uintptr(unsafe.Pointer(&freeTotal)),
	)
	if r2 == 0 {
		if e2 != nil && e2 != syscall.Errno(0) {
			return fsType, 0, fmt.Errorf("GetDiskFreeSpaceExW: %w", e2)
		}
		return fsType, 0, fmt.Errorf("GetDiskFreeSpaceExW failed")
	}
	return fsType, total, nil
}

// 读取指定卷的剩余空间
func GetFreeSize(vol string) (freeBytes uint64, err error) {
	root := normRoot(vol)
	if root == "" {
		return 0, fmt.Errorf("empty volume")
	}

	pRoot, e := syscall.UTF16PtrFromString(root)
	if e != nil {
		return 0, e
	}

	var freeAvail, total, freeTotal uint64

	r, _, e2 := procGetDiskFreeSpaceExW.Call(
		uintptr(unsafe.Pointer(pRoot)),
		uintptr(unsafe.Pointer(&freeAvail)), // 当前用户可用空间
		uintptr(unsafe.Pointer(&total)),     // 卷总大小
		uintptr(unsafe.Pointer(&freeTotal)), // 卷总空闲（包括管理员保留）
	)
	if r == 0 {
		if e2 != nil && e2 != syscall.Errno(0) {
			return 0, fmt.Errorf("GetDiskFreeSpaceExW: %w", e2)
		}
		return 0, fmt.Errorf("GetDiskFreeSpaceExW failed")
	}
	return freeAvail, nil
}

// 根据分区取第一个物理磁盘号
func GetDiskNum(vol string) (uint32, error) {
	root := normRoot(vol)
	if root == "" {
		return 0, fmt.Errorf("invalid volume: %q", vol)
	}
	// \\.\C:
	volPath := `\\.\` + strings.TrimRight(root, `\`)
	pVol, err := syscall.UTF16PtrFromString(volPath)
	if err != nil {
		return 0, err
	}

	hVol, err := syscall.CreateFile(
		pVol,
		0, // 只读
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		nil,
		syscall.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		return 0, fmt.Errorf("CreateFile volume %s failed: %w", volPath, err)
	}
	defer syscall.CloseHandle(hVol)

	out := make([]byte, 1024)
	var bytesRet uint32
	err = syscall.DeviceIoControl(
		hVol,
		ioctlVolumeGetVolumeDiskExtents,
		nil,
		0,
		&out[0],
		uint32(len(out)),
		&bytesRet,
		nil,
	)
	if err != nil {
		return 0, fmt.Errorf("DeviceIoControl IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS failed: %w", err)
	}
	if bytesRet < uint32(unsafe.Sizeof(volumeDiskExtents{})) {
		return 0, fmt.Errorf("VOLUME_DISK_EXTENTS too small: %d", bytesRet)
	}

	vde := (*volumeDiskExtents)(unsafe.Pointer(&out[0]))
	if vde.NumberOfDiskExtents == 0 {
		return 0, fmt.Errorf("no disk extents for volume %s", volPath)
	}
	//第一个Extent的DiskNumber
	//有个坑，32位偏移量是4开始，64是8开始
	//直接用 Extents[0].DiskNumber，兼容32/64
	diskNum := vde.Extents[0].DiskNumber
	return diskNum, nil
}

// 根据分区取磁盘的分区格式（MBR/GPT/RAW）
// 返回: style ("MBR"/"GPT"/"RAW")、磁盘号 (PhysicalDriveN)、错误
func GetDiskInfo(vol string) (string, uint32, error) {
	diskNum, err := GetDiskNum(vol)
	if err != nil {
		return "", 0, err
	}

	diskPath := fmt.Sprintf(`\\.\PhysicalDrive%d`, diskNum)
	pDisk, err := syscall.UTF16PtrFromString(diskPath)
	if err != nil {
		return "", 0, err
	}

	hDisk, err := syscall.CreateFile(
		pDisk,
		syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		nil,
		syscall.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		return "", 0, fmt.Errorf("CreateFile %s failed: %w", diskPath, err)
	}
	defer syscall.CloseHandle(hDisk)

	out := make([]byte, 4096)
	var bytesRet uint32
	err = syscall.DeviceIoControl(
		hDisk,
		ioctlDiskGetDriveLayoutEx,
		nil,
		0,
		&out[0],
		uint32(len(out)),
		&bytesRet,
		nil,
	)
	if err != nil {
		return "", 0, fmt.Errorf("DeviceIoControl IOCTL_DISK_GET_DRIVE_LAYOUT_EX failed: %w", err)
	}
	if bytesRet < 4 {
		return "", 0, fmt.Errorf("unexpected DRIVE_LAYOUT_INFORMATION_EX size: %d", bytesRet)
	}

	// DRIVE_LAYOUT_INFORMATION_EX 第一个字段就是 PartitionStyle (DWORD)
	styleVal := binary.LittleEndian.Uint32(out[0:4])
	var style string
	switch styleVal {
	case partitionStyleMBR:
		style = "MBR"
	case partitionStyleGPT:
		style = "GPT"
	case partitionStyleRAW:
		style = "RAW"
	default:
		style = "UNKNOWN"
	}

	fmt.Printf("[GetDiskInfo] vol=%s disk=%d style=%s\n", normRoot(vol), diskNum, style)
	return style, diskNum, nil
}

// GetDiskKind 判断指定卷所在物理盘是 SSD / HDD / 移动设备 / 光驱。
// vol 可以是 "C" / "C:" / "C:\"。
// 返回值： "SSD" / "HDD" / "Removable" / "CDROM" / "Unknown"
func GetDiskKind(vol string) (string, error) {
	root := normRoot(vol)
	if root == "" {
		return "Unknown", fmt.Errorf("invalid volume: %q", vol)
	}

	// 先看逻辑盘类型
	dt := GetDriveType(root)

	// 光驱 / 挂载的 ISO
	if dt == driveCdrom {
		return "CDROM", nil
	}

	// 后面是非光驱的情况：U 盘 / 机械 / 固态
	// 找到对应的物理磁盘号
	diskNum, err := GetDiskNum(root)
	if err != nil {
		// 如果至少知道是可移动盘，就返回 Removable
		if dt == driveRemov {
			return "Removable", nil
		}
		return "Unknown", fmt.Errorf("GetDiskNum failed: %w", err)
	}

	diskPath := fmt.Sprintf(`\\.\PhysicalDrive%d`, diskNum)
	pDisk, err := syscall.UTF16PtrFromString(diskPath)
	if err != nil {
		if dt == driveRemov {
			return "Removable", nil
		}
		return "Unknown", err
	}

	hDisk, err := syscall.CreateFile(
		pDisk,
		syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		nil,
		syscall.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		if dt == driveRemov {
			return "Removable", nil
		}
		return "Unknown", fmt.Errorf("CreateFile %s failed: %w", diskPath, err)
	}
	defer syscall.CloseHandle(hDisk)

	// 看是不是 USB 之类的移动设备
	busType := uint32(busTypeUnknown)
	{
		q := storagePropertyQuery{
			PropertyId: storagePropertyDevice,
			QueryType:  storageQueryStandard,
		}
		out := make([]byte, 512)
		var bytesRet uint32

		err = syscall.DeviceIoControl(
			hDisk,
			ioctlStorageQueryProperty,
			(*byte)(unsafe.Pointer(&q)),
			uint32(unsafe.Sizeof(q)),
			&out[0],
			uint32(len(out)),
			&bytesRet,
			nil,
		)
		if err == nil && bytesRet >= uint32(unsafe.Sizeof(storageDeviceDescriptor{})) {
			dev := (*storageDeviceDescriptor)(unsafe.Pointer(&out[0]))
			busType = dev.BusType
		}
	}

	// USB 总线 / DRIVE_REMOVABLE 认为是移动设备
	if dt == driveRemov || busType == busTypeUsb {
		return "Removable", nil
	}

	// 尝试用 SeekPenalty 判断 SSD / HDD
	hasSeekInfo := false
	incursSeek := false
	{
		q := storagePropertyQuery{
			PropertyId: storagePropertySeekPenalty,
			QueryType:  storageQueryStandard,
		}
		out := make([]byte, 32)
		var bytesRet uint32

		err = syscall.DeviceIoControl(
			hDisk,
			ioctlStorageQueryProperty,
			(*byte)(unsafe.Pointer(&q)),
			uint32(unsafe.Sizeof(q)),
			&out[0],
			uint32(len(out)),
			&bytesRet,
			nil,
		)
		if err == nil && bytesRet >= uint32(unsafe.Sizeof(storageDeviceSeekPenaltyDescriptor{})) {
			desc := (*storageDeviceSeekPenaltyDescriptor)(unsafe.Pointer(&out[0]))
			hasSeekInfo = true
			incursSeek = desc.IncursSeekPenalty != 0
		}
	}

	if hasSeekInfo {
		if incursSeek {
			return "HDD", nil // 有寻道惩罚 -> 机械盘
		}
		return "SSD", nil // 无寻道惩罚 -> 固态盘
	}

	//没拿到 SeekPenalty，就根据 BusType 做个保守猜测
	switch busType {
	case busTypeSata, busTypeSas, busTypeScsi, busTypeAta:
		return "HDD", nil // 老接口大多数是机械盘
	}

	return "Unknown", nil
}

// 返回当前系统所有逻辑盘根路径，如 "C:\", "D:\" 等。
func ListDrive() ([]string, error) {
	// GetLogicalDriveStringsW 正常拿
	buf := make([]uint16, 256)
	r, _, err := procGetLogicalDriveStringsW.Call(
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&buf[0])),
	)
	if r != 0 {
		n := int(r)
		drives := make([]string, 0, 26)
		for i := 0; i < n; {
			j := i
			for j < n && buf[j] != 0 {
				j++
			}
			if j == i {
				break
			}
			drives = append(drives, syscall.UTF16ToString(buf[i:j]))
			i = j + 1
		}
		logWrite(fmt.Sprintf("[ListDrive] 枚举磁盘: %v\n", drives))
		return drives, nil
	}

	// 失败就遍历 A-Z
	drives := make([]string, 0, 26)
	for c := 'A'; c <= 'Z'; c++ {
		root := fmt.Sprintf("%c:\\", c)
		p := syscall.StringToUTF16Ptr(root)
		t, _, _ := procGetDriveTypeW.Call(uintptr(unsafe.Pointer(p)))
		// DRIVE_NO_ROOT_DIR(1) 表示不存在
		if t != 1 {
			drives = append(drives, root)
		}
	}

	if len(drives) == 0 {
		if err != syscall.Errno(0) {
			return nil, err
		}
		return nil, fmt.Errorf("failed to list drives")
	}
	return drives, nil
}

// 判断盘符类型。
func GetDriveType(root string) uint32 {
	pRoot, err := syscall.UTF16PtrFromString(root)
	if err != nil {
		return driveUnknown
	}
	r, _, _ := procGetDriveTypeW.Call(uintptr(unsafe.Pointer(pRoot)))
	return uint32(r)
}

// 列出当前系统中的所有光驱盘符。
func ListCD() ([]string, error) {
	roots, err := ListDrive()
	if err != nil {
		return nil, err
	}
	var cds []string
	for _, r := range roots {
		if GetDriveType(r) == driveCdrom {
			cds = append(cds, r)
		}
	}
	return cds, nil
}

// 把diskpart命令写入临时文件并执行。
// 返回diskpart的输出，便于日志记录/排错。
func RunDiskpart(lines []string) (string, error) {
	if len(lines) == 0 {
		return "", fmt.Errorf("empty diskpart script")
	}

	script := strings.Join(lines, "\r\n") + "\r\n"

	// 在当前运行目录创建临时脚本文件（不使用系统临时目录）
	name := fmt.Sprintf("dp_fmt_%d.txt", time.Now().UnixNano())
	path := filepath.Join(".", name)

	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", fmt.Errorf("create script in workdir failed: %w", err)
	}
	defer Remove(path, false) //用完就删除

	if _, err := f.WriteString(script); err != nil {
		_ = f.Close()
		return "", fmt.Errorf("write script failed: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("close script failed: %w", err)
	}

	out, err := runCmd("diskpart.exe", nil, "/s", path)
	if err != nil {
		return out, fmt.Errorf("diskpart failed: %w", err)
	}
	return out, nil
}

// 使用 diskpart，按盘符格式化卷。
// letter: 盘符，可以是 "C" / "C:" / "C:\"
// fs: 文件系统，例如 "ntfs" "fat32" "exfat"
// label: 卷标，允许为空
// quick: true：快速格式化, false：全格式
func Format(letter, fs, label string, quick bool) error {
	pLetter, err := utf16Ptr(letter) // e.g. "E:"
	if err != nil {
		return err
	}
	pFs, err := utf16Ptr(fs) // "NTFS" / "FAT32"
	if err != nil {
		return err
	}
	pLabel, err := utf16Ptr(label)
	if err != nil {
		return err
	}

	var q uintptr = 0
	if quick {
		q = 1
	}

	hr, _, _ := procFormatW.Call(
		uintptr(unsafe.Pointer(pLetter)),
		uintptr(unsafe.Pointer(pFs)),
		uintptr(unsafe.Pointer(pLabel)),
		q,
	)
	return hresultErr(hr, "FormatW")

	l := strings.TrimSpace(letter)
	if l == "" {
		return fmt.Errorf("empty volume letter")
	}

	// "C:" -> "C"
	l = strings.ToUpper(l)
	if strings.HasSuffix(l, ":") {
		l = l[:len(l)-1]
	}
	if len(l) != 1 || l[0] < 'A' || l[0] > 'Z' {
		return fmt.Errorf("invalid volume letter: %q", letter)
	}

	if fs == "" {
		fs = "ntfs"
	}
	fs = strings.ToLower(fs)

	cmds := []string{
		fmt.Sprintf("select volume %s", l),
	}

	// 加上OVERRIDE强制执行
	fmtCmd := fmt.Sprintf("format fs=%s", fs)
	if label != "" {
		fmtCmd += fmt.Sprintf(" label=\"%s\"", label)
	}
	if quick {
		fmtCmd += " quick"
	}
	fmtCmd += " override" //强制格式化

	cmds = append(cmds, fmtCmd)

	out, err := RunDiskpart(cmds)
	fmt.Println("[Format] diskpart output:\n", out)
	if err != nil {
		return err
	}
	return nil
}

// FormatPartition 使用 diskpart 格式化指定磁盘上的指定分区。
// diskIdx: diskpart里的磁盘编号（list disk）
// partIdx: 该磁盘上的分区编号（list partition）
// fs/label/quick
func FormatPartition(diskIdx, partIdx int, fs, label string, quick bool) error {
	if diskIdx < 0 {
		return fmt.Errorf("invalid disk index: %d", diskIdx)
	}
	if partIdx <= 0 {
		return fmt.Errorf("invalid partition index: %d", partIdx)
	}
	if fs == "" {
		fs = "ntfs"
	}
	fs = strings.ToLower(fs)

	cmds := []string{
		fmt.Sprintf("select disk %d", diskIdx),
		fmt.Sprintf("select partition %d", partIdx),
	}

	// 加 OVERRIDE
	fmtCmd := fmt.Sprintf("format fs=%s", fs)
	if label != "" {
		fmtCmd += fmt.Sprintf(" label=\"%s\"", label)
	}
	if quick {
		fmtCmd += " quick"
	}
	fmtCmd += " override" // *** 关键：强制格式化 ***

	cmds = append(cmds, fmtCmd)

	out, err := RunDiskpart(cmds)
	fmt.Println("[FormatPartition] diskpart output:\n", out)
	if err != nil {
		return err
	}
	return nil
}
