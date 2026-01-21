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
	"unicode/utf16"
	"unsafe"
)

func parseLetter(letter string) (string, error) {
	l := strings.TrimSpace(letter)
	if l == "" {
		return "", fmt.Errorf("empty drive letter")
	}
	l = strings.ToUpper(l)
	if len(l) >= 2 && l[1] == ':' {
		l = l[:1]
	} else if len(l) >= 3 && l[1] == ':' && (l[2] == '\\' || l[2] == '/') {
		l = l[:1]
	} else if len(l) != 1 {
		return "", fmt.Errorf("invalid drive letter: %q", letter)
	}
	if l[0] < 'A' || l[0] > 'Z' {
		return "", fmt.Errorf("invalid drive letter: %q", letter)
	}
	return l, nil
}

func parseFS(fs string) (string, error) {
	fs = strings.TrimSpace(fs)
	if fs == "" {
		return "", fmt.Errorf("fs 不能为空")
	}
	fs = strings.ToUpper(fs)
	switch fs {
	case "NTFS", "FAT32":
		return fs, nil
	default:
		return "", fmt.Errorf("不支持的 fs：%q（仅支持 NTFS/FAT32）", fs)
	}
}
func collectDriveLetters() (map[string]struct{}, error) {
	drives, err := ListDrive()
	if err != nil {
		return nil, err
	}
	set := make(map[string]struct{}, len(drives))
	for _, root := range drives {
		root = strings.TrimSpace(root)
		if len(root) < 1 {
			continue
		}
		ch := strings.ToUpper(string(root[0]))
		if ch[0] >= 'A' && ch[0] <= 'Z' {
			set[ch] = struct{}{}
		}
	}
	return set, nil
}

// 根据物理磁盘号或盘符获取分区数量和盘符列表。
// diskID: 可传 "0"/"1" 或 "PhysicalDrive0"，也可传 "C"/"C:"/"C:\"。
// 返回：盘符数量、盘符数组
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
	name := fmt.Sprintf("dp_fmt_%d.txt", time.Now().UnixNano())
	baseDir := ""
	if exe, err := os.Executable(); err == nil {
		baseDir = filepath.Dir(exe)
	}
	if baseDir == "" {
		baseDir = os.TempDir()
	}
	path := filepath.Join(baseDir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", fmt.Errorf("create script in workdir failed: %w", err)
	}
	//defer Remove(path, false) //用完就删除

	if _, err := f.WriteString(script); err != nil {
		_ = f.Close()
		return "", fmt.Errorf("write script failed: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("close script failed: %w", err)
	}
	diskpart := "diskpart.exe"
	if systemArch() == "32" {
		diskpart = "C:\\Windows\\Sysnative\\diskpart.exe"
	} else {
		diskpart = "C:\\Windows\\System32\\diskpart.exe"
	}
	out, err := runCmd(diskpart, nil, "", "/s", path)
	if err != nil {
		return out, fmt.Errorf("diskpart failed: %w", err)
	}
	return out, nil

}

func ansiToUTF8(b []byte) string {
	if len(b) == 0 {
		return ""
	}

	// MultiByteToWideChar(CP_ACP, 0, ...)
	const cpACP = 0
	k32 := syscall.NewLazyDLL("kernel32.dll")
	mb2wc := k32.NewProc("MultiByteToWideChar")

	// 获取所需 UTF-16 长度
	r1, _, _ := mb2wc.Call(
		uintptr(cpACP),
		uintptr(0),
		uintptr(unsafe.Pointer(&b[0])),
		uintptr(len(b)),
		uintptr(0),
		uintptr(0),
	)
	n := int(r1)
	if n <= 0 {
		return string(b)
	}

	w := make([]uint16, n)
	r2, _, _ := mb2wc.Call(
		uintptr(cpACP),
		uintptr(0),
		uintptr(unsafe.Pointer(&b[0])),
		uintptr(len(b)),
		uintptr(unsafe.Pointer(&w[0])),
		uintptr(n),
	)
	if int(r2) <= 0 {
		return string(b)
	}

	// 转为 Go string（UTF-8）
	return string(utf16.Decode(w))
}

// 获取卷所在磁盘号 + 卷的起始偏移/长度（用于计算 /offset）。
// 只取第一个 extent（常见卷场景足够用；动态卷/多 extent 需要更复杂处理）。
type diskExtentRaw struct {
	DiskNumber     uint32
	_              uint32 // padding for 8-byte alignment
	StartingOffset int64
	ExtentLength   int64
}

type volumeDiskExtentsRaw struct {
	NumberOfDiskExtents uint32
	_                   uint32 // padding
	Extents             [1]diskExtentRaw
}

func getVolumeExtentBytes(vol string) (diskNum uint32, startBytes int64, lengthBytes int64, err error) {
	root := normRoot(vol)
	if root == "" {
		return 0, 0, 0, fmt.Errorf("invalid volume: %q", vol)
	}
	// \\.\C:
	volPath := `\\.\` + strings.TrimRight(root, `\`)
	pVol, err := syscall.UTF16PtrFromString(volPath)
	if err != nil {
		return 0, 0, 0, err
	}

	hVol, err := syscall.CreateFile(
		pVol,
		0,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		nil,
		syscall.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("CreateFile volume %s failed: %w", volPath, err)
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
		return 0, 0, 0, fmt.Errorf("DeviceIoControl IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS failed: %w", err)
	}
	if bytesRet < uint32(unsafe.Sizeof(volumeDiskExtentsRaw{})) {
		return 0, 0, 0, fmt.Errorf("VOLUME_DISK_EXTENTS too small: %d", bytesRet)
	}

	vde := (*volumeDiskExtentsRaw)(unsafe.Pointer(&out[0]))
	if vde.NumberOfDiskExtents == 0 {
		return 0, 0, 0, fmt.Errorf("no disk extents for volume %s", volPath)
	}
	ext := vde.Extents[0]
	return ext.DiskNumber, ext.StartingOffset, ext.ExtentLength, nil
}

func cleanLabel(label string) string {
	label = strings.TrimSpace(label)
	if label == "" {
		return "NO_LABEL"
	}
	// 防止破坏参数解析
	label = strings.ReplaceAll(label, "\r", " ")
	label = strings.ReplaceAll(label, "\n", " ")
	label = strings.ReplaceAll(label, `"`, `'`)
	return label
}

func diskpartQuote(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	// diskpart 支持 label="xx xx"，先去掉引号避免脚本被破坏
	s = strings.ReplaceAll(s, `"`, "")
	if strings.ContainsAny(s, " \t") {
		return `"` + s + `"`
	}
	return s
}

// diskpart 有时 exit code 仍是 0，但输出里已经报错；这里做一层保底检测。
func diskpartDetectError(out, op string) error {
	low := strings.ToLower(out)
	bad := []string{
		"diskpart has encountered an error",
		"virtual disk service error",
		"the operation failed",
		"the request is not supported",
		"there is not enough usable free space",
		"may not be shrunk",
		"may not be extended",
		"cannot be extended",
		"cannot be shrunk",
	}
	for _, b := range bad {
		if strings.Contains(low, b) {
			return fmt.Errorf("%s(diskpart) failed\n输出:\n%s", op, out)
		}
	}
	return nil
}

// ShrinkVolume 将某个卷从右侧收缩指定大小(MB)，在卷尾释放出未分配空间。
// 返回：diskpart 输出，便于日志记录。
func ShrinkVolume(vol string, sizeMB int) (string, error) {
	volLetter, err := parseLetter(vol)
	if err != nil {
		return "", err
	}
	if sizeMB <= 0 {
		return "", fmt.Errorf("sizeMB 必须大于 0")
	}

	// diskpart: select volume C  /  shrink desired=1000
	lines := []string{
		fmt.Sprintf("select volume %s", volLetter),
		fmt.Sprintf("shrink desired=%d", sizeMB),
	}

	out, err := RunDiskpart(lines)
	if err != nil {
		return out, fmt.Errorf("shrink(diskpart) failed: %w\n输出:\n%s", err, out)
	}
	if e := diskpartDetectError(out, "shrink"); e != nil {
		return out, e
	}
	return out, nil
}

// CreatePartitionAfterVolume：在 vol 卷尾紧邻的未分配空间上创建主分区、快速格式化、自动分配盘符。
// sizeMB：期望新分区大小(MB)。如果因为对齐导致 size 放不下，会做小幅降级重试。
// 返回：新分区盘符（例如 "E:"）和错误。
func CreatePartitionAfterVolume(vol string, sizeMB int, fs, label string) (string, error) {
	volLetter, err := parseLetter(vol)
	if err != nil {
		return "", err
	}
	if sizeMB <= 0 {
		return "", fmt.Errorf("sizeMB 必须大于 0")
	}

	fs2, err := parseFS(fs)
	if err != nil {
		return "", err
	}
	fs2 = strings.ToLower(fs2)

	label = cleanLabel(label)
	lblArg := ""
	if strings.TrimSpace(label) != "" {
		lblArg = " label=" + diskpartQuote(label)
	}

	// 推断新盘符
	beforeLetters, err := collectDriveLetters()
	if err != nil {
		return "", err
	}

	// 获取卷所在磁盘与卷区间
	diskNum, startBytes, lengthBytes, err := getVolumeExtentBytes(volLetter + ":")
	if err != nil {
		return "", err
	}
	endBytes := startBytes + lengthBytes
	const mb = int64(1024 * 1024)
	offsetMB := (endBytes + mb - 1) / mb
	offsetKB := offsetMB * 1024
	createSize := sizeMB
	if endBytes%mb != 0 && sizeMB > 1 {
		createSize = sizeMB - 1
	}
	formatLine := fmt.Sprintf("format fs=%s%s", fs2, lblArg)
	formatLine += " quick"

	// 创建分区可能因对齐、空间边界等失败
	trySizes := []int{createSize}
	if createSize > 2 {
		trySizes = append(trySizes, createSize-1)
	}
	if createSize > 3 {
		trySizes = append(trySizes, createSize-2)
	}

	var outCreate string
	var lastErr error

	for _, sz := range trySizes {
		lines := []string{
			fmt.Sprintf("select disk %d", diskNum),
			fmt.Sprintf("create partition primary offset=%d size=%d align=1024", offsetKB, sz),
			formatLine,
			"assign",
		}

		out, err := RunDiskpart(lines)
		if err == nil {
			if e := diskpartDetectError(out, "create/format/assign"); e == nil {
				outCreate = out
				lastErr = nil
				break
			} else {
				err = e
			}
		}
		lastErr = fmt.Errorf("create partition(diskpart) failed: %w\n输出:\n%s", err, out)
	}

	// 如果指定 size 一直失败，尝试让 diskpart 用从 offset 起的全部空间
	if lastErr != nil {
		lines := []string{
			fmt.Sprintf("select disk %d", diskNum),
			fmt.Sprintf("create partition primary offset=%d align=1024", offsetKB),
			formatLine,
			"assign",
		}
		out, err := RunDiskpart(lines)
		if err != nil {
			return "", fmt.Errorf("create partition(diskpart) failed: %w\n输出:\n%s", err, out)
		}
		if e := diskpartDetectError(out, "create/format/assign"); e != nil {
			return "", e
		}
		outCreate = out
	}

	// 推断新盘符
	for i := 0; i < 6; i++ {
		afterLetters, err := collectDriveLetters()
		if err != nil {
			return "", err
		}
		for l := range afterLetters {
			if _, ok := beforeLetters[l]; !ok {
				return l, nil
			}
		}
		time.Sleep(300 * time.Millisecond)
	}

	return "", fmt.Errorf("create finished but cannot determine new drive letter (check Disk Management)\ncreate输出:\n%s", outCreate)
}

// 使用 diskpart 将某个卷收缩指定大小(MB)，然后在释放出的未分配空间上新建分区并快速格式化。
// 返回：新分区盘符（例如 "E:"）和错误。
func SplitVolume(vol string, sizeMB int, fs, label string) (string, error) {
	if sizeMB <= 0 {
		return "", fmt.Errorf("sizeMB 必须大于 0")
	}

	outShrink, err := ShrinkVolume(vol, sizeMB)
	if err != nil {
		return "", err
	}

	newLetter, err := CreatePartitionAfterVolume(vol, sizeMB, fs, label)
	if err != nil {
		return "", fmt.Errorf("%w\nshrink输出:\n%s", err, outShrink)
	}
	return newLetter, nil
}

// 合并分区：将目标卷卷尾紧邻的未分配空间扩展到指定卷。
// sizeMB: 扩展大小（MB），<=0 表示使用全部
func MergeVolume(vol string, sizeMB int) error {
	volLetter, err := parseLetter(vol)
	if err != nil {
		return err
	}

	lines := []string{
		fmt.Sprintf("select volume %s", volLetter),
	}
	if sizeMB > 0 {
		lines = append(lines, fmt.Sprintf("extend size=%d", sizeMB))
	} else {
		lines = append(lines, "extend")
	}

	out, err := RunDiskpart(lines)
	if err != nil {
		return fmt.Errorf("merge/extend(diskpart) failed: %w\n输出:\n%s", err, out)
	}
	if e := diskpartDetectError(out, "extend"); e != nil {
		return e
	}
	return nil
}

// 删除指定卷（转为未分配空间）。
func DeleteVolume(vol string) error {
	volLetter, err := parseLetter(vol)
	if err != nil {
		return err
	}

	lines := []string{
		fmt.Sprintf("select volume %s", volLetter),
		"delete volume override",
	}

	out, err := RunDiskpart(lines)
	if err != nil {
		return fmt.Errorf("delete(diskpart) failed: %w\n输出:\n%s", err, out)
	}
	if e := diskpartDetectError(out, "delete volume"); e != nil {
		return e
	}
	return nil
}

// 按盘符格式化卷。
func Format(letter, fs, label string, quick bool) error {
	volLetter, err := parseLetter(letter)
	if err != nil {
		return err
	}

	fs2, err := parseFS(fs)
	if err != nil {
		return err
	}
	fs2 = strings.ToLower(fs2)

	label = cleanLabel(label)
	lblArg := ""
	if strings.TrimSpace(label) != "" {
		lblArg = " label=" + diskpartQuote(label)
	}

	line := fmt.Sprintf("format fs=%s%s", fs2, lblArg)
	if quick {
		line += " quick"
	}

	lines := []string{
		fmt.Sprintf("select volume %s", volLetter),
		line,
	}

	out, err := RunDiskpart(lines)
	fmt.Println(out)
	if err != nil {
		return fmt.Errorf("format(diskpart) failed: %w\n输出:\n%s", err, out)
	}
	if e := diskpartDetectError(out, "format"); e != nil {
		return e
	}
	return nil
}
