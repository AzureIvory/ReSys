package disk

import (
	"ReSys/src/log"
	"encoding/binary"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"ReSys/src/utils"
)

var (
	Kernel32                    = syscall.NewLazyDLL("kernel32.dll")
	procGetVolumeInformationW   = Kernel32.NewProc("GetVolumeInformationW")
	procGetDiskFreeSpaceExW     = Kernel32.NewProc("GetDiskFreeSpaceExW")
	procGetLogicalDriveStringsW = Kernel32.NewProc("GetLogicalDriveStringsW")
	procGetDriveTypeW           = Kernel32.NewProc("GetDriveTypeW")
	procFindFirstVolumeW        = Kernel32.NewProc("FindFirstVolumeW")
	procFindNextVolumeW         = Kernel32.NewProc("FindNextVolumeW")
	procFindVolumeClose         = Kernel32.NewProc("FindVolumeClose")
	procGetVolumePathNamesW     = Kernel32.NewProc("GetVolumePathNamesForVolumeNameW")
	Fmifs                       = syscall.NewLazyDLL("fmifs.dll")
	procFormatEx                = Fmifs.NewProc("FormatEx")
)

// CLSID / IID
var (
	CLSID_ShellLink  = GUID{0x00021401, 0x0000, 0x0000, [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}
	IID_IShellLinkW  = GUID{0x000214F9, 0x0000, 0x0000, [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}
	IID_IPersistFile = GUID{0x0000010b, 0x0000, 0x0000, [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}
	GPTTypeEfiSystem = GUID{0xC12A7328, 0xF81F, 0x11D2, [8]byte{0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B}}
	GPTTypeMsr       = GUID{0xE3C9E316, 0x0B5C, 0x4DB8, [8]byte{0x81, 0x7D, 0xF9, 0x2D, 0xF0, 0x02, 0x15, 0xAE}}
	GPTTypeBasicData = GUID{0xEBD0A0A2, 0xB9E5, 0x4433, [8]byte{0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7}}
	GPTTypeRecovery  = GUID{0xDE94BBA4, 0x06D1, 0x4D40, [8]byte{0xA1, 0x6A, 0xBF, 0xD5, 0x01, 0x79, 0xD6, 0xAC}}
)

const (
	//盘符类型
	driveUnknown = 0 //未知
	driveNoRoot  = 1 //无根目录
	driveRemov   = 2 //可移动介质
	driveFixed   = 3 //固定磁盘
	driveRemote  = 4 //网络驱动器
	driveCdrom   = 5 //光盘
	driveRamdisk = 6 //RAM盘

	//磁盘相关
	ioctlVolumeGetVolumeDiskExtents = 0x00560000 // IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS
	ioctlDiskGetDriveLayoutEx       = 0x00070050 // IOCTL_DISK_GET_DRIVE_LAYOUT_EX
	ioctlDiskGetLengthInfo          = 0x0007405C // IOCTL_DISK_GET_LENGTH_INFO
	partitionStyleMBR               = 0          // PARTITION_STYLE_MBR
	partitionStyleGPT               = 1          // PARTITION_STYLE_GPT
	partitionStyleRAW               = 2          // PARTITION_STYLE_RAW
	ioctlStorageQueryProperty       = 0x002D1400 // IOCTL_STORAGE_QUERY_PROPERTY

	// STORAGE_BUS_TYPE
	busTypeUnknown = 0
	busTypeScsi    = 1
	busTypeAtapi   = 2
	busTypeAta     = 3
	busTypeUsb     = 7
	busTypeSata    = 8
	busTypeSas     = 9

	// STORAGE_PROPERTY_ID
	storagePropertyDevice      = 0 // StorageDeviceProperty
	storagePropertySeekPenalty = 7 // StorageDeviceSeekPenaltyProperty
	// STORAGE_QUERY_TYPE
	storageQueryStandard = 0 // PropertyStandardQuery
)

// DISK_EXTENT
type diskExtent struct {
	DiskNumber     uint32
	_              uint32
	StartingOffset int64
	ExtentLength   int64
}

// VOLUME_DISK_EXTENTS
type volumeDiskExtents struct {
	NumberOfDiskExtents uint32
	_                   uint32
	Extents             [1]diskExtent
}

// STORAGE_PROPERTY_QUERY
type storagePropertyQuery struct {
	PropertyId           uint32
	QueryType            uint32
	AdditionalParameters [1]byte
}

// 对应 STORAGE_DEVICE_DESCRIPTOR（只用到 BusType）
type storageDeviceDescriptor struct {
	Version               uint32
	Size                  uint32
	DeviceType            byte
	DeviceTypeModifier    byte
	RemovableMedia        byte
	CommandQueueing       byte
	VendorIdOffset        uint32
	ProductIdOffset       uint32
	ProductRevisionOffset uint32
	SerialNumberOffset    uint32
	BusType               uint32
	RawPropertiesLength   uint32
	// RawDeviceProperties[1] 后面用大 buffer 覆盖
}

// 对应 STORAGE_DEVICE_SEEK_PENALTY_DESCRIPTOR
type storageDeviceSeekPenaltyDescriptor struct {
	Version           uint32
	Size              uint32
	IncursSeekPenalty byte
	Reserved          [3]byte // 对齐填充
}
type GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}
type getLengthInformation struct {
	Length int64
}
type PartitionInfo struct {
	DiskNumber     int
	OffsetBytes    uint64
	SizeBytes      uint64
	PartitionGuid  string
	Type           string
	HasVolume      bool
	VolumeGuidPath string
	DriveLetter    string
}
type driveLayoutInformationMbr struct {
	Signature uint32
	CheckSum  uint32
}
type driveLayoutInformationGpt struct {
	DiskId               GUID
	StartingUsableOffset int64
	UsableLength         int64
	MaxPartitionCount    uint32
	_                    uint32
}
type partitionInformationMbr struct {
	PartitionType       byte
	BootIndicator       byte
	RecognizedPartition byte
	_                   byte
	HiddenSectors       uint32
}

type partitionInformationGpt struct {
	PartitionType GUID
	PartitionId   GUID
	Attributes    uint64
	Name          [36]uint16
}
type partitionInformationEx struct {
	PartitionStyle     uint32
	StartingOffset     int64
	PartitionLength    int64
	PartitionNumber    uint32
	RewritePartition   byte
	IsServicePartition byte
	_                  [2]byte
}
type DiskInfo struct {
	DiskNumber     int
	SizeBytes      uint64
	PartitionStyle string
	UniqueId       string
	IsSystemDisk   bool
}
type VolumeInfo struct {
	DriveLetter    string
	RootPath       string
	VolumeGuidPath string
	FileSystem     string
	Label          string
	SizeBytes      uint64
	FreeBytes      uint64
	DiskNumber     int
	PartitionGuid  string
	OffsetBytes    uint64
}
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
type FreeExtent struct {
	DiskNumber  int
	OffsetBytes uint64
	SizeBytes   uint64
}
type ExtentPickPolicy struct {
	PreferNonSystemDisk    bool
	PreferLargestExtent    bool
	PreferSameDiskAsTarget bool
}

// parseFS 解析并校验文件系统类型，只允许 NTFS/FAT32（大小写不敏感）。
// 返回标准化后的文件系统名称；不支持则返回错误并记录日志。
func parseFS(fs string) (string, error) {
	fs = strings.TrimSpace(fs)
	if fs == "" {
		log.LogWrite(0, "[parseFS]parseFS 文件系统为空")
		return "", fmt.Errorf("fs 不能为空")
	}
	fs = strings.ToUpper(fs)
	switch fs {
	case "NTFS", "FAT32":
		return fs, nil
	default:
		log.LogWrite(0, "[parseFS]parseFS 不支持的文件系统: %s", fs)
		return "", fmt.Errorf("不支持的 fs：%q（仅支持 NTFS/FAT32）", fs)
	}
}

// collectDriveLetters 枚举当前系统已分配的盘符集合（A-Z），用于前后对比检测新盘符。
func collectDriveLetters() (map[string]struct{}, error) {
	drives, err := ListDrive()
	if err != nil {
		log.LogWrite(0, "[collectDriveLetters]collectDriveLetters ListDrive失败: %v", err)
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

// 判断盘符类型。
func GetDriveType(root string) uint32 {
	pRoot, err := syscall.UTF16PtrFromString(root)
	if err != nil {
		return driveUnknown
	}
	r, _, _ := procGetDriveTypeW.Call(uintptr(unsafe.Pointer(pRoot)))
	return uint32(r)
}

// 根据分区取第一个物理磁盘号
func GetDiskNum(vol string) (uint32, error) {
	root, _ := utils.NormalizeDrive(vol, 0)
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

// GetDiskKind 判断指定卷所在物理盘是 SSD / HDD / 移动设备 / 光驱。
// vol 可以是 "C" / "C:" / "C:\"。
// 返回值： "SSD" / "HDD" / "Removable" / "CDROM" / "Unknown"
func GetDiskKind(vol string) (string, error) {
	root, _ := utils.NormalizeDrive(vol, 0)
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

	normVol, _ := utils.NormalizeDrive(vol, 0)
	fmt.Printf("[GetDiskInfo] vol=%s disk=%d style=%s\n", normVol, diskNum, style)
	return style, diskNum, nil
}

// 根据物理磁盘号或盘符获取分区数量和盘符列表。
// diskID: 可传 "0"/"1" 或 "PhysicalDrive0"，也可传 "C"/"C:"/"C:\"。
// 返回：盘符数量、盘符数组
func GetDiskPartitions(diskID string) (int, []string, error) {
	diskID = strings.TrimSpace(diskID)
	if diskID == "" {
		log.LogWrite(0, "[GetDiskPartitions]GetDiskPartitions diskID为空")
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
			log.LogWrite(0, "[GetDiskPartitions]GetDiskPartitions GetDiskNum失败: root=%s err=%v", root, err)
			return 0, nil, err
		}
		diskNum = dn

	case len(diskID) == 1 &&
		((diskID[0] >= 'A' && diskID[0] <= 'Z') || (diskID[0] >= 'a' && diskID[0] <= 'z')):
		root := strings.ToUpper(diskID) + `:\`
		dn, err := GetDiskNum(root)
		if err != nil {
			log.LogWrite(0, "[GetDiskPartitions]GetDiskPartitions GetDiskNum失败: root=%s err=%v", root, err)
			return 0, nil, err
		}
		diskNum = dn

	default:
		re := regexp.MustCompile(`(?i)physicaldrive(\d+)`)
		if m := re.FindStringSubmatch(diskID); len(m) == 2 {
			n, err := strconv.ParseUint(m[1], 10, 32)
			if err != nil {
				log.LogWrite(0, "[GetDiskPartitions]GetDiskPartitions 解析磁盘号失败: %v", err)
				return 0, nil, fmt.Errorf("解析磁盘号失败: %w", err)
			}
			diskNum = uint32(n)
		} else {
			n, err := strconv.ParseUint(diskID, 10, 32)
			if err != nil {
				log.LogWrite(0, "[GetDiskPartitions]GetDiskPartitions 解析磁盘号失败: %v", err)
				return 0, nil, fmt.Errorf("解析磁盘号失败: %w", err)
			}
			diskNum = uint32(n)
		}
	}

	drives, err := ListDrive()
	if err != nil {
		log.LogWrite(0, "[GetDiskPartitions]GetDiskPartitions ListDrive失败: %v", err)
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
		log.LogWrite(0, fmt.Sprintf("[ListDrive] 枚举磁盘: %v\n", drives))
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

// formatGUID 将 GUID 结构格式化为标准字符串：xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx。
func formatGUID(g GUID) string {
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		g.Data1, g.Data2, g.Data3,
		g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
		g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7],
	)
}

// guidEqual 判断两个 GUID 是否完全相等
func guidEqual(a, b GUID) bool {
	return a.Data1 == b.Data1 &&
		a.Data2 == b.Data2 &&
		a.Data3 == b.Data3 &&
		a.Data4 == b.Data4
}

// partitionTypeFromGPT 根据 GPT 分区类型 GUID 映射为可读类型名。
// 未命中已知类型则返回空字符串。
func partitionTypeFromGPT(g GUID) string {
	switch {
	case guidEqual(g, GPTTypeEfiSystem):
		return "EFI"
	case guidEqual(g, GPTTypeMsr):
		return "MSR"
	case guidEqual(g, GPTTypeBasicData):
		return "Basic"
	case guidEqual(g, GPTTypeRecovery):
		return "Recovery"
	default:
		return ""
	}
}

// partitionTypeFromMBR 根据 MBR 分区类型字节值映射为可读类型名。
// 未命中已知类型则返回空字符串。
func partitionTypeFromMBR(partType byte) string {
	switch partType {
	case 0x07:
		return "Basic"
	case 0x0B, 0x0C:
		return "FAT32"
	case 0x27:
		return "Recovery"
	case 0xEF:
		return "EFI"
	default:
		return ""
	}
}

// openPhysicalDrive 以指定访问权限打开物理磁盘句柄（\\.\PhysicalDriveN）。
// 成功返回 Windows Handle；失败返回错误。
func openPhysicalDrive(diskNumber int, access uint32) (syscall.Handle, error) {
	diskPath := fmt.Sprintf(`\\.\PhysicalDrive%d`, diskNumber)
	pDisk, err := syscall.UTF16PtrFromString(diskPath)
	if err != nil {
		return 0, err
	}
	hDisk, err := syscall.CreateFile(
		pDisk,
		access,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		nil,
		syscall.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		return 0, err
	}
	return hDisk, nil
}

// getDiskSizeBytes 读取指定物理磁盘的总容量（字节）。
// 使用 IOCTL_DISK_GET_LENGTH_INFO 获取长度信息。
func getDiskSizeBytes(diskNumber int) (uint64, error) {
	hDisk, err := openPhysicalDrive(diskNumber, syscall.GENERIC_READ)
	if err != nil {
		return 0, err
	}
	defer syscall.CloseHandle(hDisk)

	var info getLengthInformation
	var bytesRet uint32
	err = syscall.DeviceIoControl(
		hDisk,
		ioctlDiskGetLengthInfo,
		nil,
		0,
		(*byte)(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
		&bytesRet,
		nil,
	)
	if err != nil {
		return 0, fmt.Errorf("DeviceIoControl IOCTL_DISK_GET_LENGTH_INFO failed: %w", err)
	}
	if bytesRet < uint32(unsafe.Sizeof(info)) {
		return 0, fmt.Errorf("unexpected DISK_GET_LENGTH_INFO size: %d", bytesRet)
	}
	if info.Length < 0 {
		return 0, fmt.Errorf("invalid disk length: %d", info.Length)
	}
	return uint64(info.Length), nil
}

// volumeHandlePath 将用户输入的卷标识规范化为可打开的卷设备路径。
// 支持 \\?\Volume{...} 与盘符路径；返回值形如 \\.\C: 或 \\?\Volume{...}（去掉末尾反斜杠）。
func volumeHandlePath(vol string) (string, error) {
	raw := strings.TrimSpace(vol)
	if raw == "" {
		return "", fmt.Errorf("invalid volume: %q", vol)
	}
	low := strings.ToLower(raw)
	if strings.HasPrefix(low, `\\?\volume{`) {
		return strings.TrimRight(raw, `\`), nil
	}
	root, _ := utils.NormalizeDrive(raw, 0)
	if root == "" {
		return "", fmt.Errorf("invalid volume: %q", vol)
	}
	return `\\.\` + strings.TrimRight(root, `\`), nil
}

// getVolumeInfoByPath 读取卷的文件系统信息与容量信息。
// 输入可为卷根路径或卷 GUID 路径；返回：文件系统类型、卷标、总字节数、可用字节数。
func getVolumeInfoByPath(root string) (fsType, label string, sizeBytes, freeBytes uint64, err error) {
	if root == "" {
		return "", "", 0, 0, fmt.Errorf("empty root")
	}
	pRoot, e := syscall.UTF16PtrFromString(root)
	if e != nil {
		return "", "", 0, 0, e
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
			return "", "", 0, 0, fmt.Errorf("GetVolumeInformationW: %w", e1)
		}
		return "", "", 0, 0, fmt.Errorf("GetVolumeInformationW failed")
	}
	fsType = strings.ToUpper(syscall.UTF16ToString(fsName))
	label = syscall.UTF16ToString(volName)

	var freeAvail, total, freeTotal uint64
	r2, _, e2 := procGetDiskFreeSpaceExW.Call(
		uintptr(unsafe.Pointer(pRoot)),
		uintptr(unsafe.Pointer(&freeAvail)),
		uintptr(unsafe.Pointer(&total)),
		uintptr(unsafe.Pointer(&freeTotal)),
	)
	if r2 == 0 {
		if e2 != nil && e2 != syscall.Errno(0) {
			return fsType, label, 0, 0, fmt.Errorf("GetDiskFreeSpaceExW: %w", e2)
		}
		return fsType, label, 0, 0, fmt.Errorf("GetDiskFreeSpaceExW failed")
	}
	return fsType, label, total, freeAvail, nil
}

// parseMultiSz 将 Windows 的 REG_MULTI_SZ（MULTI_SZ）UTF-16 缓冲区解析为 []string。
// 以 0 分隔字符串，以双 0 结尾。
func parseMultiSz(buf []uint16) []string {
	var out []string
	start := 0
	for i := 0; i < len(buf); i++ {
		if buf[i] == 0 {
			if i == start {
				break
			}
			out = append(out, syscall.UTF16ToString(buf[start:i]))
			start = i + 1
		}
	}
	return out
}

// getVolumePathNames 获取卷对应的挂载点列表（盘符/目录挂载路径）。
// 内部会按需扩容缓冲区并重试，最终返回解析后的 MULTI_SZ。
func getVolumePathNames(volumeName string) ([]string, error) {
	if volumeName == "" {
		return nil, fmt.Errorf("empty volume name")
	}
	pVol, err := syscall.UTF16PtrFromString(volumeName)
	if err != nil {
		return nil, err
	}
	size := uint32(256)
	for i := 0; i < 4; i++ {
		buf := make([]uint16, size)
		var retLen uint32
		r, _, e := procGetVolumePathNamesW.Call(
			uintptr(unsafe.Pointer(pVol)),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
			uintptr(unsafe.Pointer(&retLen)),
		)
		if r != 0 {
			return parseMultiSz(buf), nil
		}
		if e == syscall.ERROR_MORE_DATA && retLen > size {
			size = retLen
			continue
		}
		if e != nil && e != syscall.Errno(0) {
			return nil, fmt.Errorf("GetVolumePathNamesForVolumeNameW: %w", e)
		}
		return nil, fmt.Errorf("GetVolumePathNamesForVolumeNameW failed")
	}
	return nil, fmt.Errorf("GetVolumePathNamesForVolumeNameW failed after retries")
}

// readDriveLayout 读取物理磁盘的分区布局（GPT/MBR/RAW）、磁盘唯一标识，以及分区列表。
// GPT 返回磁盘 GUID；MBR 返回 Signature（十六进制字符串）；读取失败返回错误。
func readDriveLayout(diskNumber int) (string, string, []PartitionInfo, error) {
	hDisk, err := openPhysicalDrive(diskNumber, syscall.GENERIC_READ)
	if err != nil {
		return "", "", nil, err
	}
	defer syscall.CloseHandle(hDisk)

	out := make([]byte, 1024*128)
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
		return "", "", nil, fmt.Errorf("DeviceIoControl IOCTL_DISK_GET_DRIVE_LAYOUT_EX failed: %w", err)
	}
	if bytesRet < 8 {
		return "", "", nil, fmt.Errorf("unexpected DRIVE_LAYOUT_INFORMATION_EX size: %d", bytesRet)
	}

	styleVal := binary.LittleEndian.Uint32(out[0:4])
	count := binary.LittleEndian.Uint32(out[4:8])
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

	mbtSize := unsafe.Sizeof(driveLayoutInformationMbr{})
	gptSize := unsafe.Sizeof(driveLayoutInformationGpt{})
	unionSize := mbtSize
	if gptSize > unionSize {
		unionSize = gptSize
	}
	headerSize := 8 + unionSize
	if uint32(headerSize) > bytesRet {
		return style, "", nil, fmt.Errorf("unexpected DRIVE_LAYOUT_INFORMATION_EX header: %d", bytesRet)
	}

	var uniqueId string
	if styleVal == partitionStyleGPT {
		gpt := (*driveLayoutInformationGpt)(unsafe.Pointer(&out[8]))
		uniqueId = formatGUID(gpt.DiskId)
	} else if styleVal == partitionStyleMBR {
		mbr := (*driveLayoutInformationMbr)(unsafe.Pointer(&out[8]))
		if mbr.Signature != 0 {
			uniqueId = fmt.Sprintf("%08x", mbr.Signature)
		}
	}

	unionPartSize := unsafe.Sizeof(partitionInformationMbr{})
	if gptSize := unsafe.Sizeof(partitionInformationGpt{}); gptSize > unionPartSize {
		unionPartSize = gptSize
	}
	entrySize := unsafe.Sizeof(partitionInformationEx{}) + unionPartSize
	partitions := make([]PartitionInfo, 0, count)
	for i := uint32(0); i < count; i++ {
		baseOffset := uintptr(headerSize) + uintptr(i)*entrySize
		if baseOffset+entrySize > uintptr(bytesRet) {
			break
		}
		base := (*partitionInformationEx)(unsafe.Pointer(&out[baseOffset]))
		if base.PartitionLength <= 0 {
			continue
		}

		part := PartitionInfo{
			DiskNumber:  diskNumber,
			OffsetBytes: uint64(base.StartingOffset),
			SizeBytes:   uint64(base.PartitionLength),
		}
		unionOffset := baseOffset + unsafe.Sizeof(partitionInformationEx{})
		if base.PartitionStyle == partitionStyleGPT {
			gpt := (*partitionInformationGpt)(unsafe.Pointer(&out[unionOffset]))
			part.PartitionGuid = formatGUID(gpt.PartitionId)
			part.Type = partitionTypeFromGPT(gpt.PartitionType)
		} else if base.PartitionStyle == partitionStyleMBR {
			mbr := (*partitionInformationMbr)(unsafe.Pointer(&out[unionOffset]))
			part.Type = partitionTypeFromMBR(mbr.PartitionType)
		}
		partitions = append(partitions, part)
	}

	return style, uniqueId, partitions, nil
}

// ListPhysicalDisks 枚举系统内可访问的物理磁盘，返回磁盘容量、分区样式与唯一标识等信息。
// 会尽力识别系统盘（优先 SystemDrive，其次通过 C: 所在磁盘推断）。
func ListPhysicalDisks() ([]DiskInfo, error) {
	volumes, _ := ListVolumes()
	systemDisk := -1
	if sys := os.Getenv("SystemDrive"); sys != "" {
		if dn, err := GetDiskNum(sys); err == nil {
			systemDisk = int(dn)
		}
	}

	const maxDisks = 128
	disks := make([]DiskInfo, 0, 8)
	for i := 0; i < maxDisks; i++ {
		hDisk, err := openPhysicalDrive(i, syscall.GENERIC_READ)
		if err != nil {
			if errno, ok := err.(syscall.Errno); ok {
				if errno == syscall.ERROR_FILE_NOT_FOUND || errno == syscall.ERROR_PATH_NOT_FOUND {
					continue
				}
			}
			continue
		}
		syscall.CloseHandle(hDisk)

		style, uniqueId, _, err := readDriveLayout(i)
		if err != nil {
			continue
		}
		sizeBytes, err := getDiskSizeBytes(i)
		if err != nil {
			continue
		}

		isSystem := i == systemDisk
		if !isSystem && systemDisk == -1 {
			for _, vol := range volumes {
				if strings.EqualFold(vol.DriveLetter, "C") && vol.DiskNumber == i {
					isSystem = true
					break
				}
			}
		}

		disks = append(disks, DiskInfo{
			DiskNumber:     i,
			SizeBytes:      sizeBytes,
			PartitionStyle: style,
			UniqueId:       uniqueId,
			IsSystemDisk:   isSystem,
		})
	}
	return disks, nil
}

// ListDiskPartitions 列出指定磁盘的分区信息，并尝试关联到卷信息（盘符/卷 GUID 等）。
// 若分区 GUID 缺失，会用卷侧推断补全。
func ListDiskPartitions(diskNumber int) ([]PartitionInfo, error) {
	_, _, parts, err := readDriveLayout(diskNumber)
	if err != nil {
		return nil, err
	}

	volumes, _ := ListVolumes()
	for i := range parts {
		for _, vol := range volumes {
			if vol.DiskNumber != diskNumber {
				continue
			}
			if vol.OffsetBytes >= parts[i].OffsetBytes &&
				vol.OffsetBytes < parts[i].OffsetBytes+parts[i].SizeBytes {
				parts[i].HasVolume = true
				parts[i].VolumeGuidPath = vol.VolumeGuidPath
				parts[i].DriveLetter = vol.DriveLetter
				if parts[i].PartitionGuid == "" {
					parts[i].PartitionGuid = vol.PartitionGuid
				}
				break
			}
		}
	}
	return parts, nil
}

// 获取卷所在磁盘号 + 卷的起始偏移/长度（用于计算 /offset）。
// 只取第一个 extent（常见卷场景足够用；动态卷/多 extent 需要更复杂处理）
func getVolumeExtentBytes(vol string) (diskNum uint32, startBytes int64, lengthBytes int64, err error) {
	volPath, err := volumeHandlePath(vol)
	if err != nil {
		return 0, 0, 0, err
	}
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

// ListVolumes 枚举系统所有卷（Volume{...}），并补充挂载点、文件系统与容量信息。
// 同时尝试将卷映射回所属磁盘与分区 GUID。
func ListVolumes() ([]VolumeInfo, error) {
	buf := make([]uint16, 1024)
	r, _, err := procFindFirstVolumeW.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	handle := syscall.Handle(r)
	if r == 0 || handle == syscall.InvalidHandle {
		if err != nil && err != syscall.Errno(0) {
			return nil, fmt.Errorf("FindFirstVolumeW: %w", err)
		}
		return nil, fmt.Errorf("FindFirstVolumeW failed")
	}
	defer procFindVolumeClose.Call(uintptr(handle))

	var volumes []VolumeInfo
	for {
		volName := syscall.UTF16ToString(buf)
		volInfo := VolumeInfo{
			VolumeGuidPath: volName,
		}

		paths, _ := getVolumePathNames(volName)
		if len(paths) > 0 {
			volInfo.RootPath = paths[0]
			for _, p := range paths {
				if len(p) >= 2 && p[1] == ':' {
					volInfo.DriveLetter = strings.ToUpper(p[:1])
					volInfo.RootPath = p
					break
				}
			}
		}

		rootForInfo := volName
		if volInfo.RootPath != "" {
			rootForInfo = volInfo.RootPath
		}
		fs, label, sizeBytes, freeBytes, err := getVolumeInfoByPath(rootForInfo)
		if err == nil {
			volInfo.FileSystem = fs
			volInfo.Label = label
			volInfo.SizeBytes = sizeBytes
			volInfo.FreeBytes = freeBytes
		}

		if diskNum, offset, _, err := getVolumeExtentBytes(volName); err == nil {
			volInfo.DiskNumber = int(diskNum)
			volInfo.OffsetBytes = uint64(offset)
		}

		volumes = append(volumes, volInfo)

		r, _, e2 := procFindNextVolumeW.Call(
			uintptr(handle),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
		)
		if r == 0 {
			if e2 == syscall.ERROR_NO_MORE_FILES {
				break
			}
			if e2 != nil && e2 != syscall.Errno(0) {
				return volumes, fmt.Errorf("FindNextVolumeW: %w", e2)
			}
			break
		}
	}

	partitions := make(map[int][]PartitionInfo)
	for _, vol := range volumes {
		if _, ok := partitions[vol.DiskNumber]; ok {
			continue
		}
		if _, _, parts, err := readDriveLayout(vol.DiskNumber); err == nil {
			partitions[vol.DiskNumber] = parts
		}
	}
	for i := range volumes {
		vol := &volumes[i]
		if parts, ok := partitions[vol.DiskNumber]; ok {
			for _, part := range parts {
				if vol.OffsetBytes >= part.OffsetBytes &&
					vol.OffsetBytes < part.OffsetBytes+part.SizeBytes {
					vol.PartitionGuid = part.PartitionGuid
					break
				}
			}
		}
	}

	return volumes, nil
}

// GetDiskFreeExtents 计算指定磁盘未被分区占用的“空闲区间”列表。
// 返回结果按偏移从小到大；若无分区，则整盘视为一个空闲区间。
func GetDiskFreeExtents(diskNumber int) ([]FreeExtent, error) {
	sizeBytes, err := getDiskSizeBytes(diskNumber)
	if err != nil {
		return nil, err
	}
	parts, err := ListDiskPartitions(diskNumber)
	if err != nil {
		return nil, err
	}
	if len(parts) == 0 {
		return []FreeExtent{{DiskNumber: diskNumber, OffsetBytes: 0, SizeBytes: sizeBytes}}, nil
	}

	sort.Slice(parts, func(i, j int) bool {
		return parts[i].OffsetBytes < parts[j].OffsetBytes
	})

	var free []FreeExtent
	var cursor uint64
	for _, p := range parts {
		if p.OffsetBytes > cursor {
			free = append(free, FreeExtent{
				DiskNumber:  diskNumber,
				OffsetBytes: cursor,
				SizeBytes:   p.OffsetBytes - cursor,
			})
		}
		end := p.OffsetBytes + p.SizeBytes
		if end > cursor {
			cursor = end
		}
	}
	if cursor < sizeBytes {
		free = append(free, FreeExtent{
			DiskNumber:  diskNumber,
			OffsetBytes: cursor,
			SizeBytes:   sizeBytes - cursor,
		})
	}
	return free, nil
}

// PickFreeExtent 在所有磁盘的空闲区间中挑选一个满足容量需求的候选区间。
// policy 可控制偏好（优先最大/优先非系统盘等）；若无满足条件的区间返回错误。
func PickFreeExtent(needBytes uint64, policy ExtentPickPolicy) (FreeExtent, error) {
	disks, err := ListPhysicalDisks()
	if err != nil {
		return FreeExtent{}, err
	}
	var candidates []FreeExtent
	for _, d := range disks {
		exts, err := GetDiskFreeExtents(d.DiskNumber)
		if err != nil {
			continue
		}
		for _, e := range exts {
			if e.SizeBytes >= needBytes {
				candidates = append(candidates, e)
			}
		}
	}
	if len(candidates) == 0 {
		return FreeExtent{}, fmt.Errorf("no free extent large enough")
	}

	sort.Slice(candidates, func(i, j int) bool {
		if policy.PreferLargestExtent && candidates[i].SizeBytes != candidates[j].SizeBytes {
			return candidates[i].SizeBytes > candidates[j].SizeBytes
		}
		if policy.PreferNonSystemDisk {
			isSysI := false
			isSysJ := false
			for _, d := range disks {
				if d.DiskNumber == candidates[i].DiskNumber {
					isSysI = d.IsSystemDisk
				}
				if d.DiskNumber == candidates[j].DiskNumber {
					isSysJ = d.IsSystemDisk
				}
			}
			if isSysI != isSysJ {
				return !isSysI
			}
		}
		return candidates[i].OffsetBytes < candidates[j].OffsetBytes
	})

	return candidates[0], nil
}

// 调用 Windows API FormatEx 格式化卷。
func FormatEX(letter, fs, label string, quick bool) error {
	root, _ := utils.NormalizeDrive(letter, 0)
	if root == "" {
		return fmt.Errorf("invalid volume: %q", letter)
	}
	pRoot, err := syscall.UTF16PtrFromString(root)
	if err != nil {
		return err
	}
	pFS, err := syscall.UTF16PtrFromString(fs)
	if err != nil {
		return err
	}
	label = cleanLabel(label)
	pLabel, err := syscall.UTF16PtrFromString(label)
	if err != nil {
		return err
	}

	cb := syscall.NewCallback(func(command uint32, modifier uint32, data uintptr) uintptr {
		return 1
	})

	const mediaHardDisk = 0x00000000
	r, _, e := procFormatEx.Call(
		uintptr(unsafe.Pointer(pRoot)),
		uintptr(mediaHardDisk),
		uintptr(unsafe.Pointer(pFS)),
		uintptr(unsafe.Pointer(pLabel)),
		uintptr(boolToUintptr(quick)),
		uintptr(0),
		cb,
	)
	_ = r
	if e != nil && e != syscall.Errno(0) {
		return fmt.Errorf("FormatEx failed: %w", e)
	}
	return nil
}

func boolToUintptr(v bool) uintptr {
	if v {
		return 1
	}
	return 0
}

// 读取指定卷的剩余空间
func GetFreeSize(vol string) (freeBytes uint64, err error) {
	root, _ := utils.NormalizeDrive(vol, 0)
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

// 获取卷的文件系统类型和总大小（字节）
func GetVolumeInfo(root string) (fsType string, totalBytes uint64, err error) {
	if nr, err := utils.NormalizeDrive(root, 0); err == nil {
		root = nr
	}
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
