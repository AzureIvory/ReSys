package main

// STORAGE_PROPERTY_QUERY
type storagePropertyQuery struct {
	PropertyId           uint32
	QueryType            uint32
	AdditionalParameters [1]byte
}

// 对应 STORAGE_DEVICE_SEEK_PENALTY_DESCRIPTOR
type storageDeviceSeekPenaltyDescriptor struct {
	Version           uint32
	Size              uint32
	IncursSeekPenalty byte
	Reserved          [3]byte // 对齐填充
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

type GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
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

type partitionInformationEx struct {
	PartitionStyle     uint32
	StartingOffset     int64
	PartitionLength    int64
	PartitionNumber    uint32
	RewritePartition   byte
	IsServicePartition byte
	_                  [2]byte
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

type getLengthInformation struct {
	Length int64
}

type DiskInfo struct {
	DiskNumber     int
	SizeBytes      uint64
	PartitionStyle string
	UniqueId       string
	IsSystemDisk   bool
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

// IShellLinkW vtable
type iShellLinkWVtbl struct {
	QueryInterface      uintptr
	AddRef              uintptr
	Release             uintptr
	GetArguments        uintptr
	GetDescription      uintptr
	GetHotkey           uintptr
	GetIconLocation     uintptr
	GetIDList           uintptr
	GetPath             uintptr
	GetShowCmd          uintptr
	GetWorkingDirectory uintptr
	Resolve             uintptr
	SetArguments        uintptr
	SetDescription      uintptr
	SetHotkey           uintptr
	SetIconLocation     uintptr
	SetIDList           uintptr
	SetPath             uintptr
	SetRelativePath     uintptr
	SetShowCmd          uintptr
	SetWorkingDirectory uintptr
}

type IShellLinkW struct {
	lpVtbl *iShellLinkWVtbl
}

// IPersistFile vtable（IUnknown + IPersist + IPersistFile）
type iPersistFileVtbl struct {
	QueryInterface uintptr
	AddRef         uintptr
	Release        uintptr
	GetClassID     uintptr
	IsDirty        uintptr
	Load           uintptr
	Save           uintptr
	SaveCompleted  uintptr
	GetCurFile     uintptr
}

type IPersistFile struct {
	lpVtbl *iPersistFileVtbl
}

// LUID / TOKEN_PRIVILEGES 结构体
type luid struct {
	LowPart  uint32
	HighPart int32
}

type luidAndAttributes struct {
	Luid       luid
	Attributes uint32
}

type tokenPrivileges struct {
	PrivilegeCount uint32
	Privileges     [1]luidAndAttributes
}

// MEMORYSTATUSEX 结构体（内存）
type memoryStatusEx struct {
	dwLength                uint32
	dwMemoryLoad            uint32
	ullTotalPhys            uint64
	ullAvailPhys            uint64
	ullTotalPageFile        uint64
	ullAvailPageFile        uint64
	ullTotalVirtual         uint64
	ullAvailVirtual         uint64
	ullAvailExtendedVirtual uint64
}

// 镜像信息
type ImageMeta struct {
	Index       int
	Name        string
	Description string
	Flags       string

	SizeBytes uint64 // 原始字节数
	Size      string // 转换为MB/GB格式

	Edition      string // Professional/WindowsPE/...
	Installation string // Client/Server/WindowsPE/...
	SystemRoot   string // WINDOWS/...
	Arch         string // x86 / x64 / arm64 ...

	IsOS bool // 是否认为是系统
}

// SHFILEOPSTRUCTW 结构体（文件操作）
type shFileOpStructW struct {
	hwnd                  uintptr
	wFunc                 uint32
	pFrom                 *uint16
	pTo                   *uint16
	fFlags                uint16
	fAnyOperationsAborted int32
	hNameMappings         uintptr
	lpszProgressTitle     *uint16
}

// Windows 版本信息结构体
type VS_FIXEDFILEINFO struct {
	DwSignature        uint32
	DwStrucVersion     uint32
	DwFileVersionMS    uint32 // 高16位是Major，低16位是Minor
	DwFileVersionLS    uint32 // 高16位是Build，低16位是Revision
	DwProductVersionMS uint32
	DwProductVersionLS uint32
	DwFileFlagsMask    uint32
	DwFileFlags        uint32
	DwFileOS           uint32
	DwFileType         uint32
	DwFileSubtype      uint32
	DwFileDateMS       uint32
	DwFileDateLS       uint32
}
