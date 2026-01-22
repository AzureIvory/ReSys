package main

import "syscall"

const (
	driveUnknown = 0
	driveNoRoot  = 1
	driveRemov   = 2
	driveFixed   = 3
	driveRemote  = 4
	driveCdrom   = 5
	driveRamdisk = 6
	//磁盘相关
	ioctlVolumeGetVolumeDiskExtents = 0x00560000 // IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS
	ioctlDiskGetDriveLayoutEx       = 0x00070050 // IOCTL_DISK_GET_DRIVE_LAYOUT_EX
	ioctlDiskGetLengthInfo          = 0x0007405C // IOCTL_DISK_GET_LENGTH_INFO
	partitionStyleMBR               = 0          // PARTITION_STYLE_MBR
	partitionStyleGPT               = 1          // PARTITION_STYLE_GPT
	partitionStyleRAW               = 2          // PARTITION_STYLE_RAW
	ioctlStorageQueryProperty       = 0x002D1400 // IOCTL_STORAGE_QUERY_PROPERTY
	// STORAGE_PROPERTY_ID
	storagePropertyDevice      = 0 // StorageDeviceProperty
	storagePropertySeekPenalty = 7 // StorageDeviceSeekPenaltyProperty
	// STORAGE_QUERY_TYPE
	storageQueryStandard = 0 // PropertyStandardQuery
	// STORAGE_BUS_TYPE
	busTypeUnknown = 0
	busTypeScsi    = 1
	busTypeAtapi   = 2
	busTypeAta     = 3
	busTypeUsb     = 7
	busTypeSata    = 8
	busTypeSas     = 9
	// COM constants(创建快捷方式)
	COINIT_APARTMENTTHREADED = 0x2
	CLSCTX_INPROC_SERVER     = 0x1
	// ExitWindowsEx flags
	EWX_LOGOFF       = 0x00000000 //注销
	EWX_SHUTDOWN     = 0x00000008 //关机
	EWX_REBOOT       = 0x00000002 //重启
	EWX_FORCE        = 0x00000004 //强制关闭应用
	EWX_FORCEIFHUNG  = 0x00000010 //程序无响应，强制关闭
	ShutdownNoReboot = 0          // 只是退出系统，不重启
	ShutdownReboot   = 1          // 重启
	ShutdownPowerOff = 2          // 关机断电
	// token 权限相关
	SE_PRIVILEGE_ENABLED    = 0x00000002
	TOKEN_ADJUST_PRIVILEGES = 0x0020
	TOKEN_QUERY             = 0x0008
	// 固件类型
	fwTypeUnknown = 0
	fwTypeBios    = 1
	fwTypeUefi    = 2
	fwTypeMax     = 3
	// 注册表相关
	HKEY_LOCAL_MACHINE = syscall.Handle(0x80000002)
	KEY_READ           = 0x20019 // 标准 KEY_READ
	// ShellExecuteW相关
	swHide = 0 //挂载
	// 文件属性相关
	FILE_ATTRIBUTE_NORMAL = 0x00000080
	FO_DELETE             = 0x0003
	FOF_SILENT            = 0x0004
	FOF_NOCONFIRMATION    = 0x0010
	FOF_NOERRORUI         = 0x0400
	FOF_NOCONFIRMMKDIR    = 0x0200
	//隐藏cmd窗口
	CREATE_NO_WINDOW = 0x08000000
)
