package main

import "syscall"

var (
	//nt内核
	modNtdll             = syscall.NewLazyDLL("ntdll.dll")
	procNtShutdownSystem = modNtdll.NewProc("NtShutdownSystem")
	//文件操作相关
	modKernel32           = syscall.NewLazyDLL("kernel32.dll")
	modShell32            = syscall.NewLazyDLL("shell32.dll")
	procShellExecuteW     = modShell32.NewProc("ShellExecuteW")
	procCopyFileW         = modKernel32.NewProc("CopyFileW")
	procDeleteFileW       = modKernel32.NewProc("DeleteFileW")
	procRemoveDirectoryW  = modKernel32.NewProc("RemoveDirectoryW")
	procSetFileAttributes = modKernel32.NewProc("SetFileAttributesW")
	procFindFirstFileW    = modKernel32.NewProc("FindFirstFileW")
	procFindNextFileW     = modKernel32.NewProc("FindNextFileW")
	procFindClose         = modKernel32.NewProc("FindClose")
	procSetFileAttrsW     = modKernel32.NewProc("SetFileAttributesW")
	procSHFileOperationW  = modShell32.NewProc("SHFileOperationW")
	//退出系统相关
	modUser32              = syscall.NewLazyDLL("user32.dll")
	modAdvapi32            = syscall.NewLazyDLL("advapi32.dll")
	procExitWindowsEx      = modUser32.NewProc("ExitWindowsEx")
	procOpenProcessToken   = modAdvapi32.NewProc("OpenProcessToken")
	procLookupPrivilegeVal = modAdvapi32.NewProc("LookupPrivilegeValueW")
	procAdjustTokenPriv    = modAdvapi32.NewProc("AdjustTokenPrivileges")
	//获取物理内存总量
	procGlobalMemoryStatus = modKernel32.NewProc("GlobalMemoryStatusEx")
	//注册表相关
	advapi32             = syscall.NewLazyDLL("advapi32.dll")
	procRegLoadKeyW      = advapi32.NewProc("RegLoadKeyW")
	procRegUnLoadKeyW    = advapi32.NewProc("RegUnLoadKeyW")
	procRegOpenKeyExW    = advapi32.NewProc("RegOpenKeyExW")
	procRegCloseKey      = advapi32.NewProc("RegCloseKey")
	procRegQueryValueExW = advapi32.NewProc("RegQueryValueExW")
	//创建快捷方式相关
	ole32                = syscall.NewLazyDLL("ole32.dll")
	procCoInitializeEx   = ole32.NewProc("CoInitializeEx")
	procCoUninitialize   = ole32.NewProc("CoUninitialize")
	procCoCreateInstance = ole32.NewProc("CoCreateInstance")
	//磁盘相关
	procGetVolumeInformationW   = modKernel32.NewProc("GetVolumeInformationW")
	procGetDiskFreeSpaceExW     = modKernel32.NewProc("GetDiskFreeSpaceExW")
	procGetLogicalDriveStringsW = modKernel32.NewProc("GetLogicalDriveStringsW")
	procGetDriveTypeW           = modKernel32.NewProc("GetDriveTypeW")
	//固件类型检测BIOS/UEFI
	procGetFirmwareType = modKernel32.NewProc("GetFirmwareType")
)

// CLSID / IID
var (
	CLSID_ShellLink  = GUID{0x00021401, 0x0000, 0x0000, [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}
	IID_IShellLinkW  = GUID{0x000214F9, 0x0000, 0x0000, [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}
	IID_IPersistFile = GUID{0x0000010b, 0x0000, 0x0000, [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}
)

// disk.dll
var (
	modDisk     = syscall.NewLazyDLL("disk.dll")
	procFormatW = modDisk.NewProc("FormatW")
	procDeleteW = modDisk.NewProc("DeleteVolumeW")
	procMergeW  = modDisk.NewProc("MergeVolumeW")
	procSplitW  = modDisk.NewProc("SplitVolumeW")
)
