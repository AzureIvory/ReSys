package mslnk

import (
	"bytes"
	"encoding/binary"
	"strings"
)

// LinkInfo 只实现离线生成本地绝对路径快捷方式所需的最小子集：
// VolumeIDAndLocalBasePath + Unicode LocalBasePath/CommonPathSuffix。
// LocalBasePath 与 CommonPathSuffix 是拼接关系，例如：C:\ + drive.exe。
type LinkInfo struct {
	LinkInfoSize                    [4]byte // size in bytes of this whole struct
	LinkInfoHeaderSize              [4]byte
	LinkInfoFlags                   [4]byte
	VolumeIDOffset                  [4]byte
	LocalBasePathOffset             [4]byte
	CommonNetworkRelativeLinkOffset [4]byte
	CommonPathSuffixOffset          [4]byte

	// optional
	LocalBasePathOffsetUnicode    []byte // 4
	CommonPathSuffixOffsetUnicode []byte // 4

	// variable (and optional)
	VolumeID                  []byte // VolumeID
	LocalBasePath             []byte
	CommonNetworkRelativeLink []byte // unimplemented
	CommonPathSuffix          []byte
	LocalBasePathUnicode      []byte
	CommonPathSuffixUnicode   []byte
}

func (x *LinkInfo) Bytes() []byte {
	if x == nil || x.empty() {
		return nil
	}

	var buffer bytes.Buffer
	buffer.Write(x.LinkInfoSize[:])
	buffer.Write(x.LinkInfoHeaderSize[:])
	buffer.Write(x.LinkInfoFlags[:])
	buffer.Write(x.VolumeIDOffset[:])
	buffer.Write(x.LocalBasePathOffset[:])
	buffer.Write(x.CommonNetworkRelativeLinkOffset[:])
	buffer.Write(x.CommonPathSuffixOffset[:])

	if le32(x.LinkInfoHeaderSize[:]) >= 0x24 {
		buffer.Write(x.LocalBasePathOffsetUnicode)
		buffer.Write(x.CommonPathSuffixOffsetUnicode)
	}

	buffer.Write(x.VolumeID)
	buffer.Write(x.LocalBasePath)
	buffer.Write(x.CommonNetworkRelativeLink)
	buffer.Write(x.CommonPathSuffix)
	buffer.Write(x.LocalBasePathUnicode)
	buffer.Write(x.CommonPathSuffixUnicode)
	return buffer.Bytes()
}

func (x *LinkInfo) empty() bool {
	return x.LinkInfoSize == [4]byte{} &&
		x.LinkInfoHeaderSize == [4]byte{} &&
		x.LinkInfoFlags == [4]byte{} &&
		len(x.VolumeID) == 0 &&
		len(x.LocalBasePath) == 0 &&
		len(x.CommonPathSuffix) == 0 &&
		len(x.LocalBasePathUnicode) == 0 &&
		len(x.CommonPathSuffixUnicode) == 0
}

func newLocalLinkInfo(targetPath string) LinkInfo {
	targetPath = strings.ReplaceAll(strings.TrimSpace(targetPath), "/", "\\")
	basePath, suffix := splitLocalTargetPath(targetPath)
	volume := newVolumeID().Bytes()
	localBasePath := ansiCStringFallback(basePath)
	commonSuffix := ansiCStringFallback(suffix)
	localBasePathUnicode := utf16leNullTerminated(basePath)
	commonSuffixUnicode := utf16leNullTerminated(suffix)

	const headerSize = uint32(0x24)
	volumeOffset := headerSize
	localBasePathOffset := volumeOffset + uint32(len(volume))
	commonSuffixOffset := localBasePathOffset + uint32(len(localBasePath))
	localBasePathUnicodeOffset := commonSuffixOffset + uint32(len(commonSuffix))
	commonSuffixUnicodeOffset := localBasePathUnicodeOffset + uint32(len(localBasePathUnicode))
	infoSize := commonSuffixUnicodeOffset + uint32(len(commonSuffixUnicode))
	localBasePathUnicodeOffsetBytes := u32(localBasePathUnicodeOffset)
	commonSuffixUnicodeOffsetBytes := u32(commonSuffixUnicodeOffset)

	li := LinkInfo{
		LinkInfoSize:                    u32(infoSize),
		LinkInfoHeaderSize:              LinkInfoHeaderSize[1],
		VolumeIDOffset:                  u32(volumeOffset),
		LocalBasePathOffset:             u32(localBasePathOffset),
		CommonPathSuffixOffset:          u32(commonSuffixOffset),
		LocalBasePathOffsetUnicode:      localBasePathUnicodeOffsetBytes[:],
		CommonPathSuffixOffsetUnicode:   commonSuffixUnicodeOffsetBytes[:],
		VolumeID:                        volume,
		LocalBasePath:                   localBasePath,
		CommonPathSuffix:                commonSuffix,
		LocalBasePathUnicode:            localBasePathUnicode,
		CommonPathSuffixUnicode:         commonSuffixUnicode,
		CommonNetworkRelativeLinkOffset: [4]byte{},
	}
	li.SetLinkInfoFlag(0, true) // VolumeIDAndLocalBasePath
	return li
}

func splitLocalTargetPath(path string) (basePath string, suffix string) {
	path = strings.ReplaceAll(strings.TrimSpace(path), "/", "\\")
	idx := strings.LastIndex(path, "\\")
	if idx < 0 {
		return "", path
	}
	return path[:idx+1], path[idx+1:]
}

func (x *LinkInfo) SetLinkInfoFlag(flag byte, value bool) {
	// if the bit at index 'flag' is different than 'value'
	if ((x.LinkInfoFlags[0]>>flag)%2 == 1) != value {
		if value { // and value was true
			// we add that bit
			x.LinkInfoFlags[0] += 1 << flag
		} else {
			// otherwise we subtract it
			x.LinkInfoFlags[0] -= 1 << flag
		}
	}
}

type VolumeID struct {
	VolumeIDSize      [4]byte
	DriveType         [4]byte
	DriveSerialNumber [4]byte
	VolumeLabelOffset [4]byte

	// optional
	VolumeLabelOffsetUnicode []byte // 4

	// variable
	Data []byte
}

func newVolumeID() VolumeID {
	return VolumeID{
		VolumeIDSize:      u32(17),
		DriveType:         DriveType["DRIVE_FIXED"],
		DriveSerialNumber: [4]byte{},
		VolumeLabelOffset: u32(16),
		Data:              []byte{0},
	}
}

func (v VolumeID) Bytes() []byte {
	var buffer bytes.Buffer
	buffer.Write(v.VolumeIDSize[:])
	buffer.Write(v.DriveType[:])
	buffer.Write(v.DriveSerialNumber[:])
	buffer.Write(v.VolumeLabelOffset[:])
	buffer.Write(v.VolumeLabelOffsetUnicode)
	buffer.Write(v.Data)
	return buffer.Bytes()
}

func u32(v uint32) [4]byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return b
}

func le32(b []byte) uint32 {
	if len(b) < 4 {
		return 0
	}
	return binary.LittleEndian.Uint32(b[:4])
}

var (
	LinkInfoHeaderSize = [2][4]byte{
		{0x1C, 0x00, 0x00, 0x00},
		{0x24, 0x00, 0x00, 0x00},
	}

	LinkInfoFlags = []string{
		"VolumeIDAndLocalBasePath",
		"CommonNetworkRelativeLinkAndPathSuffix",
	}

	DriveType = map[string][4]byte{
		"DRIVE_UNKNOWN":     {0x00: 0x00, 0x00, 0x00},
		"DRIVE_NO_ROOT_DIR": {0x01, 0x00, 0x00, 0x00},
		"DRIVE_REMOVABLE":   {0x02, 0x00, 0x00, 0x00},
		"DRIVE_FIXED":       {0x03, 0x00, 0x00, 0x00},
		"DRIVE_REMOTE":      {0x04, 0x00, 0x00, 0x00},
		"DRIVE_CDROM":       {0x05, 0x00, 0x00, 0x00},
		"DRIVE_RAMDISK":     {0x06, 0x00, 0x00, 0x00},
	}
)
