//go:build windows

package disk

import (
	"ReSys/src/utils"
	"fmt"
	"strconv"
	"strings"
)

// PartitionRef 表示统一分区引用解析后的结构化结果。
//
// GPT 分区会同时携带磁盘唯一标识和分区 GUID；
// MBR 分区则携带磁盘签名与分区号。
type PartitionRef struct {
	Style           string
	DiskID          string
	PartitionGUID   string
	PartitionNumber int
}

// FormatPartitionRef 将磁盘分区身份编码为统一字符串。
//
// 设计目标是让分区引用在重启到 PE、盘符变化甚至磁盘枚举顺序变化后仍可重建：
// 1. GPT 磁盘使用 `gpt:<DiskUniqueID>:<PartitionGuid>`；
// 2. MBR 磁盘使用 `mbr:<磁盘签名>:<分区号>`。
//
// 这里会在编码前做基础校验，避免把不完整或格式错误的标识写入计划文件。
func FormatPartitionRef(style, diskID, partitionGUID string, partitionNumber int) (string, error) {
	style = strings.ToUpper(strings.TrimSpace(style))
	diskID = strings.ToLower(strings.TrimSpace(diskID))
	partitionGUID = strings.ToLower(strings.TrimSpace(partitionGUID))

	switch style {
	case "GPT":
		if !isGUIDRef(diskID) {
			return "", fmt.Errorf("invalid GPT disk unique id: %s", diskID)
		}
		if !isGUIDRef(partitionGUID) {
			return "", fmt.Errorf("invalid GPT partition guid: %s", partitionGUID)
		}
		return fmt.Sprintf("gpt:%s:%s", diskID, partitionGUID), nil
	case "MBR":
		if !isHexSignature(diskID) {
			return "", fmt.Errorf("invalid MBR disk signature: %s", diskID)
		}
		if partitionNumber <= 0 {
			return "", fmt.Errorf("invalid MBR partition number: %d", partitionNumber)
		}
		return fmt.Sprintf("mbr:%s:%d", diskID, partitionNumber), nil
	default:
		return "", fmt.Errorf("unsupported partition style: %s", style)
	}
}

// BuildPartitionRef 根据已枚举到的磁盘信息和分区信息构造统一分区引用。
//
// 该函数是上层安装流程的主要入口：当 UI 选中某个目标分区或引导分区后，
// 直接把当前枚举结果转换为稳定引用写入 `restall_win.dat`。
func BuildPartitionRef(diskInfo DiskInfo, part PartitionInfo) (string, error) {
	return FormatPartitionRef(
		diskInfo.PartitionStyle,
		diskInfo.UniqueId,
		part.PartitionGuid,
		part.PartitionNumber,
	)
}

// ParsePartitionRef 解析统一分区引用，恢复出分区样式和匹配所需的关键字段。
//
// 解析结果不会直接访问磁盘，只负责做语法和字段合法性校验。
// 真正的磁盘枚举与分区定位由 FindPartitionByRef 完成。
func ParsePartitionRef(ref string) (PartitionRef, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return PartitionRef{}, fmt.Errorf("empty partition ref")
	}

	parts := strings.Split(ref, ":")
	if len(parts) != 3 {
		return PartitionRef{}, fmt.Errorf("invalid partition ref format: %s", ref)
	}

	kind := strings.ToLower(strings.TrimSpace(parts[0]))
	diskID := strings.ToLower(strings.TrimSpace(parts[1]))
	third := strings.TrimSpace(parts[2])

	switch kind {
	case "gpt":
		if !isGUIDRef(diskID) {
			return PartitionRef{}, fmt.Errorf("invalid GPT disk unique id: %s", diskID)
		}
		partitionGUID := strings.ToLower(third)
		if !isGUIDRef(partitionGUID) {
			return PartitionRef{}, fmt.Errorf("invalid GPT partition guid: %s", partitionGUID)
		}
		return PartitionRef{
			Style:         "GPT",
			DiskID:        diskID,
			PartitionGUID: partitionGUID,
		}, nil
	case "mbr":
		if !isHexSignature(diskID) {
			return PartitionRef{}, fmt.Errorf("invalid MBR disk signature: %s", diskID)
		}
		partitionNumber, err := strconv.Atoi(third)
		if err != nil {
			return PartitionRef{}, fmt.Errorf("invalid MBR partition number: %w", err)
		}
		if partitionNumber <= 0 {
			return PartitionRef{}, fmt.Errorf("invalid MBR partition number: %d", partitionNumber)
		}
		return PartitionRef{
			Style:           "MBR",
			DiskID:          diskID,
			PartitionNumber: partitionNumber,
		}, nil
	default:
		return PartitionRef{}, fmt.Errorf("unsupported partition ref type: %s", kind)
	}
}

// FindPartitionByRef 按统一分区引用重新定位当前系统中的目标分区。
//
// 它会先解析引用，再遍历当前可见物理磁盘并比对磁盘唯一标识，
// 最后在目标磁盘上按 GPT 的 PartitionGuid 或 MBR 的分区号找到分区。
// 返回值同时包含 DiskInfo 和 PartitionInfo，方便上层继续构造路径或挂载卷。
func FindPartitionByRef(ref string) (DiskInfo, PartitionInfo, error) {
	parsed, err := ParsePartitionRef(ref)
	if err != nil {
		return DiskInfo{}, PartitionInfo{}, err
	}

	disks, err := ListPhysicalDisks()
	if err != nil {
		return DiskInfo{}, PartitionInfo{}, err
	}
	for _, diskInfo := range disks {
		if !strings.EqualFold(strings.TrimSpace(diskInfo.PartitionStyle), parsed.Style) {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(diskInfo.UniqueId), parsed.DiskID) {
			continue
		}

		parts, err := ListDiskPartitions(diskInfo.DiskNumber)
		if err != nil {
			return DiskInfo{}, PartitionInfo{}, err
		}
		for _, part := range parts {
			switch parsed.Style {
			case "GPT":
				if strings.EqualFold(strings.TrimSpace(part.PartitionGuid), parsed.PartitionGUID) {
					return diskInfo, part, nil
				}
			case "MBR":
				if part.PartitionNumber == parsed.PartitionNumber {
					return diskInfo, part, nil
				}
			}
		}
		return DiskInfo{}, PartitionInfo{}, fmt.Errorf("partition not found on disk: %s", ref)
	}

	return DiskInfo{}, PartitionInfo{}, fmt.Errorf("disk not found for partition ref: %s", ref)
}

// FindPartitionByRoot 根据当前可访问的卷根路径反查它所属的稳定分区身份。
//
// 这个函数用于“从当前在线系统环境生成计划文件”的场景：
// 先按盘符或卷 GUID 找到卷，再关联到物理磁盘和具体分区，
// 最终拿到可用于 BuildPartitionRef 的原始磁盘/分区信息。
func FindPartitionByRoot(root string) (DiskInfo, PartitionInfo, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return DiskInfo{}, PartitionInfo{}, fmt.Errorf("empty root")
	}

	volumes, err := ListVolumes()
	if err != nil {
		return DiskInfo{}, PartitionInfo{}, err
	}
	disks, err := ListPhysicalDisks()
	if err != nil {
		return DiskInfo{}, PartitionInfo{}, err
	}

	for _, vol := range volumes {
		if !volumeMatchesRoot(vol, root) {
			continue
		}

		var diskInfo DiskInfo
		foundDisk := false
		for _, item := range disks {
			if item.DiskNumber == vol.DiskNumber {
				diskInfo = item
				foundDisk = true
				break
			}
		}
		if !foundDisk {
			return DiskInfo{}, PartitionInfo{}, fmt.Errorf("disk not found for root: %s", root)
		}

		parts, err := ListDiskPartitions(vol.DiskNumber)
		if err != nil {
			return DiskInfo{}, PartitionInfo{}, err
		}
		for _, part := range parts {
			if partitionMatchesVolume(part, vol) {
				return diskInfo, part, nil
			}
		}
		return DiskInfo{}, PartitionInfo{}, fmt.Errorf("partition not found for root: %s", root)
	}

	return DiskInfo{}, PartitionInfo{}, fmt.Errorf("volume not found for root: %s", root)
}

// isGUIDRef 判断字符串是否满足标准 GUID 文本格式。
//
// 这里只做格式级校验，不区分该 GUID 在业务上代表磁盘还是分区。
func isGUIDRef(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) != 36 {
		return false
	}
	for idx, ch := range value {
		switch idx {
		case 8, 13, 18, 23:
			if ch != '-' {
				return false
			}
		default:
			if !isHexChar(byte(ch)) {
				return false
			}
		}
	}
	return true
}

// isHexSignature 判断字符串是否是合法的 8 位十六进制 MBR 磁盘签名。
func isHexSignature(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) != 8 {
		return false
	}
	for i := range value {
		if !isHexChar(value[i]) {
			return false
		}
	}
	return true
}

// isHexChar 判断单个 ASCII 字符是否属于十六进制字符集。
func isHexChar(ch byte) bool {
	switch {
	case ch >= '0' && ch <= '9':
		return true
	case ch >= 'a' && ch <= 'f':
		return true
	default:
		return false
	}
}

// volumeMatchesRoot 判断一个卷是否与调用方给出的根路径指向同一逻辑卷。
//
// 为了兼容在线系统和 PE 环境，这里同时支持盘符根路径与卷 GUID 路径比较。
func volumeMatchesRoot(vol VolumeInfo, root string) bool {
	if utils.SameVolume(root, vol.RootPath) {
		return true
	}
	if vol.DriveLetter != "" && utils.SameVolume(root, vol.DriveLetter+`:\`) {
		return true
	}
	if strings.EqualFold(
		strings.TrimRight(strings.TrimSpace(root), `\`),
		strings.TrimRight(strings.TrimSpace(vol.VolumeGuidPath), `\`),
	) {
		return true
	}
	return false
}

// partitionMatchesVolume 判断分区与卷枚举结果是否可以视为同一对象。
//
// 优先使用更稳定的 PartitionGuid 做匹配；若卷侧没有 GUID，则退化为按偏移区间
// 和盘符信息判断，确保旧式卷信息也能映射回对应分区。
func partitionMatchesVolume(part PartitionInfo, vol VolumeInfo) bool {
	if part.PartitionGuid != "" && vol.PartitionGuid != "" {
		return strings.EqualFold(part.PartitionGuid, vol.PartitionGuid)
	}
	if vol.OffsetBytes >= part.OffsetBytes && vol.OffsetBytes < part.OffsetBytes+part.SizeBytes {
		return true
	}
	if part.DriveLetter != "" && vol.DriveLetter != "" {
		return strings.EqualFold(strings.TrimSpace(part.DriveLetter), strings.TrimSpace(vol.DriveLetter))
	}
	return false
}
