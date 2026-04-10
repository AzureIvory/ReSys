package utils

import (
	"fmt"
	"strconv"
	"strings"
)

// ParsePartRef 解析 `磁盘号:分区号` 形式的引用。
func ParsePartRef(ref string) (int, int, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return 0, 0, fmt.Errorf("未选择引导分区")
	}

	parts := strings.Split(ref, ":")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("分区引用格式无效: %s", ref)
	}

	diskNumber, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return 0, 0, fmt.Errorf("磁盘号无效: %w", err)
	}
	partNumber, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return 0, 0, fmt.Errorf("分区号无效: %w", err)
	}
	return diskNumber, partNumber, nil
}

// BootType 根据修复模式和目标磁盘分区表类型推断应使用 UEFI 还是 BIOS。
func BootType(mode, diskStyle string) string {
	switch strings.TrimSpace(mode) {
	case "manual_uefi":
		return "UEFI"
	case "manual_bios":
		return "BIOS"
	default:
		if strings.EqualFold(strings.TrimSpace(diskStyle), "GPT") {
			return "UEFI"
		}
		return "BIOS"
	}
}

// NeedBootPart 判断当前模式是否要求手动选择引导分区。
func NeedBootPart(mode string) bool {
	switch strings.TrimSpace(mode) {
	case "manual", "manual_uefi", "manual_bios":
		return true
	default:
		return false
	}
}
