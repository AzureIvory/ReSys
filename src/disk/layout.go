package disk

import (
	"fmt"
	"os"
	"strings"
	"time"
)

const MSRSizeMB = 16

// LayoutPart 描述一个需要创建并格式化的普通分区。
// SizeMB 小于等于 0 表示使用剩余全部空间，且只能出现在最后一个分区。
type LayoutPart struct {
	SizeMB int
	FS     string
	Label  string
	Letter string
}

type layoutReq struct {
	DiskNumber int
	Style      string
	EFISizeMB  int
	Parts      []LayoutPart
}

// ApplyDiskLayout 清空指定磁盘后重建分区布局。
// 仅允许操作非当前系统盘；GPT 会自动创建 EFI 和 16MB 的 MSR。
func ApplyDiskLayout(
	diskNumber int,
	style string,
	efiSizeMB int,
	partitions []LayoutPart,
) ([]PartitionInfo, error) {
	systemDisk, err := currentSystemDisk()
	if err != nil {
		return nil, fmt.Errorf("get current system disk: %w", err)
	}

	req, err := normLayout(diskNumber, style, efiSizeMB, partitions, systemDisk)
	if err != nil {
		return nil, err
	}

	lines, err := layoutScript(req)
	if err != nil {
		return nil, err
	}

	out, err := RunDiskpart(lines)
	if err != nil {
		return nil, fmt.Errorf("apply disk layout failed: %w\n输出:\n%s", err, out)
	}
	if err := diskpartDetectError(out, "apply disk layout"); err != nil {
		return nil, err
	}

	parts, err := waitLayoutParts(req.DiskNumber, wantLayoutCount(req))
	if err != nil {
		return nil, fmt.Errorf("read disk layout after apply: %w", err)
	}
	return parts, nil
}

// normLayout 负责做危险操作前的参数校验和标准化。
func normLayout(
	diskNumber int,
	style string,
	efiSizeMB int,
	partitions []LayoutPart,
	systemDisk int,
) (layoutReq, error) {
	if diskNumber < 0 {
		return layoutReq{}, fmt.Errorf("diskNumber 不能小于 0")
	}
	if systemDisk >= 0 && diskNumber == systemDisk {
		return layoutReq{}, fmt.Errorf("禁止在线清空当前系统盘: disk %d", diskNumber)
	}

	style, err := normLayoutStyle(style)
	if err != nil {
		return layoutReq{}, err
	}
	if len(partitions) == 0 {
		return layoutReq{}, fmt.Errorf("partitions 不能为空")
	}
	if style == "GPT" && efiSizeMB <= 0 {
		return layoutReq{}, fmt.Errorf("GPT 模式下 efiSizeMB 必须大于 0")
	}
	if style == "MBR" && len(partitions) > 4 {
		return layoutReq{}, fmt.Errorf("MBR 模式最多只支持 4 个主分区")
	}

	parts := make([]LayoutPart, 0, len(partitions))
	letters := map[string]struct{}{}
	for i, part := range partitions {
		fs, err := parseFS(part.FS)
		if err != nil {
			return layoutReq{}, fmt.Errorf("partition %d fs 无效: %w", i+1, err)
		}

		sizeMB := part.SizeMB
		if sizeMB <= 0 && i != len(partitions)-1 {
			return layoutReq{}, fmt.Errorf("仅最后一个分区允许使用剩余空间")
		}

		letter, err := normLetter(part.Letter)
		if err != nil {
			return layoutReq{}, fmt.Errorf("partition %d 盘符无效: %w", i+1, err)
		}
		if letter != "" {
			if _, ok := letters[letter]; ok {
				return layoutReq{}, fmt.Errorf("partition %d 盘符重复: %s", i+1, letter)
			}
			letters[letter] = struct{}{}
		}

		parts = append(parts, LayoutPart{
			SizeMB: sizeMB,
			FS:     fs,
			Label:  cleanScriptText(part.Label),
			Letter: letter,
		})
	}

	return layoutReq{
		DiskNumber: diskNumber,
		Style:      style,
		EFISizeMB:  efiSizeMB,
		Parts:      parts,
	}, nil
}

// layoutScript 生成整盘重建所需的 diskpart 脚本。
func layoutScript(req layoutReq) ([]string, error) {
	lines := []string{
		fmt.Sprintf("select disk %d", req.DiskNumber),
		"online disk noerr",
		"attributes disk clear readonly noerr",
		"clean",
		fmt.Sprintf("convert %s", strings.ToLower(req.Style)),
	}

	if req.Style == "GPT" {
		lines = append(
			lines,
			fmt.Sprintf("create partition efi size=%d", req.EFISizeMB),
			"format quick fs=fat32 label=SYSTEM",
			fmt.Sprintf("create partition msr size=%d", MSRSizeMB),
		)
	}

	for _, part := range req.Parts {
		createLine := "create partition primary"
		if part.SizeMB > 0 {
			createLine = fmt.Sprintf("%s size=%d", createLine, part.SizeMB)
		}

		formatLine := fmt.Sprintf("format quick fs=%s", strings.ToLower(part.FS))
		if label := formatLabelArg(part.Label); label != "" {
			formatLine += " label=" + label
		}

		assignLine := "assign"
		if part.Letter != "" {
			assignLine = fmt.Sprintf("assign letter=%s", part.Letter)
		}

		lines = append(lines, createLine, formatLine, assignLine)
	}

	return lines, nil
}

// currentSystemDisk 返回当前在线系统盘号。
func currentSystemDisk() (int, error) {
	systemDrive := strings.TrimSpace(os.Getenv("SystemDrive"))
	if systemDrive == "" {
		systemDrive = "C:"
	}

	diskNumber, err := GetDiskNum(systemDrive)
	if err != nil {
		return -1, err
	}
	return int(diskNumber), nil
}

// wantLayoutCount 返回目标布局创建完成后预计应看到的分区数量。
func wantLayoutCount(req layoutReq) int {
	count := len(req.Parts)
	if req.Style == "GPT" {
		count += 2
	}
	return count
}

// waitLayoutParts 等待磁盘布局刷新完成后再读取分区列表。
func waitLayoutParts(diskNumber int, wantCount int) ([]PartitionInfo, error) {
	var lastParts []PartitionInfo
	var lastErr error

	for range 8 {
		parts, err := ListDiskPartitions(diskNumber)
		if err == nil && len(parts) >= wantCount {
			return parts, nil
		}
		lastParts = parts
		lastErr = err
		time.Sleep(300 * time.Millisecond)
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return lastParts, nil
}

// normLayoutStyle 统一分区表类型入参，兼容 GUID/GPT 写法。
func normLayoutStyle(style string) (string, error) {
	switch strings.ToUpper(strings.TrimSpace(style)) {
	case "GPT", "GUID":
		return "GPT", nil
	case "MBR":
		return "MBR", nil
	default:
		return "", fmt.Errorf("不支持的分区表类型: %q", style)
	}
}

// normLetter 规范化可选盘符，只保留单个 A-Z 字母。
func normLetter(letter string) (string, error) {
	letter = strings.ToUpper(strings.TrimSpace(letter))
	letter = strings.TrimRight(letter, `:\`)
	if letter == "" {
		return "", nil
	}
	if len(letter) != 1 || letter[0] < 'A' || letter[0] > 'Z' {
		return "", fmt.Errorf("盘符必须是 A-Z 的单个字母")
	}
	return letter, nil
}

// cleanScriptText 清理标签等脚本文本，避免破坏 diskpart 参数解析。
func cleanScriptText(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, `"`, `'`)
	return s
}

// formatLabelArg 为带空格的卷标补齐引号。
func formatLabelArg(label string) string {
	label = cleanScriptText(label)
	if label == "" {
		return ""
	}
	if strings.ContainsAny(label, " \t") {
		return `"` + label + `"`
	}
	return label
}
