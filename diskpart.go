package main

import (
	"fmt"
	"strings"
	"time"
)

// -------------------- diskpart helpers --------------------

func diskpartQuoteIfNeeded(s string) string {
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
func checkDiskpartOutput(out, op string) error {
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

// -------------------- 1) shrink volume (right) --------------------

// ShrinkVolumeRightDiskpart 将某个卷从右侧收缩指定大小(MB)，在卷尾释放出未分配空间。
// 返回：diskpart 输出，便于日志记录。
func ShrinkVolumeRightDiskpart(vol string, sizeMB int) (string, error) {
	volLetter, err := normalizeDriveLetter(vol)
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
	if e := checkDiskpartOutput(out, "shrink"); e != nil {
		return out, e
	}
	return out, nil
}

// -------------------- 2) create partition from tail unallocated --------------------

// CreatePartitionFromTailUnallocatedDiskpart：在 vol 卷尾紧邻的未分配空间上创建主分区、快速格式化、自动分配盘符。
// sizeMB：期望新分区大小(MB)。如果因为对齐导致 size 放不下，会做小幅降级重试。
// 返回：新分区盘符（例如 "E:"）和错误。
func CreatePartitionFromTailUnallocatedDiskpart(vol string, sizeMB int, fs, label string) (string, error) {
	volLetter, err := normalizeDriveLetter(vol)
	if err != nil {
		return "", err
	}
	if sizeMB <= 0 {
		return "", fmt.Errorf("sizeMB 必须大于 0")
	}

	fs2, err := toDiskToolFS(fs)
	if err != nil {
		return "", err
	}
	fs2 = strings.ToLower(fs2)

	label = sanitizePartAssistLabel(label) // 复用你现有的 label 清洗逻辑
	lblArg := ""
	if strings.TrimSpace(label) != "" {
		lblArg = " label=" + diskpartQuoteIfNeeded(label)
	}

	// 用于推断新盘符
	beforeLetters, err := collectDriveLetters()
	if err != nil {
		return "", err
	}

	// 获取卷所在磁盘与卷区间，用于计算卷尾 offset
	diskNum, startBytes, lengthBytes, err := getVolumeExtentBytes(volLetter + ":")
	if err != nil {
		return "", err
	}
	endBytes := startBytes + lengthBytes

	const mb = int64(1024 * 1024)

	// diskpart 的 offset 单位是 KB。这里先算 offsetMB（ceil 到 MB），再转 KB。
	offsetMB := (endBytes + mb - 1) / mb
	offsetKB := offsetMB * 1024

	// 如果卷尾不是 MB 对齐，offset 上取整会“吃掉 <1MB”，把 size 略减更稳
	createSize := sizeMB
	if endBytes%mb != 0 && sizeMB > 1 {
		createSize = sizeMB - 1
	}

	// 组装 format 命令
	formatLine := fmt.Sprintf("format fs=%s%s", fs2, lblArg)

	// quick 格式化：SplitVolume1 场景默认 quick
	formatLine += " quick"

	// 创建分区可能因对齐、空间边界等失败：做小幅降级尝试
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
			// offset 单位 KB，align=1024 表示 1MB 对齐（单位 KB）
			fmt.Sprintf("create partition primary offset=%d size=%d align=1024", offsetKB, sz),
			formatLine,
			"assign", // 自动分配下一个可用盘符
		}

		out, err := RunDiskpart(lines)
		if err == nil {
			if e := checkDiskpartOutput(out, "create/format/assign"); e == nil {
				outCreate = out
				lastErr = nil
				break
			} else {
				err = e
			}
		}
		lastErr = fmt.Errorf("create partition(diskpart) failed: %w\n输出:\n%s", err, out)
	}

	// 兜底：如果指定 size 一直失败，尝试让 diskpart 用“从 offset 起的全部空间”
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
		if e := checkDiskpartOutput(out, "create/format/assign"); e != nil {
			return "", e
		}
		outCreate = out
	}

	// 推断新盘符（diskpart assign 有时枚举会有延迟）
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

// -------------------- SplitVolume1 using the two functions --------------------

// 使用 diskpart 将某个卷收缩指定大小(MB)，然后在释放出的未分配空间上新建分区并快速格式化。
// 返回：新分区盘符（例如 "E:"）和错误。
func SplitVolume11(vol string, sizeMB int, fs, label string) (string, error) {
	if sizeMB <= 0 {
		return "", fmt.Errorf("sizeMB 必须大于 0")
	}

	outShrink, err := ShrinkVolumeRightDiskpart(vol, sizeMB)
	if err != nil {
		return "", err
	}

	newLetter, err := CreatePartitionFromTailUnallocatedDiskpart(vol, sizeMB, fs, label)
	if err != nil {
		return "", fmt.Errorf("%w\nshrink输出:\n%s", err, outShrink)
	}
	return newLetter, nil
}

// -------------------- MergeVolume / DeleteVolume / Format (diskpart) --------------------

// 合并分区：将目标卷卷尾紧邻的未分配空间扩展到指定卷。
// sizeMB: 扩展大小（MB），<=0 表示使用全部
func MergeVolume1(vol string, sizeMB int) error {
	volLetter, err := normalizeDriveLetter(vol)
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
	if e := checkDiskpartOutput(out, "extend"); e != nil {
		return e
	}
	return nil
}

// 删除指定卷（转为未分配空间）。
func DeleteVolume1(vol string) error {
	volLetter, err := normalizeDriveLetter(vol)
	if err != nil {
		return err
	}

	lines := []string{
		fmt.Sprintf("select volume %s", volLetter),
		// override 更接近 PartAssist 的“强删”行为；如果你想更保守，可以改成 "delete volume"
		"delete volume override",
	}

	out, err := RunDiskpart(lines)
	if err != nil {
		return fmt.Errorf("delete(diskpart) failed: %w\n输出:\n%s", err, out)
	}
	if e := checkDiskpartOutput(out, "delete volume"); e != nil {
		return e
	}
	return nil
}

// 按盘符格式化卷。
func Format1(letter, fs, label string, quick bool) error {
	volLetter, err := normalizeDriveLetter(letter)
	if err != nil {
		return err
	}

	fs2, err := toDiskToolFS(fs)
	if err != nil {
		return err
	}
	fs2 = strings.ToLower(fs2)

	label = sanitizePartAssistLabel(label)
	lblArg := ""
	if strings.TrimSpace(label) != "" {
		lblArg = " label=" + diskpartQuoteIfNeeded(label)
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
	if e := checkDiskpartOutput(out, "format"); e != nil {
		return e
	}
	return nil
}
