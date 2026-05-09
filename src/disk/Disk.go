package disk

import (
	"ReSys/src/log"
	"ReSys/src/tools"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"ReSys/src/utils"
)

const (
	minImageBytes uint64 = 7 * 1024 * 1024 * 1024
	tempLabel            = "TEMP"
)

// 返回有足够大小的分区数组
// SSD>HDD>USB
func Findpart() []string {
	D, err := ListDrive()
	if err != nil {
		return nil
	}
	minFreeSpace := minFreeSpaceThreshold()

	type cand struct {
		path string
		kind string
		free uint64
		pri  int
	}

	var cs []cand

	for i := 0; i < len(D); i++ {
		root := D[i]

		freeBytes, err := GetFreeSize(root)
		if err != nil {
			continue
		}
		if freeBytes <= minFreeSpace {
			continue
		}

		// 磁盘类型
		kind, err := GetDiskKind(root)
		if err != nil {
			continue
		}
		if kind == "CDROM" || kind == "Unknown" {
			continue
		}

		pri := 0
		switch kind {
		case "SSD":
			pri = 3
		case "HDD":
			pri = 2
		case "Removable":
			pri = 1
		default:
			pri = 0
		}
		if pri == 0 {
			continue
		}

		cs = append(cs, cand{
			path: root,
			kind: kind,
			free: freeBytes,
			pri:  pri,
		})
	}

	// 排序
	if len(cs) == 0 {
		return nil
	}

	sort.Slice(cs, func(i, j int) bool {
		if cs[i].pri != cs[j].pri {
			return cs[i].pri > cs[j].pri // 类型优先级高的在前
		}
		if cs[i].free != cs[j].free {
			return cs[i].free > cs[j].free // 同一类型剩余空间大的在前
		}
		return cs[i].path < cs[j].path
	})

	part := make([]string, 0, len(cs))
	for _, c := range cs {
		part = append(part, c.path)
	}
	log.LogWrite(0, "[Findpart]Findpart: %v", part)
	return part
}

// 把diskpart命令写入临时文件并执行。
// 返回diskpart的输出，便于日志记录/排错。
func RunDiskpart(lines []string) (string, error) {
	if len(lines) == 0 {
		return "", fmt.Errorf("empty diskpart script")
	}

	script := strings.Join(lines, "\r\n") + "\r\n"
	out, err := runDiskpartScriptFile(script)
	if err == nil {
		return out, nil
	}

	outDirect, directErr := runDiskpartDirect(script)
	if directErr == nil {
		return outDirect, nil
	}
	return outDirect, fmt.Errorf("diskpart failed (script file): %w; direct failed: %v\n直接执行输出:\n%s", err, directErr, outDirect)
}

// runDiskpartScriptFile 函数。
func runDiskpartScriptFile(script string) (string, error) {
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
	defer os.Remove(path) //用完就删除

	if _, err := f.WriteString(script); err != nil {
		_ = f.Close()
		return "", fmt.Errorf("write script failed: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("close script failed: %w", err)
	}
	diskpart := diskpartBinary()
	out, err := tools.RunCmd(diskpart, nil, nil, "", "/s", path)
	if err != nil {
		return out, fmt.Errorf("diskpart failed: %w", err)
	}
	return out, nil

}

// runDiskpartDirect 函数。
func runDiskpartDirect(script string) (string, error) {
	script = strings.TrimRight(script, "\r\n") + "\r\nexit\r\n"
	diskpart := diskpartBinary()
	out, err := tools.RunCmd(diskpart, []byte(script), nil, "")
	if err != nil {
		return out, fmt.Errorf("diskpart direct failed: %w", err)
	}
	return out, nil
}

// diskpartBinary 函数。
func diskpartBinary() string {
	return utils.GetSystemExe("diskpart.exe")
}

// cleanLabel 对卷标做基础清洗，保证可安全写入脚本或命令参数。
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

// diskpartQuote 按 diskpart 语法为标签补齐引号。
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
		"diskpart 遇到错误",
		"虚拟磁盘服务错误",
		"操作失败",
		"没有足够的可用空间",
		"请求不受支持",
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
	volLetter, err := utils.NormalizeDrive(vol, 1)
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
	volLetter, err := utils.NormalizeDrive(vol, 1)
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

// CreatePartitionFromFreeExtent 在指定空闲区间上创建新分区并格式化，返回新分配的盘符。
// sizeBytes 为 0 或超出空闲区间时会自动收敛到可用大小；fs/label 用于 format 参数。
// 通过 diskpart 执行：create partition + format + assign，并轮询检测新盘符出现。
func CreatePartitionFromFreeExtent(extent FreeExtent, sizeBytes uint64, fs, label string) (string, error) {
	if extent.SizeBytes == 0 {
		return "", fmt.Errorf("free extent size is 0")
	}
	if sizeBytes == 0 || sizeBytes > extent.SizeBytes {
		sizeBytes = extent.SizeBytes
	}
	fs2, err := parseFS(fs)
	if err != nil {
		return "", err
	}
	fs2 = strings.ToLower(fs2)

	sizeMB64 := sizeBytes / (1024 * 1024)
	if sizeMB64 == 0 {
		return "", fmt.Errorf("sizeBytes too small")
	}
	maxInt := int(^uint(0) >> 1)
	if sizeMB64 > uint64(maxInt) {
		return "", fmt.Errorf("sizeBytes too large")
	}
	sizeMB := int(sizeMB64)

	label = cleanLabel(label)
	lblArg := ""
	if strings.TrimSpace(label) != "" {
		lblArg = " label=" + diskpartQuote(label)
	}

	beforeLetters, err := collectDriveLetters()
	if err != nil {
		return "", err
	}

	offsetKB := (extent.OffsetBytes + 1023) / 1024
	lines := []string{
		fmt.Sprintf("select disk %d", extent.DiskNumber),
		fmt.Sprintf("create partition primary offset=%d size=%d align=1024", offsetKB, sizeMB),
		fmt.Sprintf("format fs=%s%s quick", fs2, lblArg),
		"assign",
	}

	out, err := RunDiskpart(lines)
	if err != nil {
		return "", fmt.Errorf("create partition(diskpart) failed: %w\n输出:\n%s", err, out)
	}
	if e := diskpartDetectError(out, "create/format/assign"); e != nil {
		return "", e
	}

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
	return "", fmt.Errorf("create finished but cannot determine new drive letter")
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
	volLetter, err := utils.NormalizeDrive(vol, 1)
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
	volLetter, err := utils.NormalizeDrive(vol, 1)
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

// 按盘符格式化卷
func Format(letter, fs, label string, quick bool) error {
	volLetter, err := utils.NormalizeDrive(letter, 1)
	if err != nil {
		return err
	}

	fsCanon, err := parseFS(fs)
	if err != nil {
		return err
	}

	label = cleanLabel(label)
	fs2 := strings.ToLower(fsCanon)

	lblArg := ""
	if strings.TrimSpace(label) != "" {
		lblArg = " label=" + diskpartQuote(label)
	}

	line := fmt.Sprintf("format fs=%s%s", fs2, lblArg)
	if quick {
		line += " quick"
	}
	line += " override"

	lines := []string{
		fmt.Sprintf("select volume %s", volLetter),
		line,
	}

	out, err := RunDiskpart(lines)
	log.LogWrite(0, out)
	if err != nil {
		return fmt.Errorf("format(diskpart) failed: %w\n输出:\n%s", err, out)
	}
	if e := diskpartDetectError(out, "format"); e != nil {
		return e
	}
	return nil
}

// 优先用连续未分配空间创建 TEMP 分区；失败再最后 SplitVolume(C)，目前只能在运行中的正常系统使用
// needBytes：需要的空间
func NewTempVolume(needBytes uint64) (string, error) {
	needBytes = resolveTempVolumeNeedBytes(needBytes)

	// 先用未分配空间（全盘扫描，支持另一块盘全未分配的情况）
	extent, err := PickFreeExtent(needBytes, ExtentPickPolicy{
		PreferNonSystemDisk: true,
		PreferLargestExtent: true,
	})
	if err == nil && extent.SizeBytes >= needBytes {
		letter, err2 := CreatePartitionFromFreeExtent(extent, needBytes, "ntfs", tempLabel)
		if err2 == nil {
			root, _ := utils.NormalizeDrive(letter, 0)
			if root != "" {
				// 写 marker
				marker := filepath.Join(root, tempMarkerRelativePath())
				_ = os.MkdirAll(filepath.Dir(marker), 0o755)
				_ = os.WriteFile(marker, []byte(time.Now().Format(time.RFC3339)), 0o644)
				log.LogWrite(0, "[ensureTempVolumeForBytes]已使用未分配空间创建 TEMP 分区：%s", root)
				return root, nil
			}
		} else {
			log.LogWrite(0, "[ensureTempVolumeForBytes]CreatePartitionFromFreeExtent失败：%v", err2)
		}
	} else {
		if err != nil {
			log.LogWrite(0, "[ensureTempVolumeForBytes]PickFreeExtent未找到足够大的未分配段：%v", err)
		}
	}

	//拆分系统盘
	// 尝试先清理一下，增加 shrink 成功率
	//windows.ClearPartition()

	sizeMB64 := (needBytes + 1024*1024 - 1) / (1024 * 1024)
	sizeMB := int(sizeMB64)
	if sizeMB < 1024 {
		sizeMB = 1024
	}

	newVol, err := SplitVolume("C", sizeMB, "ntfs", tempLabel)
	if err != nil {
		return "", err
	}
	root, _ := utils.NormalizeDrive(newVol, 0)
	if root == "" {
		return "", fmt.Errorf("SplitVolume成功但未解析到新分区盘符: %v", newVol)
	}

	// 写 marker
	marker := filepath.Join(root, tempMarkerRelativePath())
	_ = os.MkdirAll(filepath.Dir(marker), 0o755)
	_ = os.WriteFile(marker, []byte(time.Now().Format(time.RFC3339)), 0o644)

	log.LogWrite(0, "[ensureTempVolumeForBytes]已通过拆分C盘创建 TEMP 分区：%s", root)
	return root, nil
}
