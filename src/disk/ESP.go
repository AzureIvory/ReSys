package disk

import (
	"ReSys/src/tools"
	"ReSys/src/utils"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const espMountWait = 3 * time.Second

type espCandidate struct {
	Root      string
	Cleanup   func()
	SizeBytes uint64
	Score     int
}

type shrinkCandidate struct {
	Root      string
	FreeBytes uint64
	IsOSRoot  bool
}

// EnsureESPRoot 确保 EFI 分区可访问并返回可用的根路径。
func EnsureESPRoot(part PartitionInfo) (string, func(), error) {
	if part.DriveLetter != "" {
		if root, err := utils.NormalizeDrive(part.DriveLetter, 0); err == nil && root != "" {
			if err := validateESPRoot(root); err == nil {
				return root, nil, nil
			}
		}
	}
	root, cleanup, err := MountVolumeToTempLetter(part)
	if err != nil {
		return "", nil, err
	}
	if err := validateESPRoot(root); err != nil {
		if cleanup != nil {
			cleanup()
		}
		return "", nil, err
	}
	return root, cleanup, nil
}

// CreateESPFromExtent 在指定未分配空间上创建并挂载 ESP 分区。
func CreateESPFromExtent(extent FreeExtent, sizeMB int, label string) (string, func(), error) {
	if sizeMB <= 0 {
		return "", nil, fmt.Errorf("sizeMB must be positive")
	}
	letter, err := chooseTempDriveLetter()
	if err != nil {
		return "", nil, err
	}
	offsetKB := (extent.OffsetBytes + 1023) / 1024
	label = cleanLabel(label)
	lines := []string{
		fmt.Sprintf("select disk %d", extent.DiskNumber),
		fmt.Sprintf("create partition efi size=%d offset=%d", sizeMB, offsetKB),
		fmt.Sprintf("format quick fs=fat32 label=%s", diskpartQuote(label)),
		fmt.Sprintf("assign letter=%s", letter),
	}
	out, err := RunDiskpart(lines)
	if err != nil {
		return "", nil, fmt.Errorf("create EFI partition failed: %w\n输出:\n%s", err, out)
	}
	if err := diskpartDetectError(out, "create EFI partition"); err != nil {
		return "", nil, err
	}

	root := letter + `:\`
	if err := waitForDriveReady(root); err != nil {
		_ = removeDriveLetter(letter)
		return "", nil, err
	}
	cleanup := func() {
		if err := removeDriveLetter(letter); err != nil {
			fmt.Printf("[CreateESP] cleanup %s failed: %v\n", root, err)
		}
	}
	return root, cleanup, nil
}

// MountVolumeToTempLetter 将指定卷 GUID 临时挂载到空闲盘符；失败时回退到 diskpart。
func MountVolumeToTempLetter(part PartitionInfo) (string, func(), error) {
	letter, err := chooseTempDriveLetter()
	if err != nil {
		return "", nil, err
	}
	volumeGuid := strings.TrimSpace(part.VolumeGuidPath)
	var mountvolErr error
	if volumeGuid != "" {
		if !strings.HasSuffix(volumeGuid, `\`) {
			volumeGuid += `\`
		}

		root, cleanup, err := mountVolumeWithMountvol(volumeGuid, letter)
		if err == nil {
			return root, cleanup, nil
		}
		mountvolErr = err
		fmt.Printf("[MountVolumeToTempLetter] mountvol failed, fallback to diskpart: %v\n", mountvolErr)
	}

	root, cleanup, diskpartErr := mountVolumeWithDiskpart(part, letter)
	if diskpartErr == nil {
		return root, cleanup, nil
	}
	if volumeGuid == "" {
		return "", nil, fmt.Errorf("mount partition via diskpart failed: %w", diskpartErr)
	}
	return "", nil, fmt.Errorf("mount volume %s failed: mountvol=%v; diskpart=%v", volumeGuid, mountvolErr, diskpartErr)
}

// FindESPOnDisk 枚举指定磁盘上的 EFI 分区并返回最合适的候选。
func FindESPOnDisk(diskNumber int) (string, func(), bool, error) {
	parts, err := ListDiskPartitions(diskNumber)
	if err != nil {
		return "", nil, false, err
	}
	sort.Slice(parts, func(i, j int) bool {
		if parts[i].SizeBytes != parts[j].SizeBytes {
			return parts[i].SizeBytes < parts[j].SizeBytes
		}
		return parts[i].OffsetBytes < parts[j].OffsetBytes
	})

	var best espCandidate
	found := false
	for _, part := range parts {
		if !strings.EqualFold(part.Type, "EFI") {
			continue
		}
		root, cleanup, err := EnsureESPRoot(part)
		if err != nil {
			fmt.Printf("[FindESP] skip EFI on disk %d offset=%d: %v\n", diskNumber, part.OffsetBytes, err)
			continue
		}
		cand := espCandidate{
			Root:      root,
			Cleanup:   cleanup,
			SizeBytes: part.SizeBytes,
			Score:     scoreESPRoot(root),
		}
		if !found || cand.Score > best.Score || (cand.Score == best.Score && cand.SizeBytes < best.SizeBytes) {
			if best.Cleanup != nil {
				best.Cleanup()
			}
			best = cand
			found = true
			continue
		}
		if cleanup != nil {
			cleanup()
		}
	}
	if !found {
		return "", nil, false, nil
	}
	return best.Root, best.Cleanup, true, nil
}

// scoreESPRoot 按 ESP 内已有启动文件的完整度给候选打分。
func scoreESPRoot(root string) int {
	bootDir := filepath.Join(root, "EFI", "Microsoft", "Boot")
	if st, err := os.Stat(bootDir); err == nil && st.IsDir() {
		return 3
	}
	efiDir := filepath.Join(root, "EFI")
	if st, err := os.Stat(efiDir); err == nil && st.IsDir() {
		return 2
	}
	return 1
}

// ShouldSkipFallbackDisk 判断回退扫描时是否应跳过该磁盘，例如 U 盘、光盘或 PE 盘。
func ShouldSkipFallbackDisk(diskNumber int, volumes []VolumeInfo) bool {
	for _, vol := range volumes {
		if vol.DiskNumber != diskNumber {
			continue
		}

		root := vol.RootPath
		if root == "" {
			root = vol.DriveLetter
		}
		if root == "" {
			continue
		}
		root, err := utils.NormalizeDrive(root, 0)
		if err != nil || root == "" {
			continue
		}
		if strings.EqualFold(root, "X:\\") {
			return true
		}
		kind, err := GetDiskKind(root)
		if err == nil && (kind == "Removable" || kind == "CDROM") {
			return true
		}
	}
	return false
}

// PickESPFreeExtent 从未分配空间里挑出最适合创建 ESP 的区间。
func PickESPFreeExtent(extents []FreeExtent, minSizeBytes uint64) (FreeExtent, bool) {
	var candidates []FreeExtent
	for _, extent := range extents {
		if extent.SizeBytes >= minSizeBytes {
			candidates = append(candidates, extent)
		}
	}
	if len(candidates) == 0 {
		return FreeExtent{}, false
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].SizeBytes != candidates[j].SizeBytes {
			return candidates[i].SizeBytes < candidates[j].SizeBytes
		}
		return candidates[i].OffsetBytes < candidates[j].OffsetBytes
	})
	return candidates[0], true
}

// PickESPShrinkVolume 在目标磁盘上选择一个适合收缩的卷来腾出 ESP 空间。
func PickESPShrinkVolume(osRoot string, targetDisk int, requiredFreeBytes uint64) (string, error) {
	volumes, err := ListVolumes()
	if err != nil {
		return "", fmt.Errorf("ListVolumes: %w", err)
	}
	parts, err := ListDiskPartitions(targetDisk)
	if err != nil {
		return "", fmt.Errorf("ListDiskPartitions: %w", err)
	}

	var candidates []shrinkCandidate
	for _, vol := range volumes {
		if vol.DiskNumber != targetDisk {
			continue
		}

		root := vol.RootPath
		if root == "" {
			root = vol.DriveLetter
		}
		if root == "" {
			continue
		}
		root, err := utils.NormalizeDrive(root, 0)
		if err != nil || root == "" || strings.EqualFold(root, "X:\\") {
			continue
		}
		if !strings.EqualFold(vol.FileSystem, "NTFS") {
			continue
		}
		kind, err := GetDiskKind(root)
		if err == nil && (kind == "Removable" || kind == "CDROM") {
			continue
		}
		partType := partitionTypeForVolume(vol, parts)
		if partType != "" && !strings.EqualFold(partType, "Basic") {
			continue
		}
		if vol.FreeBytes < requiredFreeBytes {
			continue
		}
		candidates = append(candidates, shrinkCandidate{
			Root:      root,
			FreeBytes: vol.FreeBytes,
			IsOSRoot:  strings.EqualFold(root, osRoot),
		})
	}
	if len(candidates) == 0 {
		return "", fmt.Errorf("no shrinkable same-disk volume for creating ESP")
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].IsOSRoot != candidates[j].IsOSRoot {
			return !candidates[i].IsOSRoot
		}
		if candidates[i].FreeBytes != candidates[j].FreeBytes {
			return candidates[i].FreeBytes > candidates[j].FreeBytes
		}
		return candidates[i].Root < candidates[j].Root
	})
	return candidates[0].Root, nil
}

// partitionTypeForVolume 根据卷偏移匹配其所属分区类型。
func partitionTypeForVolume(vol VolumeInfo, parts []PartitionInfo) string {
	for _, part := range parts {
		if vol.OffsetBytes >= part.OffsetBytes && vol.OffsetBytes < part.OffsetBytes+part.SizeBytes {
			return part.Type
		}
	}
	return ""
}

// FindESPFreeExtentAfterShrink 在收缩卷后寻找新腾出的未分配空间。
func FindESPFreeExtentAfterShrink(root string, targetDisk int, minSizeBytes, probeWindowBytes uint64) (FreeExtent, error) {
	extents, err := GetDiskFreeExtents(targetDisk)
	if err != nil {
		return FreeExtent{}, fmt.Errorf("GetDiskFreeExtents: %w", err)
	}
	volumes, err := ListVolumes()
	if err != nil {
		return FreeExtent{}, fmt.Errorf("ListVolumes: %w", err)
	}

	var expectedStart uint64
	for _, vol := range volumes {
		if vol.DiskNumber != targetDisk {
			continue
		}

		volRoot := vol.RootPath
		if volRoot == "" {
			volRoot = vol.DriveLetter
		}
		if volRoot == "" {
			continue
		}
		volRoot, err := utils.NormalizeDrive(volRoot, 0)
		if err != nil || volRoot == "" {
			continue
		}
		if strings.EqualFold(volRoot, root) {
			expectedStart = vol.OffsetBytes + vol.SizeBytes
			break
		}
	}
	if expectedStart != 0 {
		var (
			best      FreeExtent
			bestDelta uint64 = ^uint64(0)
			found     bool
		)
		for _, extent := range extents {
			if extent.SizeBytes < minSizeBytes {
				continue
			}
			delta := absDiffUint64(extent.OffsetBytes, expectedStart)
			if delta > probeWindowBytes {
				continue
			}
			if !found || delta < bestDelta || (delta == bestDelta && extent.SizeBytes < best.SizeBytes) {
				best = extent
				bestDelta = delta
				found = true
			}
		}
		if found {
			return best, nil
		}
	}
	if extent, ok := PickESPFreeExtent(extents, minSizeBytes); ok {
		return extent, nil
	}
	return FreeExtent{}, fmt.Errorf("no free extent found after shrinking %s", root)
}

// absDiffUint64 返回两个 uint64 的绝对差值。
func absDiffUint64(a, b uint64) uint64 {
	if a > b {
		return a - b
	}
	return b - a
}

// mountVolumeWithMountvol 使用 mountvol 把卷 GUID 挂载到空闲盘符。
func mountVolumeWithMountvol(volumeGuid, letter string) (string, func(), error) {
	mountvol := utils.GetSystemExe("mountvol.exe")
	target := letter + ":"
	out, err := tools.RunCmd(mountvol, nil, nil, "", target, volumeGuid)
	if err != nil {
		_ = removeDriveLetter(letter)
		return "", nil, fmt.Errorf("mountvol %s -> %s failed: %w\n输出:\n%s", target, volumeGuid, err, out)
	}
	root := letter + `:\`
	if err := waitForDriveReady(root); err != nil {
		_ = removeDriveLetter(letter)
		return "", nil, err
	}
	cleanup := func() {
		if err := removeDriveLetter(letter); err != nil {
			fmt.Printf("[MountVolumeToTempLetter] unmount %s failed: %v\n", root, err)
		}
	}
	return root, cleanup, nil
}

// mountVolumeWithDiskpart 用 diskpart 选中分区并分配临时盘符。
func mountVolumeWithDiskpart(part PartitionInfo, letter string) (string, func(), error) {
	if part.DiskNumber < 0 || part.PartitionNumber <= 0 {
		return "", nil, fmt.Errorf("partition info is incomplete for diskpart fallback")
	}
	out, err := RunDiskpart([]string{
		fmt.Sprintf("select disk %d", part.DiskNumber),
		fmt.Sprintf("select partition %d", part.PartitionNumber),
		fmt.Sprintf("assign letter=%s", letter),
	})
	if err != nil {
		return "", nil, fmt.Errorf("diskpart assign %s on disk %d partition %d failed: %w\n输出:\n%s", letter, part.DiskNumber, part.PartitionNumber, err, out)
	}
	if err := diskpartDetectError(out, "assign drive letter"); err != nil {
		return "", nil, err
	}
	root := letter + `:\`
	if err := waitForDriveReady(root); err != nil {
		_ = removeDriveLetter(letter)
		return "", nil, err
	}
	cleanup := func() {
		if err := removeDriveLetter(letter); err != nil {
			fmt.Printf("[MountVolumeToTempLetter] unmount %s failed: %v\n", root, err)
		}
	}
	return root, cleanup, nil
}

func validateESPRoot(root string) error {
	if root == "" {
		return fmt.Errorf("empty ESP root")
	}
	fs, _, err := GetVolumeInfo(root)
	if err != nil {
		return err
	}
	if !strings.EqualFold(fs, "FAT32") {
		return fmt.Errorf("fs=%s, want FAT32", fs)
	}
	return nil
}

func removeDriveLetter(letter string) error {
	letter = strings.ToUpper(strings.TrimSpace(letter))
	letter = strings.TrimSuffix(letter, ":")
	if letter == "" {
		return fmt.Errorf("empty drive letter")
	}
	mountvol := utils.GetSystemExe("mountvol.exe")
	target := letter + ":"
	out, err := tools.RunCmd(mountvol, nil, nil, "", target, "/D")
	if err == nil {
		return nil
	}
	out2, err2 := RunDiskpart([]string{
		fmt.Sprintf("select volume %s", letter),
		fmt.Sprintf("remove letter=%s", letter),
	})
	if err2 == nil {
		if detectErr := diskpartDetectError(out2, "remove drive letter"); detectErr == nil {
			return nil
		}
	}
	return fmt.Errorf("remove drive letter %s failed: mountvol=%v output=%s; diskpart=%v output=%s", target, err, out, err2, out2)
}

func chooseTempDriveLetter() (string, error) {
	roots, err := ListDrive()
	if err != nil {
		return "", fmt.Errorf("ListDrive: %w", err)
	}
	used := map[string]struct{}{"X": {}}
	for _, root := range roots {
		if letter, err := utils.NormalizeDrive(root, 1); err == nil {
			used[strings.ToUpper(letter)] = struct{}{}
		}
	}
	for ch := 'Z'; ch >= 'D'; ch-- {
		letter := string(ch)
		if _, ok := used[letter]; ok {
			continue
		}
		return letter, nil
	}
	return "", fmt.Errorf("no free drive letter available")
}

func waitForDriveReady(root string) error {
	deadline := time.Now().Add(espMountWait)
	for {
		if st, err := os.Stat(root); err == nil && st.IsDir() {
			return nil
		}
		if _, _, err := GetVolumeInfo(root); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("volume %s is not ready", root)
}
