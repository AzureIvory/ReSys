//go:build windows

// 手动模式的分区/卷枚举与展示文本构建。
//
// 手动模式需要展示两类信息：
// 1) “目标分区列表”：通常来自已挂载卷（有盘符），用户用它来选择安装目标。
// 2) “引导分区候选”：来自物理磁盘分区（可能无盘符），用于 UEFI/BIOS 引导修复的选择。
//
// 本文件把来自 disk 包/bitlocker 包的原始信息整理为 PartitionRow，便于 JSONUI 绑定：
// - Summary：列表里展示的一行摘要
// - Detail：右侧详情框多行文本
// - Ref：UI 列表项 Value，用于后续在 Store 中保存/恢复选择
package ui

import (
	bl "ReSys/src/bitlocker"
	"ReSys/src/disk"
	"ReSys/src/dism"
	"ReSys/src/utils"
	winos "ReSys/src/windows"
	"fmt"
	"sort"
	"strings"
)

// manualCollectPartitionRows 枚举系统中的卷与物理分区，并生成两份列表：
// - rows：用于“目标分区”列表（优先选择有盘符的卷，便于安装目标定位）。
// - bootRows：用于“引导分区”候选（包含无盘符的 EFI/MSR/恢复分区等）。
//
// 返回的 rows 会按“当前系统优先 -> 盘符 -> 磁盘号 -> 分区号”排序。
func manualCollectPartitionRows() ([]PartitionRow, []PartitionRow, error) {
	volumes, err := disk.ListVolumes()
	if err != nil {
		return nil, nil, err
	}

	diskInfoByDisk := map[int]disk.DiskInfo{}
	diskStyleByDisk := map[int]string{}
	if disks, err := disk.ListPhysicalDisks(); err == nil {
		for _, info := range disks {
			diskInfoByDisk[info.DiskNumber] = info
			diskStyleByDisk[info.DiskNumber] = strings.TrimSpace(info.PartitionStyle)
		}
	}

	kindByDisk := map[int]string{}
	for _, vol := range volumes {
		root := strings.TrimSpace(vol.RootPath)
		if root == "" && vol.DriveLetter != "" {
			root = vol.DriveLetter
		}
		if root == "" {
			continue
		}
		if _, ok := kindByDisk[vol.DiskNumber]; ok {
			continue
		}
		norm, err := utils.NormalizeDrive(root, 0)
		if err != nil || norm == "" {
			continue
		}
		if kind, err := disk.GetDiskKind(norm); err == nil {
			kindByDisk[vol.DiskNumber] = kind
		}
	}

	diskNumbers := map[int]struct{}{}
	for _, vol := range volumes {
		diskNumbers[vol.DiskNumber] = struct{}{}
	}
	for diskNumber := range diskStyleByDisk {
		diskNumbers[diskNumber] = struct{}{}
	}

	manager := bl.New()
	bitlockerReady := manager.IsAvailable()

	orderedDisks := make([]int, 0, len(diskNumbers))
	for diskNumber := range diskNumbers {
		orderedDisks = append(orderedDisks, diskNumber)
	}
	sort.Ints(orderedDisks)

	bootRows := manualBuildBootRows(
		orderedDisks,
		volumes,
		diskInfoByDisk,
		diskStyleByDisk,
		kindByDisk,
		manager,
		bitlockerReady,
	)
	partByGUID := make(map[string]PartitionRow, len(bootRows))
	partByLetter := make(map[string]PartitionRow, len(bootRows))
	for _, row := range bootRows {
		if key := manualNormalizeGUID(row.VolumeGuidPath); key != "" {
			partByGUID[key] = row
		}
		if key := manualNormalizeDriveLetter(row.DriveLetter); key != "" {
			partByLetter[key] = row
		}
	}

	rows := make([]PartitionRow, 0, len(volumes))
	for _, vol := range volumes {
		letter := manualNormalizeDriveLetter(vol.DriveLetter)
		if letter == "" {
			continue
		}
		targetRoot, err := utils.NormalizeDrive(letter, 0)
		if err != nil || targetRoot == "" {
			continue
		}

		row := PartitionRow{
			DiskNumber:     vol.DiskNumber,
			PartitionType:  T("manual.partition.unknown"),
			DiskStyle:      strings.TrimSpace(diskStyleByDisk[vol.DiskNumber]),
			DiskKind:       utils.FirstNonEmpty(kindByDisk[vol.DiskNumber], "Unknown"),
			FileSystem:     strings.TrimSpace(vol.FileSystem),
			VolumeLabel:    strings.TrimSpace(vol.Label),
			VolumeGuidPath: strings.TrimSpace(vol.VolumeGuidPath),
			DriveLetter:    letter,
			TargetRoot:     targetRoot,
			SizeBytes:      vol.SizeBytes,
			FreeBytes:      vol.FreeBytes,
		}

		if part, ok := partByGUID[manualNormalizeGUID(vol.VolumeGuidPath)]; ok {
			row.PartitionNumber = part.PartitionNumber
			row.PartitionType = utils.FirstNonEmpty(part.PartitionType, row.PartitionType)
			row.Ref = part.Ref
		} else if part, ok := partByLetter[letter]; ok {
			row.PartitionNumber = part.PartitionNumber
			row.PartitionType = utils.FirstNonEmpty(part.PartitionType, row.PartitionType)
			row.Ref = part.Ref
		}

		if row.DiskStyle == "" {
			if style, _, err := disk.GetDiskInfo(row.TargetRoot); err == nil {
				row.DiskStyle = style
			}
		}
		if row.DiskKind == "Unknown" {
			if kind, err := disk.GetDiskKind(row.TargetRoot); err == nil {
				row.DiskKind = kind
			}
		}
		if row.Ref == "" {
			if diskInfo, part, err := disk.FindPartitionByRoot(row.TargetRoot); err == nil {
				row.PartitionNumber = part.PartitionNumber
				row.PartitionType = utils.FirstNonEmpty(part.Type, row.PartitionType)
				if row.DiskStyle == "" {
					row.DiskStyle = strings.TrimSpace(diskInfo.PartitionStyle)
				}
				if ref, err := disk.BuildPartitionRef(diskInfo, part); err == nil {
					row.Ref = ref
				}
			}
		}

		row.CurrentSystem = utils.NeedsPE(row.TargetRoot, winos.SystemDriveRoot())
		row.BitLocker = manualBitLockerText(manager, bitlockerReady, row.TargetRoot)
		row.TargetSelectable = manualIsInstallTarget(row)
		row.Summary = manualPartitionSummary(row)
		row.Detail = manualPartitionDetail(row)
		rows = append(rows, row)
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].CurrentSystem != rows[j].CurrentSystem {
			return rows[i].CurrentSystem
		}
		if rows[i].DriveLetter != rows[j].DriveLetter {
			if rows[i].DriveLetter == "" {
				return false
			}
			if rows[j].DriveLetter == "" {
				return true
			}
			return rows[i].DriveLetter < rows[j].DriveLetter
		}
		if rows[i].DiskNumber != rows[j].DiskNumber {
			return rows[i].DiskNumber < rows[j].DiskNumber
		}
		if rows[i].PartitionNumber != rows[j].PartitionNumber {
			return rows[i].PartitionNumber < rows[j].PartitionNumber
		}
		return rows[i].TargetRoot < rows[j].TargetRoot
	})

	if len(rows) == 0 {
		return nil, bootRows, fmt.Errorf("%s", T("manual.partitions.noneFound"))
	}
	return rows, bootRows, nil
}

// manualBuildBootRows 以“物理磁盘分区”为基础构建 bootRows。
//
// 说明：
// - 物理分区可能没有盘符/挂载点，但仍然可能是 EFI/BIOS 引导分区；
// - 这里会尝试用 VolumeGuidPath 或 DriveLetter 把分区与卷信息关联起来，以补全文件系统/标签/容量。
// - Ref 统一为 `diskNumber:partitionNumber`，便于在下拉框中稳定引用。
func manualBuildBootRows(
	orderedDisks []int,
	volumes []disk.VolumeInfo,
	diskInfoByDisk map[int]disk.DiskInfo,
	diskStyleByDisk map[int]string,
	kindByDisk map[int]string,
	manager *bl.BitLockerManager,
	bitlockerReady bool,
) []PartitionRow {
	volByGUID := map[string]disk.VolumeInfo{}
	volByLetter := map[string]disk.VolumeInfo{}
	for _, vol := range volumes {
		if key := manualNormalizeGUID(vol.VolumeGuidPath); key != "" {
			volByGUID[key] = vol
		}
		if key := manualNormalizeDriveLetter(vol.DriveLetter); key != "" {
			volByLetter[key] = vol
		}
	}

	rows := make([]PartitionRow, 0, len(orderedDisks)*4)
	for _, diskNumber := range orderedDisks {
		parts, err := disk.ListDiskPartitions(diskNumber)
		if err != nil {
			continue
		}
		for _, part := range parts {
			row := PartitionRow{
				DiskNumber:      diskNumber,
				PartitionNumber: part.PartitionNumber,
				PartitionType:   utils.FirstNonEmpty(strings.TrimSpace(part.Type), T("manual.partition.unknown")),
				DiskStyle:       strings.TrimSpace(diskStyleByDisk[diskNumber]),
				DiskKind:        utils.FirstNonEmpty(kindByDisk[diskNumber], "Unknown"),
				VolumeGuidPath:  strings.TrimSpace(part.VolumeGuidPath),
				DriveLetter:     manualNormalizeDriveLetter(part.DriveLetter),
				SizeBytes:       part.SizeBytes,
			}
			if diskInfo, ok := diskInfoByDisk[diskNumber]; ok {
				if ref, err := disk.BuildPartitionRef(diskInfo, part); err == nil {
					row.Ref = ref
				}
			}

			vol, ok := volByGUID[manualNormalizeGUID(part.VolumeGuidPath)]
			if !ok && row.DriveLetter != "" {
				vol, ok = volByLetter[row.DriveLetter]
			}
			if ok {
				if vol.SizeBytes > 0 {
					row.SizeBytes = vol.SizeBytes
					row.FreeBytes = vol.FreeBytes
				}
				row.FileSystem = strings.TrimSpace(vol.FileSystem)
				row.VolumeLabel = strings.TrimSpace(vol.Label)
				if row.VolumeGuidPath == "" {
					row.VolumeGuidPath = strings.TrimSpace(vol.VolumeGuidPath)
				}
			}

			root := ""
			if ok && strings.TrimSpace(vol.RootPath) != "" {
				root = strings.TrimSpace(vol.RootPath)
			} else if row.DriveLetter != "" {
				root = row.DriveLetter
			}
			if norm, err := utils.NormalizeDrive(root, 0); err == nil {
				row.TargetRoot = norm
			}

			if row.DiskStyle == "" && row.TargetRoot != "" {
				if style, _, err := disk.GetDiskInfo(row.TargetRoot); err == nil {
					row.DiskStyle = style
				}
			}
			if row.DiskKind == "Unknown" && row.TargetRoot != "" {
				if kind, err := disk.GetDiskKind(row.TargetRoot); err == nil {
					row.DiskKind = kind
				}
			}

			row.CurrentSystem = utils.NeedsPE(row.TargetRoot, winos.SystemDriveRoot())
			row.BitLocker = manualBitLockerText(manager, bitlockerReady, row.TargetRoot)
			row.TargetSelectable = manualIsInstallTarget(row)
			row.Summary = manualPartitionSummary(row)
			row.Detail = manualPartitionDetail(row)
			rows = append(rows, row)
		}
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].DiskNumber != rows[j].DiskNumber {
			return rows[i].DiskNumber < rows[j].DiskNumber
		}
		return rows[i].PartitionNumber < rows[j].PartitionNumber
	})
	return rows
}

// manualCollectBootTargets 按引导类型（UEFI/BIOS）从 bootRows 中筛选候选分区。
// 排序策略为“同盘优先”，避免用户误选到其它磁盘的引导分区。
func manualCollectBootTargets(target PartitionRow, mode string) []BootTargetOption {
	rows := make([]PartitionRow, 0, 4)
	if utils.BootType(mode, target.DiskStyle) == "UEFI" {
		for _, row := range manual.bootRows {
			if !manualIsUEFIBootPartition(row) {
				continue
			}
			rows = append(rows, row)
		}
		sort.Slice(rows, func(i, j int) bool {
			if rows[i].DiskNumber != rows[j].DiskNumber {
				if rows[i].DiskNumber == target.DiskNumber {
					return true
				}
				if rows[j].DiskNumber == target.DiskNumber {
					return false
				}
				return rows[i].DiskNumber < rows[j].DiskNumber
			}
			return rows[i].PartitionNumber < rows[j].PartitionNumber
		})
		return manualBootTargetOptions(rows)
	}

	for _, row := range manual.bootRows {
		if !manualIsBIOSBootPartition(row) {
			continue
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].DiskNumber != rows[j].DiskNumber {
			if rows[i].DiskNumber == target.DiskNumber {
				return true
			}
			if rows[j].DiskNumber == target.DiskNumber {
				return false
			}
			return rows[i].DiskNumber < rows[j].DiskNumber
		}
		if rows[i].Ref == target.Ref {
			return true
		}
		if rows[j].Ref == target.Ref {
			return false
		}
		return rows[i].PartitionNumber < rows[j].PartitionNumber
	})
	return manualBootTargetOptions(rows)
}

// manualBootTargetOptions 将内部的分区行模型转换为引导分区下拉框可用的选项。
//
// 这里保留 `row.Ref` 作为稳定值，显示文本则继续复用现有的人类可读摘要，
// 从而保证 UI 展示不变，但实际提交给安装流程的是新的统一分区引用。
func manualBootTargetOptions(rows []PartitionRow) []BootTargetOption {
	options := make([]BootTargetOption, 0, len(rows))
	for _, row := range rows {
		options = append(options, BootTargetOption{
			Ref:  row.Ref,
			Text: manualBootTargetText(row),
		})
	}
	return options
}

// manualIsUEFIBootPartition 判断分区是否可能是 EFI 系统分区（ESP）。
// 这里用 “GPT + (类型为 EFI 或 FAT32 + 标签包含 efi/esp 或小容量且不可作为安装目标)” 的启发式规则。
func manualIsUEFIBootPartition(row PartitionRow) bool {
	if !strings.EqualFold(strings.TrimSpace(row.DiskStyle), "GPT") {
		return false
	}
	partType := strings.ToUpper(strings.TrimSpace(row.PartitionType))
	if partType == "EFI" {
		return true
	}
	if !strings.EqualFold(strings.TrimSpace(row.FileSystem), "FAT32") {
		return false
	}
	label := strings.ToLower(strings.TrimSpace(row.VolumeLabel))
	if strings.Contains(label, "efi") || strings.Contains(label, "esp") {
		return true
	}
	return row.SizeBytes > 0 && row.SizeBytes <= 2*1024*1024*1024 && !row.TargetSelectable
}

// manualIsBIOSBootPartition 判断分区是否可能用于 BIOS 引导修复。
// 这里主要筛选 MBR 磁盘上“可访问且不是 EFI/MSR”的分区作为候选。
func manualIsBIOSBootPartition(row PartitionRow) bool {
	if !strings.EqualFold(strings.TrimSpace(row.DiskStyle), "MBR") {
		return false
	}
	if strings.TrimSpace(row.TargetRoot) == "" {
		return false
	}
	partType := strings.ToUpper(strings.TrimSpace(row.PartitionType))
	return partType != "EFI" && partType != "MSR"
}

// manualDefaultPartitionIndex 选择一个默认的目标分区：
// - 优先：当前系统分区且可作为安装目标（常用于“就地重装”场景）。
// - 其次：任意可作为安装目标的分区。
// - 最后：列表首项。
func manualDefaultPartitionIndex() int {
	for i, row := range manual.partitionRows {
		if row.CurrentSystem && row.TargetSelectable {
			return i
		}
	}
	for i, row := range manual.partitionRows {
		if row.TargetSelectable {
			return i
		}
	}
	if len(manual.partitionRows) > 0 {
		return 0
	}
	return -1
}

// manualFindPartitionIndex 在当前 partitionRows 中查找 ref 对应的行索引。
// ref 来自 Store 的 `manual.partitions.selected`，用于校验选择是否仍然有效。
func manualFindPartitionIndex(ref string) int {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return -1
	}
	for i, row := range manual.partitionRows {
		if strings.EqualFold(row.Ref, ref) {
			return i
		}
	}
	return -1
}

// manualIsInstallTarget 判断一个分区是否可作为安装目标。
// 规则偏保守：排除 X:\、EFI/MSR/Recovery、FAT32 等明显不适合作为系统安装分区的项。
func manualIsInstallTarget(row PartitionRow) bool {
	if strings.TrimSpace(row.TargetRoot) == "" || strings.EqualFold(row.TargetRoot, "X:\\") {
		return false
	}
	switch strings.ToUpper(strings.TrimSpace(row.PartitionType)) {
	case "EFI", "MSR", "RECOVERY":
		return false
	}
	return !strings.EqualFold(strings.TrimSpace(row.FileSystem), "FAT32")
}

// manualBitLockerText 将 BitLocker 状态转换为 UI 文案。
// 当分区未挂载或 BitLocker 不可用时，会返回“未挂载/未知”。
func manualBitLockerText(manager *bl.BitLockerManager, ready bool, root string) string {
	if strings.TrimSpace(root) == "" {
		return T("manual.partition.notMounted")
	}
	if !ready || manager == nil {
		return T("manual.partition.bitlocker.unknown")
	}
	letter := strings.TrimSpace(root)
	if len(letter) == 0 {
		return T("manual.partition.bitlocker.unknown")
	}
	switch manager.GetStatus(letter[0]) {
	case bl.VolNotEncrypted:
		return T("manual.partition.bitlocker.notEncrypted")
	case bl.VolEncryptedUnlocked:
		return T("manual.partition.bitlocker.unlocked")
	case bl.VolEncryptedLocked:
		return T("manual.partition.bitlocker.locked")
	case bl.VolEncrypting:
		return T("manual.partition.bitlocker.encrypting")
	case bl.VolDecrypting:
		return T("manual.partition.bitlocker.decrypting")
	default:
		return T("manual.partition.bitlocker.unknown")
	}
}

// manualImageInfoText 构建镜像索引下拉框的显示文本：Index | 名称/描述 | 架构。
func manualImageInfoText(info dism.ImageMeta) string {
	parts := []string{fmt.Sprintf("%d", info.Index)}
	if desc := strings.TrimSpace(info.Description); desc != "" && !strings.EqualFold(desc, info.Name) {
		parts = append(parts, desc)
	} else if name := strings.TrimSpace(info.Name); name != "" {
		parts = append(parts, name)
	}
	if arch := strings.TrimSpace(utils.NormalizeArch(info.Arch)); arch != "" {
		parts = append(parts, manualFriendlyArch(arch))
	}
	return strings.Join(parts, " | ")
}

// manualPartitionSummary 构建“目标分区列表”中的单行摘要文本。
func manualPartitionSummary(row PartitionRow) string {
	parts := make([]string, 0, 5)
	if drive := strings.TrimRight(strings.TrimSpace(row.TargetRoot), `\`); drive != "" {
		parts = append(parts, drive)
	} else {
		parts = append(parts, fmt.Sprintf(T("manual.partition.diskPartitionCompact"), row.DiskNumber, row.PartitionNumber))
	}
	if label := strings.TrimSpace(row.VolumeLabel); label != "" {
		parts = append(parts, label)
	}
	if size := manualSizeText(row.SizeBytes); size != "-" {
		parts = append(parts, size)
	}
	if style := strings.TrimSpace(row.DiskStyle); style != "" {
		parts = append(parts, style)
	}
	if kind := strings.TrimSpace(row.DiskKind); kind != "" && !strings.EqualFold(kind, "Unknown") {
		parts = append(parts, kind)
	}
	return strings.Join(parts, " ")
}

// manualPartitionDetail 构建右侧“分区详情”多行文本。
// 文案会包含容量、文件系统、磁盘/分区编号、分区类型、磁盘类型、BitLocker、是否当前系统等信息。
func manualPartitionDetail(row PartitionRow) string {
	modeText := T("manual.partition.detail.selectable")
	if !row.TargetSelectable {
		modeText = T("manual.partition.detail.viewOnly")
	}
	currentText := T("common.no")
	if row.CurrentSystem {
		currentText = T("common.yes")
	}
	return fmt.Sprintf(
		T("manual.partition.detail.template"),
		utils.FirstNonEmpty(strings.TrimRight(row.TargetRoot, `\`), T("manual.partition.notMounted")),
		utils.FirstNonEmpty(row.VolumeLabel, "-"),
		manualSizeDetailText(row.SizeBytes, row.FreeBytes),
		utils.FirstNonEmpty(row.FileSystem, "-"),
		row.DiskNumber,
		row.PartitionNumber,
		utils.FirstNonEmpty(row.PartitionType, "-"),
		utils.FirstNonEmpty(row.DiskStyle, "-"),
		manualDisplayDiskKind(row.DiskKind),
		utils.FirstNonEmpty(row.BitLocker, "-"),
		currentText,
		modeText,
	)
}

// manualPartitionDisplayName 构建用于列表显示的分区名称（盘符/标签优先）。
func manualPartitionDisplayName(row PartitionRow) string {
	base := strings.TrimRight(row.TargetRoot, `\`)
	if base == "" {
		base = fmt.Sprintf(T("manual.partition.diskPartition"), row.DiskNumber, row.PartitionNumber)
	}
	if row.VolumeLabel != "" {
		base += " " + row.VolumeLabel
	}
	return base
}

// manualBootTargetText 构建“引导分区”下拉框的候选项显示文本。
func manualBootTargetText(row PartitionRow) string {
	name := strings.TrimRight(strings.TrimSpace(row.TargetRoot), `\`)
	if name == "" {
		name = fmt.Sprintf(T("manual.partition.diskPartitionCompact"), row.DiskNumber, row.PartitionNumber)
	}
	if label := strings.TrimSpace(row.VolumeLabel); label != "" {
		name += " " + label
	}
	return fmt.Sprintf(T("manual.boot.targetFormat"), name, row.DiskNumber, row.PartitionNumber)
}

// FriendlyTarget 将内部目标系统标识转为用户可读文本。
func FriendlyTarget(target string) string {
	switch strings.ToLower(strings.TrimSpace(target)) {
	case targetWin7:
		return "Windows 7"
	case targetWin11:
		return "Windows 11"
	case targetWin10:
		return "Windows 10"
	default:
		return T("manual.target.unknown")
	}
}

// manualFriendlyArch 将内部架构标识转为用户可读文本。
func manualFriendlyArch(arch string) string {
	switch strings.TrimSpace(arch) {
	case "32":
		return T("manual.arch.x86")
	case "64":
		return T("manual.arch.x64")
	default:
		if arch == "" {
			return T("manual.arch.unknown")
		}
		return arch
	}
}

// manualSizeText 将字节数转换为简短容量文本（例如 “222.0 GB”）。
func manualSizeText(size uint64) string {
	if size == 0 {
		return "-"
	}
	return dism.BytesToMBGBStr(size)
}

// manualSizeDetailText 生成“总计/可用”容量文本。
func manualSizeDetailText(sizeBytes, freeBytes uint64) string {
	if sizeBytes == 0 {
		return "-"
	}
	if freeBytes == 0 {
		return fmt.Sprintf(T("manual.size.total"), manualSizeText(sizeBytes))
	}
	return fmt.Sprintf(T("manual.size.totalFree"), manualSizeText(sizeBytes), manualSizeText(freeBytes))
}

func manualDisplayDiskKind(kind string) string {
	if strings.EqualFold(strings.TrimSpace(kind), "Unknown") {
		return T("manual.partition.unknown")
	}
	return utils.FirstNonEmpty(kind, "-")
}

// manualNormalizeGUID 规范化 GUID 路径（统一大小写/空白）。
func manualNormalizeGUID(path string) string {
	return strings.ToUpper(strings.TrimSpace(path))
}

// manualNormalizeDriveLetter 规范化盘符（返回单字母，如 "C"；无效则返回空）。
func manualNormalizeDriveLetter(letter string) string {
	letter = strings.ToUpper(strings.TrimSpace(letter))
	letter = strings.TrimRight(letter, `:\`)
	if len(letter) == 1 {
		return letter
	}
	return ""
}
