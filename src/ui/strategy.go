//go:build windows

// 手动模式（高级模式）的派生状态与配置构建。
//
// 与 manual_runtime.go 的区别：
// - runtime 负责响应事件、异步加载并 Patch Store。
// - strategy 负责基于当前 Store/缓存计算“应该显示什么/是否就绪/最终配置是什么”。
//
// 这里的函数大多是纯逻辑（或只读 Store），便于以后将策略与 UI 宿主解耦。
package ui

import (
	"ReSys/src/config"
	"ReSys/src/dism"
	imgsvc "ReSys/src/image"
	"ReSys/src/utils"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/AzureIvory/winui/widgets"
)

var manualConfigPath = func() (string, error) {
	return utils.ProjectFile(filepath.Join("rules", "install", "default.json"))
}

var manualAutoConfigPath = func(targetOS string) (string, error) {
	return utils.ProjectFile(
		filepath.Join("rules", "install", "auto", manualTemplateTargetOS(targetOS)+".json"),
	)
}

// manualDefaultConfig 读取手动重装的默认 JSON 配置。
func manualDefaultConfig() (config.Config, error) {
	path, err := manualConfigPath()
	if err != nil {
		return config.Config{}, err
	}
	return config.ParseSource(path)
}

func manualAutoTemplateConfig(targetOS string) (config.Config, error) {
	path, err := manualAutoConfigPath(targetOS)
	if err != nil {
		return config.Config{}, err
	}
	return config.ParseSource(path)
}

func manualTemplateTargetOS(targetOS string) string {
	switch strings.ToLower(strings.TrimSpace(targetOS)) {
	case targetWin7:
		return targetWin7
	case targetWin11:
		return targetWin11
	default:
		return targetWin10
	}
}

// manualUpdateDetail 根据当前选择生成“分区详情”文本。
// 当分区与镜像都已选择时，会把镜像索引/架构等信息追加到详情中，便于用户确认。
func manualUpdateDetail() {
	detail := T("manual.detail.default")
	switch {
	case manual.partitionLoading:
		detail = T("manual.detail.loading")
	default:
		row, ok := manualSelectedPartition()
		if ok {
			detail = row.Detail
			if info, ok := mSelectedImageInfo(); ok {
				detail += fmt.Sprintf(
					T("manual.detail.imageLine"),
					FriendlyTarget(mSelectedTargetOS()),
					info.Index,
					manualFriendlyArch(utils.NormalizeArch(info.Arch)),
				)
			}
		}
	}
	manualSetState("manual.partitions.detail", detail)
}

// RefreshBootTargets 根据目标分区与引导修复模式，刷新“引导分区”下拉候选项。
//
// 注意：
// - 自动模式下不需要用户选择引导分区，因此这里会清空 targets，只更新 placeholder 文案。
// - 手动模式下会从 manual.bootRows 中筛选 EFI/BIOS 候选分区，并按“同盘优先”排序。
func RefreshBootTargets() {
	if manual.partitionLoading {
		manual.bootTargets = nil
		manualPatchState(map[string]any{
			"manual.boot.targets":       []widgets.ListItem{},
			"manual.boot.target":        "",
			"manual.boot.placeholder":   T("manual.loading.disks"),
			"manual.boot.targetEnabled": false,
		})
		UpdateBootTargetState()
		return
	}

	row, ok := manualSelectedPartition()
	mode := manualSelectedBootMode()
	if !ok {
		manual.bootTargets = nil
		manualPatchState(map[string]any{
			"manual.boot.targets":     []widgets.ListItem{},
			"manual.boot.target":      "",
			"manual.boot.placeholder": T("manual.boot.placeholder.selectTarget"),
		})
		UpdateBootTargetState()
		return
	}

	if mode == manualBootRepairSkip {
		manual.bootTargets = nil
		manualPatchState(map[string]any{
			"manual.boot.targets":     []widgets.ListItem{},
			"manual.boot.target":      "",
			"manual.boot.placeholder": T("manual.boot.placeholder.disabled"),
		})
		UpdateBootTargetState()
		return
	}

	if mode == manualBootRepairAuto {
		manual.bootTargets = nil
		placeholder := T("manual.boot.placeholder.autoBIOS")
		if strings.EqualFold(row.DiskStyle, "GPT") {
			placeholder = T("manual.boot.placeholder.autoUEFI")
		}
		manualPatchState(map[string]any{
			"manual.boot.targets":     []widgets.ListItem{},
			"manual.boot.target":      "",
			"manual.boot.placeholder": placeholder,
		})
		UpdateBootTargetState()
		return
	}

	prevRef := manualSelectedBootTargetRef()
	manual.bootTargets = manualCollectBootTargets(row, mode)
	items := make([]widgets.ListItem, 0, len(manual.bootTargets))
	selectedRef := ""
	for _, option := range manual.bootTargets {
		items = append(items, widgets.ListItem{Value: option.Ref, Text: option.Text})
		if strings.EqualFold(option.Ref, prevRef) {
			selectedRef = option.Ref
		}
	}
	placeholder := T("manual.boot.placeholder.selectBIOS")
	if utils.BootType(mode, row.DiskStyle) == "UEFI" {
		placeholder = T("manual.boot.placeholder.selectUEFI")
	}
	if len(items) == 0 {
		if utils.BootType(mode, row.DiskStyle) == "UEFI" {
			placeholder = T("manual.boot.placeholder.noUEFI")
		} else {
			placeholder = T("manual.boot.placeholder.noBIOS")
		}
	}
	manualPatchState(map[string]any{
		"manual.boot.targets":     items,
		"manual.boot.target":      selectedRef,
		"manual.boot.placeholder": placeholder,
	})
	UpdateBootTargetState()
}

// manualUpdatePEInputState 控制“自动处理 PE”与“手动 PE WIM 路径”的可用性。
// 规则：当目标分区就是当前系统分区时，通常需要 PE 环境协助（否则会覆盖正在运行的系统）。
func manualUpdatePEInputState() {
	if manual.partitionLoading {
		manualPatchState(map[string]any{
			"manual.options.autoPEEnabled": false,
			"manual.options.peEnabled":     false,
		})
		return
	}

	row, ok := manualSelectedPartition()
	needsPE := ok && row.CurrentSystem
	manualPatchState(map[string]any{
		"manual.options.autoPEEnabled": needsPE,
		"manual.options.peEnabled":     needsPE && !manualOptionAutoPE(),
	})
}

// UpdateBootTargetState 根据当前模式与候选数量，决定下拉框是否可操作。
// 同时会联动更新“开始重装”按钮是否可点（manualUpdateActionState）。
func UpdateBootTargetState() {
	manualSetState(
		"manual.boot.targetEnabled",
		!manual.partitionLoading && manualUsesBootTarget() && len(manual.bootTargets) > 0,
	)
	manualUpdateActionState()
}

// manualUpdateActionState 根据校验结果更新“开始重装”按钮状态。
func manualUpdateActionState() {
	manualSetState("manual.options.startEnabled", manualValidationReason() == "")
}

func manualSyncDerivedOptionState() {
	manualSetState("manual.options.win7FixEnabled", true)
}

// manualUpdateSummary 更新底部汇总提示。
//
// 汇总内容来源于当前缓存 + Store：
// - 镜像是否已解析、目标系统/架构信息
// - 目标分区是否可作为安装目标
// - 引导修复概览（自动/UEFI/BIOS/关闭）
// - 选项开关（格式化/备份驱动/无人值守/自动重启）
// - 未就绪原因（manualValidationReason）
func manualUpdateSummary() {
	if ui.store == nil {
		return
	}

	manualSyncDerivedOptionState()

	parts := make([]string, 0, 8)
	if manual.partitionLoading {
		parts = append(parts, T("manual.loading.disks"))
	}

	if strings.TrimSpace(manual.imagePath) == "" {
		parts = append(parts, T("manual.summary.noImage"))
	} else if manual.imageParseErr != "" {
		parts = append(parts, manual.imageParseErr)
	} else if info, ok := mSelectedImageInfo(); ok {
		parts = append(parts, fmt.Sprintf(
			T("manual.summary.image"),
			FriendlyTarget(mSelectedTargetOS()),
			info.Index,
			manualFriendlyArch(utils.NormalizeArch(info.Arch)),
		))
	} else {
		parts = append(parts, T("manual.summary.waitingIndex"))
	}

	if row, ok := manualSelectedPartition(); ok {
		if row.TargetSelectable {
			parts = append(parts, fmt.Sprintf(T("manual.summary.target"), manualPartitionDisplayName(row)))
			if row.CurrentSystem {
				if manualOptionAutoPE() {
					parts = append(parts, T("manual.summary.currentAutoPE"))
				} else {
					parts = append(parts, T("manual.summary.currentManualPE"))
				}
			} else {
				parts = append(parts, T("manual.summary.offlineInstall"))
			}
		} else {
			parts = append(parts, fmt.Sprintf(T("manual.summary.viewOnly"), manualPartitionDisplayName(row)))
		}
	} else if manual.partitionError != "" {
		parts = append(parts, manual.partitionError)
	} else {
		parts = append(parts, T("manual.summary.noTarget"))
	}

	if bootSummary := manualBootRepairSummary(); bootSummary != "" {
		parts = append(parts, bootSummary)
	}

	options := make([]string, 0, 6)
	if manualOptionFormatTarget() {
		options = append(options, T("manual.option.short.format"))
	}
	if manualOptionBackupDrivers() {
		options = append(options, T("manual.option.short.backupDrivers"))
	}
	if manualOptionAutoDeploy() {
		options = append(options, T("manual.option.short.autoDeploy"))
	}
	if manualOptionAutoReboot() {
		options = append(options, T("manual.option.short.autoReboot"))
	}
	if manualOptionWin7Fix() {
		options = append(options, T("manual.option.short.win7Fix"))
	}
	if manualOptionPostProcess() {
		options = append(options, T("manual.option.short.postProcess"))
	}
	if len(options) > 0 {
		parts = append(parts, T("manual.summary.optionsPrefix")+strings.Join(options, "/"))
	}

	if reason := manualValidationReason(); reason != "" {
		parts = append(parts, T("manual.summary.notReadyPrefix")+reason)
	}

	ui.store.Set("manual.summary", strings.Join(parts, " | "))
	manualUpdateActionState()
}

// manualBuildJSON 将当前 UI 状态收敛为手动重装 JSON 文本。
func manualBuildJSON() (string, error) {
	if reason := manualValidationReason(); reason != "" {
		return "", fmt.Errorf("%s", reason)
	}

	cfg, err := manualDefaultConfig()
	if err != nil {
		return "", err
	}

	row, _ := manualSelectedPartition()
	info, _ := mSelectedImageInfo()
	partition := strings.TrimRight(strings.TrimSpace(row.TargetRoot), `\`)
	peWIM := ""
	if row.CurrentSystem && !manualOptionAutoPE() {
		peWIM = manualPEPath()
	}

	bootPart := config.Auto
	if text := strings.TrimSpace(manualSelectedBootTargetRef()); text != "" {
		bootPart = text
	}

	fileRules := []string{}
	guidRules := []string{}
	backupDrivers := manualOptionBackupDrivers()
	if backupDrivers {
		fileRules = SelectedDriverFileRules()
		guidRules = SelectedDriverGUIDs()
		if len(fileRules) == 0 && len(guidRules) == 0 {
			backupDrivers = false
		}
	}

	targetOS := mSelectedTargetOS()
	postProcessEnabled := manualOptionPostProcess()
	files := []config.FileItem{}
	shortcuts := []config.ShortcutItem{}
	if postProcessEnabled {
		files = normalizePostProcessFileItems(manual.postProcessFiles)
		shortcuts = cloneShortcutItems(manual.postProcessShortcuts)
	}
	win7Fix, err := manualDefaultWin7Fix(targetOS)
	if err != nil {
		return "", err
	}
	if !manualOptionWin7Fix() {
		win7Fix = config.Win7Fix{}
	}

	cfg.Mode = "manual"
	cfg.TargetOS = targetOS
	cfg.ImageArch = utils.NormalizeArch(info.Arch)
	cfg.ImagePath = strings.TrimSpace(manual.imagePath)
	cfg.Index = info.Index
	cfg.Partition = partition
	cfg.PEWIM = peWIM
	cfg.Boot = config.Boot{
		Method:        manualSelectedBootMode(),
		BootPartition: bootPart,
	}
	cfg.Restart = manualOptionAutoReboot()
	cfg.Unattended = config.Unattended{
		State: manualOptionAutoDeploy(),
		File:  config.Auto,
	}
	cfg.BackupDriver = config.BackupDriver{
		State: backupDrivers,
		File:  fileRules,
		GUID:  guidRules,
	}
	cfg.Format = config.Format{
		State:  manualOptionFormatTarget(),
		FS:     "NTFS",
		Quick:  true,
		Letter: config.Auto,
		Label:  "",
	}
	cfg.File = config.FileConfig{
		State: len(files) > 0,
		Items: files,
	}
	cfg.Shortcut = config.Shortcut{
		State: len(shortcuts) > 0,
		Items: shortcuts,
	}
	cfg.Win7Fix = win7Fix
	return config.Marshal(cfg)
}

func manualDefaultWin7Fix(targetOS string) (config.Win7Fix, error) {
	cfg, err := manualAutoTemplateConfig(targetWin7)
	if err != nil {
		return config.Win7Fix{}, err
	}
	return cfg.Win7Fix, nil
}

// mSelectedImageInfo 从缓存的 imageInfos 中按 Store 里选中的索引找出对应镜像元信息。
func mSelectedImageInfo() (dism.ImageMeta, bool) {
	selected := manualStoreString("manual.image.selected", "")
	if selected == "" {
		return dism.ImageMeta{}, false
	}
	for _, info := range manual.imageInfos {
		if fmt.Sprintf("%d", info.Index) == selected {
			return info, true
		}
	}
	return dism.ImageMeta{}, false
}

// manualSelectedPartition 根据 Store 中选中的 Ref，返回对应的分区行模型。
func manualSelectedPartition() (PartitionRow, bool) {
	ref := manualSelectedPartitionRef()
	if ref == "" {
		return PartitionRow{}, false
	}
	for _, row := range manual.partitionRows {
		if strings.EqualFold(row.Ref, ref) {
			return row, true
		}
	}
	return PartitionRow{}, false
}

// manualSelectedPartitionRef 返回 Store 中当前选择的目标分区 Ref。
func manualSelectedPartitionRef() string {
	return manualStoreString("manual.partitions.selected", "")
}

// manualSelectedBootMode 返回当前引导修复模式，空值会回退到 auto。
func manualSelectedBootMode() string {
	mode := manualStoreString("manual.boot.mode", manualBootRepairAuto)
	if mode == "" {
		return manualBootRepairAuto
	}
	return mode
}

// manualBootRepairSummary 生成引导修复的可读摘要，用于底部汇总提示。
func manualBootRepairSummary() string {
	switch manualSelectedBootMode() {
	case manualBootRepairSkip:
		return T("manual.boot.summary.disabled")
	case manualBootRepairUEFI:
		if text := manualSelectedBootTargetText(); text != "" {
			return fmt.Sprintf(T("manual.boot.summary.uefiTarget"), text)
		}
		return T("manual.boot.summary.uefi")
	case manualBootRepairBIOS:
		if text := manualSelectedBootTargetText(); text != "" {
			return fmt.Sprintf(T("manual.boot.summary.biosTarget"), text)
		}
		return T("manual.boot.summary.bios")
	default:
		row, ok := manualSelectedPartition()
		if ok {
			return fmt.Sprintf(T("manual.boot.summary.autoType"), utils.BootType(manualBootRepairAuto, row.DiskStyle))
		}
		return T("manual.boot.summary.auto")
	}
}

// manualSelectedBootTargetText 将当前选中的 BootTargetRef 转换为显示文本。
func manualSelectedBootTargetText() string {
	ref := strings.TrimSpace(manualSelectedBootTargetRef())
	if ref == "" {
		return ""
	}
	for _, option := range manual.bootTargets {
		if strings.EqualFold(option.Ref, ref) {
			return option.Text
		}
	}
	return ""
}

// manualSelectedBootTargetRef 返回 Store 中当前选择的引导分区 Ref。
func manualSelectedBootTargetRef() string {
	return manualStoreString("manual.boot.target", "")
}

// mSelectedTargetOS 尝试从镜像信息推断目标系统（Win7/10/11）。
// 优先使用 image 服务的 DetectTargetFromInfos；否则再做简单的字符串包含匹配。
func mSelectedTargetOS() string {
	if target := imgsvc.DetectTargetFromInfos(manual.imageInfos); target != "" {
		return target
	}
	info, ok := mSelectedImageInfo()
	if !ok {
		return ""
	}
	return utils.DetectTarget(info.Name, info.Description, info.Edition, info.Flags)
}

// manualValidationReason 返回“当前不允许开始安装”的原因（空字符串表示就绪）。
// 该函数集中描述 UI 就绪条件，用于：
// - 底部汇总提示里的“未就绪: ...”
// - 开始按钮 enable/disable
func manualValidationReason() string {
	if manual.partitionLoading {
		return T("manual.validation.loading")
	}
	if strings.TrimSpace(manual.imagePath) == "" {
		return T("manual.validation.selectImage")
	}
	if manual.imageParseErr != "" {
		return manual.imageParseErr
	}
	info, ok := mSelectedImageInfo()
	if !ok || info.Index <= 0 {
		return T("manual.validation.selectIndex")
	}
	row, ok := manualSelectedPartition()
	if !ok {
		return T("manual.validation.selectTarget")
	}
	if !row.TargetSelectable {
		return T("manual.validation.targetNotSelectable")
	}
	if utils.MissingPE(row.CurrentSystem, manualOptionAutoPE(), manualPEPath()) {
		return T("manual.validation.peRequired")
	}
	return ""
}

// manualOptionAutoPE 从 Store 读取“自动处理 PE”开关。
func manualOptionAutoPE() bool {
	return manualStoreBool("manual.options.autoPE", true)
}

// manualOptionFormatTarget 从 Store 读取“格式化目标分区”开关。
func manualOptionFormatTarget() bool {
	return manualStoreBool("manual.options.formatTarget", true)
}

// manualOptionBackupDrivers 从 Store 读取“备份驱动”开关。
func manualOptionBackupDrivers() bool {
	return manualStoreBool("manual.options.backupDrivers", false)
}

// manualOptionAutoDeploy 从 Store 读取“无人值守”开关。
func manualOptionAutoDeploy() bool {
	return manualStoreBool("manual.options.autoDeploy", true)
}

// manualOptionAutoReboot 从 Store 读取“自动重启”开关。
func manualOptionAutoReboot() bool {
	return manualStoreBool("manual.options.autoReboot", true)
}

func manualOptionWin7Fix() bool {
	return manualStoreBool("manual.options.win7Fix", false)
}

func manualOptionPostProcess() bool {
	return manualStoreBool("manual.options.postProcess", false)
}

// manualPEPath 读取“手动指定 PE WIM”的路径。
func manualPEPath() string {
	return manualStoreString("manual.options.pePath", "")
}

func manualUsesBootTarget() bool {
	switch manualSelectedBootMode() {
	case manualBootRepairUEFI, manualBootRepairBIOS:
		return true
	default:
		return false
	}
}

// manualPatchState 批量 Patch Store（适合一次更新多个字段）。
// Patch 支持 `a.b.c` 路径语法，JSONUI 会自动把更改分发到绑定的控件。
func manualPatchState(values map[string]any) {
	if ui.store == nil || len(values) == 0 {
		return
	}
	ui.store.Patch(values)
}

// manualSetState 设置单个 Store 字段。
func manualSetState(path string, value any) {
	if ui.store == nil || strings.TrimSpace(path) == "" {
		return
	}
	ui.store.Set(path, value)
}

// manualStoreString 从 Store 中读取字符串。
// Store 里的值可能来自控件上报，因此这里做了类型与空白修剪兜底。
func manualStoreString(path string, fallback string) string {
	if ui.store == nil {
		return fallback
	}
	value, ok := ui.store.Get(path)
	if !ok || value == nil {
		return fallback
	}
	switch text := value.(type) {
	case string:
		text = strings.TrimSpace(text)
		if text == "" {
			return fallback
		}
		return text
	default:
		textValue := strings.TrimSpace(fmt.Sprint(value))
		if textValue == "" {
			return fallback
		}
		return textValue
	}
}

// manualStoreBool 从 Store 中读取布尔值。
// 兼容控件上报字符串形式（"true"/"1"/"on" 等）。
func manualStoreBool(path string, fallback bool) bool {
	if ui.store == nil {
		return fallback
	}
	value, ok := ui.store.Get(path)
	if !ok || value == nil {
		return fallback
	}
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		switch strings.ToLower(strings.TrimSpace(typed)) {
		case "true", "1", "yes", "on":
			return true
		case "false", "0", "no", "off":
			return false
		}
	}
	return fallback
}
