//go:build windows

// 手动模式（高级模式）的运行时逻辑。
//
// 这个文件负责“事件处理 + 异步加载 + Store 更新”，不负责实际的安装动作。
// UI 的结构/布局在 JSON 中声明（json ui），Go 侧通过修改 Store 来驱动 UI：
// - 镜像选择/索引：`manual.image.*`
// - 分区列表/详情：`manual.partitions.*`
// - 引导修复：`manual.boot.*`
// - 安装选项与按钮状态：`manual.options.*`
//
// 实际安装流程由外部注入的 StartManualInstall 执行；本文件只负责收集参数并触发它。
package ui

import (
	"ReSys/src/dism"
	imgsvc "ReSys/src/image"
	"fmt"
	"strings"

	"github.com/AzureIvory/winui/widgets"
)

// StartManualInstall 由安装模块在初始化时注入，用于执行手动模式的实际安装流程。
//
// UI 层只负责收集参数并触发该回调：
// - 不在这里做分区格式化/应用镜像/引导修复等耗时操作；
// - 该回调会在 goroutine 中调用，不保证运行在 UI 线程。
var StartManualInstall = func(src string) {}

// manualUIState 是手动模式的内存状态缓存。
// JSONUI 的 Store 适合做“可绑定的 UI 状态”，而一些派生数据/缓存更适合留在 Go 内存里：
// - imageInfos/partitionRows/bootRows：避免每次读取 Store 都要重复解析/计算；
// - partitionLoadID：用于异步加载的“代号”，防止慢请求覆盖新请求的结果。
type manualUIState struct {
	imagePath        string
	imageInfos       []dism.ImageMeta
	imageParseErr    string
	partitionRows    []manualPartitionRow
	bootRows         []manualPartitionRow
	partitionError   string
	bootTargets      []manualBootTargetOption
	partitionLoading bool
	partitionLoadID  uint64
}

// manualPartitionRow 是手动模式里展示分区/卷信息的行模型。
//
// 其中 Ref 是 UI 列表项的 Value：
// - 对“已挂载卷”通常是类似 `C:\` 的根路径；
// - 对“未挂载/引导候选分区”通常是 `diskNumber:partitionNumber`。
type manualPartitionRow struct {
	DiskNumber       int
	PartitionNumber  int
	PartitionType    string
	DiskStyle        string
	DiskKind         string
	FileSystem       string
	VolumeLabel      string
	VolumeGuidPath   string
	DriveLetter      string
	TargetRoot       string
	SizeBytes        uint64
	FreeBytes        uint64
	BitLocker        string
	TargetSelectable bool
	CurrentSystem    bool
	Ref              string
	Summary          string
	Detail           string
}

// manualBootTargetOption 是“引导分区”下拉框的候选项。
type manualBootTargetOption struct {
	Ref  string
	Text string
}

const (
	// manualBootRepairAuto: 自动判断 BIOS/UEFI，并选择合适的引导分区。
	manualBootRepairAuto = "auto"
	// manualBootRepairSkip: 不做引导修复。
	manualBootRepairSkip = "skip"
	// manualBootRepairUEFI: 强制按 UEFI 修复引导。
	manualBootRepairUEFI = "uefi"
	// manualBootRepairBIOS: 强制按 BIOS 修复引导。
	manualBootRepairBIOS = "bios"
)

var manual manualUIState

// destroyManualMode 释放手动模式的内存缓存。
// 当页面销毁/切换时可调用，避免残留旧数据影响下一次进入。
func destroyManualMode() {
	manual = manualUIState{}
}

// UiShowManualMode 切换到“手动模式”页面，并异步加载分区列表。
//
// 设计要点：
// - 页面切换必须在 UI 线程执行；
// - 磁盘枚举/分区扫描较慢，放到后台 goroutine，完成后再 Post 回 UI 线程更新 Store。
func UiShowManualMode() {
	show := func() {
		applyMode(modeManual)
		if ui.app != nil {
			manualRefreshPartitionsAsync()
		}
	}
	if ui.app == nil || ui.app.IsUIThread() {
		show()
		return
	}
	_ = ui.app.Post(show)
}

// manualHandleImageIndexChange 处理“镜像索引”变更。
// 这里会更新 Store，并联动刷新：引导分区候选、详情文本、底部汇总说明。
func manualHandleImageIndexChange(value string) {
	manualSetState("manual.image.selected", strings.TrimSpace(value))
	manualRefreshBootTargets()
	manualUpdateDetail()
	manualUpdateSummary()
}

// manualHandlePartitionChange 处理“目标分区”变更。
func manualHandlePartitionChange(ref string) {
	manualApplyPartitionSelection(ref)
}

// manualHandleAutoPEChange 处理“自动处理 PE”开关。
func manualHandleAutoPEChange(checked bool) {
	manualSetState("manual.options.autoPE", checked)
	manualUpdatePEInputState()
	manualUpdateSummary()
}

// manualHandlePEPathChange 处理“PE WIM 路径”输入变更。
func manualHandlePEPathChange(path string) {
	manualSetState("manual.options.pePath", strings.TrimSpace(path))
	manualUpdateSummary()
}

// manualHandleBootModeChange 处理“引导修复模式”变更。
func manualHandleBootModeChange(value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		value = manualBootRepairAuto
	}
	manualSetState("manual.boot.mode", value)
	manualRefreshBootTargets()
	manualUpdateSummary()
}

// manualHandleBootTargetChange 处理“引导分区”下拉框变更。
func manualHandleBootTargetChange(value string) {
	manualSetState("manual.boot.target", strings.TrimSpace(value))
	manualUpdateSummary()
}

// manualHandleOptionChange 处理通用的布尔选项变更（格式化/备份驱动/无人值守/自动重启等）。
func manualHandleOptionChange(path string, checked bool) {
	manualSetState(path, checked)
	manualUpdateSummary()
}

// manualHandleStart 点击“开始重装”。
// 这里仅做校验与二次确认，然后切到进度页并在后台调用 StartManualInstall。
func manualHandleStart() {
	text, err := manualBuildJSON()
	if err != nil {
		UiShowError("", err.Error())
		return
	}
	if !Message("", T("dialog.manualInstallConfirm")) {
		return
	}
	applyMode(modeProgress)
	go StartManualInstall(text)
}

// manualLoadImage 处理“安装镜像路径”变更：解析镜像并刷新索引列表。
//
// 解析结果会缓存在 manual.imageInfos 中，用于后续派生：
// - 自动推断目标系统（Win7/10/11）
// - 汇总显示架构/版本信息
func manualLoadImage(path string) {
	path = strings.TrimSpace(path)
	manual.imagePath = path
	manual.imageInfos = nil
	manual.imageParseErr = ""
	manualPatchState(map[string]any{
		"manual.image.path":             path,
		"manual.image.items":            []widgets.ListItem{},
		"manual.image.selected":         "",
		"manual.image.indexPlaceholder": T("manual.image.indexPlaceholder"),
	})
	if path == "" {
		manualRefreshBootTargets()
		manualUpdateDetail()
		manualUpdateSummary()
		return
	}

	infos, err := imgsvc.DetectImageInfos(path)
	if err != nil {
		manual.imageParseErr = fmt.Sprintf(T("manual.image.parseFailed"), err)
		manualSetState("manual.image.indexPlaceholder", T("manual.image.parseFailedShort"))
		manualRefreshBootTargets()
		manualUpdateDetail()
		manualUpdateSummary()
		return
	}

	manual.imageInfos = infos
	items := make([]widgets.ListItem, 0, len(infos))
	selectedIndex := 0
	preferredIndex := imgsvc.SelectInstallIndex(infos)
	for i, info := range infos {
		items = append(items, widgets.ListItem{
			Value: fmt.Sprintf("%d", info.Index),
			Text:  manualImageInfoText(info),
		})
		if info.Index == preferredIndex {
			selectedIndex = i
		}
	}

	selectedValue := ""
	placeholder := T("manual.image.selectIndex")
	if len(items) > 0 {
		selectedValue = items[selectedIndex].Value
	} else {
		placeholder = T("manual.image.noIndex")
	}
	manualPatchState(map[string]any{
		"manual.image.items":            items,
		"manual.image.selected":         selectedValue,
		"manual.image.indexPlaceholder": placeholder,
	})
	manualRefreshBootTargets()
	manualUpdateDetail()
	manualUpdateSummary()
}

// manualRefreshPartitionsAsync 异步扫描分区/卷信息。
//
// 由于扫描可能耗时且会触发外部命令/系统 API，因此放到后台 goroutine。
// partitionLoadID 用作“加载代号”：当多次触发刷新时，旧请求完成后会被丢弃，避免覆盖新结果。
func manualRefreshPartitionsAsync() {
	if ui.app == nil {
		return
	}

	prevRef := manualSelectedPartitionRef()
	manual.partitionLoadID++
	loadID := manual.partitionLoadID
	manual.partitionError = ""
	manualSetLoading(true, T("manual.loading.disks"))
	go func(prevRef string, loadID uint64) {
		rows, bootRows, err := manualCollectPartitionRows()
		if ui.app == nil {
			return
		}
		_ = ui.app.Post(func() {
			if loadID != manual.partitionLoadID {
				return
			}
			manualApplyPartitionRows(prevRef, rows, bootRows, err)
		})
	}(prevRef, loadID)
}

// manualSetLoading 同步更新“加载中/可操作”状态，并联动刷新派生状态。
// 当 loading=true 时会禁用分区列表与引导选择，避免用户在数据未就绪时操作。
func manualSetLoading(loading bool, text string) {
	if strings.TrimSpace(text) == "" {
		text = T("manual.loading.disks")
	}
	manual.partitionLoading = loading
	patch := map[string]any{
		"manual.partitions.loading":     loading,
		"manual.partitions.loadingText": text,
		"manual.partitions.listEnabled": !loading,
	}
	if loading {
		patch["manual.partitions.selected"] = ""
		patch["manual.partitions.detail"] = T("manual.detail.loading")
		patch["manual.boot.targets"] = []widgets.ListItem{}
		patch["manual.boot.target"] = ""
		patch["manual.boot.placeholder"] = T("manual.loading.disks")
	}
	manualPatchState(patch)
	manualUpdatePEInputState()
	manualUpdateBootTargetState()
	manualUpdateSummary()
}

// manualApplyPartitionRows 将扫描结果写入内存缓存与 Store。
// - 成功：填充分区列表 items，并尽量保持上一次选择（prevRef）；否则选择一个默认分区。
// - 失败：清空列表并提示错误信息。
func manualApplyPartitionRows(prevRef string, rows, bootRows []manualPartitionRow, err error) {
	manual.partitionRows = rows
	manual.bootRows = bootRows
	manual.partitionError = ""
	manualSetLoading(false, "")
	if err != nil {
		manual.partitionRows = nil
		manual.bootRows = nil
		manual.partitionError = err.Error()
		manualPatchState(map[string]any{
			"manual.partitions.items":    []widgets.ListItem{},
			"manual.partitions.selected": "",
			"manual.partitions.detail":   T("manual.partitions.readFailed"),
		})
		manualRefreshBootTargets()
		manualUpdatePEInputState()
		manualUpdateSummary()
		return
	}

	items := make([]widgets.ListItem, 0, len(rows))
	for _, row := range rows {
		items = append(items, widgets.ListItem{Value: row.Ref, Text: row.Summary})
	}

	selectedRef := strings.TrimSpace(prevRef)
	if manualFindPartitionIndex(selectedRef) < 0 {
		selectedRef = ""
		if selectedIndex := manualDefaultPartitionIndex(); selectedIndex >= 0 {
			selectedRef = rows[selectedIndex].Ref
		}
	}
	manualPatchState(map[string]any{
		"manual.partitions.items":    items,
		"manual.partitions.selected": selectedRef,
	})
	if selectedRef != "" {
		manualApplyPartitionSelection(selectedRef)
		return
	}
	manualSetState("manual.partitions.detail", T("manual.partitions.none"))
	manualRefreshBootTargets()
	manualUpdatePEInputState()
	manualUpdateSummary()
}

// manualApplyPartitionSelection 应用用户选择的目标分区，并刷新详情/引导候选/汇总。
func manualApplyPartitionSelection(ref string) {
	ref = strings.TrimSpace(ref)
	if manualFindPartitionIndex(ref) < 0 {
		manualPatchState(map[string]any{
			"manual.partitions.selected": "",
			"manual.partitions.detail":   T("manual.detail.default"),
		})
		manualRefreshBootTargets()
		manualUpdatePEInputState()
		manualUpdateSummary()
		return
	}
	manualSetState("manual.partitions.selected", ref)
	manualUpdateDetail()
	manualRefreshBootTargets()
	manualUpdatePEInputState()
	manualUpdateSummary()
}
