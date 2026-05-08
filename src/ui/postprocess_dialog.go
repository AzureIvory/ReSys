package ui

import (
	"ReSys/src/config"
	"ReSys/src/utils"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/AzureIvory/winui/widgets"
)

// postProcessModalSnapshot 保存打开对话框前的已有配置，取消时用于回滚。
type postProcessModalSnapshot struct {
	enabled   bool
	files     []config.FileItem
	shortcuts []config.ShortcutItem
}

const defaultPostProcessShortcutDir = `\Users\Public\Desktop`

// HandlePostProcessChange 响应用户勾选或取消后处理选项。
// 勾选时打开配置对话框，取消时清空所有后处理状态。
func HandlePostProcessChange(checked bool) {
	previousEnabled := manualOptionPostProcess()
	if !checked {
		manualResetPostProcessState()
		manualSetState("manual.options.postProcess", false)
		manualUpdateSummary()
		return
	}

	if err := manualOpenPostProcessDialog(previousEnabled); err != nil {
		manualResetPostProcessState()
		manualSetState("manual.options.postProcess", false)
		UiShowError("", err.Error())
		manualUpdateSummary()
		return
	}

	manualSetState("manual.options.postProcess", true)
	manualUpdateSummary()
}

// HandlePostProcessReset 根据当前目标系统重新加载默认的文件和快捷方式模板，
// 并重新解析启动预设。
func HandlePostProcessReset() {
	files, shortcuts, err := manualDefaultPostProcessPayload(mSelectedTargetOS())
	if err != nil {
		UiShowError("", err.Error())
		return
	}

	manual.postProcessLaunchPresets = parseLaunchPresets(mSelectedTargetOS())
	manual.postProcessDraftFiles = files
	manual.postProcessDraftShortcuts = shortcuts
	manualSyncPostProcessStore()
}

// HandlePostProcessConfirm 确认对话框中的修改，将草稿正式生效。
func HandlePostProcessConfirm() {
	manual.postProcessFiles = normalizePostProcessFileItems(manual.postProcessDraftFiles)
	manual.postProcessShortcuts = cloneShortcutItems(manual.postProcessDraftShortcuts)
	manual.postProcessOpen = postProcessModalSnapshot{}
	manualSetState("manual.options.postProcess", true)
	manualSetState("manual.postprocess.visible", false)
	manualUpdateSummary()
}

// HandlePostProcessCancel 取消对话框修改，恢复到打开前的快照状态。
func HandlePostProcessCancel() {
	if manual.postProcessOpen.enabled {
		manual.postProcessFiles = cloneFileItems(manual.postProcessOpen.files)
		manual.postProcessShortcuts = cloneShortcutItems(manual.postProcessOpen.shortcuts)
		manualSetState("manual.options.postProcess", true)
	} else {
		manualResetPostProcessState()
		manualSetState("manual.options.postProcess", false)
	}

	manual.postProcessDraftFiles = nil
	manual.postProcessDraftShortcuts = nil
	manual.postProcessOpen = postProcessModalSnapshot{}
	manualSetState("manual.postprocess.visible", false)
	manualUpdateSummary()
}

// HandlePostProcessFileSelect 选中文件列表中的某一项，回填到编辑表单。
// 同时根据目标路径自动匹配启动方式：可启动文件（bat/cmd/exe/msi）匹配 .cmd 预设，
// 不可启动文件（如 xml）强制"不启动"并禁用下拉框。
func HandlePostProcessFileSelect(value string) {
	if idx, ok := postProcessSelectionIndex(value, len(manual.postProcessDraftFiles)); ok {
		item := manual.postProcessDraftFiles[idx]
		launch, launchEnabled := detectLaunchType(item.Dst)
		manual.postProcessDraftFiles[idx].Launch = launch
		manualPatchState(map[string]any{
			"manual.postprocess.files.selected":           strconv.Itoa(idx),
			"manual.postprocess.files.form.src":           item.Src,
			"manual.postprocess.files.form.dst":           item.Dst,
			"manual.postprocess.files.form.overwrite":     item.Overwrite,
			"manual.postprocess.files.form.required":      item.Required,
			"manual.postprocess.files.form.launch":        launch,
			"manual.postprocess.files.form.launchEnabled": launchEnabled,
		})
		return
	}

	manualPatchState(blankPostProcessFileFormPatch(""))
}

// HandlePostProcessFileAdd 从表单取值并追加到文件草稿列表。
func HandlePostProcessFileAdd() {
	item, err := manualPostProcessFileFormItem()
	if err != nil {
		UiShowError("", err.Error())
		return
	}

	manual.postProcessDraftFiles = append(manual.postProcessDraftFiles, item)
	manualSyncPostProcessStore()
	HandlePostProcessFileSelect(strconv.Itoa(len(manual.postProcessDraftFiles) - 1))
}

// HandlePostProcessFileSave 将表单修改保存到当前选中的文件项。
func HandlePostProcessFileSave() {
	item, err := manualPostProcessFileFormItem()
	if err != nil {
		UiShowError("", err.Error())
		return
	}

	idx, ok := postProcessSelectionIndex(manualStoreString("manual.postprocess.files.selected", ""), len(manual.postProcessDraftFiles))
	if !ok {
		HandlePostProcessFileAdd()
		return
	}

	manual.postProcessDraftFiles[idx] = item
	manualSyncPostProcessStore()
	HandlePostProcessFileSelect(strconv.Itoa(idx))
}

// HandlePostProcessFileDelete 从草稿列表中删除当前选中的文件项。
func HandlePostProcessFileDelete() {
	idx, ok := postProcessSelectionIndex(manualStoreString("manual.postprocess.files.selected", ""), len(manual.postProcessDraftFiles))
	if !ok {
		return
	}

	manual.postProcessDraftFiles = append(
		cloneFileItems(manual.postProcessDraftFiles[:idx]),
		manual.postProcessDraftFiles[idx+1:]...,
	)
	manualSyncPostProcessStore()
}

// HandlePostProcessShortcutSelect 选中快捷方式列表中的某一项，回填到编辑表单。
func HandlePostProcessShortcutSelect(value string) {
	if idx, ok := postProcessSelectionIndex(value, len(manual.postProcessDraftShortcuts)); ok {
		item := manual.postProcessDraftShortcuts[idx]
		manualPatchState(map[string]any{
			"manual.postprocess.shortcuts.selected":    strconv.Itoa(idx),
			"manual.postprocess.shortcuts.form.target": item.Target,
			"manual.postprocess.shortcuts.form.name":   item.Name,
			"manual.postprocess.shortcuts.form.dir":    item.Dir,
		})
		return
	}

	manualPatchState(blankPostProcessShortcutFormPatch(""))
}

// HandlePostProcessShortcutAdd 从表单取值并追加到快捷方式草稿列表。
func HandlePostProcessShortcutAdd() {
	item, err := manualPostProcessShortcutFormItem()
	if err != nil {
		UiShowError("", err.Error())
		return
	}

	manual.postProcessDraftShortcuts = append(manual.postProcessDraftShortcuts, item)
	manualSyncPostProcessStore()
	HandlePostProcessShortcutSelect(strconv.Itoa(len(manual.postProcessDraftShortcuts) - 1))
}

// HandlePostProcessShortcutSave 将表单修改保存到当前选中的快捷方式项。
func HandlePostProcessShortcutSave() {
	item, err := manualPostProcessShortcutFormItem()
	if err != nil {
		UiShowError("", err.Error())
		return
	}

	idx, ok := postProcessSelectionIndex(
		manualStoreString("manual.postprocess.shortcuts.selected", ""),
		len(manual.postProcessDraftShortcuts),
	)
	if !ok {
		HandlePostProcessShortcutAdd()
		return
	}

	manual.postProcessDraftShortcuts[idx] = item
	manualSyncPostProcessStore()
	HandlePostProcessShortcutSelect(strconv.Itoa(idx))
}

// HandlePostProcessShortcutDelete 从草稿列表中删除当前选中的快捷方式项。
func HandlePostProcessShortcutDelete() {
	idx, ok := postProcessSelectionIndex(
		manualStoreString("manual.postprocess.shortcuts.selected", ""),
		len(manual.postProcessDraftShortcuts),
	)
	if !ok {
		return
	}

	manual.postProcessDraftShortcuts = append(
		cloneShortcutItems(manual.postProcessDraftShortcuts[:idx]),
		manual.postProcessDraftShortcuts[idx+1:]...,
	)
	manualSyncPostProcessStore()
}

// manualOpenPostProcessDialog 打开后处理配置对话框。
// 首次启用时加载默认模板，再次打开则保留已有配置。
func manualOpenPostProcessDialog(previousEnabled bool) error {
	manual.postProcessOpen = postProcessModalSnapshot{
		enabled:   previousEnabled,
		files:     normalizePostProcessFileItems(manual.postProcessFiles),
		shortcuts: cloneShortcutItems(manual.postProcessShortcuts),
	}

	// 解析当前系统的 .cmd 预设，用于后续自动匹配启动方式。
	manual.postProcessLaunchPresets = parseLaunchPresets(mSelectedTargetOS())

	files := normalizePostProcessFileItems(manual.postProcessFiles)
	shortcuts := cloneShortcutItems(manual.postProcessShortcuts)
	if !previousEnabled {
		var err error
		files, shortcuts, err = manualDefaultPostProcessPayload(mSelectedTargetOS())
		if err != nil {
			return err
		}
	}

	manual.postProcessDraftFiles = files
	manual.postProcessDraftShortcuts = shortcuts
	manualSyncPostProcessStore()
	manualSetState("manual.postprocess.visible", true)
	return nil
}

// manualResetPostProcessState 清空所有后处理相关状态。
func manualResetPostProcessState() {
	manual.postProcessFiles = nil
	manual.postProcessDraftFiles = nil
	manual.postProcessShortcuts = nil
	manual.postProcessDraftShortcuts = nil
	manual.postProcessOpen = postProcessModalSnapshot{}
	manualPatchState(map[string]any{
		"manual.postprocess.visible":                  false,
		"manual.postprocess.files.items":              []widgets.ListItem{},
		"manual.postprocess.files.selected":           "",
		"manual.postprocess.files.form.src":           "",
		"manual.postprocess.files.form.dst":           "",
		"manual.postprocess.files.form.overwrite":     true,
		"manual.postprocess.files.form.required":      false,
		"manual.postprocess.files.form.launch":        config.LaunchNone,
		"manual.postprocess.files.form.launchItems":   postProcessLaunchItems(),
		"manual.postprocess.files.form.launchEnabled": false,
		"manual.postprocess.shortcuts.items":          []widgets.ListItem{},
		"manual.postprocess.shortcuts.selected":       "",
		"manual.postprocess.shortcuts.form.target":    "",
		"manual.postprocess.shortcuts.form.name":      "",
		"manual.postprocess.shortcuts.form.dir":       defaultPostProcessShortcutDir,
	})
}

// manualSyncPostProcessStore 将草稿列表同步到 UI 状态树，刷新列表视图和表单。
func manualSyncPostProcessStore() {
	fileSelected := manualStoreString("manual.postprocess.files.selected", "")
	shortcutSelected := manualStoreString("manual.postprocess.shortcuts.selected", "")

	fileFormPatch := blankPostProcessFileFormPatch(fileSelected)
	if idx, ok := postProcessSelectionIndex(fileSelected, len(manual.postProcessDraftFiles)); ok {
		item := manual.postProcessDraftFiles[idx]
		_, launchEnabled := detectLaunchType(item.Dst)
		fileFormPatch = map[string]any{
			"manual.postprocess.files.selected":           strconv.Itoa(idx),
			"manual.postprocess.files.form.src":           item.Src,
			"manual.postprocess.files.form.dst":           item.Dst,
			"manual.postprocess.files.form.overwrite":     item.Overwrite,
			"manual.postprocess.files.form.required":      item.Required,
			"manual.postprocess.files.form.launch":        item.Launch,
			"manual.postprocess.files.form.launchItems":   postProcessLaunchItems(),
			"manual.postprocess.files.form.launchEnabled": launchEnabled,
		}
	}

	shortcutFormPatch := blankPostProcessShortcutFormPatch(shortcutSelected)
	if idx, ok := postProcessSelectionIndex(shortcutSelected, len(manual.postProcessDraftShortcuts)); ok {
		shortcutFormPatch = map[string]any{
			"manual.postprocess.shortcuts.selected":    strconv.Itoa(idx),
			"manual.postprocess.shortcuts.form.target": manual.postProcessDraftShortcuts[idx].Target,
			"manual.postprocess.shortcuts.form.name":   manual.postProcessDraftShortcuts[idx].Name,
			"manual.postprocess.shortcuts.form.dir":    manual.postProcessDraftShortcuts[idx].Dir,
		}
	}

	patch := map[string]any{
		"manual.postprocess.files.items":     postProcessFileListItems(manual.postProcessDraftFiles),
		"manual.postprocess.shortcuts.items": postProcessShortcutListItems(manual.postProcessDraftShortcuts),
	}
	for key, value := range fileFormPatch {
		patch[key] = value
	}
	for key, value := range shortcutFormPatch {
		patch[key] = value
	}
	manualPatchState(patch)
}

// manualDefaultPostProcessPayload 根据目标系统加载默认的后处理模板。
func manualDefaultPostProcessPayload(targetOS string) ([]config.FileItem, []config.ShortcutItem, error) {
	cfg, err := manualAutoTemplateConfig(targetOS)
	if err != nil {
		return nil, nil, err
	}
	return normalizePostProcessFileItems(cfg.File.Items), cloneShortcutItems(cfg.Shortcut.Items), nil
}

// manualPostProcessFileFormItem 从文件编辑表单中读取并校验数据。
func manualPostProcessFileFormItem() (config.FileItem, error) {
	item := config.FileItem{
		Src:       strings.TrimSpace(manualStoreString("manual.postprocess.files.form.src", "")),
		Dst:       strings.TrimSpace(manualStoreString("manual.postprocess.files.form.dst", "")),
		Overwrite: true,
		Required:  false,
		Launch:    strings.TrimSpace(manualStoreString("manual.postprocess.files.form.launch", config.LaunchNone)),
	}
	if item.Src == "" {
		return config.FileItem{}, fmt.Errorf("请填写文件源路径")
	}
	if item.Dst == "" {
		return config.FileItem{}, fmt.Errorf("请填写文件目标路径")
	}
	return item, nil
}

// manualPostProcessShortcutFormItem 从快捷方式编辑表单中读取并校验数据。
func manualPostProcessShortcutFormItem() (config.ShortcutItem, error) {
	item := config.ShortcutItem{
		Target: strings.TrimSpace(manualStoreString("manual.postprocess.shortcuts.form.target", "")),
		Name:   strings.TrimSpace(manualStoreString("manual.postprocess.shortcuts.form.name", "")),
		Dir:    strings.TrimSpace(manualStoreString("manual.postprocess.shortcuts.form.dir", defaultPostProcessShortcutDir)),
	}
	if item.Target == "" {
		return config.ShortcutItem{}, fmt.Errorf("请填写快捷方式目标")
	}
	if item.Name == "" {
		return config.ShortcutItem{}, fmt.Errorf("请填写快捷方式名称")
	}
	if item.Dir == "" {
		return config.ShortcutItem{}, fmt.Errorf("请填写快捷方式目录")
	}
	return item, nil
}

// postProcessSelectionIndex 将 UI 传来的字符串索引转为合法的 int 下标。
func postProcessSelectionIndex(raw string, length int) (int, bool) {
	if length <= 0 {
		return 0, false
	}
	index, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || index < 0 || index >= length {
		return 0, false
	}
	return index, true
}

// postProcessFileListItems 将文件列表转为 UI 组件需要的 ListItem 格式。
func postProcessFileListItems(items []config.FileItem) []widgets.ListItem {
	out := make([]widgets.ListItem, 0, len(items))
	for i, item := range items {
		text := fmt.Sprintf("%s -> %s", strings.TrimSpace(item.Src), strings.TrimSpace(item.Dst))
		if badge := postProcessLaunchBadge(item.Launch); badge != "" {
			text = badge + " " + text
		}
		out = append(out, widgets.ListItem{
			Value: strconv.Itoa(i),
			Text:  text,
		})
	}
	return out
}

// postProcessLaunchBadge 返回启动方式的简短本地化标签。
func postProcessLaunchBadge(launch string) string {
	switch launch {
	case config.LaunchFirstLogon:
		return "[" + T("manual.postprocess.launch.badge.firstLogon") + "]"
	case config.LaunchSpecialize:
		return "[" + T("manual.postprocess.launch.badge.specialize") + "]"
	default:
		return ""
	}
}

// postProcessLaunchItems 返回启动方式下拉框的三个选项。
func postProcessLaunchItems() []widgets.ListItem {
	return []widgets.ListItem{
		{Value: config.LaunchNone, Text: T("manual.postprocess.launch.none")},
		{Value: config.LaunchFirstLogon, Text: T("manual.postprocess.launch.firstLogon")},
		{Value: config.LaunchSpecialize, Text: T("manual.postprocess.launch.specialize")},
	}
}

// HandlePostProcessFileLaunchChange 处理启动方式下拉框变更。
func HandlePostProcessFileLaunchChange(value string) {
	idx, ok := postProcessSelectionIndex(
		manualStoreString("manual.postprocess.files.selected", ""),
		len(manual.postProcessDraftFiles),
	)
	if !ok {
		return
	}
	manual.postProcessDraftFiles[idx].Launch = strings.TrimSpace(value)
	manualSyncPostProcessStore()
}

// postProcessShortcutListItems 将快捷方式列表转为 UI 组件需要的 ListItem 格式。
func postProcessShortcutListItems(items []config.ShortcutItem) []widgets.ListItem {
	out := make([]widgets.ListItem, 0, len(items))
	for i, item := range items {
		out = append(out, widgets.ListItem{
			Value: strconv.Itoa(i),
			Text:  fmt.Sprintf("%s -> %s", strings.TrimSpace(item.Name), strings.TrimSpace(item.Target)),
		})
	}
	return out
}

// blankPostProcessFileFormPatch 返回清空文件表单的状态补丁。
func blankPostProcessFileFormPatch(selected string) map[string]any {
	return map[string]any{
		"manual.postprocess.files.selected":           selected,
		"manual.postprocess.files.form.src":           "",
		"manual.postprocess.files.form.dst":           "",
		"manual.postprocess.files.form.overwrite":     true,
		"manual.postprocess.files.form.required":      false,
		"manual.postprocess.files.form.launch":        config.LaunchNone,
		"manual.postprocess.files.form.launchItems":   postProcessLaunchItems(),
		"manual.postprocess.files.form.launchEnabled": false,
	}
}

// blankPostProcessShortcutFormPatch 返回清空快捷方式表单的状态补丁。
func blankPostProcessShortcutFormPatch(selected string) map[string]any {
	return map[string]any{
		"manual.postprocess.shortcuts.selected":    selected,
		"manual.postprocess.shortcuts.form.target": "",
		"manual.postprocess.shortcuts.form.name":   "",
		"manual.postprocess.shortcuts.form.dir":    defaultPostProcessShortcutDir,
	}
}

// cloneFileItems 深拷贝文件列表，避免共享底层数组。
func cloneFileItems(items []config.FileItem) []config.FileItem {
	if len(items) == 0 {
		return []config.FileItem{}
	}
	cloned := make([]config.FileItem, len(items))
	copy(cloned, items)
	return cloned
}

// normalizePostProcessFileItems 规范化文件项：统一设置 Overwrite 和 Required 字段。
func normalizePostProcessFileItems(items []config.FileItem) []config.FileItem {
	if len(items) == 0 {
		return []config.FileItem{}
	}
	normalized := make([]config.FileItem, 0, len(items))
	for _, item := range items {
		item.Overwrite = true
		item.Required = false
		normalized = append(normalized, item)
	}
	return normalized
}

// cloneShortcutItems 深拷贝快捷方式列表，避免共享底层数组。
func cloneShortcutItems(items []config.ShortcutItem) []config.ShortcutItem {
	if len(items) == 0 {
		return []config.ShortcutItem{}
	}
	cloned := make([]config.ShortcutItem, len(items))
	copy(cloned, items)
	return cloned
}

// detectLaunchType 根据目标路径判断启动方式和下拉框是否可用。
// 只有 bat/cmd/exe/msi 文件可选启动方式，其余强制"不启动"并禁用。
func detectLaunchType(dst string) (launch string, enabled bool) {
	ext := strings.ToLower(filepath.Ext(dst))
	launch = config.LaunchNone
	switch ext {
	case ".bat", ".cmd", ".exe", ".msi":
		enabled = true
		name := strings.ToLower(filepath.Base(dst))
		if t, ok := manual.postProcessLaunchPresets[name]; ok {
			launch = t
		}
	default:
		enabled = false
	}
	return
}

// parseLaunchPresets 解析对应系统的 .cmd 文件中 start 命令，
// 返回“文件名 → 启动方式”的映射。
func parseLaunchPresets(targetOS string) map[string]string {
	presets := map[string]string{}
	var cmdFiles map[string]string

	switch normalizeManualTargetOS(targetOS) {
	case targetWin7:
		cmdFiles = map[string]string{
			`tools\Setup\Scripts7\Scripts\FirstLogon.cmd`: config.LaunchFirstLogon,
			`tools\Setup\Scripts7\Scripts\Specialize.cmd`: config.LaunchSpecialize,
		}
	case targetWin10, targetWin11:
		cmdFiles = map[string]string{
			`tools\Setup\Scripts\unattend-01.cmd`: config.LaunchFirstLogon,
			`tools\Setup\Scripts\unattend-02.cmd`: config.LaunchSpecialize,
		}
	default:
		return presets
	}

	for cmdRelPath, launchType := range cmdFiles {
		absPath, err := utils.ProjectFile(filepath.FromSlash(cmdRelPath))
		if err != nil {
			continue
		}
		data, err := os.ReadFile(absPath)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			if target := parseStartTarget(line); target != "" {
				presets[strings.ToLower(filepath.Base(target))] = launchType
			}
		}
	}
	return presets
}

// parseStartTarget 从一行 start 命令中提取被启动的可执行文件路径。
// 支持 "start \"title\" \"C:\\path\\to\\file.exe\" /args" 和 "start C:\\file.exe" 两种格式。
func parseStartTarget(line string) string {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(strings.ToLower(line), "start ") {
		return ""
	}
	rest := strings.TrimSpace(line[6:])
	// 跳过可选的带引号标题
	if strings.HasPrefix(rest, "\"") {
		if end := strings.IndexByte(rest[1:], '"'); end >= 0 {
			rest = strings.TrimSpace(rest[end+2:])
		}
	}
	// 下一个参数是被启动的目标（可能带引号）
	if strings.HasPrefix(rest, "\"") {
		if end := strings.IndexByte(rest[1:], '"'); end >= 0 {
			return rest[1 : end+1]
		}
	}
	fields := strings.Fields(rest)
	if len(fields) > 0 {
		return fields[0]
	}
	return ""
}
