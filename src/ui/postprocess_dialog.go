package ui

import (
	"ReSys/src/config"
	"fmt"
	"strconv"
	"strings"

	"github.com/AzureIvory/winui/widgets"
)

type postProcessModalSnapshot struct {
	enabled   bool
	files     []config.FileItem
	shortcuts []config.ShortcutItem
}

const defaultPostProcessShortcutDir = `\Users\Public\Desktop`

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

func HandlePostProcessReset() {
	files, shortcuts, err := manualDefaultPostProcessPayload(mSelectedTargetOS())
	if err != nil {
		UiShowError("", err.Error())
		return
	}

	manual.postProcessDraftFiles = files
	manual.postProcessDraftShortcuts = shortcuts
	manualSyncPostProcessStore()
}

func HandlePostProcessConfirm() {
	manual.postProcessFiles = normalizePostProcessFileItems(manual.postProcessDraftFiles)
	manual.postProcessShortcuts = cloneShortcutItems(manual.postProcessDraftShortcuts)
	manual.postProcessOpen = postProcessModalSnapshot{}
	manualSetState("manual.options.postProcess", true)
	manualSetState("manual.postprocess.visible", false)
	manualUpdateSummary()
}

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

func HandlePostProcessFileSelect(value string) {
	if idx, ok := postProcessSelectionIndex(value, len(manual.postProcessDraftFiles)); ok {
		item := manual.postProcessDraftFiles[idx]
		manualPatchState(map[string]any{
			"manual.postprocess.files.selected":       strconv.Itoa(idx),
			"manual.postprocess.files.form.src":       item.Src,
			"manual.postprocess.files.form.dst":       item.Dst,
			"manual.postprocess.files.form.overwrite": item.Overwrite,
			"manual.postprocess.files.form.required":  item.Required,
		})
		return
	}

	manualPatchState(blankPostProcessFileFormPatch(""))
}

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

func manualOpenPostProcessDialog(previousEnabled bool) error {
	manual.postProcessOpen = postProcessModalSnapshot{
		enabled:   previousEnabled,
		files:     normalizePostProcessFileItems(manual.postProcessFiles),
		shortcuts: cloneShortcutItems(manual.postProcessShortcuts),
	}

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

func manualResetPostProcessState() {
	manual.postProcessFiles = nil
	manual.postProcessDraftFiles = nil
	manual.postProcessShortcuts = nil
	manual.postProcessDraftShortcuts = nil
	manual.postProcessOpen = postProcessModalSnapshot{}
	manualPatchState(map[string]any{
		"manual.postprocess.visible":               false,
		"manual.postprocess.files.items":           []widgets.ListItem{},
		"manual.postprocess.files.selected":        "",
		"manual.postprocess.files.form.src":        "",
		"manual.postprocess.files.form.dst":        "",
		"manual.postprocess.files.form.overwrite":  true,
		"manual.postprocess.files.form.required":   false,
		"manual.postprocess.shortcuts.items":       []widgets.ListItem{},
		"manual.postprocess.shortcuts.selected":    "",
		"manual.postprocess.shortcuts.form.target": "",
		"manual.postprocess.shortcuts.form.name":   "",
		"manual.postprocess.shortcuts.form.dir":    defaultPostProcessShortcutDir,
	})
}

func manualSyncPostProcessStore() {
	fileSelected := manualStoreString("manual.postprocess.files.selected", "")
	shortcutSelected := manualStoreString("manual.postprocess.shortcuts.selected", "")

	fileFormPatch := blankPostProcessFileFormPatch(fileSelected)
	if idx, ok := postProcessSelectionIndex(fileSelected, len(manual.postProcessDraftFiles)); ok {
		fileFormPatch = map[string]any{
			"manual.postprocess.files.selected":       strconv.Itoa(idx),
			"manual.postprocess.files.form.src":       manual.postProcessDraftFiles[idx].Src,
			"manual.postprocess.files.form.dst":       manual.postProcessDraftFiles[idx].Dst,
			"manual.postprocess.files.form.overwrite": manual.postProcessDraftFiles[idx].Overwrite,
			"manual.postprocess.files.form.required":  manual.postProcessDraftFiles[idx].Required,
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

func manualDefaultPostProcessPayload(targetOS string) ([]config.FileItem, []config.ShortcutItem, error) {
	cfg, err := manualAutoTemplateConfig(targetOS)
	if err != nil {
		return nil, nil, err
	}
	return normalizePostProcessFileItems(cfg.File.Items), cloneShortcutItems(cfg.Shortcut.Items), nil
}

func manualPostProcessFileFormItem() (config.FileItem, error) {
	item := config.FileItem{
		Src:       strings.TrimSpace(manualStoreString("manual.postprocess.files.form.src", "")),
		Dst:       strings.TrimSpace(manualStoreString("manual.postprocess.files.form.dst", "")),
		Overwrite: true,
		Required:  false,
	}
	if item.Src == "" {
		return config.FileItem{}, fmt.Errorf("请填写文件源路径")
	}
	if item.Dst == "" {
		return config.FileItem{}, fmt.Errorf("请填写文件目标路径")
	}
	return item, nil
}

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

func postProcessFileListItems(items []config.FileItem) []widgets.ListItem {
	out := make([]widgets.ListItem, 0, len(items))
	for i, item := range items {
		out = append(out, widgets.ListItem{
			Value: strconv.Itoa(i),
			Text:  fmt.Sprintf("%s -> %s", strings.TrimSpace(item.Src), strings.TrimSpace(item.Dst)),
		})
	}
	return out
}

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

func blankPostProcessFileFormPatch(selected string) map[string]any {
	return map[string]any{
		"manual.postprocess.files.selected":       selected,
		"manual.postprocess.files.form.src":       "",
		"manual.postprocess.files.form.dst":       "",
		"manual.postprocess.files.form.overwrite": true,
		"manual.postprocess.files.form.required":  false,
	}
}

func blankPostProcessShortcutFormPatch(selected string) map[string]any {
	return map[string]any{
		"manual.postprocess.shortcuts.selected":    selected,
		"manual.postprocess.shortcuts.form.target": "",
		"manual.postprocess.shortcuts.form.name":   "",
		"manual.postprocess.shortcuts.form.dir":    defaultPostProcessShortcutDir,
	}
}

func cloneFileItems(items []config.FileItem) []config.FileItem {
	if len(items) == 0 {
		return []config.FileItem{}
	}
	cloned := make([]config.FileItem, len(items))
	copy(cloned, items)
	return cloned
}

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

func cloneShortcutItems(items []config.ShortcutItem) []config.ShortcutItem {
	if len(items) == 0 {
		return []config.ShortcutItem{}
	}
	cloned := make([]config.ShortcutItem, len(items))
	copy(cloned, items)
	return cloned
}
