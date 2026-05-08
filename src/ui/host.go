//go:build windows

// JSONUI 宿主加载与运行时桥接。
//
// 目标：让 UI 的“结构/布局/样式”全部在 json ui中声明，
// Go 侧只负责三件事：
// 1) 初始化 Store（UI 状态容器），并提供默认状态（defaultUIState）。
// 2) 把 JSON 中声明的 action 名称映射到 Go 回调（uiActionHandlers）。
// 3) 准备资源与主题：把内嵌图标/GIF 解包到临时目录（ensureUIAssets），并提供 Theme。
//
// 约定：Store 的 key 路径（例如 `manual.partitions.items`）必须与 JSON 中的 data 绑定一致，
// 否则控件虽然能渲染出来，但不会显示正确的数据/状态。
package ui

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"ReSys/res"
	"ReSys/src/config"
	"ReSys/src/utils"

	"github.com/AzureIvory/winui/widgets"
	"github.com/AzureIvory/winui/widgets/jsonui"
)

var (
	// uiAssetsOnce 确保资源只解包一次，避免反复写临时文件造成 IO 开销。
	uiAssetsOnce    sync.Once
	uiAssetsDir     string
	uiAssetsErr     error
	loadUIAppConfig = config.LoadAppConfig
	uiLayoutExists  = utils.FileExists
	uiProjectFile   = utils.ProjectFile
)

// newUIStore 创建一个新的 Store，并填充默认 UI 状态。
// Store 是 JSONUI 的“数据源”，UI 只声明 data 绑定路径，不直接访问业务层对象。
func newUIStore() *jsonui.Store {
	return jsonui.NewStore(defaultUIState())
}

// loadUIJSON 读取布局 JSON，组装成可运行的 jsonui.Document。
//
// 这里会同时注入：
// - ActionHandlers：把 UI 事件回调到 Go。
// - AssetsDir：JSON 中引用的 image/gif 等资源的实际目录（由 ensureUIAssets 解包提供）。
// - Data：Store（用于 data 绑定与 Patch/Set 驱动 UI 更新）。
// - Theme：统一字体、颜色、按钮风格等。
//
// ImageSizeDP 设为 48，作为窗口/按钮图片的默认 DP 基准尺寸。
func loadUIJSON(store *jsonui.Store) (*jsonui.Document, error) {
	if store == nil {
		store = newUIStore()
	}

	layoutPath, err := uiLayoutPath()
	if err != nil {
		return nil, err
	}

	assetsDir, err := ensureUIAssets()
	if err != nil {
		return nil, err
	}

	return jsonui.LoadDocumentFile(layoutPath, jsonui.LoadOptions{
		ActionHandlers: uiActionHandlers(),
		AssetsDir:      assetsDir,
		Data:           store,
		DefaultMode:    widgets.ModeCustom,
		Theme:          widgets.DefaultTheme(),
		ImageSizeDP:    48,
	})
}

// uiLayoutPath 在运行时定位 `rules/ui/default/default.json`。
//
// 兼容两种常见启动方式：
// - 开发期：从当前工作目录开始向上查找。
// - 发布版：从可执行文件所在目录开始向上查找。
//
// 为了避免扫描整个磁盘，这里最多向上回溯 5 层目录。
func uiLayoutPath() (string, error) {
	if cfg, err := loadUIAppConfig(); err == nil {
		themePath := cfg.UI.Theme
		if themePath != "" && uiLayoutExists(themePath) {
			return themePath, nil
		}
	}
	return uiProjectFile(config.DefaultUIThemeRelativePath)
}

// defaultUIState 定义 UI 初始状态。
//
// 说明：
// - JSONUI 的 Patch/Set 支持使用 `a.b.c` 的路径写入嵌套对象。
// - 列表型字段使用空切片而不是 nil，避免渲染层把 nil 视作 “没有数据结构”。
// - 这里的 key 路径应与 `rules/ui/default/default.json` 中的 data 绑定一致。
func defaultUIState() map[string]any {
	return map[string]any{
		"i18n": i18nSnapshot(),
		"window": map[string]any{
			"title": T("window.title"),
		},
		"pages": map[string]any{
			"selectVisible":   true,
			"progressVisible": false,
			"manualVisible":   false,
		},
		"progress": map[string]any{
			"status":         T("progress.preparing"),
			"value":          int32(0),
			"spinnerPlaying": false,
		},
		"manual": map[string]any{
			"summary": T("manual.summary.default"),
			"image": map[string]any{
				"path":             "",
				"placeholder":      T("manual.image.placeholder"),
				"indexPlaceholder": T("manual.image.indexPlaceholder"),
				"selected":         "",
				"items":            []widgets.ListItem{},
			},
			"system": map[string]any{
				"selected": targetOther,
				"items":    localizedTargetSystemItems(),
			},
			"language": map[string]any{
				"selected": i18nLanguage,
				"items":    availableLanguages(),
			},
			"partitions": map[string]any{
				"selected":    "",
				"items":       []widgets.ListItem{},
				"detail":      T("manual.detail.default"),
				"loading":     false,
				"loadingText": T("manual.loading.disks"),
				"listEnabled": true,
			},
			"boot": map[string]any{
				"mode":          manualBootRepairAuto,
				"modeItems":     localizedBootModeItems(),
				"target":        "",
				"targets":       []widgets.ListItem{},
				"targetEnabled": false,
				"placeholder":   T("manual.boot.placeholder.auto"),
			},
			"options": map[string]any{
				"autoPE":         true,
				"autoPEEnabled":  false,
				"pePath":         "",
				"peEnabled":      false,
				"formatTarget":   true,
				"backupDrivers":  false,
				"autoReboot":     true,
				"win7Fix":        false,
				"win7FixEnabled": false,
				"postProcess":    false,
				"startEnabled":   false,
			},
			"driver": map[string]any{
				"visible":     false,
				"infPatterns": "",
				"summary":     T("manual.driver.summary.empty"),
			},
			"postprocess": map[string]any{
				"visible": false,
				"files": map[string]any{
					"items":    []widgets.ListItem{},
					"selected": "",
					"form": map[string]any{
						"src":       "",
						"dst":       "",
						"overwrite": true,
						"required":  false,
					},
				},
				"shortcuts": map[string]any{
					"items":    []widgets.ListItem{},
					"selected": "",
					"form": map[string]any{
						"target": "",
						"name":   "",
						"dir":    `\Users\Public\Desktop`,
					},
				},
			},
		},
		"prompt": map[string]any{
			"visible":    false,
			"title":      T("prompt.title"),
			"text":       "",
			"error":      "",
			"credential": "",
		},
		"msgbox": map[string]any{
			"visible":    false,
			"title":      "",
			"text":       "",
			"showOk":     false,
			"showCancel": false,
			"showYes":    false,
			"showNo":     false,
			"showRetry":  false,
			"okText":     T("common.ok"),
			"cancelText": T("common.cancel"),
			"yesText":    T("common.yes"),
			"noText":     T("common.no"),
			"retryText":  T("common.retry"),
		},
	}
}

// ensureUIAssets 把内嵌资源解包到临时目录，并返回该目录路径。
//
// JSONUI 只认识文件路径（例如 `image: "win11.png"`），因此这里需要把 res 包里的字节资源
// 写到磁盘上供运行时加载。使用 sync.Once 避免重复写入。
func ensureUIAssets() (string, error) {
	uiAssetsOnce.Do(func() {
		uiAssetsDir = filepath.Join(os.TempDir(), "resys-jsonui-assets")
		if err := os.MkdirAll(uiAssetsDir, 0o755); err != nil {
			uiAssetsErr = err
			return
		}

		assets := map[string][]byte{
			"icon.png":  res.PngApp,
			"win7.png":  res.PngWin7,
			"win10.png": res.PngWin10,
			"win11.png": res.PngWin11,
			"wait.gif":  res.WaitGIF,
		}
		for name, data := range assets {
			if err := os.WriteFile(filepath.Join(uiAssetsDir, name), data, 0o600); err != nil {
				uiAssetsErr = fmt.Errorf("write ui asset %q: %w", name, err)
				return
			}
		}
		if err := copyUIComponentAssets(uiAssetsDir); err != nil {
			uiAssetsErr = err
			return
		}
	})

	return uiAssetsDir, uiAssetsErr
}

func copyUIComponentAssets(dstRoot string) error {
	srcDir, err := utils.ProjectDir("rules", "ui", "default", "components")
	if err != nil {
		return err
	}
	dstDir := filepath.Join(dstRoot, "components")
	return copyUIDir(srcDir, dstDir)
}

func copyUIDir(srcDir, dstDir string) error {
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return fmt.Errorf("read ui dir %q: %w", srcDir, err)
	}
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return fmt.Errorf("create ui dir %q: %w", dstDir, err)
	}

	for _, entry := range entries {
		srcPath := filepath.Join(srcDir, entry.Name())
		dstPath := filepath.Join(dstDir, entry.Name())
		if entry.IsDir() {
			if err := copyUIDir(srcPath, dstPath); err != nil {
				return err
			}
			continue
		}

		data, err := os.ReadFile(srcPath)
		if err != nil {
			return fmt.Errorf("read ui file %q: %w", srcPath, err)
		}
		if err := os.WriteFile(dstPath, data, 0o600); err != nil {
			return fmt.Errorf("write ui file %q: %w", dstPath, err)
		}
	}
	return nil
}

// uiActionHandlers 返回 action 名称到回调函数的映射表。
//
// 这些 key 必须与 JSON 布局里声明的 action 名称一致。
// ActionContext 会携带控件上报的数据（例如 Value/Checked），用于更新 Store 或触发业务动作。
func uiActionHandlers() map[string]func(jsonui.ActionContext) {
	return map[string]func(jsonui.ActionContext){
		"install-win7": func(jsonui.ActionContext) {
			startInstall(targetWin7)
		},
		"install-win10": func(jsonui.ActionContext) {
			startInstall(targetWin10)
		},
		"install-win11": func(jsonui.ActionContext) {
			startInstall(targetWin11)
		},
		"install-smart": func(jsonui.ActionContext) {
			runSmart()
		},
		"open-manual": func(jsonui.ActionContext) {
			UiShowManualMode()
		},
		"manual-back": func(jsonui.ActionContext) {
			applyMode(modeSelect)
		},
		"manual-image-change": func(ctx jsonui.ActionContext) {
			manualLoadImage(ctx.Value)
		},
		"manual-index-change": func(ctx jsonui.ActionContext) {
			HandleIndexChange(ctx.Value)
		},
		"manual-system-change": func(ctx jsonui.ActionContext) {
			HandleSystemChange(ctx.Value)
		},
		"manual-language-change": func(ctx jsonui.ActionContext) {
			HandleLanguageChange(ctx.Value)
		},
		"manual-partition-change": func(ctx jsonui.ActionContext) {
			HandlePartitionChange(ctx.Value)
		},
		"manual-auto-pe-change": func(ctx jsonui.ActionContext) {
			HandleAutoPEChange(ctx.Checked)
		},
		"manual-pe-change": func(ctx jsonui.ActionContext) {
			HandlePEPathChange(ctx.Value)
		},
		"manual-boot-mode-change": func(ctx jsonui.ActionContext) {
			HandleBootModeChange(ctx.Value)
		},
		"manual-boot-target-change": func(ctx jsonui.ActionContext) {
			HandleBootTargetChange(ctx.Value)
		},
		"manual-format-change": func(ctx jsonui.ActionContext) {
			HandleOptionChange("manual.options.formatTarget", ctx.Checked)
		},
		"manual-backup-change": func(ctx jsonui.ActionContext) {
			HandleBackupDriversChange(ctx.Checked)
		},
		"manual-driver-pattern-change": func(ctx jsonui.ActionContext) {
			HandleDriverPatternChange(ctx.Value)
		},
		"manual-driver-confirm": func(jsonui.ActionContext) {
			HandleDriverDialogConfirm()
		},
		"manual-driver-cancel": func(jsonui.ActionContext) {
			HandleDriverDialogCancel()
		},
		"manual-reboot-change": func(ctx jsonui.ActionContext) {
			HandleOptionChange("manual.options.autoReboot", ctx.Checked)
		},
		"manual-win7-fix-change": func(ctx jsonui.ActionContext) {
			HandleOptionChange("manual.options.win7Fix", ctx.Checked)
		},
		"manual-postprocess-change": func(ctx jsonui.ActionContext) {
			HandlePostProcessChange(ctx.Checked)
		},
		"manual-postprocess-file-select": func(ctx jsonui.ActionContext) {
			HandlePostProcessFileSelect(ctx.Value)
		},
		"manual-postprocess-file-src-change": func(ctx jsonui.ActionContext) {
			manualSetState("manual.postprocess.files.form.src", ctx.Value)
		},
		"manual-postprocess-file-dst-change": func(ctx jsonui.ActionContext) {
			manualSetState("manual.postprocess.files.form.dst", ctx.Value)
		},
		"manual-postprocess-file-overwrite-change": func(ctx jsonui.ActionContext) {
			manualSetState("manual.postprocess.files.form.overwrite", ctx.Checked)
		},
		"manual-postprocess-file-required-change": func(ctx jsonui.ActionContext) {
			manualSetState("manual.postprocess.files.form.required", ctx.Checked)
		},
		"manual-postprocess-file-launch-change": func(ctx jsonui.ActionContext) {
			HandlePostProcessFileLaunchChange(ctx.Value)
		},
		"manual-postprocess-file-add": func(jsonui.ActionContext) {
			HandlePostProcessFileAdd()
		},
		"manual-postprocess-file-save": func(jsonui.ActionContext) {
			HandlePostProcessFileSave()
		},
		"manual-postprocess-file-delete": func(jsonui.ActionContext) {
			HandlePostProcessFileDelete()
		},
		"manual-postprocess-shortcut-select": func(ctx jsonui.ActionContext) {
			HandlePostProcessShortcutSelect(ctx.Value)
		},
		"manual-postprocess-shortcut-target-change": func(ctx jsonui.ActionContext) {
			manualSetState("manual.postprocess.shortcuts.form.target", ctx.Value)
		},
		"manual-postprocess-shortcut-name-change": func(ctx jsonui.ActionContext) {
			manualSetState("manual.postprocess.shortcuts.form.name", ctx.Value)
		},
		"manual-postprocess-shortcut-dir-change": func(ctx jsonui.ActionContext) {
			manualSetState("manual.postprocess.shortcuts.form.dir", ctx.Value)
		},
		"manual-postprocess-shortcut-add": func(jsonui.ActionContext) {
			HandlePostProcessShortcutAdd()
		},
		"manual-postprocess-shortcut-save": func(jsonui.ActionContext) {
			HandlePostProcessShortcutSave()
		},
		"manual-postprocess-shortcut-delete": func(jsonui.ActionContext) {
			HandlePostProcessShortcutDelete()
		},
		"manual-postprocess-reset": func(jsonui.ActionContext) {
			HandlePostProcessReset()
		},
		"manual-postprocess-confirm": func(jsonui.ActionContext) {
			HandlePostProcessConfirm()
		},
		"manual-postprocess-cancel": func(jsonui.ActionContext) {
			HandlePostProcessCancel()
		},
		"manual-start": func(jsonui.ActionContext) {
			HandleStart()
		},
		"prompt-input-change": func(ctx jsonui.ActionContext) {
			bitLockerInput(ctx.Value)
		},
		"prompt-submit-password": func(jsonui.ActionContext) {
			submitBitLocker(false)
		},
		"prompt-submit-recovery": func(jsonui.ActionContext) {
			submitBitLocker(true)
		},
		"prompt-cancel": func(jsonui.ActionContext) {
			cancelBitLocker()
		},
		"msgbox-ok": func(jsonui.ActionContext) {
			resolveMsgBox(msgBoxBtnOK)
		},
		"msgbox-cancel": func(jsonui.ActionContext) {
			resolveMsgBox(msgBoxBtnCancel)
		},
		"msgbox-yes": func(jsonui.ActionContext) {
			resolveMsgBox(msgBoxBtnYes)
		},
		"msgbox-no": func(jsonui.ActionContext) {
			resolveMsgBox(msgBoxBtnNo)
		},
		"msgbox-retry": func(jsonui.ActionContext) {
			resolveMsgBox(msgBoxBtnRetry)
		},
	}
}

// modeStatePatch 生成“页面切换”时需要批量写入 Store 的 patch。
//
// 当 promptVisible 为 true 时，优先展示 prompt（覆盖层），此时 progress 页面不显示，
// 同时停止 progress 的 spinner 动画，避免后台页面仍在绘制造成视觉噪声。
func modeStatePatch(prevMode, nextMode uiMode, promptVisible bool) map[string]any {
	progressVisible := nextMode == modeProgress && !promptVisible

	patch := map[string]any{
		"pages.selectVisible":     nextMode == modeSelect,
		"pages.progressVisible":   progressVisible,
		"pages.manualVisible":     nextMode == modeManual,
		"prompt.visible":          promptVisible,
		"progress.spinnerPlaying": progressVisible,
	}

	if progressVisible && prevMode != modeProgress {
		patch["progress.status"] = T("progress.preparingInstall")
		patch["progress.value"] = int32(0)
	}

	return patch
}
