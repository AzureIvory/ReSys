//go:build windows

// Package ui 负责 ReSys 的图形界面宿主逻辑（Windows）。
//
// 本项目的 UI 采用 winui 的 JSONUI（声明式 UI）实现：
// - UI 结构/布局/样式在 `rules/ui/layout.ui.json` 中声明。
// - Go 侧只负责：窗口生命周期、状态存储（jsonui.Store）、动作回调（ActionHandlers）以及少量必须在宿主完成的桥接（例如 BitLocker 解锁弹窗需要阻塞等待用户输入）。
// 运行时由 core.App 驱动，widgets.Scene 承载渲染；UI 分为三个主要页面：
// - 选择页（modeSelect）：Win7/Win10/Win11 卡片 + “高级模式”
// - 进度页（modeProgress）：安装进度与等待动画
// - 高级模式页（modeManual）：手动选择镜像、分区、引导修复等
package ui

import (
	"strings"
	"time"

	"github.com/AzureIvory/winui/core"
	"github.com/AzureIvory/winui/widgets"
	"github.com/AzureIvory/winui/widgets/jsonui"
)

// targetWin* 是“目标系统”在业务层/安装层使用的稳定标识符。
const (
	targetWin7  = "win7"
	targetWin10 = "win10"
	targetWin11 = "win11"
)

// StartInstall 由安装模块注入（见 src/install）。
// UI 侧只负责切页与用户确认，不包含实际安装逻辑。
var StartInstall = func(target string) {}

// uiMode 是 UI 当前所在的页面/模式。
type uiMode int

const (
	modeSelect uiMode = iota
	modeProgress
	modeManual
)

// adapterUI 是 UI 宿主适配层：持有 App/Scene、当前模式、JSONUI 的 store/document/window，
// 以及需要跨 goroutine 协作的状态（例如 BitLocker prompt 的可见性与结果通道）。
type adapterUI struct {
	app    *core.App
	scene  *widgets.Scene
	mode   uiMode
	store  *jsonui.Store
	doc    *jsonui.Document
	window *jsonui.Window

	bitLockerPromptVisible bool
	bitLockerPromptResult  chan bitLockerPromptResult
}

var ui adapterUI

// Uiinit 初始化窗口并绑定 Scene 生命周期回调。
// 注意：真正加载 JSONUI 文档与 attach 发生在 OnCreate 回调里。
func Uiinit() {
	if ui.app != nil {
		return
	}
	if err := initI18n(); err != nil {
		panic(err)
	}

	opts := core.Options{
		ClassName:      "ReSys",
		Title:          T("window.title"),
		Width:          760,
		Height:         460,
		Style:          core.DefaultWindowStyle,
		ExStyle:        core.DefaultWindowExStyle,
		Cursor:         core.CursorArrow,
		Background:     core.RGB(255, 255, 255),
		DoubleBuffered: true,
		RenderMode:     core.RenderModeAuto,
	}
	widgets.BindScene(&opts, widgets.SceneHooks{
		OnCreate:     onCreate,
		OnResize:     onResize,
		OnDPIChanged: onDPIChanged,
		OnDestroy:    onDestroy,
	})

	app, err := core.NewApp(opts)
	if err != nil {
		panic(err)
	}

	ui.app = app
	if err := app.Init(); err != nil {
		panic(err)
	}
}

// UiRun 进入消息循环。
func UiRun() {
	if ui.app == nil {
		return
	}
	ui.app.Run()
}

// UiSetStatus 更新进度页状态文本（只改 store，不直接操作控件树）。
func UiSetStatus(status string) {
	if ui.store == nil {
		return
	}
	ui.store.Set("progress.status", status)
}

// UiSetProgress 更新进度条百分比（只改 store，不直接操作控件树）。
func UiSetProgress(value int32) {
	if ui.store == nil {
		return
	}
	ui.store.Set("progress.value", value)
}

// UiShowError 弹出一个错误提示框（同步 MessageBox）。
func UiShowError(title, text string) {
	if strings.TrimSpace(title) == "" {
		title = T("dialog.error")
	}
	_ = core.MessageBeep()
	Message(title, text)
}

// Win2 是历史遗留的入口（旧代码可能调用它切到进度页）。
func Win2() {
	switchToProgress()
}

// Message 弹出 OK/Cancel，对用户点击 OK 返回 true。
func Message(title, text string) bool {
	if ui.app == nil {
		return false
	}
	if strings.TrimSpace(title) == "" {
		title = T("dialog.prompt")
	}
	ret, _ := ui.app.MessageBox(title, text, core.MessageBoxOKCancel, 10*time.Second)
	return ret == core.MessageBoxResultOK
}

// MessageRetryExit 弹出 Retry/Cancel，对用户点击 Retry 返回 true。
func MessageRetryExit(title, text string) bool {
	if ui.app == nil {
		return false
	}
	if strings.TrimSpace(title) == "" {
		title = T("dialog.prompt")
	}
	ret, _ := ui.app.MessageBox(title, text, core.MessageBoxRetryCancel, 0)
	return ret == core.MessageBoxResultRetry
}

// onCreate 在窗口创建时触发：加载 JSONUI 文档、attach 到 scene，并设置初始 bounds。
func onCreate(app *core.App, scene *widgets.Scene) error {
	ui.app = app
	ui.scene = scene
	ui.mode = modeSelect
	ui.store = newUIStore()

	doc, err := loadUIDocument(ui.store)
	if err != nil {
		return err
	}
	ui.doc = doc
	ui.window = doc.PrimaryWindow()
	if ui.window == nil {
		return nil
	}
	if err := ui.window.Attach(scene); err != nil {
		return err
	}

	size := app.ClientSize()
	if ui.window.Root != nil {
		ui.window.Root.SetBounds(widgets.Rect{W: size.Width, H: size.Height})
	}

	applyMode(modeSelect)
	return nil
}

// onResize 同步根节点 bounds，使 abs 布局表达式按最新窗口尺寸重新计算。
func onResize(_ *core.App, _ *widgets.Scene, size core.Size) {
	if ui.window == nil || ui.window.Root == nil {
		return
	}
	ui.window.Root.SetBounds(widgets.Rect{W: size.Width, H: size.Height})
}

// onDPIChanged 触发资源重载（主要是 icon 等），并同步根节点 bounds。
func onDPIChanged(_ *core.App, _ *widgets.Scene, _ core.DPIInfo) {
	if ui.window != nil {
		_ = ui.window.ReloadResources(jsonui.ReloadReasonDPIChanged)
	}
	if ui.app == nil || ui.window == nil || ui.window.Root == nil {
		return
	}
	size := ui.app.ClientSize()
	ui.window.Root.SetBounds(widgets.Rect{W: size.Width, H: size.Height})
}

// onDestroy 清理 UI 相关引用与可能挂起的弹窗。
func onDestroy(_ *core.App, _ *widgets.Scene) {
	closePendingBitLockerPrompt()
	destroyManualMode()
	ui.scene = nil
	ui.store = nil
	ui.doc = nil
	ui.window = nil
	ui.app = nil
}

// switchToProgress 切换到进度页（通过 applyMode 打补丁）。
func switchToProgress() {
	applyMode(modeProgress)
}

// applyMode 根据 mode 生成一组 store patch：
// - 控制各页面可见性（pages.*Visible）
// - 控制进度页等待动画播放（progress.spinnerPlaying）
func applyMode(mode uiMode) {
	prevMode := ui.mode
	ui.mode = mode
	if ui.store == nil {
		return
	}
	ui.store.Patch(modeStatePatch(prevMode, mode, ui.bitLockerPromptVisible))
}

// startInstall 负责选择页“开始安装”的最小宿主行为：
// 1) 弹确认框
// 2) 切到进度页
// 3) 异步调用安装层注入的 StartInstall
func startInstall(target string) {
	if !Message("", T("dialog.installConfirm")) {
		return
	}
	applyMode(modeProgress)
	go StartInstall(target)
}

// secondaryButtonStyle 返回“次级按钮”样式，用于返回/浏览/取消等非主操作按钮。
func secondaryButtonStyle() widgets.ButtonStyle {
	return widgets.ButtonStyle{
		Font: widgets.FontSpec{
			Face:   "Microsoft YaHei",
			SizeDP: 14,
			Weight: 400,
		},
		TextAlign:    widgets.AlignCenter,
		TextColor:    core.RGB(71, 85, 105),
		DownText:     core.RGB(255, 255, 255),
		DisabledText: core.RGB(148, 163, 184),
		Background:   core.RGB(255, 255, 255),
		Hover:        core.RGB(248, 250, 252),
		Pressed:      core.RGB(15, 23, 42),
		Disabled:     core.RGB(241, 245, 249),
		Border:       core.RGB(226, 232, 240),
		CornerRadius: 10,
		PadDP:        12,
	}
}
