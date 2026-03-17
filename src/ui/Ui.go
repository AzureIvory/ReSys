package ui

import (
	"ReSys/res"
	"ReSys/src/winui/core"
	"ReSys/src/winui/widgets"
	"time"
)

const (
	targetWin7  = "win7"
	targetWin10 = "win10"
	targetWin11 = "win11"
)

var StartInstall = func(target string) {}

type uiMode int

const (
	modeSelect uiMode = iota
	modeProgress
)

type adapterUI struct {
	app   *core.App
	scene *widgets.Scene
	mode  uiMode

	iconApp *core.Icon
	icon7   *core.Icon
	icon10  *core.Icon
	icon11  *core.Icon

	titleLabel  *widgets.Label
	statusLabel *widgets.Label
	waitImage   *widgets.AnimatedImage
	progressBar *widgets.ProgressBar
	btn7        *widgets.Button
	btn10       *widgets.Button
	btn11       *widgets.Button
	btnAdv      *widgets.Button
}

var ui adapterUI

func Uiinit() {
	if ui.app != nil {
		return
	}

	ui.iconApp, _ = core.LoadIconFromICO(res.IcoApp, 32)

	app, err := core.NewApp(core.Options{
		ClassName:      "ReSys",
		Title:          "ReSys-一键重装",
		Width:          600,
		Height:         400,
		Style:          core.DefaultWindowStyle,
		ExStyle:        core.DefaultWindowExStyle,
		Cursor:         core.CursorArrow,
		Icon:           ui.iconApp,
		Background:     core.RGB(255, 255, 255),
		DoubleBuffered: true,
		OnCreate:       onCreate,
		OnPaint:        onPaint,
		OnResize:       onResize,
		OnMouseMove:    onMouseMove,
		OnMouseLeave:   onMouseLeave,
		OnMouseDown:    onMouseDown,
		OnMouseUp:      onMouseUp,
		OnKeyDown:      onKeyDown,
		OnChar:         onChar,
		OnFocus:        onFocus,
		OnTimer:        onTimer,
		OnDPIChanged:   onDPIChanged,
		OnDestroy:      onDestroy,
	})
	if err != nil {
		panic(err)
	}

	ui.app = app
	if err := app.Init(); err != nil {
		panic(err)
	}
}

func UiRun() {
	if ui.app == nil {
		return
	}
	ui.app.Run()
}

func UiSetStatus(status string) {
	if ui.statusLabel == nil {
		return
	}
	ui.statusLabel.SetText(status)
}

func UiSetProgress(value int32) {
	if ui.progressBar == nil {
		return
	}
	ui.progressBar.SetValue(value)
}

func UiShowError(title, text string) {
	_ = core.MessageBeep()
	Message(title, text)
}

func Win2() {
	switchToProgress()
}

func Message(title, text string) bool {
	if ui.app == nil {
		return false
	}
	ret, _ := ui.app.MessageBox(title, text, core.MessageBoxOKCancel, 10*time.Second)
	return ret == core.MessageBoxResultOK
}

func MessageRetryExit(title, text string) bool {
	if ui.app == nil {
		return false
	}
	ret, _ := ui.app.MessageBox(title, text, core.MessageBoxRetryCancel, 0)
	return ret == core.MessageBoxResultRetry
}

func onCreate(app *core.App) error {
	ui.app = app
	ui.scene = widgets.NewScene(app)
	ui.mode = modeSelect

	root := ui.scene.Root()

	ui.titleLabel = widgets.NewLabel("title", "请选择要安装的操作系统")
	ui.titleLabel.SetStyle(widgets.TextStyle{
		Font: widgets.FontSpec{
			Face:   "Microsoft YaHei UI",
			SizeDP: 20,
		},
		Color:  core.RGB(16, 16, 16),
		Format: core.DTCenter | core.DTVCenter | core.DTSingleLine,
	})

	ui.statusLabel = widgets.NewLabel("status", "正在准备...")
	ui.statusLabel.SetStyle(widgets.TextStyle{
		Font: widgets.FontSpec{
			Face:   "Microsoft YaHei UI",
			SizeDP: 20,
		},
		Color:  core.RGB(16, 16, 16),
		Format: core.DTCenter | core.DTVCenter | core.DTSingleLine | core.DTEndEllipsis,
	})

	ui.waitImage = widgets.NewAnimatedImage("wait")
	ui.waitImage.SetScaleMode(widgets.ImageScaleContain)
	_ = ui.waitImage.LoadGIF(res.WaitGIF)

	ui.progressBar = widgets.NewProgressBar("progress")
	ui.progressBar.SetStyle(widgets.ProgressStyle{
		Font: widgets.FontSpec{
			Face:   "Microsoft YaHei UI",
			SizeDP: 14,
			Weight: 700,
		},
		TextColor:    core.RGB(255, 255, 255),
		TrackColor:   core.RGB(243, 244, 246),
		FillColor:    core.RGB(5, 200, 5),
		BubbleColor:  core.RGB(5, 200, 5),
		CornerRadius: 12,
		ShowPercent:  true,
	})

	ui.btn7 = widgets.NewButton("btn-win7", "重装 win7")
	ui.btn10 = widgets.NewButton("btn-win10", "重装 win10")
	ui.btn11 = widgets.NewButton("btn-win11", "重装 win11")
	ui.btnAdv = widgets.NewButton("btn-advanced", "高级模式")

	ui.btn7.SetOnClick(func() { startInstall(targetWin7) })
	ui.btn10.SetOnClick(func() { startInstall(targetWin10) })
	ui.btn11.SetOnClick(func() { startInstall(targetWin11) })
	ui.btnAdv.SetOnClick(func() { UiSetStatus("高级模式：TODO") })

	root.Add(ui.titleLabel)
	root.Add(ui.statusLabel)
	root.Add(ui.waitImage)
	root.Add(ui.progressBar)
	root.Add(ui.btn7)
	root.Add(ui.btn10)
	root.Add(ui.btn11)
	root.Add(ui.btnAdv)

	reloadIcons()
	applyMode(modeSelect)
	return nil
}

func onPaint(_ *core.App, canvas *core.Canvas) {
	if ui.scene == nil {
		return
	}
	ui.scene.PaintCore(canvas)
}

func onResize(_ *core.App, size core.Size) {
	if ui.scene == nil {
		return
	}
	ui.scene.Resize(core.Rect{X: 0, Y: 0, W: size.Width, H: size.Height})
	layoutCurrent(size.Width, size.Height)
}

func onMouseMove(_ *core.App, ev core.MouseEvent) {
	if ui.scene != nil {
		ui.scene.DispatchMouseMove(ev)
	}
}

func onMouseLeave(_ *core.App) {
	if ui.scene != nil {
		ui.scene.DispatchMouseLeave()
	}
}

func onMouseDown(_ *core.App, ev core.MouseEvent) {
	if ui.scene != nil {
		ui.scene.DispatchMouseDown(ev)
	}
}

func onMouseUp(_ *core.App, ev core.MouseEvent) {
	if ui.scene != nil {
		ui.scene.DispatchMouseUp(ev)
	}
}

// onKeyDown 转发按键消息到 widgets 场景。
func onKeyDown(_ *core.App, ev core.KeyEvent) {
	if ui.scene != nil {
		ui.scene.DispatchKeyDown(ev)
	}
}

// onChar 转发字符输入到 widgets 场景。
func onChar(_ *core.App, ch rune) {
	if ui.scene != nil {
		ui.scene.DispatchChar(ch)
	}
}

// onFocus 在窗口失焦时清空控件焦点。
func onFocus(_ *core.App, focused bool) {
	if ui.scene != nil && !focused {
		ui.scene.Blur()
	}
}

func onTimer(_ *core.App, id uintptr) {
	if ui.scene != nil {
		ui.scene.HandleTimer(id)
	}
}

func onDPIChanged(_ *core.App, _ core.DPIInfo) {
	reloadIcons()
	if ui.scene != nil {
		ui.scene.ReloadResources()
	}
	size := ui.app.ClientSize()
	layoutCurrent(size.Width, size.Height)
}

func onDestroy(_ *core.App) {
	if ui.scene != nil {
		_ = ui.scene.Close()
	}
	ui.scene = nil
	_ = closeIcon(ui.icon7)
	_ = closeIcon(ui.icon10)
	_ = closeIcon(ui.icon11)
	_ = closeIcon(ui.iconApp)
	ui.icon7 = nil
	ui.icon10 = nil
	ui.icon11 = nil
	ui.iconApp = nil
	ui.app = nil
}

func reloadIcons() {
	if ui.app == nil {
		return
	}

	icon7, _ := core.LoadIconFromICO(res.IcoWin7, ui.app.DP(48))
	icon10, _ := core.LoadIconFromICO(res.IcoWin10, ui.app.DP(48))
	icon11, _ := core.LoadIconFromICO(res.IcoWin11, ui.app.DP(48))

	_ = closeIcon(ui.icon7)
	_ = closeIcon(ui.icon10)
	_ = closeIcon(ui.icon11)

	ui.icon7 = icon7
	ui.icon10 = icon10
	ui.icon11 = icon11

	if ui.btn7 != nil {
		ui.btn7.SetIcon(icon7)
	}
	if ui.btn10 != nil {
		ui.btn10.SetIcon(icon10)
	}
	if ui.btn11 != nil {
		ui.btn11.SetIcon(icon11)
	}
}

func switchToProgress() {
	if ui.app == nil {
		return
	}
	_ = ui.app.Post(func() {
		applyMode(modeProgress)
	})
}

func applyMode(mode uiMode) {
	ui.mode = mode

	selectVisible := mode == modeSelect
	progressVisible := mode == modeProgress

	ui.titleLabel.SetVisible(selectVisible)
	ui.btn7.SetVisible(selectVisible)
	ui.btn10.SetVisible(selectVisible)
	ui.btn11.SetVisible(selectVisible)
	ui.btnAdv.SetVisible(selectVisible)

	ui.statusLabel.SetVisible(progressVisible)
	ui.waitImage.SetVisible(progressVisible)
	ui.progressBar.SetVisible(progressVisible)

	if progressVisible {
		ui.progressBar.SetValue(0)
		ui.statusLabel.SetText("正在寻找镜像...")
	}

	size := ui.app.ClientSize()
	layoutCurrent(size.Width, size.Height)
	if ui.scene != nil {
		ui.scene.Invalidate(nil)
	}
}

func layoutCurrent(w, h int32) {
	if ui.scene == nil {
		return
	}

	switch ui.mode {
	case modeProgress:
		layoutProgress(w, h)
	default:
		layoutSelect(w, h)
	}
}

func layoutSelect(w, h int32) {
	btnSize := ui.app.DP(120)
	gap := ui.app.DP(50)
	btnY := h/2 - btnSize/2 + ui.app.DP(20)
	totalWidth := btnSize*3 + gap*2
	startX := (w - totalWidth) / 2

	ui.titleLabel.SetBounds(core.Rect{
		X: 0,
		Y: h/2 - ui.app.DP(120),
		W: w,
		H: ui.app.DP(40),
	})

	ui.btn7.SetBounds(core.Rect{X: startX, Y: btnY, W: btnSize, H: btnSize})
	ui.btn10.SetBounds(core.Rect{X: startX + btnSize + gap, Y: btnY, W: btnSize, H: btnSize})
	ui.btn11.SetBounds(core.Rect{X: startX + (btnSize+gap)*2, Y: btnY, W: btnSize, H: btnSize})

	advW := ui.app.DP(90)
	advH := ui.app.DP(34)
	ui.btnAdv.SetBounds(core.Rect{
		X: w - advW - ui.app.DP(20),
		Y: ui.app.DP(20),
		W: advW,
		H: advH,
	})

	ui.statusLabel.SetBounds(core.Rect{})
	ui.waitImage.SetBounds(core.Rect{})
	ui.progressBar.SetBounds(core.Rect{})
}

func layoutProgress(w, h int32) {
	waitSize := ui.waitImage.NaturalSize()
	waitW := ui.app.DP(waitSize.Width)
	waitH := ui.app.DP(waitSize.Height)
	waitX := (w - waitW) / 2
	waitY := h/2 - waitH/2 - ui.app.DP(40)
	waitBottom := waitY + waitH

	ui.waitImage.SetBounds(core.Rect{
		X: waitX,
		Y: waitY,
		W: waitW,
		H: waitH,
	})

	textY := waitBottom + ui.app.DP(20)
	barW := int32(float64(w) * 0.7)
	barH := ui.app.DP(12)
	barX := (w - barW) / 2
	barY := textY + ui.app.DP(78)

	ui.statusLabel.SetBounds(core.Rect{
		X: ui.app.DP(20),
		Y: textY,
		W: w - ui.app.DP(40),
		H: ui.app.DP(30),
	})
	ui.progressBar.SetBounds(core.Rect{
		X: barX,
		Y: barY,
		W: barW,
		H: barH,
	})
}

func startInstall(target string) {
	if !Message("提示", "重装系统将会清除C盘数据，是否继续？") {
		return
	}
	applyMode(modeProgress)
	go StartInstall(target)
}

func closeIcon(icon *core.Icon) error {
	if icon == nil {
		return nil
	}
	return icon.Close()
}
