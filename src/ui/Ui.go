//go:build windows

package ui

import (
	"ReSys/res"
	"time"

	"github.com/AzureIvory/winui/core"
	"github.com/AzureIvory/winui/widgets"
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

	bitLockerPromptVisible     bool
	bitLockerPromptResult      chan bitLockerPromptResult
	bitLockerPromptPanel       *widgets.Panel
	bitLockerPromptTitleLabel  *widgets.Label
	bitLockerPromptTextLabel   *widgets.Label
	bitLockerPromptErrorLabel  *widgets.Label
	bitLockerPromptInput       *widgets.EditBox
	bitLockerPromptPasswordBtn *widgets.Button
	bitLockerPromptRecoveryBtn *widgets.Button
	bitLockerPromptCancelBtn   *widgets.Button
}

var ui adapterUI

func Uiinit() {
	if ui.app != nil {
		return
	}

	ui.iconApp, _ = core.LoadIconFromICO(res.IcoApp, 32)

	opts := core.Options{
		ClassName:      "ReSys",
		Title:          "ReSys-一键重装",
		Width:          700,
		Height:         400,
		Style:          core.DefaultWindowStyle,
		ExStyle:        core.DefaultWindowExStyle,
		Cursor:         core.CursorArrow,
		Icon:           ui.iconApp,
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

func onCreate(app *core.App, scene *widgets.Scene) error {
	ui.app = app
	ui.scene = scene
	ui.mode = modeSelect

	theme := widgets.DefaultTheme()
	theme.Text = widgets.TextStyle{
		Font: widgets.FontSpec{
			Face:   "Microsoft YaHei UI",
			SizeDP: 16,
		},
		Color:  core.RGB(15, 23, 42),
		Format: core.DTCenter | core.DTVCenter | core.DTSingleLine,
	}
	theme.Title = widgets.TextStyle{
		Font: widgets.FontSpec{
			Face:   "Microsoft YaHei UI",
			SizeDP: 20,
			Weight: 700,
		},
		Color:  core.RGB(15, 23, 42),
		Format: core.DTCenter | core.DTVCenter | core.DTSingleLine,
	}
	theme.Button = selectButtonStyle()
	theme.Button.Border = 0
	theme.Progress = widgets.ProgressStyle{
		Font: widgets.FontSpec{
			Face:   "Microsoft YaHei UI",
			SizeDP: 14,
			Weight: 700,
		},
		TextColor:    core.RGB(255, 255, 255),
		TrackColor:   core.RGB(243, 244, 246),
		FillColor:    core.RGB(34, 197, 94),
		BubbleColor:  core.RGB(22, 163, 74),
		CornerRadius: 12,
		ShowPercent:  true,
	}
	ui.scene.SetTheme(theme)

	root := scene.Root()

	ui.titleLabel = widgets.NewLabel("title", "请选择要安装的操作系统")
	ui.titleLabel.SetStyle(theme.Title)

	ui.statusLabel = widgets.NewLabel("status", "正在准备...")
	ui.statusLabel.SetStyle(widgets.TextStyle{
		Font: widgets.FontSpec{
			Face:   "Microsoft YaHei UI",
			SizeDP: 18,
			Weight: 700,
		},
		Color:  core.RGB(15, 23, 42),
		Format: core.DTCenter | core.DTVCenter | core.DTSingleLine | core.DTEndEllipsis,
	})

	ui.waitImage = widgets.NewAnimatedImage("wait")
	ui.waitImage.SetScaleMode(widgets.ImageScaleContain)
	_ = ui.waitImage.LoadGIF(res.WaitGIF)

	ui.progressBar = widgets.NewProgressBar("progress")
	ui.progressBar.SetStyle(theme.Progress)

	ui.btn7 = widgets.NewButton("btn-win7", "重装 Win7", 0)
	ui.btn10 = widgets.NewButton("btn-win10", "重装 Win10", 0)
	ui.btn11 = widgets.NewButton("btn-win11", "重装 Win11", 0)
	ui.btnAdv = widgets.NewButton("btn-advanced", "高级模式", 0)

	ui.btn7.SetKind(widgets.BtnTop)
	ui.btn10.SetKind(widgets.BtnTop)
	ui.btn11.SetKind(widgets.BtnTop)
	ui.btn7.SetStyle(widgets.ButtonStyle{
		Pressed: core.RGB(67, 205, 128),
	})
	ui.btn11.SetStyle(widgets.ButtonStyle{
		Pressed: core.RGB(0, 191, 255),
	})

	ui.btn7.SetOnClick(func() { startInstall(targetWin7) })
	ui.btn10.SetOnClick(func() { startInstall(targetWin10) })
	ui.btn11.SetOnClick(func() { startInstall(targetWin11) })
	ui.btnAdv.SetOnClick(func() { UiSetStatus("高级模式：TODO") })
	ui.btnAdv.SetStyle(secondaryButtonStyle())

	root.AddAll(
		ui.titleLabel,
		ui.statusLabel,
		ui.waitImage,
		ui.progressBar,
		ui.btn7,
		ui.btn10,
		ui.btn11,
		ui.btnAdv,
	)
	initBitLockerPrompt(theme, root)

	reloadIcons()
	applyMode(modeSelect)
	return nil
}

func onResize(_ *core.App, _ *widgets.Scene, size core.Size) {
	if ui.scene == nil {
		return
	}
	layoutCurrent(size.Width, size.Height)
}

func onDPIChanged(_ *core.App, _ *widgets.Scene, _ core.DPIInfo) {
	reloadIcons()
	size := ui.app.ClientSize()
	layoutCurrent(size.Width, size.Height)
}

func onDestroy(_ *core.App, _ *widgets.Scene) {
	closePendingBitLockerPrompt()
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

	iconSize := ui.app.DP(48)
	icon7, _ := core.LoadIconFromICO(res.IcoWin7, iconSize)
	icon10, _ := core.LoadIconFromICO(res.IcoWin10, iconSize)
	icon11, _ := core.LoadIconFromICO(res.IcoWin11, iconSize)

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
	prevMode := ui.mode
	ui.mode = mode

	selectVisible := mode == modeSelect
	progressVisible := mode == modeProgress && !ui.bitLockerPromptVisible
	promptVisible := mode == modeProgress && ui.bitLockerPromptVisible

	ui.titleLabel.SetVisible(selectVisible)
	ui.btn7.SetVisible(selectVisible)
	ui.btn10.SetVisible(selectVisible)
	ui.btn11.SetVisible(selectVisible)
	ui.btnAdv.SetVisible(selectVisible)

	ui.statusLabel.SetVisible(progressVisible)
	ui.waitImage.SetVisible(progressVisible)
	ui.waitImage.SetPlaying(progressVisible)
	ui.progressBar.SetVisible(progressVisible)
	if ui.bitLockerPromptPanel != nil {
		ui.bitLockerPromptPanel.SetVisible(promptVisible)
	}

	if progressVisible && prevMode != modeProgress {
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
		if ui.bitLockerPromptVisible {
			layoutBitLockerPrompt(w, h)
		} else {
			layoutProgress(w, h)
		}
	default:
		layoutSelect(w, h)
	}
}

func layoutSelect(w, h int32) {
	btnSize := ui.app.DP(120)
	gap := ui.app.DP(48)
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

	advW := ui.app.DP(96)
	advH := ui.app.DP(36)
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
	if !Message("提示", "重装系统将会清除 C 盘数据，是否继续？") {
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

func selectButtonStyle() widgets.ButtonStyle {
	return widgets.ButtonStyle{
		Font: widgets.FontSpec{
			Face:   "Microsoft YaHei UI",
			SizeDP: 15,
			Weight: 700,
		},
		TextColor:    core.RGB(15, 23, 42),
		DownText:     core.RGB(255, 255, 255),
		DisabledText: core.RGB(148, 163, 184),
		Background:   core.RGB(255, 255, 255),
		Hover:        core.RGB(248, 250, 252),
		Pressed:      core.RGB(37, 99, 235),
		Disabled:     core.RGB(241, 245, 249),
		Border:       core.RGB(226, 232, 240),
		CornerRadius: 12,
		IconSizeDP:   40,
		TextInsetDP:  24,
		GapDP:        8,
		PadDP:        12,
	}
}

func secondaryButtonStyle() widgets.ButtonStyle {
	return widgets.ButtonStyle{
		Font: widgets.FontSpec{
			Face:   "Microsoft YaHei",
			SizeDP: 14,
			Weight: 400,
		},
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
