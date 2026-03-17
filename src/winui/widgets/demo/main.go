package main

import (
	"ReSys/res"
	"ReSys/src/winui/core"
	"ReSys/src/winui/widgets"
)

type demoUI struct {
	app   *core.App
	scene *widgets.Scene

	waitAnim *widgets.AnimatedImage
	title    *widgets.Label
	status   *widgets.Label
	progress *widgets.ProgressBar
	check    *widgets.CheckBox
	radioA   *widgets.RadioButton
	radioB   *widgets.RadioButton
	list     *widgets.ListBox
	combo    *widgets.ComboBox
	edit     *widgets.EditBox
	btnStep  *widgets.Button
	btnReset *widgets.Button
	btnMode  *widgets.Button

	iconApp *core.Icon
	icon7   *core.Icon
	icon10  *core.Icon
	icon11  *core.Icon
}

var ui demoUI

func main() {
	ui.iconApp, _ = core.LoadIconFromICO(res.IcoApp, 32)

	app, err := core.NewApp(core.Options{
		ClassName:      "WinUIWidgetsDemo",
		Title:          "winui-widgets demo",
		Width:          720,
		Height:         620,
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
	app.Run()
}

func onCreate(app *core.App) error {
	ui.app = app
	ui.scene = widgets.NewScene(app)

	ui.title = widgets.NewLabel("title", "winui-widgets demo")
	ui.title.SetStyle(widgets.TextStyle{
		Font: widgets.FontSpec{
			Face:   "Microsoft YaHei UI",
			SizeDP: 20,
		},
		Color:  core.RGB(16, 16, 16),
		Format: core.DTCenter | core.DTVCenter | core.DTSingleLine,
	})

	ui.status = widgets.NewLabel("status", "Ready")
	ui.status.SetStyle(widgets.TextStyle{
		Font: widgets.FontSpec{
			Face:   "Microsoft YaHei UI",
			SizeDP: 16,
		},
		Color:  core.RGB(16, 16, 16),
		Format: core.DTCenter | core.DTVCenter | core.DTSingleLine | core.DTEndEllipsis,
	})

	ui.progress = widgets.NewProgressBar("progress")
	ui.progress.SetStyle(widgets.ProgressStyle{
		Font: widgets.FontSpec{
			Face:   "Microsoft YaHei UI",
			SizeDP: 14,
			Weight: 700,
		},
		TextColor:    core.RGB(255, 255, 255),
		TrackColor:   core.RGB(243, 244, 246),
		FillColor:    core.RGB(124, 58, 237),
		BubbleColor:  core.RGB(147, 51, 234),
		CornerRadius: 12,
		ShowPercent:  true,
	})
	ui.progress.SetValue(25)

	ui.waitAnim = widgets.NewAnimatedImage("wait")
	ui.waitAnim.SetScaleMode(widgets.ImageScaleContain)
	_ = ui.waitAnim.LoadGIF(res.WaitGIF)

	ui.check = widgets.NewCheckBox("check", "Enable safe mode")
	ui.check.SetOnChange(func(checked bool) {
		if checked {
			ui.status.SetText("Checkbox enabled")
			return
		}
		ui.status.SetText("Checkbox disabled")
	})

	ui.radioA = widgets.NewRadioButton("radio-fast", "Quick install")
	ui.radioA.SetGroup("mode")
	ui.radioA.SetChecked(true)
	ui.radioA.SetOnChange(func(checked bool) {
		if checked {
			ui.status.SetText("Quick mode selected")
		}
	})

	ui.radioB = widgets.NewRadioButton("radio-full", "Full install")
	ui.radioB.SetGroup("mode")
	ui.radioB.SetOnChange(func(checked bool) {
		if checked {
			ui.status.SetText("Full mode selected")
		}
	})

	ui.list = widgets.NewListBox("list")
	ui.list.SetItems([]widgets.ListItem{
		{Value: "win7", Text: "Windows 7"},
		{Value: "win10", Text: "Windows 10"},
		{Value: "win11", Text: "Windows 11"},
	})
	ui.list.SetSelected(1)
	ui.list.SetOnChange(func(_ int, item widgets.ListItem) {
		ui.status.SetText("List selected: " + displayItem(item))
	})

	ui.combo = widgets.NewComboBox("combo")
	ui.combo.SetPlaceholder("Select accent color")
	ui.combo.SetItems([]widgets.ListItem{
		{Value: "purple", Text: "Purple"},
		{Value: "green", Text: "Green"},
		{Value: "blue", Text: "Blue"},
	})
	ui.combo.SetSelected(0)
	ui.combo.SetOnChange(func(_ int, item widgets.ListItem) {
		ui.status.SetText("Combo selected: " + displayItem(item))
	})

	ui.edit = widgets.NewEditBox("edit")
	ui.edit.SetPlaceholder("Type a custom image label")
	ui.edit.SetOnChange(func(text string) {
		if text == "" {
			ui.status.SetText("Input cleared")
			return
		}
		ui.status.SetText("Input: " + text)
	})

	ui.btnStep = widgets.NewButton("btn-step", "Advance")
	ui.btnReset = widgets.NewButton("btn-reset", "Reset")
	ui.btnMode = widgets.NewButton("btn-mode", "Disable Reset")

	root := ui.scene.Root()
	root.Add(ui.title)
	root.Add(ui.status)
	root.Add(ui.waitAnim)
	root.Add(ui.progress)
	root.Add(ui.check)
	root.Add(ui.radioA)
	root.Add(ui.radioB)
	root.Add(ui.list)
	root.Add(ui.combo)
	root.Add(ui.edit)
	root.Add(ui.btnStep)
	root.Add(ui.btnReset)
	root.Add(ui.btnMode)

	reloadIcons()

	ui.btnStep.SetOnClick(func() {
		next := ui.progress.Value() + 15
		if next > 100 {
			next = 100
		}
		ui.progress.SetValue(next)
		ui.status.SetText("Progress updated")
	})

	ui.btnReset.SetOnClick(func() {
		ui.progress.SetValue(0)
		ui.status.SetText("Progress reset")
	})

	ui.btnMode.SetOnClick(func() {
		enabled := ui.btnReset.Enabled()
		ui.btnReset.SetEnabled(!enabled)
		if enabled {
			ui.btnMode.SetText("Enable Reset")
			ui.status.SetText("Reset button disabled")
		} else {
			ui.btnMode.SetText("Disable Reset")
			ui.status.SetText("Reset button enabled")
		}
	})

	size := app.ClientSize()
	layout(size.Width, size.Height)
	return nil
}

func onPaint(_ *core.App, canvas *core.Canvas) {
	if ui.scene != nil {
		ui.scene.PaintCore(canvas)
	}
}

func onResize(_ *core.App, size core.Size) {
	if ui.scene == nil {
		return
	}
	ui.scene.Resize(core.Rect{X: 0, Y: 0, W: size.Width, H: size.Height})
	layout(size.Width, size.Height)
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
	if ui.scene != nil {
		ui.scene.ReloadResources()
	}
	reloadIcons()
	size := ui.app.ClientSize()
	layout(size.Width, size.Height)
}

func onDestroy(_ *core.App) {
	if ui.scene != nil {
		_ = ui.scene.Close()
	}
	_ = closeIcon(ui.icon7)
	_ = closeIcon(ui.icon10)
	_ = closeIcon(ui.icon11)
	_ = closeIcon(ui.iconApp)
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

	ui.btnStep.SetIcon(icon7)
	ui.btnReset.SetIcon(icon10)
	ui.btnMode.SetIcon(icon11)
}

func layout(w, h int32) {
	if ui.app == nil {
		return
	}

	ui.title.SetBounds(core.Rect{X: 0, Y: ui.app.DP(28), W: w, H: ui.app.DP(36)})
	ui.status.SetBounds(core.Rect{X: ui.app.DP(20), Y: ui.app.DP(76), W: w - ui.app.DP(40), H: ui.app.DP(28)})

	animSize := ui.waitAnim.NaturalSize()
	animW := ui.app.DP(animSize.Width)
	animH := ui.app.DP(animSize.Height)
	ui.waitAnim.SetBounds(core.Rect{
		X: ui.app.DP(28),
		Y: ui.app.DP(120),
		W: animW,
		H: animH,
	})

	leftX := ui.app.DP(28)
	leftW := int32(float64(w) * 0.42)
	rightX := leftX + leftW + ui.app.DP(28)
	rightW := w - rightX - ui.app.DP(28)
	barW := leftW
	ui.progress.SetBounds(core.Rect{
		X: leftX,
		Y: ui.app.DP(258),
		W: barW,
		H: ui.app.DP(12),
	})

	ui.check.SetBounds(core.Rect{X: leftX, Y: ui.app.DP(306), W: leftW, H: ui.app.DP(32)})
	ui.radioA.SetBounds(core.Rect{X: leftX, Y: ui.app.DP(346), W: leftW, H: ui.app.DP(32)})
	ui.radioB.SetBounds(core.Rect{X: leftX, Y: ui.app.DP(386), W: leftW, H: ui.app.DP(32)})
	ui.edit.SetBounds(core.Rect{X: leftX, Y: ui.app.DP(434), W: leftW, H: ui.app.DP(42)})

	ui.list.SetBounds(core.Rect{X: rightX, Y: ui.app.DP(120), W: rightW, H: ui.app.DP(188)})
	ui.combo.SetBounds(core.Rect{X: rightX, Y: ui.app.DP(328), W: rightW, H: ui.app.DP(42)})

	btnY := h - ui.app.DP(160)
	btnSize := ui.app.DP(108)
	gap := ui.app.DP(24)
	totalW := btnSize*3 + gap*2
	startX := (w - totalW) / 2

	ui.btnStep.SetBounds(core.Rect{X: startX, Y: btnY, W: btnSize, H: btnSize})
	ui.btnReset.SetBounds(core.Rect{X: startX + btnSize + gap, Y: btnY, W: btnSize, H: btnSize})
	ui.btnMode.SetBounds(core.Rect{X: startX + (btnSize+gap)*2, Y: btnY, W: btnSize, H: btnSize})
}

func closeIcon(icon *core.Icon) error {
	if icon == nil {
		return nil
	}
	return icon.Close()
}

// displayItem 返回列表项的展示文本。
func displayItem(item widgets.ListItem) string {
	if item.Text != "" {
		return item.Text
	}
	return item.Value
}
