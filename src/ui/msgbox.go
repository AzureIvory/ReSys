//go:build windows

package ui

import "strings"

// msgBoxButton 表示消息框的按钮类型。
type msgBoxButton int

const (
	msgBoxBtnOK     msgBoxButton = iota
	msgBoxBtnCancel
	msgBoxBtnYes
	msgBoxBtnNo
	msgBoxBtnRetry
)

// msgBoxConfig 定义消息框的配置。
type msgBoxConfig struct {
	title   string
	text    string
	buttons []msgBoxButton
}

// msgBoxCallback 是异步消息框的回调类型。
type msgBoxCallback func(button msgBoxButton)

// showMsgBox 在 UI 线程上展示消息框 modal。
// resultCh 非 nil 时使用同步模式（channel 回传），cb 非 nil 时使用异步模式（回调）。
func showMsgBox(cfg msgBoxConfig, resultCh chan msgBoxButton, cb msgBoxCallback) {
	if ui.store == nil {
		if resultCh != nil {
			resultCh <- msgBoxBtnCancel
			close(resultCh)
		}
		if cb != nil {
			cb(msgBoxBtnCancel)
		}
		return
	}

	ui.msgBoxVisible = true
	ui.msgBoxResultCh = resultCh
	ui.msgBoxCallback = cb

	if ui.scene != nil {
		ui.scene.Blur()
	}

	hasButton := func(b msgBoxButton) bool {
		for _, btn := range cfg.buttons {
			if btn == b {
				return true
			}
		}
		return false
	}

	title := strings.TrimSpace(cfg.title)
	if title == "" {
		title = T("dialog.prompt")
	}

	ui.store.Patch(map[string]any{
		"msgbox.visible":    true,
		"msgbox.title":      title,
		"msgbox.text":       cfg.text,
		"msgbox.showOk":     hasButton(msgBoxBtnOK),
		"msgbox.showCancel": hasButton(msgBoxBtnCancel),
		"msgbox.showYes":    hasButton(msgBoxBtnYes),
		"msgbox.showNo":     hasButton(msgBoxBtnNo),
		"msgbox.showRetry":  hasButton(msgBoxBtnRetry),
	})
}

// resolveMsgBox 关闭消息框 modal 并回传结果。
func resolveMsgBox(button msgBoxButton) {
	if !ui.msgBoxVisible {
		return
	}

	ui.msgBoxVisible = false
	resultCh := ui.msgBoxResultCh
	cb := ui.msgBoxCallback
	ui.msgBoxResultCh = nil
	ui.msgBoxCallback = nil

	if ui.store != nil {
		ui.store.Patch(map[string]any{
			"msgbox.visible":    false,
			"msgbox.showOk":     false,
			"msgbox.showCancel": false,
			"msgbox.showYes":    false,
			"msgbox.showNo":     false,
			"msgbox.showRetry":  false,
		})
	}
	if ui.scene != nil {
		ui.scene.Blur()
	}

	if resultCh != nil {
		resultCh <- button
		close(resultCh)
	}
	if cb != nil {
		cb(button)
	}
}

// showMsgBoxSync 同步展示消息框，阻塞直到用户响应。必须在非 UI 线程调用。
func showMsgBoxSync(cfg msgBoxConfig) msgBoxButton {
	if ui.app == nil {
		return msgBoxBtnCancel
	}

	resultCh := make(chan msgBoxButton, 1)
	if err := ui.app.Post(func() {
		showMsgBox(cfg, resultCh, nil)
	}); err != nil {
		return msgBoxBtnCancel
	}

	result, ok := <-resultCh
	if !ok {
		return msgBoxBtnCancel
	}
	return result
}

// showMsgBoxAsync 异步展示消息框，通过回调返回结果。可在 UI 线程调用。
func showMsgBoxAsync(cfg msgBoxConfig, cb msgBoxCallback) {
	if ui.app == nil {
		if cb != nil {
			cb(msgBoxBtnCancel)
		}
		return
	}
	if cb == nil {
		cb = func(msgBoxButton) {}
	}
	showMsgBox(cfg, nil, cb)
}

// msgBoxClean 在窗口销毁时清理未关闭的消息框。
func msgBoxClean() {
	if ui.msgBoxVisible {
		resolveMsgBox(msgBoxBtnCancel)
	}
}
