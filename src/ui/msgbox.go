//go:build windows

package ui

// Windows MessageBox constants.
const (
	MB_OK          = 0x00000000
	MB_OKCANCEL    = 0x00000001
	MB_YESNOCANCEL = 0x00000003
	MB_RETRYCANCEL = 0x00000005

	MB_ICONERROR       = 0x00000010
	MB_ICONWARNING     = 0x00000030
	MB_ICONINFORMATION = 0x00000040

	IDOK     = 1
	IDCANCEL = 2
	IDRETRY  = 4
	IDYES    = 6
	IDNO     = 7
)

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

// msgBoxFlags 根据按钮组合计算出对应的 MessageBox flags。
func msgBoxFlags(cfg msgBoxConfig) uint32 {
	var buttonFlag uint32
	switch {
	case hasButtons(cfg.buttons, msgBoxBtnRetry):
		buttonFlag = MB_RETRYCANCEL
	case hasButtons(cfg.buttons, msgBoxBtnYes):
		buttonFlag = MB_YESNOCANCEL
	case hasButtons(cfg.buttons, msgBoxBtnCancel):
		buttonFlag = MB_OKCANCEL
	default:
		buttonFlag = MB_OK
	}

	switch {
	case !hasButtons(cfg.buttons, msgBoxBtnCancel) && !hasButtons(cfg.buttons, msgBoxBtnYes):
		return buttonFlag | MB_ICONERROR
	default:
		return buttonFlag | MB_ICONWARNING
	}
}

func hasButtons(buttons []msgBoxButton, btn msgBoxButton) bool {
	for _, b := range buttons {
		if b == btn {
			return true
		}
	}
	return false
}

func mapResult(result int) msgBoxButton {
	switch result {
	case IDOK:
		return msgBoxBtnOK
	case IDCANCEL:
		return msgBoxBtnCancel
	case IDYES:
		return msgBoxBtnYes
	case IDNO:
		return msgBoxBtnNo
	case IDRETRY:
		return msgBoxBtnRetry
	default:
		return msgBoxBtnCancel
	}
}

// showMsgBox 展示原生 Windows MessageBox 并回传结果。
func showMsgBox(cfg msgBoxConfig, resultCh chan msgBoxButton, cb msgBoxCallback) {
	ui.msgBoxVisible = true

	result, err := ui.app.MessageBox(cfg.title, cfg.text, msgBoxFlags(cfg), 0)

	ui.msgBoxVisible = false

	button := msgBoxBtnCancel
	if err == nil {
		button = mapResult(result)
	}

	if resultCh != nil {
		resultCh <- button
		close(resultCh)
	}
	if cb != nil {
		cb(button)
	}
}

// resolveMsgBox 在窗口销毁时兜底清理消息框状态。
func resolveMsgBox() {
	if !ui.msgBoxVisible {
		return
	}
	ui.msgBoxVisible = false
	ui.msgBoxResultCh = nil
	ui.msgBoxCallback = nil
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
	if ui.app.IsUIThread() {
		showMsgBox(cfg, nil, cb)
		return
	}
	if err := ui.app.Post(func() {
		showMsgBox(cfg, nil, cb)
	}); err != nil {
		cb(msgBoxBtnCancel)
	}
}

// msgBoxClean 在窗口销毁时清理未关闭的消息框。
func msgBoxClean() {
	resolveMsgBox()
}
