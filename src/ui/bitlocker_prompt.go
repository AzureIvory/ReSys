//go:build windows

package ui

import (
	"errors"
	"strings"

	"github.com/AzureIvory/winui/core"
	"github.com/AzureIvory/winui/widgets"
)

type bitLockerPromptResult struct {
	Credential     string
	UseRecoveryKey bool
	Canceled       bool
}

func UiPromptBitLockerUnlock(title, prompt string) (credential string, useRecoveryKey bool, canceled bool, err error) {
	if ui.app == nil {
		return "", false, false, errors.New("ui is not initialized")
	}
	if ui.app.IsUIThread() {
		return "", false, false, errors.New("bitlocker prompt cannot block on UI thread")
	}
	if ui.bitLockerPromptVisible {
		return "", false, false, errors.New("bitlocker prompt is already visible")
	}

	resultCh := make(chan bitLockerPromptResult, 1)
	if err := ui.app.Post(func() {
		showBitLockerPrompt(title, prompt, resultCh)
	}); err != nil {
		return "", false, false, err
	}

	result, ok := <-resultCh
	if !ok {
		return "", false, true, errors.New("bitlocker prompt was closed")
	}
	return result.Credential, result.UseRecoveryKey, result.Canceled, nil
}

func initBitLockerPrompt(theme *widgets.Theme, root *widgets.Panel) {
	if root == nil || theme == nil {
		return
	}

	ui.bitLockerPromptPanel = widgets.NewPanel("bitlocker-prompt")
	ui.bitLockerPromptPanel.SetVisible(false)
	ui.bitLockerPromptPanel.SetStyle(widgets.PanelStyle{
		Background:   core.RGB(255, 255, 255),
		BorderColor:  core.RGB(203, 213, 225),
		CornerRadius: 14,
		BorderWidth:  1,
	})

	ui.bitLockerPromptTitleLabel = widgets.NewLabel("bitlocker-prompt-title", "BitLocker 解锁")
	ui.bitLockerPromptTitleLabel.SetStyle(widgets.TextStyle{
		Font: widgets.FontSpec{
			Face:   "Microsoft YaHei UI",
			SizeDP: 20,
			Weight: 700,
		},
		Color:  core.RGB(15, 23, 42),
		Format: 0,
	})

	ui.bitLockerPromptTextLabel = widgets.NewLabel("bitlocker-prompt-text", "")
	ui.bitLockerPromptTextLabel.SetStyle(widgets.TextStyle{
		Font: widgets.FontSpec{
			Face:   "Microsoft YaHei UI",
			SizeDP: 15,
		},
		Color:  core.RGB(51, 65, 85),
		Format: 0,
	})

	ui.bitLockerPromptErrorLabel = widgets.NewLabel("bitlocker-prompt-error", "")
	ui.bitLockerPromptErrorLabel.SetStyle(widgets.TextStyle{
		Font: widgets.FontSpec{
			Face:   "Microsoft YaHei UI",
			SizeDP: 14,
		},
		Color:  core.RGB(220, 38, 38),
		Format: 0,
	})

	ui.bitLockerPromptInput = widgets.NewEditBox("bitlocker-prompt-input", 0)
	ui.bitLockerPromptInput.SetStyle(theme.Edit)
	ui.bitLockerPromptInput.SetPlaceholder("请输入密码或 48 位恢复密钥")
	ui.bitLockerPromptInput.SetOnSubmit(func(string) {
		submitBitLockerPrompt(false)
	})

	ui.bitLockerPromptPasswordBtn = widgets.NewButton("bitlocker-prompt-password", "用密码解锁", 0)
	ui.bitLockerPromptPasswordBtn.SetStyle(dialogPrimaryButtonStyle())
	ui.bitLockerPromptPasswordBtn.SetOnClick(func() {
		submitBitLockerPrompt(false)
	})

	ui.bitLockerPromptRecoveryBtn = widgets.NewButton("bitlocker-prompt-recovery", "用恢复密钥", 0)
	ui.bitLockerPromptRecoveryBtn.SetStyle(dialogPrimaryButtonStyle())
	ui.bitLockerPromptRecoveryBtn.SetOnClick(func() {
		submitBitLockerPrompt(true)
	})

	ui.bitLockerPromptCancelBtn = widgets.NewButton("bitlocker-prompt-cancel", "取消", 0)
	ui.bitLockerPromptCancelBtn.SetStyle(secondaryButtonStyle())
	ui.bitLockerPromptCancelBtn.SetOnClick(func() {
		cancelBitLockerPrompt()
	})

	ui.bitLockerPromptPanel.AddAll(
		ui.bitLockerPromptTitleLabel,
		ui.bitLockerPromptTextLabel,
		ui.bitLockerPromptErrorLabel,
		ui.bitLockerPromptInput,
		ui.bitLockerPromptPasswordBtn,
		ui.bitLockerPromptRecoveryBtn,
		ui.bitLockerPromptCancelBtn,
	)
	root.Add(ui.bitLockerPromptPanel)
}

func showBitLockerPrompt(title, prompt string, resultCh chan bitLockerPromptResult) {
	if ui.bitLockerPromptPanel == nil {
		if resultCh != nil {
			resultCh <- bitLockerPromptResult{Canceled: true}
			close(resultCh)
		}
		return
	}

	ui.bitLockerPromptVisible = true
	ui.bitLockerPromptResult = resultCh
	ui.bitLockerPromptTitleLabel.SetText(strings.TrimSpace(title))
	ui.bitLockerPromptTextLabel.SetText(strings.TrimSpace(prompt))
	ui.bitLockerPromptErrorLabel.SetText("")
	ui.bitLockerPromptInput.SetText("")
	ui.bitLockerPromptInput.SetPlaceholder("请输入密码或 48 位恢复密钥")
	if ui.scene != nil {
		ui.scene.Blur()
	}

	applyMode(modeProgress)
}

func submitBitLockerPrompt(useRecoveryKey bool) {
	if !ui.bitLockerPromptVisible {
		return
	}

	credential := strings.TrimSpace(ui.bitLockerPromptInput.TextValue())
	if credential == "" {
		ui.bitLockerPromptErrorLabel.SetText("请输入密码或恢复密钥。")
		return
	}

	resolveBitLockerPrompt(bitLockerPromptResult{
		Credential:     credential,
		UseRecoveryKey: useRecoveryKey,
	})
}

func cancelBitLockerPrompt() {
	if !ui.bitLockerPromptVisible {
		return
	}
	resolveBitLockerPrompt(bitLockerPromptResult{Canceled: true})
}

func closePendingBitLockerPrompt() {
	if !ui.bitLockerPromptVisible && ui.bitLockerPromptResult == nil {
		return
	}
	resolveBitLockerPrompt(bitLockerPromptResult{Canceled: true})
}

func resolveBitLockerPrompt(result bitLockerPromptResult) {
	resultCh := ui.bitLockerPromptResult

	ui.bitLockerPromptVisible = false
	ui.bitLockerPromptResult = nil
	if ui.bitLockerPromptErrorLabel != nil {
		ui.bitLockerPromptErrorLabel.SetText("")
	}
	if ui.bitLockerPromptInput != nil {
		ui.bitLockerPromptInput.SetText("")
	}
	if ui.scene != nil {
		ui.scene.Blur()
	}

	applyMode(modeProgress)

	if resultCh != nil {
		resultCh <- result
		close(resultCh)
	}
}

func layoutBitLockerPrompt(w, h int32) {
	if ui.bitLockerPromptPanel == nil || ui.app == nil {
		return
	}

	margin := ui.app.DP(24)
	panelW := ui.app.DP(560)
	panelH := ui.app.DP(290)
	maxW := w - ui.app.DP(40)
	if panelW > maxW {
		panelW = maxW
	}
	if panelW < ui.app.DP(320) {
		panelW = ui.app.DP(320)
	}
	panelX := (w - panelW) / 2
	panelY := (h - panelH) / 2

	ui.bitLockerPromptPanel.SetBounds(core.Rect{
		X: panelX,
		Y: panelY,
		W: panelW,
		H: panelH,
	})

	contentW := panelW - margin*2
	titleH := ui.app.DP(30)
	textH := ui.app.DP(108)
	inputH := ui.app.DP(40)
	errorH := ui.app.DP(24)
	btnH := ui.app.DP(38)
	btnGap := ui.app.DP(12)

	y := panelY + margin
	ui.bitLockerPromptTitleLabel.SetBounds(core.Rect{
		X: panelX + margin,
		Y: y,
		W: contentW,
		H: titleH,
	})

	y += titleH + ui.app.DP(12)
	ui.bitLockerPromptTextLabel.SetBounds(core.Rect{
		X: panelX + margin,
		Y: y,
		W: contentW,
		H: textH,
	})

	y += textH + ui.app.DP(10)
	ui.bitLockerPromptInput.SetBounds(core.Rect{
		X: panelX + margin,
		Y: y,
		W: contentW,
		H: inputH,
	})

	y += inputH + ui.app.DP(8)
	ui.bitLockerPromptErrorLabel.SetBounds(core.Rect{
		X: panelX + margin,
		Y: y,
		W: contentW,
		H: errorH,
	})

	btnW := (contentW - btnGap*2) / 3
	btnY := panelY + panelH - margin - btnH
	ui.bitLockerPromptPasswordBtn.SetBounds(core.Rect{
		X: panelX + margin,
		Y: btnY,
		W: btnW,
		H: btnH,
	})
	ui.bitLockerPromptRecoveryBtn.SetBounds(core.Rect{
		X: panelX + margin + btnW + btnGap,
		Y: btnY,
		W: btnW,
		H: btnH,
	})
	ui.bitLockerPromptCancelBtn.SetBounds(core.Rect{
		X: panelX + margin + (btnW+btnGap)*2,
		Y: btnY,
		W: btnW,
		H: btnH,
	})
}

func dialogPrimaryButtonStyle() widgets.ButtonStyle {
	return widgets.ButtonStyle{
		Font: widgets.FontSpec{
			Face:   "Microsoft YaHei UI",
			SizeDP: 14,
			Weight: 700,
		},
		TextColor:    core.RGB(255, 255, 255),
		DownText:     core.RGB(255, 255, 255),
		DisabledText: core.RGB(191, 219, 254),
		Background:   core.RGB(37, 99, 235),
		Hover:        core.RGB(29, 78, 216),
		Pressed:      core.RGB(30, 64, 175),
		Disabled:     core.RGB(96, 165, 250),
		Border:       0,
		CornerRadius: 10,
		PadDP:        12,
	}
}
