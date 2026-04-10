//go:build windows

// BitLocker 解锁提示（JSONUI 版本）。
//
// 这里不创建独立的原生弹窗窗口，而是通过 JSONUI 的 Store 状态来控制
// `rules/ui/layout.ui.json` 中的 prompt 区域显示/隐藏：
// - 显示：设置 `prompt.visible=true`，并填充 `prompt.title/prompt.text` 等字段。
// - 输入：Edit 的变更通过 action 回调写回 `prompt.credential`。
// - 提交/取消：将结果通过 channel 回传给阻塞式调用者，并清理 prompt 状态。
//
// 重要约束：
// UiPromptBitLockerUnlock 是“阻塞式”等待用户输入的 API，必须在非 UI 线程调用。
// 如果在 UI 线程阻塞等待，会卡死消息循环，界面无法响应。
package ui

import (
	"errors"
	"strings"
)

// bitLockerPromptResult 用于在“阻塞式 API”和“UI 回调”之间传递结果。
type bitLockerPromptResult struct {
	Credential     string
	UseRecoveryKey bool
	Canceled       bool
}

// UiPromptBitLockerUnlock 在 UI 中显示 BitLocker 解锁提示，并阻塞等待用户输入。
//
// 返回值约定：
// - credential: 用户输入的密码/恢复密钥（空字符串表示未提供）。
// - useRecoveryKey: true 表示用户选择按“恢复密钥”方式解锁。
// - canceled: true 表示用户取消/窗口关闭。
//
// 注意：
// - 该函数不能在 UI 线程调用（会阻塞导致界面卡死）。
// - 同一时刻只允许出现一个 prompt，重复调用会返回错误。
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

// showBitLockerPrompt 在 UI 线程内生效：切换页面、模糊背景，并把 prompt 字段写入 Store。
func showBitLockerPrompt(title, prompt string, resultCh chan bitLockerPromptResult) {
	if strings.TrimSpace(title) == "" {
		title = T("prompt.title")
	}

	ui.bitLockerPromptVisible = true
	ui.bitLockerPromptResult = resultCh
	if ui.scene != nil {
		ui.scene.Blur()
	}

	applyMode(modeProgress)
	if ui.store != nil {
		ui.store.Patch(map[string]any{
			"prompt.visible":    true,
			"prompt.title":      strings.TrimSpace(title),
			"prompt.text":       strings.TrimSpace(prompt),
			"prompt.error":      "",
			"prompt.credential": "",
		})
	}
}

// bitLockerPromptInputChanged 由 Edit 输入框的 action 回调触发。
// 为了避免“用户输入后仍显示旧错误提示”，这里会同时清空 `prompt.error`。
func bitLockerPromptInputChanged(value string) {
	if ui.store == nil {
		return
	}
	ui.store.Patch(map[string]any{
		"prompt.credential": value,
		"prompt.error":      "",
	})
}

// submitBitLockerPrompt 由“确认”按钮触发。
// 如果输入为空，提示错误并保持 prompt 可见；否则把结果回传并关闭 prompt。
func submitBitLockerPrompt(useRecoveryKey bool) {
	if !ui.bitLockerPromptVisible {
		return
	}

	credential := strings.TrimSpace(promptCredential())
	if credential == "" {
		if ui.store != nil {
			ui.store.Set("prompt.error", T("prompt.error.emptyCredential"))
		}
		return
	}

	resolveBitLockerPrompt(bitLockerPromptResult{
		Credential:     credential,
		UseRecoveryKey: useRecoveryKey,
	})
}

// cancelBitLockerPrompt 由“取消”按钮触发。
func cancelBitLockerPrompt() {
	if !ui.bitLockerPromptVisible {
		return
	}
	resolveBitLockerPrompt(bitLockerPromptResult{Canceled: true})
}

// closePendingBitLockerPrompt 用于窗口销毁时的兜底清理（见 Ui.go 的 onDestroy）。
// 目的是避免外部 goroutine 永久阻塞在等待结果的 channel 上。
func closePendingBitLockerPrompt() {
	if !ui.bitLockerPromptVisible && ui.bitLockerPromptResult == nil {
		return
	}
	resolveBitLockerPrompt(bitLockerPromptResult{Canceled: true})
}

// resolveBitLockerPrompt 统一收口：隐藏 prompt、恢复背景效果，并回传结果。
//
// 这里会 close 掉 resultCh，调用方的 `<-resultCh` 会解除阻塞。
func resolveBitLockerPrompt(result bitLockerPromptResult) {
	resultCh := ui.bitLockerPromptResult

	ui.bitLockerPromptVisible = false
	ui.bitLockerPromptResult = nil

	applyMode(modeProgress)
	if ui.store != nil {
		ui.store.Patch(map[string]any{
			"prompt.visible":    false,
			"prompt.error":      "",
			"prompt.credential": "",
		})
	}
	if ui.scene != nil {
		ui.scene.Blur()
	}

	if resultCh != nil {
		resultCh <- result
		close(resultCh)
	}
}

// promptCredential 从 Store 中读取当前输入框内容。
func promptCredential() string {
	if ui.store == nil {
		return ""
	}
	value, ok := ui.store.Get("prompt.credential")
	if !ok {
		return ""
	}
	text, ok := value.(string)
	if !ok {
		return ""
	}
	return text
}
