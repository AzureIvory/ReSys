//go:build windows

package ui

import (
	"encoding/base64"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"unicode/utf16"
)

func openImageFileDialog(initial string) (string, error) {
	return openFileDialog(
		"选择安装镜像",
		"安装镜像 (*.iso;*.wim;*.esd)|*.iso;*.wim;*.esd|所有文件 (*.*)|*.*",
		initial,
	)
}

func openPEFileDialog(initial string) (string, error) {
	return openFileDialog(
		"选择 PE WIM",
		"PE WIM (*.wim)|*.wim|所有文件 (*.*)|*.*",
		initial,
	)
}

func openFileDialog(title, filter, initial string) (string, error) {
	initialDir := strings.TrimSpace(initial)
	if initialDir != "" {
		if ext := strings.TrimSpace(filepath.Ext(initialDir)); ext != "" {
			initialDir = filepath.Dir(initialDir)
		}
	}

	script := strings.Builder{}
	script.WriteString("[Console]::OutputEncoding = [System.Text.Encoding]::UTF8;")
	script.WriteString("Add-Type -AssemblyName System.Windows.Forms;")
	script.WriteString("$dialog = New-Object System.Windows.Forms.OpenFileDialog;")
	script.WriteString("$dialog.Title = " + powerShellQuote(title) + ";")
	script.WriteString("$dialog.Filter = " + powerShellQuote(filter) + ";")
	script.WriteString("$dialog.CheckFileExists = $true;")
	script.WriteString("$dialog.CheckPathExists = $true;")
	script.WriteString("$dialog.Multiselect = $false;")
	if initialDir != "" && initialDir != "." {
		script.WriteString("$dialog.InitialDirectory = " + powerShellQuote(initialDir) + ";")
	}
	script.WriteString("if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {[Console]::Write($dialog.FileName)}")

	cmd := exec.Command(
		"powershell.exe",
		"-NoLogo",
		"-NoProfile",
		"-NonInteractive",
		"-STA",
		"-EncodedCommand",
		encodePowerShellScript(script.String()),
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(output))
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("打开文件选择窗口失败: %s", msg)
	}

	return strings.TrimSpace(string(output)), nil
}

func powerShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func encodePowerShellScript(script string) string {
	encoded := utf16.Encode([]rune(script))
	buf := make([]byte, len(encoded)*2)
	for i, r := range encoded {
		buf[i*2] = byte(r)
		buf[i*2+1] = byte(r >> 8)
	}
	return base64.StdEncoding.EncodeToString(buf)
}
