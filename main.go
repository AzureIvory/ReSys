package main

import (
	"os"
	"strings"

	"ReSys/src/install"
	"ReSys/src/log"
	"ReSys/src/tools"
	"ReSys/src/ui"
	"ReSys/src/utils"
	"ReSys/src/windows"
)

// ImageProgress is injected by the UI layer when image operations need progress updates.
var ImageProgress func(phase string, percent float64, raw string)

func GetBootMode() (int, int) {
	if !utils.DirExists("tools\\BootMode.exe") {
		return -1, -1
	}

	text, err := tools.RunCmd("tools\\BootMode.exe", nil, nil, "", "")
	if err != nil {
		return -1, -1
	}

	text = strings.TrimSpace(text)
	parts := strings.Split(text, " | ")
	if len(parts) != 2 {
		return -1, -1
	}

	mode := 0
	if parts[0] == "UEFI" || parts[0] == "efi" {
		mode = 1
	}

	safe := 1
	if parts[1] == "SecureBoot: disabled" {
		safe = 0
	}

	return mode, safe
}

func PE() int {
	ui.Win2()

	if err := install.RunPEInstall(); err != nil {
		ui.UiShowError("", err.Error())
		os.Exit(-1)
		return -1
	}

	return 0
}

func main() {
	if !tools.IsAdmin() {
		if err := tools.RestartAsAdmin(); err != nil {
			panic(err)
		}
		return
	}

	ui.Uiinit()
	if windows.IsWinPE() {
		go PE()
	}

	log.LogWrite(0, "[main]Run\n")
	ui.UiRun()
}
