package main

import (
	"os"

	"ReSys/src/install"
	"ReSys/src/log"
	"ReSys/src/tools"
	"ReSys/src/ui"
	"ReSys/src/windows"
)

// ImageProgress is injected by the UI layer when image operations need progress updates.
var ImageProgress func(phase string, percent float64, raw string)

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
