package main

import (
	"fmt"
	"os"
	"strings"

	D "ReSys/src/dism"
	"ReSys/src/install"
	"ReSys/src/log"
	"ReSys/src/tools"
	"ReSys/src/ui"
	"ReSys/src/utils"
	"ReSys/src/wimlib"
)

var t = D.NewDism()
var dism, _ = t.GetDismCmd()

// 用于显示进度条。
var ImageProgress func(phase string, percent float64, raw string)

// 获取启动模式
// 引导 ：0 BIOS 1 UEFI -1错误
// 安全启动：0 关闭 1开启 -1错误
func GetBootMode() (int, int) {
	if utils.DirExists("tools\\BootMode.exe") != true {
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
	var mode int
	var safe int
	if parts[0] == "UEFI" || parts[0] == "efi" {
		mode = 1
	} else {
		mode = 0
	}
	if parts[1] == "SecureBoot: disabled" {
		safe = 0
	} else {
		safe = 1
	}
	return mode, safe
}

// pe专用
func PE() int {
	ui.Win2()

	if err := install.RunPEInstall(); err != nil {
		ui.UiShowError("错误", err.Error())
		os.Exit(-1)
		return -1
	}
	return 0
}

func main() {

	//fmt.Println(dism)
	fmt.Println(wimlib.ListImageInfos(`C:\111111\win10_Iot_Ltsc2021_5198_X64 [AEC155F5].esd`))

	os.Exit(1)

	if dism == "" {
		dism = "dism.exe"
	}
	ui.Uiinit()
	//判断是否在PE
	if strings.ToUpper(os.Getenv("SystemRoot")) == `X:\WINDOWS` {
		go PE()
	}
	log.LogWrite(0, "[main]Run\n")
	ui.UiRun()
}
