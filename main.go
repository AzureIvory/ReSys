package main

import (
	"fmt"
	"os"
	"strings"

	D "ReSys/src/dism"
	"ReSys/src/download"
	"ReSys/src/install"
	"ReSys/src/log"
	"ReSys/src/tools"
	"ReSys/src/ui"
	"ReSys/src/utils"
	"ReSys/src/windows"
	"ReSys/src/data"
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
func test() {
	magnet := "magnet:?xt=urn:btih:585DF592DE43A067C75CFE5A639B41FC3F24DA6F&dn=cn_windows_7_ultimate_with_sp1_x86_dvd_u_677486.iso&xl=2653276160"
	dir := "./downloads"

	_, err := download.DownloadBT(magnet, dir, func(pct int, speed, done, total int64) {
		fmt.Printf(
			"\rBT下载进度: %3d%%  速度: %-10s  已下: %-10s  总计: %-10s",
			pct,
			fmt.Sprint(speed),
			fmt.Sprint(done),
			fmt.Sprint(total),
		)

		if pct >= 100 {
			fmt.Println()
		}
	})
	if err != nil {
		fmt.Println("BT下载失败:", err)
		return
	}

}

func main() {
	fmt.Println(data.ParseRuleWinImgs(`C:\Users\Administrator\Desktop\ReSys\rules\core\image-sources\10\win10-ms.json`))

	//os.Exit(1)
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
