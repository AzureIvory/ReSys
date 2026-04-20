package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	nlog "log"
	"os"
	"strings"
	"time"

	"ReSys/src/download"
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

func test() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	res, err := download.Download(ctx, download.NOptions{
		URL:         "https://mirrors.sdu.edu.cn/wepe/WePE_64_V2.3.exe",
		Destination: "./1.exe",
		Concurrency: 1,
		ChunkSize:   4 << 20, // 4 MiB
		Header:      nil,     // 默认空
		SkipProbe:   true,    // 跳过探测阶段，直接进入下载阶段

		VerifyChecksum: &download.ChecksumConfig{
			Name:        "sha256",
			New:         sha256.New,
			ExpectedHex: "", // 留空表示只计算并返回，不做比对
		},

		OnProgress: func(p download.NProgress) {
			fmt.Printf(
				"\rstatus=%s %.2f%% downloaded=%d/%d speed=%.2f MiB/s verified=%d chunks=%d/%d",
				p.Status,
				p.Percent*100,
				p.BytesDownloaded,
				p.BytesTotal,
				p.SpeedBPS/1024/1024,
				p.BytesVerified,
				p.ChunksCompleted,
				p.ChunksTotal,
			)
		},
	})
	if err != nil {
		nlog.Fatalf(
			"download failed: status=%s code=%d reason=%s err=%v",
			res.Status,
			res.DownloadStatusCode,
			res.ErrorReason,
			err,
		)
	}

	fmt.Printf(
		"\nOK: status=%s probe=%d download=%d sha256=%s\n",
		res.Status,
		res.ProbeStatusCode,
		res.DownloadStatusCode,
		res.ChecksumHex,
	)
}

func main() {
	test()

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
