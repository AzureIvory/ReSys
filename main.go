package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"ReSys/src/install"
	"ReSys/src/log"
	"ReSys/src/tools"
	"ReSys/src/ui"
	"ReSys/src/windows"
)

// ImageProgress is injected by the UI layer when image operations need progress updates.
var ImageProgress func(phase string, percent float64, raw string)

type cmdOpt struct {
	src string
	tar string
}

var goJSN = install.StartJSON
var goTar = install.StartInstall
var smtTar = ui.SmartTar

func PE() int {
	ui.Win2()

	if err := install.RunPEInstall(); err != nil {
		ui.UiShowError("", err.Error())
		os.Exit(-1)
		return -1
	}

	return 0
}

// cliOpt 解析命令行安装入口，支持 JSON、自定义目标与智能重装。
func cliOpt(args []string) (cmdOpt, error) {
	fs := flag.NewFlagSet("resys", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	opt := cmdOpt{}
	var src string
	var w7 bool
	var w10 bool
	var w11 bool
	var smt bool

	fs.StringVar(&src, "json", "", "install json source")
	fs.BoolVar(&w7, "win7", false, "auto install win7")
	fs.BoolVar(&w10, "win10", false, "auto install win10")
	fs.BoolVar(&w11, "win11", false, "auto install win11")
	fs.BoolVar(&smt, "smart", false, "smart install")
	if err := fs.Parse(args); err != nil {
		return cmdOpt{}, err
	}
	if len(fs.Args()) != 0 {
		return cmdOpt{}, fmt.Errorf("unexpected args: %s", strings.Join(fs.Args(), " "))
	}

	opt.src = strings.TrimSpace(src)
	if w7 {
		opt.tar = "win7"
	}
	if w10 {
		if opt.tar != "" || opt.src != "" {
			return cmdOpt{}, fmt.Errorf("install args conflict")
		}
		opt.tar = "win10"
	}
	if w11 {
		if opt.tar != "" || opt.src != "" {
			return cmdOpt{}, fmt.Errorf("install args conflict")
		}
		opt.tar = "win11"
	}
	if smt {
		if opt.tar != "" || opt.src != "" {
			return cmdOpt{}, fmt.Errorf("install args conflict")
		}
		opt.tar = "smart"
	}
	if opt.src != "" && opt.tar != "" {
		return cmdOpt{}, fmt.Errorf("install args conflict")
	}
	return opt, nil
}

// runArg 根据解析后的命令行参数启动对应安装入口。
func runArg(opt cmdOpt) {
	if opt.src != "" {
		goJSN(opt.src)
		return
	}
	if opt.tar == "" {
		return
	}
	tar := opt.tar
	if tar == "smart" {
		tar = smtTar()
	}
	goTar(tar)
}

func main() {
	opt, err := cliOpt(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
		return
	}

	if !tools.IsAdmin() {
		if err := tools.RestartAsAdmin(); err != nil {
			panic(err)
		}
		return
	}

	ui.Uiinit()
	if windows.IsWinPE() {
		go PE()
	} else if opt.src != "" || opt.tar != "" {
		ui.Win2()
		go runArg(opt)
	}

	log.LogWrite(0, "[main]Run\n")
	ui.UiRun()
}
