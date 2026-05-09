package install

import (
	"ReSys/src/config"
	"ReSys/src/log"
	"ReSys/src/ui"
	"fmt"
	"strings"
)

var parseCfg = config.ParseSource
var runAuto = startAuto
var runMan = startMan
var showErr = onStartErr

// StartJSON 按 JSON 中的 mode 字段分派自动或手动重装入口。
func StartJSON(src string) {
	cfg, err := parseCfg(src)
	if err != nil {
		showErr(err, false)
		return
	}

	mode, err := cfgMode(cfg)
	if err != nil {
		showErr(err, false)
		return
	}

	if mode == ReinstallModeAuto {
		runAuto(cfg)
		return
	}
	runMan(cfg)
}

// cfgMode 只负责把配置中的 mode 归一化为安装入口模式。
func cfgMode(cfg config.Config) (ReinstallMode, error) {
	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	switch mode {
	case string(ReinstallModeAuto):
		return ReinstallModeAuto, nil
	case string(ReinstallModeManual):
		return ReinstallModeManual, nil
	case "":
		return "", fmt.Errorf("install mode is empty")
	default:
		return "", fmt.Errorf("unsupported install mode: %s", cfg.Mode)
	}
}

// onStartErr 统一处理命令行入口在分派前的错误，并回退到选择页。
func onStartErr(err error, isMan bool) {
	markJSNErr(err)
	log.LogWrite(-2, "[StartJSON] failed: %v", err)
	ui.Warning("", err.Error())
	if isMan {
		ui.UiShowManualMode()
		return
	}
	ui.UiShowSelectMode()
}

// markJSNErr 将 JSON 入口错误写入进度文件，方便外部 AI 读取失败原因。
func markJSNErr(err error) {
	if err == nil {
		return
	}
	msg := strings.TrimSpace(err.Error())
	if msg == "" {
		msg = "unknown error"
	}
	ui.UiSetProgress(0)
	ui.UiSetStatus("JSON配置错误: " + msg)
}
