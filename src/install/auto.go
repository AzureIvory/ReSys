package install

import (
	"ReSys/src/config"
	"ReSys/src/log"
	"ReSys/src/ui"
	"ReSys/src/utils"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
)

// init 将安装入口绑定到界面层。
func init() {
	ui.StartInstall = StartInstall
}

// StartInstall 启动 Windows 侧的自动重装准备流程。
func StartInstall(target string) {
	cfg, err := autoCfg(target)
	if err != nil {
		log.LogWrite(-2, "[StartInstall] load config failed: %v", err)
		if ui.Warning("", err.Error()) {
			os.Exit(-1)
		}
		ui.UiShowSelectMode()
		return
	}
	runAuto(cfg)
}

// startAuto 负责自动模式的通用启动逻辑，供 UI 与命令行共用。
func startAuto(cfg config.Config) {
	plan, err := planAuto(cfg)
	if err != nil {
		log.LogWrite(-2, "[startAuto] plan failed: %v", err)
		if ui.Warning("", err.Error()) {
			os.Exit(-1)
		}
		ui.UiShowSelectMode()
		return
	}
	ctx := NewInstallContext(plan)

	log.LogWrite(0, "[startAuto] target=%s imageArch=%s peArch=%s", plan.TargetOS, plan.ImageArch, plan.PEArch)
	if err := runFlowWithGuard("StartInstall", func() error {
		return runAutoPrepareFlow(ctx)
	}); err != nil {
		log.LogWrite(-2, "[startAuto] failed: %v", err)
		if !errors.Is(err, ErrInstallCanceled) {
			if ui.Warning("", err.Error()) {
				os.Exit(-1)
			}
			ui.UiShowSelectMode()
			return
		}
		os.Exit(-1)
		return
	}

	ui.UiSetProgress(100)
	ui.UiSetStatus(ui.Tr("install.auto.prepareDone"))
	log.LogWrite(0, "[startAuto] prepare finished")
}

// loadAutoInstallPlan 读取自动重装 JSON 并转换为安装计划。
func loadAutoInstallPlan(target string) (*InstallPlan, error) {
	cfg, err := autoCfg(target)
	if err != nil {
		return nil, err
	}
	return planAuto(cfg)
}

func autoCfg(target string) (config.Config, error) {
	target = strings.ToLower(strings.TrimSpace(target))
	if target == "" {
		return config.Config{}, fmt.Errorf("empty target os")
	}

	cfgPath, err := autoConfigPath(target)
	if err != nil {
		return config.Config{}, err
	}
	cfg, err := config.ParseSource(cfgPath)
	if err != nil {
		return config.Config{}, err
	}
	if strings.TrimSpace(cfg.Mode) == "" {
		cfg.Mode = string(ReinstallModeAuto)
	}
	if strings.TrimSpace(cfg.TargetOS) == "" {
		cfg.TargetOS = target
	}
	return cfg, nil
}

func planAuto(cfg config.Config) (*InstallPlan, error) {
	plan := planFromCfg(cfg)
	plan.Mode = ReinstallModeAuto
	if err := NormalizeInstallPlan(plan); err != nil {
		return nil, err
	}
	return plan, nil
}

func autoConfigPath(target string) (string, error) {
	switch target {
	case TargetWin7, TargetWin10, TargetWin11:
	default:
		return "", fmt.Errorf("unsupported target os: %s", target)
	}
	return utils.ProjectFile(filepath.Join("rules", "install", "auto", target+".json"))
}

// RunPEInstall 执行 PE 内的自动安装流程。
func RunPEInstall() error {
	ui.UiSetProgress(0)
	ui.UiSetStatus(ui.Tr("install.auto.readInstallInfo"))
	log.LogWrite(0, "[RunPEInstall] enter PE install flow")

	ctx := NewInstallContext(nil)
	if err := runFlowWithGuard("RunPEInstall", func() error {
		plan, err := LoadInstallPlan()
		if err != nil {
			return err
		}
		ctx.Plan = plan
		if plan.Mode == ReinstallModeManual {
			return runManualPEFlow(ctx)
		}
		return runAutoPEFlow(ctx)
	}); err != nil {
		log.LogWrite(-2, "[RunPEInstall] failed: %v", err)
		return err
	}

	ui.UiSetStatus(ui.Tr("install.auto.completed"))
	ui.UiSetProgress(100)
	log.LogWrite(0, "[RunPEInstall] completed")
	return nil
}

// runAutoPrepareFlow 按阶段完成进入 PE 前的自动准备。
func runAutoPrepareFlow(ctx *InstallContext) error {
	stages := []*Stage{
		{
			Name: "预检查",
			Run: func(ctx *InstallContext) error {
				ui.UiSetProgress(0)
				ui.UiSetStatus(ui.Tr("install.auto.checkEnvironment"))
				return NormalizeInstallPlan(ctx.Plan)
			},
		},
		{
			Name:      "获取镜像",
			Retryable: true,
			Run: func(ctx *InstallContext) error {
				ui.UiSetProgress(0)
				ui.UiSetStatus(ui.Tr("install.auto.findImage"))
				_, err := AcquireInstallImage(ctx.Plan)
				return err
			},
		},
		{
			Name:      "BitLocker 预处理",
			Retryable: false,
			Run: func(ctx *InstallContext) error {
				ui.UiSetProgress(50)
				ui.UiSetStatus(ui.Tr("install.auto.handleBitLocker"))
				return handleBitLocker(ctx)
			},
		},
		{
			Name:      "准备ISO镜像",
			Retryable: true,
			Run: func(ctx *InstallContext) error {
				ui.UiSetProgress(55)
				ui.UiSetStatus("准备ISO安装镜像")
				return prepISO(ctx.Plan)
			},
		},
		{
			Name:      "保存安装计划",
			Retryable: true,
			Run: func(ctx *InstallContext) error {
				ui.UiSetProgress(60)
				ui.UiSetStatus(ui.Tr("install.auto.writeInstallInfo"))
				return SaveInstallPlan(ctx.Plan)
			},
		},
		{
			Name: "HookBeforeEnterPE",
			Run: func(ctx *InstallContext) error {
				return ctx.RunHooks(HookBeforeEnterPE)
			},
		},
		{
			Name:      "准备PE",
			Retryable: true,
			Run: func(ctx *InstallContext) error {
				ui.UiSetProgress(70)
				ui.UiSetStatus(ui.Tr("install.auto.preparePE"))
				return PreparePEEnvironment(ctx)
			},
		},
		{
			Name:      "设置下次启动进入PE",
			Retryable: true,
			Run: func(ctx *InstallContext) error {
				return SetNextBootToPE(ctx)
			},
		},
	}

	return RunStages(ctx, stages)
}

// runAutoPEFlow 按阶段完成 PE 内的自动安装。
func runAutoPEFlow(ctx *InstallContext) error {
	stages := []*Stage{
		{
			Name: "读取安装计划",
			Run: func(ctx *InstallContext) error {
				ui.UiSetProgress(0)
				ui.UiSetStatus(ui.Tr("install.auto.readInstallInfo"))
				plan, err := LoadInstallPlan()
				if err != nil {
					return err
				}
				ctx.Plan = plan
				return nil
			},
		},
		{
			Name:      "恢复镜像路径",
			Retryable: true,
			Run: func(ctx *InstallContext) error {
				if err := NormalizeInstallPlan(ctx.Plan); err != nil {
					return err
				}
				_, err := RecoverOrAcquireInstallImage(ctx.Plan)
				if err != nil {
					return fmt.Errorf("未找到镜像且下载失败: %w", err)
				}
				return nil
			},
		},
		{
			Name: "HookBeforeResolveDisk",
			Run: func(ctx *InstallContext) error {
				return ctx.RunHooks(HookBeforeResolveDisk)
			},
		},
		{
			Name:      "解析目标分区",
			Retryable: true,
			Run: func(ctx *InstallContext) error {
				ui.UiSetStatus(ui.Tr("install.auto.resolveTarget"))
				return ResolveInstallTarget(ctx.Plan)
			},
		},
		{
			Name: "HookBeforeFormatTarget",
			Run: func(ctx *InstallContext) error {
				return ctx.RunHooks(HookBeforeFormatTarget)
			},
		},
		{
			Name:      "格式化目标分区",
			Retryable: true,
			Run: func(ctx *InstallContext) error {
				ui.UiSetProgress(10)
				ui.UiSetStatus(ui.Tr("install.auto.formatTarget"))
				return FormatTargetPartition(ctx.Plan)
			},
		},
		{
			Name:      "选择镜像索引",
			Retryable: true,
			Run: func(ctx *InstallContext) error {
				ui.UiSetProgress(20)
				ui.UiSetStatus(ui.Tr("install.auto.parseImage"))
				if err := ResolveInstallImageIndex(ctx); err != nil {
					return err
				}
				infos := installImageInfosFromContext(ctx)
				log.LogWrite(0, "[RunPEInstall] image infos: %s", formatImageInfos(infos))
				log.LogWrite(0, "[RunPEInstall] apply image: image=%s target=%s index=%d", ctx.Plan.ImagePath, ctx.Plan.TargetRoot, ctx.Plan.ImageIndex)
				return nil
			},
		},
		{
			Name: "HookBeforeApplyImage",
			Run: func(ctx *InstallContext) error {
				return ctx.RunHooks(HookBeforeApplyImage)
			},
		},
		{
			Name: "应用镜像",
			Run: func(ctx *InstallContext) error {
				progressCb := func(phase string, pct float64, raw string) {
					_ = raw
					ui.UiSetStatus(ui.Trf("install.auto.applyImagePhase", phase, pct))
					ui.UiSetProgress(MapPct(20, 50, pct))
				}
				return ApplyInstallImage(ctx.Plan, progressCb)
			},
		},
		{
			Name: "HookAfterApplyImage",
			Run: func(ctx *InstallContext) error {
				return ctx.RunHooks(HookAfterApplyImage)
			},
		},
		{
			Name: "修复引导",
			Run: func(ctx *InstallContext) error {
				ui.UiSetProgress(75)
				ui.UiSetStatus(ui.Tr("install.auto.repairBoot"))
				return RepairInstallBoot(ctx.Plan)
			},
		},
		{
			Name: "HookAfterRepairBoot",
			Run: func(ctx *InstallContext) error {
				return ctx.RunHooks(HookAfterRepairBoot)
			},
		},
		{
			Name: "HookAfterInstall",
			Run: func(ctx *InstallContext) error {
				return ctx.RunHooks(HookAfterInstall)
			},
		},
	}

	return RunStages(ctx, stages)
}

// runFlowWithGuard 为流程执行提供统一的崩溃保护。
func runFlowWithGuard(flow string, fn func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			log.LogWrite(-2, "[%s] panic: panic=%v stack=%s", flow, r, string(debug.Stack()))
			err = fmt.Errorf("%s panic: %v", flow, r)
		}
	}()
	return fn()
}
