package install

import (
	"ReSys/src/log"
	"ReSys/src/ui"
	"ReSys/src/windows"
	"fmt"
	"os"
	"runtime/debug"
)

// init 将安装入口绑定到界面层。
func init() {
	ui.StartInstall = StartInstall
}

// StartInstall 启动 Windows 侧的自动重装准备流程。
func StartInstall(target string) {
	plan := &InstallPlan{
		Mode:         ReinstallModeAuto,
		TargetOS:     target,
		ImageArch:    windows.DesiredArch(),
		PEArch:       windows.SystemArch(),
		AutoPE:       true,
		FormatTarget: true,
		BootRepair:   BootRepairModeAuto,
		Flags: InstallFlags{
			NeedBitLockerHandling: true,
			NeedBackupBeforePE:    true,
			NeedOfflineDrivers:    true,
			NeedCopyXMLAfterBoot:  true,
		},
	}
	ctx := NewInstallContext(plan)

	log.LogWrite(0, "[StartInstall] target=%s imageArch=%s peArch=%s", target, plan.ImageArch, plan.PEArch)
	if err := runFlowWithGuard("StartInstall", func() error {
		return runAutoPrepareFlow(ctx)
	}); err != nil {
		log.LogWrite(-2, "[StartInstall] failed: %v", err)
		ui.UiShowError("错误", err.Error())
		os.Exit(-1)
		return
	}

	ui.UiSetProgress(100)
	ui.UiSetStatus("准备完成，重启后将进入PE...")
	log.LogWrite(0, "[StartInstall] prepare finished")
}

// RunPEInstall 执行 PE 内的自动安装流程。
func RunPEInstall() error {
	ui.UiSetProgress(0)
	ui.UiSetStatus("正在读取重装信息...")
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

	ui.UiSetStatus("安装完成，正在重启...")
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
				ui.UiSetStatus("正在检查安装环境...")
				return NormalizeInstallPlan(ctx.Plan)
			},
		},
		{
			Name:      "获取镜像",
			Retryable: true,
			Run: func(ctx *InstallContext) error {
				ui.UiSetProgress(0)
				ui.UiSetStatus("正在寻找镜像...")
				_, err := AcquireInstallImage(ctx.Plan)
				return err
			},
		},
		{
			Name:      "BitLocker 预处理",
			Retryable: false,
			Run: func(ctx *InstallContext) error {
				ui.UiSetProgress(50)
				ui.UiSetStatus("正在处理 BitLocker...")
				return handleBitLockerBeforeEnterPE(ctx)
			},
		},
		{
			Name:      "保存安装计划",
			Retryable: true,
			Run: func(ctx *InstallContext) error {
				ui.UiSetProgress(60)
				ui.UiSetStatus("正在写入重装信息...")
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
				ui.UiSetStatus("正在准备PE环境...")
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
				ui.UiSetStatus("正在读取重装信息...")
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
				ui.UiSetStatus("正在解析目标分区...")
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
				ui.UiSetStatus("正在格式化分区...")
				return FormatTargetPartition(ctx.Plan)
			},
		},
		{
			Name:      "选择镜像索引",
			Retryable: true,
			Run: func(ctx *InstallContext) error {
				ui.UiSetProgress(20)
				ui.UiSetStatus("正在解析镜像...")
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
					ui.UiSetStatus(fmt.Sprintf("正在应用镜像... %s %.1f%%", phase, pct))
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
				ui.UiSetStatus("正在修复引导...")
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
