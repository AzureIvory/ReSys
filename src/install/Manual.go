package install

import (
	"ReSys/src/boot"
	"ReSys/src/disk"
	imgsvc "ReSys/src/image"
	"ReSys/src/log"
	"ReSys/src/tools"
	"ReSys/src/ui"
	"ReSys/src/utils"
	"ReSys/src/windows"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func init() {
	ui.StartManualInstall = StartManualInstall
}

// StartManualInstall starts the advanced manual reinstall flow.
func StartManualInstall(cfg ui.ManualInstallConfig) {
	plan, err := buildManualInstallPlan(cfg)
	if err != nil {
		ui.UiShowError("错误", err.Error())
		ui.UiShowManualMode()
		return
	}

	ctx := NewInstallContext(plan)
	log.LogWrite(0, "[StartManualInstall] image=%s index=%d target=%s mode=%s", plan.ImagePath, plan.ImageIndex, plan.TargetRoot, plan.Mode)

	if manualTargetNeedsPE(plan) {
		if err := runFlowWithGuard("StartManualInstallPreparePE", func() error {
			return runManualPrepareFlow(ctx)
		}); err != nil {
			log.LogWrite(-2, "[StartManualInstall] prepare failed: %v", err)
			ui.UiShowError("错误", err.Error())
			ui.UiShowManualMode()
			return
		}
		ui.UiSetProgress(100)
		if plan.AutoReboot {
			ui.UiSetStatus("正在重启进入PE...")
			time.Sleep(500 * time.Millisecond)
			tools.Shutdown(true)
			return
		}
		ui.UiSetStatus("准备完成，请手动重启进入PE。")
		return
	}

	if err := runFlowWithGuard("StartManualInstallDirect", func() error {
		return runManualDirectFlow(ctx)
	}); err != nil {
		log.LogWrite(-2, "[StartManualInstall] direct install failed: %v", err)
		ui.UiShowError("错误", err.Error())
		ui.UiShowManualMode()
		return
	}

	finishManualInstall(ctx.Plan)
}

func buildManualInstallPlan(cfg ui.ManualInstallConfig) (*InstallPlan, error) {
	plan := &InstallPlan{
		Mode:          ReinstallModeManual,
		TargetOS:      strings.TrimSpace(cfg.TargetOS),
		ImageArch:     utils.NormalizeArch(cfg.ImageArch),
		PEArch:        windows.SystemArch(),
		ImagePath:     strings.TrimSpace(cfg.ImagePath),
		ImageIndex:    cfg.ImageIndex,
		TargetRoot:    strings.TrimSpace(cfg.TargetRoot),
		AutoPE:        cfg.AutoPE,
		ManualPEWIM:   strings.TrimSpace(cfg.ManualPEWIM),
		FormatTarget:  cfg.FormatTarget,
		AutoReboot:    cfg.AutoReboot,
		BootRepair:    BootRepairMode(strings.TrimSpace(cfg.BootRepair)),
		BootTargetRef: strings.TrimSpace(cfg.BootTargetRef),
		Flags: InstallFlags{
			NeedBitLockerHandling: true,
			NeedBackupBeforePE:    cfg.BackupDrivers,
			NeedOfflineDrivers:    cfg.BackupDrivers,
			NeedCopyXMLAfterBoot:  cfg.AutoDeploy,
		},
	}
	if plan.BootRepair == "" {
		plan.BootRepair = BootRepairModeAuto
	}
	if err := NormalizeInstallPlan(plan); err != nil {
		return nil, err
	}
	if root, err := utils.NormalizeDrive(plan.TargetRoot, 0); err == nil {
		plan.TargetRoot = root
	}
	if strings.TrimSpace(plan.ImagePath) == "" {
		return nil, fmt.Errorf("请选择安装镜像")
	}
	if strings.TrimSpace(plan.TargetRoot) == "" {
		return nil, fmt.Errorf("请选择安装分区")
	}

	infos, err := imgsvc.DetectImageInfos(plan.ImagePath)
	if err != nil {
		return nil, fmt.Errorf("解析镜像失败: %w", err)
	}
	if plan.ImageIndex <= 0 {
		plan.ImageIndex = SelectInstallIndex(infos)
	}
	if plan.TargetOS == "" {
		plan.TargetOS = imgsvc.DetectTargetFromInfos(infos)
	}
	if plan.ImageArch == "" {
		for _, info := range infos {
			if info.Index == plan.ImageIndex {
				plan.ImageArch = utils.NormalizeArch(info.Arch)
				break
			}
		}
	}
	if plan.ImageArch == "" {
		plan.ImageArch = windows.DesiredArch()
	}
	if manualTargetNeedsPE(plan) && !plan.AutoPE && strings.TrimSpace(plan.ManualPEWIM) == "" {
		return nil, fmt.Errorf("当前系统分区安装必须指定 PE WIM，或启用自动处理PE")
	}
	return plan, nil
}

func runManualPrepareFlow(ctx *InstallContext) error {
	stages := []*Stage{
		{
			Name: "预检查",
			Run: func(ctx *InstallContext) error {
				ui.UiSetProgress(0)
				ui.UiSetStatus("正在检查安装参数...")
				if err := NormalizeInstallPlan(ctx.Plan); err != nil {
					return err
				}
				return ResolveInstallTarget(ctx.Plan)
			},
		},
		{
			Name: "BitLocker 预处理",
			Run: func(ctx *InstallContext) error {
				ui.UiSetProgress(20)
				ui.UiSetStatus("正在处理 BitLocker...")
				return handleBitLockerBeforeEnterPE(ctx)
			},
		},
		{
			Name: "保存安装计划",
			Run: func(ctx *InstallContext) error {
				ui.UiSetProgress(35)
				ui.UiSetStatus("正在写入安装计划...")
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
			Name: "准备PE",
			Run: func(ctx *InstallContext) error {
				ui.UiSetProgress(65)
				ui.UiSetStatus("正在准备PE环境...")
				return prepareSelectedPEEnvironment(ctx)
			},
		},
		{
			Name: "设置下次启动进入PE",
			Run: func(ctx *InstallContext) error {
				ui.UiSetProgress(85)
				ui.UiSetStatus("正在设置下次启动进入PE...")
				return SetNextBootToPE(ctx)
			},
		},
	}
	return RunStages(ctx, stages)
}

func runManualDirectFlow(ctx *InstallContext) error {
	stages := []*Stage{
		{
			Name: "预检查",
			Run: func(ctx *InstallContext) error {
				ui.UiSetProgress(0)
				ui.UiSetStatus("正在检查安装参数...")
				if err := NormalizeInstallPlan(ctx.Plan); err != nil {
					return err
				}
				return ResolveInstallTarget(ctx.Plan)
			},
		},
		{
			Name: "备份驱动",
			Run: func(ctx *InstallContext) error {
				if ctx == nil || ctx.Plan == nil || !ctx.Plan.Flags.NeedBackupBeforePE {
					return nil
				}
				ui.UiSetProgress(8)
				ui.UiSetStatus("正在备份当前驱动...")
				return ctx.RunHooks(HookBeforeEnterPE)
			},
		},
		{
			Name: "格式化目标分区",
			Run: func(ctx *InstallContext) error {
				if !ctx.Plan.FormatTarget {
					return nil
				}
				ui.UiSetProgress(15)
				ui.UiSetStatus("正在格式化分区...")
				return FormatTargetPartition(ctx.Plan)
			},
		},
		{
			Name: "解析镜像索引",
			Run: func(ctx *InstallContext) error {
				ui.UiSetProgress(22)
				ui.UiSetStatus("正在解析镜像...")
				return ResolveInstallImageIndex(ctx)
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
					_ = phase
					_ = raw
					ui.UiSetStatus(fmt.Sprintf("正在应用镜像... %.1f%%", pct))
					ui.UiSetProgress(MapPct(22, 40, pct))
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
				ui.UiSetProgress(70)
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
				ui.UiSetProgress(90)
				ui.UiSetStatus("正在完成安装后步骤...")
				return ctx.RunHooks(HookAfterInstall)
			},
		},
	}
	return RunStages(ctx, stages)
}

func runManualPEFlow(ctx *InstallContext) error {
	stages := []*Stage{
		{
			Name: "读取安装计划",
			Run: func(ctx *InstallContext) error {
				ui.UiSetProgress(0)
				ui.UiSetStatus("正在读取安装计划...")
				plan, err := LoadInstallPlan()
				if err != nil {
					return err
				}
				ctx.Plan = plan
				return nil
			},
		},
		{
			Name: "恢复镜像路径",
			Run: func(ctx *InstallContext) error {
				if ctx.Plan == nil {
					return fmt.Errorf("install plan is nil")
				}
				if _, err := RecoverInstallImagePath(ctx.Plan); err != nil {
					return fmt.Errorf("手动模式未找到已选镜像: %w", err)
				}
				return nil
			},
		},
		{
			Name: "解析目标分区",
			Run: func(ctx *InstallContext) error {
				ui.UiSetStatus("正在解析目标分区...")
				return ResolveInstallTarget(ctx.Plan)
			},
		},
		{
			Name: "格式化目标分区",
			Run: func(ctx *InstallContext) error {
				if !ctx.Plan.FormatTarget {
					return nil
				}
				ui.UiSetProgress(12)
				ui.UiSetStatus("正在格式化分区...")
				return FormatTargetPartition(ctx.Plan)
			},
		},
		{
			Name: "解析镜像索引",
			Run: func(ctx *InstallContext) error {
				ui.UiSetProgress(20)
				ui.UiSetStatus("正在解析镜像...")
				return ResolveInstallImageIndex(ctx)
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
					_ = phase
					_ = raw
					ui.UiSetStatus(fmt.Sprintf("正在应用镜像... %.1f%%", pct))
					ui.UiSetProgress(MapPct(20, 45, pct))
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
				ui.UiSetProgress(92)
				ui.UiSetStatus("正在完成安装后步骤...")
				return ctx.RunHooks(HookAfterInstall)
			},
		},
	}
	return RunStages(ctx, stages)
}

func prepareSelectedPEEnvironment(ctx *InstallContext) error {
	if ctx == nil || ctx.Plan == nil {
		return fmt.Errorf("install context is nil")
	}
	if ctx.Plan.AutoPE {
		return PreparePEEnvironment(ctx)
	}

	wimPath := strings.TrimSpace(ctx.Plan.ManualPEWIM)
	if wimPath == "" {
		return fmt.Errorf("未指定 PE WIM 镜像")
	}
	if !utils.FileExists(wimPath) {
		return fmt.Errorf("PE WIM 不存在: %s", wimPath)
	}
	sdiPath := resolveSdiPath(wimPath)
	if sdiPath == "" {
		return fmt.Errorf("未找到与 PE WIM 配套的 SDI 文件")
	}
	return patchPreparedPE(ctx, preparedPE{
		WIMPath: wimPath,
		SDIPath: sdiPath,
	})
}

func finishManualInstall(plan *InstallPlan) {
	ui.UiSetProgress(100)
	if plan != nil && plan.AutoReboot {
		ui.UiSetStatus("安装完成，正在重启...")
		time.Sleep(500 * time.Millisecond)
		tools.Shutdown(true)
		return
	}
	ui.UiSetStatus("安装完成。")
}

func manualTargetNeedsPE(plan *InstallPlan) bool {
	if plan == nil {
		return false
	}
	targetRoot, err := utils.NormalizeDrive(plan.TargetRoot, 0)
	if err != nil || targetRoot == "" {
		return false
	}
	systemRoot, err := utils.NormalizeDrive(os.Getenv("SystemDrive"), 0)
	if err != nil || systemRoot == "" {
		systemRoot = windows.SystemDriveRoot()
	}
	if root, err := utils.NormalizeDrive(systemRoot, 0); err == nil && root != "" {
		systemRoot = root
	}
	return strings.EqualFold(targetRoot, systemRoot)
}

func repairInstallBootManual(plan *InstallPlan) error {
	if plan == nil {
		return fmt.Errorf("install plan is nil")
	}
	part, err := findBootPartition(plan.BootTargetRef)
	if err != nil {
		return err
	}

	targetRoot, err := utils.NormalizeDrive(plan.TargetRoot, 0)
	if err != nil || targetRoot == "" {
		return fmt.Errorf("invalid install target root: %s", plan.TargetRoot)
	}
	switch plan.BootRepair {
	case BootRepairModeManualUEFI:
		return repairInstallBootManualUEFI(targetRoot, part)
	case BootRepairModeManualBIOS:
		return repairInstallBootManualBIOS(targetRoot, part)
	}

	style, _, err := disk.GetDiskInfo(targetRoot)
	if err != nil {
		return fmt.Errorf("GetDiskInfo: %w", err)
	}
	if strings.EqualFold(style, "GPT") {
		return repairInstallBootManualUEFI(targetRoot, part)
	}
	return repairInstallBootManualBIOS(targetRoot, part)
}

func repairInstallBootManualUEFI(targetRoot string, part disk.PartitionInfo) error {
	if !strings.EqualFold(strings.TrimSpace(part.Type), "EFI") {
		return fmt.Errorf("所选分区不是 EFI 分区，无法按 UEFI 方式修复")
	}
	espRoot, cleanup, err := disk.EnsureESPRoot(part)
	if err != nil {
		return fmt.Errorf("mount EFI partition failed: %w", err)
	}
	if cleanup != nil {
		defer cleanup()
	}
	return boot.FixUEFI(targetRoot, espRoot, "zh-cn")
}

func repairInstallBootManualBIOS(targetRoot string, part disk.PartitionInfo) error {
	if strings.TrimSpace(part.DriveLetter) == "" {
		return fmt.Errorf("所选 BIOS 引导分区没有盘符，无法手动修复")
	}
	sysRoot, err := utils.NormalizeDrive(part.DriveLetter, 0)
	if err != nil || sysRoot == "" {
		return fmt.Errorf("invalid BIOS boot partition: %s", part.DriveLetter)
	}
	return boot.FixBIOS(targetRoot, sysRoot, "zh-cn")
}

func findBootPartition(ref string) (disk.PartitionInfo, error) {
	diskNumber, partNumber, err := parseBootTargetRef(ref)
	if err != nil {
		return disk.PartitionInfo{}, err
	}
	parts, err := disk.ListDiskPartitions(diskNumber)
	if err != nil {
		return disk.PartitionInfo{}, err
	}
	for _, part := range parts {
		if part.PartitionNumber == partNumber {
			return part, nil
		}
	}
	return disk.PartitionInfo{}, fmt.Errorf("未找到引导分区: %s", ref)
}

func parseBootTargetRef(ref string) (int, int, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return 0, 0, fmt.Errorf("未选择引导分区")
	}
	parts := strings.Split(ref, ":")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid boot target ref: %s", ref)
	}
	diskNumber, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return 0, 0, fmt.Errorf("invalid boot disk number: %w", err)
	}
	partNumber, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return 0, 0, fmt.Errorf("invalid boot partition number: %w", err)
	}
	return diskNumber, partNumber, nil
}

func detectManualTargetOS(imagePath string, infos []imgsvc.ImageMeta) string {
	_ = imagePath
	target := imgsvc.DetectTargetFromInfos(infos)
	if target != "" {
		return target
	}
	return TargetWin10
}

func detectManualInstallWIM(imagePath string) (string, error) {
	path := strings.TrimSpace(imagePath)
	if path == "" {
		return "", fmt.Errorf("empty image path")
	}
	if !strings.EqualFold(filepath.Ext(path), ".iso") {
		return path, nil
	}
	isoRoot, err := imgsvc.MountISO(path, 30*time.Second)
	if err != nil {
		return "", err
	}
	installPath := filepath.Join(isoRoot, "sources", "install.wim")
	if _, err := os.Stat(installPath); err == nil {
		return installPath, nil
	}
	installPath = filepath.Join(isoRoot, "sources", "install.esd")
	if _, err := os.Stat(installPath); err == nil {
		return installPath, nil
	}
	return "", fmt.Errorf("ISO 中未找到安装镜像")
}
