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
		ui.UiShowError("", err.Error())
		ui.UiShowManualMode()
		return
	}

	ctx := NewInstallContext(plan)
	log.LogWrite(0, "[StartManualInstall] image=%s index=%d target=%s mode=%s", plan.ImagePath, plan.ImageIndex, plan.TargetRoot, plan.Mode)

	if utils.NeedsPE(plan.TargetRoot, os.Getenv("SystemDrive")) {
		if err := runFlowWithGuard("StartManualInstallPreparePE", func() error {
			return runManualPrepareFlow(ctx)
		}); err != nil {
			log.LogWrite(-2, "[StartManualInstall] prepare failed: %v", err)
			ui.UiShowError("", err.Error())
			ui.UiShowManualMode()
			return
		}
		ui.UiSetProgress(100)
		if plan.AutoReboot {
			ui.UiSetStatus(ui.Tr("install.manual.rebootToPE"))
			time.Sleep(500 * time.Millisecond)
			tools.Shutdown(true)
			return
		}
		ui.UiSetStatus(ui.Tr("install.manual.prepareDone"))
		return
	}

	if err := runFlowWithGuard("StartManualInstallDirect", func() error {
		return runManualDirectFlow(ctx)
	}); err != nil {
		log.LogWrite(-2, "[StartManualInstall] direct install failed: %v", err)
		ui.UiShowError("", err.Error())
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
		TargetPartRef: strings.TrimSpace(cfg.TargetPartRef),
		AutoPE:        cfg.AutoPE,
		ManualPEWIM:   strings.TrimSpace(cfg.ManualPEWIM),
		FormatTarget:  cfg.FormatTarget,
		AutoReboot:    cfg.AutoReboot,
		BootRepair:    BootRepairMode(strings.TrimSpace(cfg.BootRepair)),
		BootPartRef:   strings.TrimSpace(cfg.BootPartRef),
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
		return nil, fmt.Errorf("%s", ui.Tr("manual.validation.selectImage"))
	}
	if strings.TrimSpace(plan.TargetRoot) == "" {
		return nil, fmt.Errorf("%s", ui.Tr("manual.validation.selectTarget"))
	}
	if strings.TrimSpace(plan.TargetPartRef) == "" {
		return nil, fmt.Errorf("%s", ui.Tr("manual.validation.selectTarget"))
	}

	infos, err := imgsvc.DetectImageInfos(plan.ImagePath)
	if err != nil {
		return nil, fmt.Errorf(ui.Tr("manual.image.parseFailed"), err)
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
	if utils.NeedBootPart(string(plan.BootRepair)) && strings.TrimSpace(plan.BootPartRef) == "" {
		return nil, fmt.Errorf("%s", ui.Tr("manual.validation.selectBoot"))
	}
	if utils.MissingPE(utils.NeedsPE(plan.TargetRoot, os.Getenv("SystemDrive")), plan.AutoPE, plan.ManualPEWIM) {
		return nil, fmt.Errorf("%s", ui.Tr("manual.validation.peRequired"))
	}
	return plan, nil
}

func runManualPrepareFlow(ctx *InstallContext) error {
	stages := []*Stage{
		{
			Name: "预检查",
			Run: func(ctx *InstallContext) error {
				ui.UiSetProgress(0)
				ui.UiSetStatus(ui.Tr("install.manual.checkArgs"))
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
				ui.UiSetStatus(ui.Tr("install.auto.handleBitLocker"))
				return handleBitLockerBeforeEnterPE(ctx)
			},
		},
		{
			Name: "淇濆瓨瀹夎璁″垝",
			Run: func(ctx *InstallContext) error {
				ui.UiSetProgress(35)
				ui.UiSetStatus(ui.Tr("install.manual.writePlan"))
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
			Name: "鍑嗗PE",
			Run: func(ctx *InstallContext) error {
				ui.UiSetProgress(65)
				ui.UiSetStatus(ui.Tr("install.manual.preparePE"))
				return prepareSelectedPEEnvironment(ctx)
			},
		},
		{
			Name: "璁剧疆涓嬫鍚姩杩涘叆PE",
			Run: func(ctx *InstallContext) error {
				ui.UiSetProgress(85)
				ui.UiSetStatus(ui.Tr("install.manual.setNextBootPE"))
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
				ui.UiSetStatus(ui.Tr("install.manual.checkArgs"))
				if err := NormalizeInstallPlan(ctx.Plan); err != nil {
					return err
				}
				return ResolveInstallTarget(ctx.Plan)
			},
		},
		{
			Name: "澶囦唤椹卞姩",
			Run: func(ctx *InstallContext) error {
				if ctx == nil || ctx.Plan == nil || !ctx.Plan.Flags.NeedBackupBeforePE {
					return nil
				}
				ui.UiSetProgress(8)
				ui.UiSetStatus(ui.Tr("install.manual.backupDrivers"))
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
				ui.UiSetStatus(ui.Tr("install.auto.formatTarget"))
				return FormatTargetPartition(ctx.Plan)
			},
		},
		{
			Name: "瑙ｆ瀽闀滃儚绱㈠紩",
			Run: func(ctx *InstallContext) error {
				ui.UiSetProgress(22)
				ui.UiSetStatus(ui.Tr("install.auto.parseImage"))
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
			Name: "搴旂敤闀滃儚",
			Run: func(ctx *InstallContext) error {
				progressCb := func(phase string, pct float64, raw string) {
					_ = phase
					_ = raw
					ui.UiSetStatus(ui.Trf("install.manual.applyImagePct", pct))
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
			Name: "淇寮曞",
			Run: func(ctx *InstallContext) error {
				ui.UiSetProgress(70)
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
				ui.UiSetProgress(90)
				ui.UiSetStatus(ui.Tr("install.manual.finishHooks"))
				return ctx.RunHooks(HookAfterInstall)
			},
		},
	}
	return RunStages(ctx, stages)
}

func runManualPEFlow(ctx *InstallContext) error {
	stages := []*Stage{
		{
			Name: "璇诲彇瀹夎璁″垝",
			Run: func(ctx *InstallContext) error {
				ui.UiSetProgress(0)
				ui.UiSetStatus(ui.Tr("install.manual.readPlan"))
				plan, err := LoadInstallPlan()
				if err != nil {
					return err
				}
				ctx.Plan = plan
				return nil
			},
		},
		{
			Name: "鎭㈠闀滃儚璺緞",
			Run: func(ctx *InstallContext) error {
				if ctx.Plan == nil {
					return fmt.Errorf("install plan is nil")
				}
				if _, err := RecoverInstallImagePath(ctx.Plan); err != nil {
					return fmt.Errorf("鎵嬪姩妯″紡鏈壘鍒板凡閫夐暅鍍? %w", err)
				}
				return nil
			},
		},
		{
			Name: "瑙ｆ瀽鐩爣鍒嗗尯",
			Run: func(ctx *InstallContext) error {
				ui.UiSetStatus(ui.Tr("install.auto.resolveTarget"))
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
				ui.UiSetStatus(ui.Tr("install.auto.formatTarget"))
				return FormatTargetPartition(ctx.Plan)
			},
		},
		{
			Name: "瑙ｆ瀽闀滃儚绱㈠紩",
			Run: func(ctx *InstallContext) error {
				ui.UiSetProgress(20)
				ui.UiSetStatus(ui.Tr("install.auto.parseImage"))
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
			Name: "搴旂敤闀滃儚",
			Run: func(ctx *InstallContext) error {
				progressCb := func(phase string, pct float64, raw string) {
					_ = phase
					_ = raw
					ui.UiSetStatus(ui.Trf("install.manual.applyImagePct", pct))
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
			Name: "淇寮曞",
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
				ui.UiSetProgress(92)
				ui.UiSetStatus(ui.Tr("install.manual.finishHooks"))
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
		return fmt.Errorf("鏈寚瀹?PE WIM 闀滃儚")
	}
	if !utils.FileExists(wimPath) {
		return fmt.Errorf("PE WIM 涓嶅瓨鍦? %s", wimPath)
	}
	sdiPath := resolveSdiPath(wimPath)
	if sdiPath == "" {
		return fmt.Errorf("鏈壘鍒颁笌 PE WIM 閰嶅鐨?SDI 鏂囦欢")
	}
	return patchPreparedPE(ctx, preparedPE{
		WIMPath: wimPath,
		SDIPath: sdiPath,
	})
}

func finishManualInstall(plan *InstallPlan) {
	ui.UiSetProgress(100)
	if plan != nil && plan.AutoReboot {
		ui.UiSetStatus(ui.Tr("install.manual.completedReboot"))
		time.Sleep(500 * time.Millisecond)
		tools.Shutdown(true)
		return
	}
	ui.UiSetStatus(ui.Tr("install.manual.completed"))
}

func repairInstallBootManual(plan *InstallPlan) error {
	if plan == nil {
		return fmt.Errorf("install plan is nil")
	}
	part, err := findBootPartition(plan.BootPartRef)
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
	if utils.BootType(string(plan.BootRepair), style) == "UEFI" {
		return repairInstallBootManualUEFI(targetRoot, part)
	}
	return repairInstallBootManualBIOS(targetRoot, part)
}

func repairInstallBootManualUEFI(targetRoot string, part disk.PartitionInfo) error {
	if !strings.EqualFold(strings.TrimSpace(part.Type), "EFI") {
		return fmt.Errorf("鎵€閫夊垎鍖轰笉鏄?EFI 鍒嗗尯锛屾棤娉曟寜 UEFI 鏂瑰紡淇")
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
	_, part, err := disk.FindPartitionByRef(ref)
	if err != nil {
		return disk.PartitionInfo{}, err
	}
	return part, nil
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
	return "", fmt.Errorf("ISO 涓湭鎵惧埌瀹夎闀滃儚")
}
