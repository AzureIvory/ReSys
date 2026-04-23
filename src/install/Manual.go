package install

import (
	"ReSys/src/boot"
	"ReSys/src/config"
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
func StartManualInstall(src string) {
	plan, err := buildManualInstallPlan(src)
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

func buildManualInstallPlan(src string) (*InstallPlan, error) {
	cfg, err := config.ParseSource(src)
	if err != nil {
		return nil, err
	}

	plan := planFromCfg(cfg)
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
	if utils.MissingPE(utils.NeedsPE(plan.TargetRoot, os.Getenv("SystemDrive")), plan.AutoPE, plan.ManualPEWIM) {
		return nil, fmt.Errorf("%s", ui.Tr("manual.validation.peRequired"))
	}
	return plan, nil
}

// planFromCfg 把手动重装 JSON 配置映射成安装计划。
//
// 这里只做字段翻译，不做磁盘扫描、镜像解析等依赖系统状态的动作，
// 这样测试可以稳定覆盖 JSON 语义本身。
func planFromCfg(cfg config.Config) *InstallPlan {
	mode := ReinstallModeManual
	if strings.EqualFold(strings.TrimSpace(cfg.Mode), string(ReinstallModeAuto)) {
		mode = ReinstallModeAuto
	}

	files := []InstallFile{}
	if cfg.File.State {
		files = make([]InstallFile, 0, len(cfg.File.Items))
		for _, item := range cfg.File.Items {
			files = append(files, InstallFile{
				Src:       item.Src,
				Dst:       item.Dst,
				Overwrite: item.Overwrite,
				Required:  item.Required,
			})
		}
	}

	plan := &InstallPlan{
		Mode:         mode,
		TargetOS:     strings.TrimSpace(cfg.TargetOS),
		ImageArch:    planArch(cfg.ImageArch),
		PEArch:       planArch(cfg.PEArch),
		ImagePath:    strings.TrimSpace(cfg.ImagePath),
		ImageIndex:   cfg.Index,
		TargetRoot:   strings.TrimSpace(cfg.Partition),
		AutoPE:       strings.TrimSpace(cfg.PEWIM) == "",
		ManualPEWIM:  strings.TrimSpace(cfg.PEWIM),
		FormatTarget: cfg.Format.State,
		FormatFS:     strings.TrimSpace(cfg.Format.FS),
		FormatLabel:  strings.TrimSpace(cfg.Format.Label),
		FormatQuick:  cfg.Format.Quick,
		AutoReboot:   cfg.Restart,
		BootRepair:   BootRepairMode(strings.ToLower(strings.TrimSpace(cfg.Boot.Method))),
		UnattendFile: strings.TrimSpace(cfg.Unattended.File),
		DriverFiles:  append([]string{}, cfg.BackupDriver.File...),
		DriverGUIDs:  append([]string{}, cfg.BackupDriver.GUID...),
		Files:        files,
		Flags: InstallFlags{
			NeedBitLockerHandling: true,
			NeedBackupBeforePE:    cfg.BackupDriver.State,
			NeedOfflineDrivers:    cfg.BackupDriver.State,
			NeedCopyXMLAfterBoot:  cfg.Unattended.State || cfg.File.State,
		},
	}
	if strings.EqualFold(strings.TrimSpace(cfg.Boot.BootPartition), config.Auto) {
		plan.BootPartRef = ""
	} else {
		plan.BootPartRef = strings.TrimSpace(cfg.Boot.BootPartition)
	}
	return plan
}

func planArch(arch string) string {
	arch = strings.TrimSpace(arch)
	if strings.EqualFold(arch, "auto") {
		return ""
	}
	return arch
}

// unattendedPath 返回本次安装应使用的无人值守文件路径。
func unattendedPath(plan *InstallPlan, baseDir string) string {
	if plan == nil {
		return ""
	}

	path := strings.TrimSpace(plan.UnattendFile)
	if path == "" || strings.EqualFold(path, config.Auto) {
		if strings.EqualFold(plan.TargetOS, TargetWin7) {
			return filepath.Join(baseDir, "tools", "win7.xml")
		}
		return filepath.Join(baseDir, "tools", "win10.xml")
	}
	return path
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
				return handleBitLocker(ctx)
			},
		},
		{
			Name: "保存安装计划",
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
			Name: "准备PE",
			Run: func(ctx *InstallContext) error {
				ui.UiSetProgress(65)
				ui.UiSetStatus(ui.Tr("install.manual.preparePE"))
				return preparePEEnvir(ctx)
			},
		},
		{
			Name: "设置下次启动进入PE",
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
			Name: "备份驱动",
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
			Name: "解析镜像索引",
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
			Name: "应用镜像",
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
			Name: "修复引导",
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
			Name: "读取安装计划",
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
			Name: "解析镜像索引",
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
			Name: "应用镜像",
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
				ui.UiSetProgress(92)
				ui.UiSetStatus(ui.Tr("install.manual.finishHooks"))
				return ctx.RunHooks(HookAfterInstall)
			},
		},
	}
	return RunStages(ctx, stages)
}

func preparePEEnvir(ctx *InstallContext) error {
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

	targetRoot, err := utils.NormalizeDrive(plan.TargetRoot, 0)
	if err != nil || targetRoot == "" {
		return fmt.Errorf("invalid install target root: %s", plan.TargetRoot)
	}

	manualUEFI := false
	switch plan.BootRepair {
	case BootRepairModeUEFI:
		manualUEFI = true
	case BootRepairModeBIOS:
		manualUEFI = false
	default:
		style, _, err := disk.GetDiskInfo(targetRoot)
		if err != nil {
			return fmt.Errorf("GetDiskInfo: %w", err)
		}
		manualUEFI = utils.BootType(string(plan.BootRepair), style) == "UEFI"
	}

	var part disk.PartitionInfo
	if manualUEFI {
		if markerPart, markerErr := findBootPartitionByMarker(plan); markerErr == nil {
			part = markerPart
		} else {
			log.LogWrite(0, "[repairInstallBootManual] marker not found, fallback to boot_part_ref: %v", markerErr)
			part, err = findBootPartition(plan.BootPartRef)
			if err != nil {
				return err
			}
		}
	} else {
		part, err = findBootPartition(plan.BootPartRef)
		if err != nil {
			return err
		}
	}

	if manualUEFI {
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
	return "", fmt.Errorf("ISO 中未找到安装镜像")
}
