package install

import (
	"ReSys/src/boot"
	"ReSys/src/disk"
	"ReSys/src/dism"
	"ReSys/src/file"
	"ReSys/src/image"
	"ReSys/src/log"
	"ReSys/src/tools"
	"ReSys/src/utils"
	"ReSys/src/windows"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ===== 领域类型 =====

type ReinstallMode string

const (
	ReinstallModeAuto   ReinstallMode = "auto"
	ReinstallModeManual ReinstallMode = "manual"
)

type BootRepairMode string

const (
	BootRepairModeAuto       BootRepairMode = "auto"
	BootRepairModeSkip       BootRepairMode = "skip"
	BootRepairModeManual     BootRepairMode = "manual"
	BootRepairModeManualUEFI BootRepairMode = "manual_uefi"
	BootRepairModeManualBIOS BootRepairMode = "manual_bios"
)

type InstallFlags struct {
	NeedBitLockerHandling bool
	NeedBackupBeforePE    bool
	NeedOfflineDrivers    bool
	NeedCopyXMLAfterBoot  bool
}

type InstallPlan struct {
	Mode          ReinstallMode
	TargetOS      string
	ImageArch     string
	PEArch        string
	PreparedPEWIM string
	ImagePath     string
	ImageIndex    int
	TargetRoot    string
	DiskPath      string
	VolumeGUID    string
	DiskUniqueID  string
	ImageRel      string
	AutoPE        bool
	ManualPEWIM   string
	FormatTarget  bool
	AutoReboot    bool
	BootRepair    BootRepairMode
	BootTargetRef string
	Flags         InstallFlags
}

type InstallContext struct {
	Plan  *InstallPlan
	Hooks HookRegistry
	State map[string]any
}

type HookPoint string

const (
	HookBeforeEnterPE      HookPoint = "before_enter_pe"
	HookBeforeResolveDisk  HookPoint = ""
	HookBeforeFormatTarget HookPoint = "before_forbefore_resolve_diskmat_target"
	HookBeforeApplyImage   HookPoint = "before_apply_image"
	HookAfterApplyImage    HookPoint = "after_apply_image"
	HookAfterRepairBoot    HookPoint = "after_repair_boot"
	HookAfterInstall       HookPoint = "after_install"
)

type HookFunc func(*InstallContext) error

type HookRegistry map[HookPoint][]HookFunc

// ===== 阶段运行时 =====

type StageStatus string

const (
	StageStatusPending   StageStatus = "pending"
	StageStatusRunning   StageStatus = "running"
	StageStatusCompleted StageStatus = "completed"
	StageStatusFailed    StageStatus = "failed"
)

type Stage struct {
	Name      string
	Status    StageStatus
	Retryable bool
	Run       func(*InstallContext) error
}

// NormalizeInstallPlan 补齐安装计划默认值并校验关键字段。
func NormalizeInstallPlan(plan *InstallPlan) error {
	if plan == nil {
		return fmt.Errorf("install plan is nil")
	}

	if plan.Mode == "" {
		plan.Mode = ReinstallModeAuto
	}

	target := strings.ToLower(strings.TrimSpace(plan.TargetOS))
	switch target {
	case "":
		plan.TargetOS = TargetWin10
	case TargetWin7, TargetWin10, TargetWin11:
		plan.TargetOS = target
	default:
		return fmt.Errorf("unsupported target os: %s", plan.TargetOS)
	}

	if strings.TrimSpace(plan.ImageArch) == "" {
		plan.ImageArch = windows.DesiredArch()
	}
	if strings.TrimSpace(plan.PEArch) == "" {
		plan.PEArch = windows.SystemArch()
	}
	if plan.BootRepair == "" {
		plan.BootRepair = BootRepairModeAuto
	}
	if !plan.Flags.NeedBitLockerHandling &&
		!plan.Flags.NeedBackupBeforePE &&
		!plan.Flags.NeedOfflineDrivers &&
		!plan.Flags.NeedCopyXMLAfterBoot {
		plan.Flags.NeedBitLockerHandling = true
		plan.Flags.NeedBackupBeforePE = true
		plan.Flags.NeedOfflineDrivers = true
		plan.Flags.NeedCopyXMLAfterBoot = true
	}

	return nil
}

// NewInstallContext 创建带内建钩子的安装上下文。
func NewInstallContext(plan *InstallPlan) *InstallContext {
	ctx := &InstallContext{
		Plan:  plan,
		Hooks: NewHookRegistry(),
		State: map[string]any{},
	}
	registerBuiltInHooks(ctx)
	return ctx
}

// NewHookRegistry 返回一个空的钩子注册表。
func NewHookRegistry() HookRegistry {
	return HookRegistry{}
}

// Add 向指定钩子点追加处理函数。
func (r HookRegistry) Add(point HookPoint, hook HookFunc) {
	if hook == nil {
		return
	}
	r[point] = append(r[point], hook)
}

// Run 依次执行指定钩子点上的处理函数。
func (r HookRegistry) Run(point HookPoint, ctx *InstallContext) error {
	for _, hook := range r[point] {
		if err := hook(ctx); err != nil {
			return err
		}
	}
	return nil
}

// RunHooks 执行当前安装上下文绑定的钩子。
func (ctx *InstallContext) RunHooks(point HookPoint) error {
	if ctx == nil {
		return fmt.Errorf("install context is nil")
	}
	if ctx.Hooks == nil {
		ctx.Hooks = NewHookRegistry()
	}
	return ctx.Hooks.Run(point, ctx)
}

// RunStages 顺序执行阶段列表并在失败时停止。
func RunStages(ctx *InstallContext, stages []*Stage) error {
	for _, stage := range stages {
		if err := runStage(ctx, stage); err != nil {
			return fmt.Errorf("%s失败: %w", stage.Name, err)
		}
	}
	return nil
}

// runStage 执行单个阶段并在允许时重试一次。
func runStage(ctx *InstallContext, stage *Stage) error {
	if stage == nil || stage.Run == nil {
		return nil
	}

	attempts := 1
	if stage.Retryable {
		attempts = 2
	}

	stage.Status = StageStatusPending
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		stage.Status = StageStatusRunning
		log.LogWrite(0, "[stageRunner] start: %s (attempt=%d/%d)", stage.Name, attempt, attempts)

		if err := stage.Run(ctx); err == nil {
			stage.Status = StageStatusCompleted
			log.LogWrite(0, "[stageRunner] completed: %s", stage.Name)
			return nil
		} else {
			lastErr = err
			stage.Status = StageStatusFailed
			log.LogWrite(0, "[stageRunner] %s failed: %v", stage.Name, err)
			if attempt < attempts {
				log.LogWrite(0, "[stageRunner] %s failed, retrying once", stage.Name)
				time.Sleep(2 * time.Second)
			}
		}
	}

	return lastErr
}

// ===== 安装计划持久化 =====

// SaveInstallPlan 持久化安装计划供重启后恢复。
func SaveInstallPlan(plan *InstallPlan) error {
	if err := NormalizeInstallPlan(plan); err != nil {
		return err
	}

	plan.ImagePath = strings.TrimSpace(plan.ImagePath)
	if plan.ImagePath == "" {
		return fmt.Errorf("install image path is empty")
	}

	if absPath, err := filepath.Abs(plan.ImagePath); err == nil {
		plan.ImagePath = absPath
	}

	if plan.ImageIndex <= 0 {
		if infos, err := image.DetectImageInfos(plan.ImagePath); err == nil {
			plan.ImageIndex = SelectInstallIndex(infos)
		}
	}

	if err := captureInstallImageLocation(plan); err != nil {
		return err
	}

	if root, err := utils.NormalizeDrive(plan.TargetRoot, 0); err == nil {
		plan.TargetRoot = root
	}

	systemDrive := os.Getenv("SystemDrive")
	if systemDrive == "" {
		systemDrive = "C:"
	}
	sysRoot, _ := utils.NormalizeDrive(systemDrive, 0)
	if sysRoot == "" {
		sysRoot = systemDrive + `\`
	}
	restallPath := filepath.Join(sysRoot, "restall_win.dat")

	lines := []string{
		fmt.Sprintf("mode=%s", plan.Mode),
		fmt.Sprintf("image=%s", plan.ImagePath),
	}
	if plan.TargetRoot != "" {
		lines = append(lines, fmt.Sprintf("target_root=%s", plan.TargetRoot))
	}
	if plan.DiskPath != "" {
		lines = append(lines, fmt.Sprintf("disk=%s", plan.DiskPath))
	}
	if plan.VolumeGUID != "" {
		lines = append(lines, fmt.Sprintf("volume_guid=%s", plan.VolumeGUID))
	}
	if plan.DiskUniqueID != "" {
		lines = append(lines, fmt.Sprintf("disk_unique_id=%s", plan.DiskUniqueID))
	}
	if plan.ImageRel != "" {
		lines = append(lines, fmt.Sprintf("image_rel=%s", plan.ImageRel))
	}
	if plan.TargetOS != "" {
		lines = append(lines, fmt.Sprintf("target=%s", plan.TargetOS))
	}
	if plan.ImageArch != "" {
		lines = append(lines, fmt.Sprintf("arch=%s", plan.ImageArch))
	}
	if plan.PEArch != "" {
		lines = append(lines, fmt.Sprintf("pe_arch=%s", plan.PEArch))
	}
	if plan.PreparedPEWIM != "" {
		lines = append(lines, fmt.Sprintf("prepared_pe_wim=%s", plan.PreparedPEWIM))
	}
	lines = append(lines,
		fmt.Sprintf("auto_pe=%t", plan.AutoPE),
		fmt.Sprintf("format_target=%t", plan.FormatTarget),
		fmt.Sprintf("auto_reboot=%t", plan.AutoReboot),
		fmt.Sprintf("boot_repair=%s", plan.BootRepair),
	)
	if plan.ManualPEWIM != "" {
		lines = append(lines, fmt.Sprintf("manual_pe_wim=%s", plan.ManualPEWIM))
	}
	if plan.BootTargetRef != "" {
		lines = append(lines, fmt.Sprintf("boot_target_ref=%s", plan.BootTargetRef))
	}
	if plan.ImageIndex > 0 {
		lines = append(lines, fmt.Sprintf("index=%d", plan.ImageIndex))
	}
	lines = append(lines,
		fmt.Sprintf("flag_need_bitlocker=%t", plan.Flags.NeedBitLockerHandling),
		fmt.Sprintf("flag_need_backup_before_pe=%t", plan.Flags.NeedBackupBeforePE),
		fmt.Sprintf("flag_need_offline_drivers=%t", plan.Flags.NeedOfflineDrivers),
		fmt.Sprintf("flag_need_copy_xml_after_boot=%t", plan.Flags.NeedCopyXMLAfterBoot),
	)

	if err := os.WriteFile(restallPath, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		return err
	}

	imageRoot, _ := utils.NormalizeDrive(plan.ImagePath, 2)
	if plan.DiskPath == "" && imageRoot != "" {
		imgDat := filepath.Join(imageRoot, "restall_img.dat")
		_ = os.WriteFile(imgDat, []byte("image="+plan.ImagePath+"\n"), 0o644)
	}

	return nil
}

// captureInstallImageLocation 记录镜像所在磁盘与卷的元数据。
func captureInstallImageLocation(plan *InstallPlan) error {
	if plan == nil {
		return fmt.Errorf("install plan is nil")
	}

	plan.DiskPath = ""
	plan.VolumeGUID = ""
	plan.DiskUniqueID = ""
	plan.ImageRel = ""

	imageRoot, _ := utils.NormalizeDrive(plan.ImagePath, 2)
	if imageRoot == "" {
		return nil
	}

	plan.ImageRel = strings.TrimPrefix(plan.ImagePath, imageRoot)
	if plan.ImageRel != "" && !strings.HasPrefix(plan.ImageRel, `\`) {
		plan.ImageRel = `\` + plan.ImageRel
	}

	if diskNum, err := disk.GetDiskNum(imageRoot); err == nil {
		plan.DiskPath = fmt.Sprintf(`\\.\PhysicalDrive%d`, diskNum)
		if disks, derr := disk.ListPhysicalDisks(); derr == nil {
			for _, d := range disks {
				if d.DiskNumber == int(diskNum) {
					plan.DiskUniqueID = strings.TrimSpace(d.UniqueId)
					break
				}
			}
		}
	}

	if vols, err := disk.ListVolumes(); err == nil {
		for _, v := range vols {
			vRoot, _ := utils.NormalizeDrive(v.RootPath, 0)
			if strings.EqualFold(vRoot, imageRoot) {
				plan.VolumeGUID = strings.TrimSpace(v.VolumeGuidPath)
				break
			}
		}
	}

	return nil
}

// LoadInstallPlan 从磁盘恢复已持久化的安装计划。
func LoadInstallPlan() (*InstallPlan, error) {
	drives, err := disk.ListDrive()
	if err != nil {
		return nil, err
	}

	type hit struct {
		root  string
		path  string
		score int
	}

	var hits []hit
	for _, d := range drives {
		root, _ := utils.NormalizeDrive(d, 0)
		if root == "" || strings.HasPrefix(strings.ToUpper(root), "X:") {
			continue
		}

		cand := filepath.Join(root, "restall_win.dat")
		if _, err := os.Stat(cand); err != nil {
			continue
		}

		score := 0
		if disk.GetDriveType(root) == 3 {
			score += 10
		}
		kind, _ := disk.GetDiskKind(root)
		switch kind {
		case "SSD":
			score += 30
		case "HDD":
			score += 20
		case "Removable":
			score -= 50
		}
		if _, werr := windows.DetectWin(root); werr == nil {
			score += 100
		}

		hits = append(hits, hit{root: root, path: cand, score: score})
	}

	if len(hits) == 0 {
		return nil, fmt.Errorf("未找到 restall_win.dat")
	}

	for len(hits) > 0 {
		bestIdx := -1
		bestScore := -1
		for i := range hits {
			if hits[i].score > bestScore {
				bestScore = hits[i].score
				bestIdx = i
			}
		}
		if bestIdx < 0 {
			break
		}

		h := hits[bestIdx]
		hits = append(hits[:bestIdx], hits[bestIdx+1:]...)

		b, err := os.ReadFile(h.path)
		if err != nil {
			log.LogWrite(0, "[LoadInstallPlan] failed to read %s: %v", h.path, err)
			if len(hits) == 0 {
				return nil, err
			}
			continue
		}

		plan := &InstallPlan{
			Mode:       ReinstallModeAuto,
			TargetRoot: h.root,
		}
		for _, ln := range strings.Split(string(b), "\n") {
			ln = strings.TrimSpace(ln)
			if ln == "" {
				continue
			}
			parts := strings.SplitN(ln, "=", 2)
			if len(parts) != 2 {
				continue
			}

			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			switch key {
			case "mode":
				plan.Mode = ReinstallMode(val)
			case "target_root":
				plan.TargetRoot = val
			case "disk":
				plan.DiskPath = val
			case "image":
				plan.ImagePath = val
			case "volume_guid":
				plan.VolumeGUID = val
			case "disk_unique_id":
				plan.DiskUniqueID = val
			case "image_rel":
				plan.ImageRel = val
			case "target":
				plan.TargetOS = val
			case "arch":
				plan.ImageArch = val
			case "pe_arch":
				plan.PEArch = val
			case "prepared_pe_wim":
				plan.PreparedPEWIM = val
			case "auto_pe":
				plan.AutoPE = parsePlanBool(val)
			case "manual_pe_wim":
				plan.ManualPEWIM = val
			case "format_target":
				plan.FormatTarget = parsePlanBool(val)
			case "auto_reboot":
				plan.AutoReboot = parsePlanBool(val)
			case "boot_repair":
				plan.BootRepair = BootRepairMode(strings.TrimSpace(val))
			case "boot_target_ref":
				plan.BootTargetRef = val
			case "index":
				if v, e := strconv.Atoi(val); e == nil {
					plan.ImageIndex = v
				}
			case "flag_need_bitlocker":
				plan.Flags.NeedBitLockerHandling = parsePlanBool(val)
			case "flag_need_backup_before_pe":
				plan.Flags.NeedBackupBeforePE = parsePlanBool(val)
			case "flag_need_offline_drivers":
				plan.Flags.NeedOfflineDrivers = parsePlanBool(val)
			case "flag_need_copy_xml_after_boot":
				plan.Flags.NeedCopyXMLAfterBoot = parsePlanBool(val)
			}
		}

		if err := NormalizeInstallPlan(plan); err != nil {
			return nil, err
		}
		if root, err := utils.NormalizeDrive(plan.TargetRoot, 0); err == nil {
			plan.TargetRoot = root
		}
		return plan, nil
	}

	return nil, fmt.Errorf("读取 restall_win.dat 失败")
}

// ===== 目标分区解析与格式化 =====

// FindTempRootByMarker 根据标记文件查找临时分区。
func FindTempRootByMarker() string {
	drives, _ := disk.ListDrive()
	for _, d := range drives {
		root, _ := utils.NormalizeDrive(d, 0)
		if root == "" || strings.HasPrefix(strings.ToUpper(root), "X:") {
			continue
		}
		marker := filepath.Join(root, tempMarkerRel)
		if st, err := os.Stat(marker); err == nil && !st.IsDir() {
			return root
		}
	}
	return ""
}

// ResolveInstallTarget 解析并规范化本次安装的目标分区。
func ResolveInstallTarget(plan *InstallPlan) error {
	if plan == nil {
		return fmt.Errorf("install plan is nil")
	}

	if root, err := utils.NormalizeDrive(plan.TargetRoot, 0); err == nil {
		plan.TargetRoot = root
	}
	if strings.TrimSpace(plan.TargetRoot) == "" {
		plan.TargetRoot = chooseInstallTargetRoot()
	}
	if strings.TrimSpace(plan.TargetRoot) == "" {
		return fmt.Errorf("未找到可用系统分区")
	}

	return EnsureInstallImageOutsideTarget(plan)
}

// FormatTargetPartition 按安装要求格式化目标分区。
func FormatTargetPartition(plan *InstallPlan) error {
	if plan == nil {
		return fmt.Errorf("install plan is nil")
	}
	if strings.TrimSpace(plan.TargetRoot) == "" {
		return fmt.Errorf("install target root is empty")
	}

	letter := strings.ReplaceAll(strings.ReplaceAll(plan.TargetRoot, `\`, ""), ":", "")
	return disk.Format(letter, "ntfs", "Windows", true)
}

// chooseInstallTargetRoot 选择优先用于安装的目标分区。
func chooseInstallTargetRoot() string {
	parts := disk.Findpart()
	if len(parts) > 0 {
		log.LogWrite(0, "[chooseInstallTargetRoot] selected uninstalled system partition: %s", parts[0])
		root, _ := utils.NormalizeDrive(parts[0], 0)
		return root
	}

	drives, _ := disk.ListDrive()
	for _, d := range drives {
		if strings.HasPrefix(strings.ToUpper(d), "X:") {
			continue
		}
		if disk.GetDriveType(d) == 3 {
			log.LogWrite(0, "[chooseInstallTargetRoot] fallback selected fixed drive partition: %s", d)
			root, _ := utils.NormalizeDrive(d, 0)
			return root
		}
	}
	return ""
}

// getotherVolumes 列出目标分区之外的其他固定卷。
func getotherVolumes(targetRoot string) []string {
	drives, _ := disk.ListDrive()
	var out []string
	for _, d := range drives {
		root, _ := utils.NormalizeDrive(d, 0)
		if root == "" || strings.EqualFold(root, targetRoot) {
			continue
		}
		if disk.GetDriveType(root) == 3 {
			out = append(out, root)
		}
	}
	return out
}

// ===== 镜像应用与引导修复 =====

// ApplyInstallImage 将选定镜像索引应用到目标分区。
func ApplyInstallImage(plan *InstallPlan, progress func(string, float64, string)) error {
	if plan == nil {
		return fmt.Errorf("install plan is nil")
	}

	imagePath := strings.TrimSpace(plan.ImagePath)
	targetRoot := strings.TrimSpace(plan.TargetRoot)
	if imagePath == "" || targetRoot == "" {
		return fmt.Errorf("install image or target root is empty")
	}

	ext := strings.ToLower(filepath.Ext(imagePath))
	applyPath := imagePath
	if ext == ".iso" {
		isoRoot, err := image.MountISO(imagePath, 30*time.Second)
		if err != nil {
			return err
		}
		applyPath = filepath.Join(isoRoot, "sources", "install.wim")
		if _, err := os.Stat(applyPath); err != nil {
			applyPath = filepath.Join(isoRoot, "sources", "install.esd")
		}
	}

	log.LogWrite(0, "[ApplyInstallImage] ext=%s image=%s applyPath=%s target=%s index=%d", ext, imagePath, applyPath, targetRoot, plan.ImageIndex)
	dismSvc := dism.NewDism()

	if progress == nil {
		return dismSvc.ApplyImageCmd(applyPath, targetRoot, uint32(plan.ImageIndex), nil)
	}

	progressCh := make(chan dism.DismProgress, 16)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for p := range progressCh {
			progress("apply", float64(p.Percentage), p.Status)
		}
	}()

	err := dismSvc.ApplyImageCmd(applyPath, targetRoot, uint32(plan.ImageIndex), progressCh)
	close(progressCh)
	<-done
	return err
}

// RepairInstallBoot 为已安装系统修复引导。
func RepairInstallBoot(plan *InstallPlan) error {
	if plan == nil {
		return fmt.Errorf("install plan is nil")
	}
	switch plan.BootRepair {
	case BootRepairModeSkip:
		return nil
	case BootRepairModeManual, BootRepairModeManualUEFI, BootRepairModeManualBIOS:
		return repairInstallBootManual(plan)
	}
	return boot.FixBoot(plan.TargetRoot, "", "zh-cn")
}

// ===== 内建钩子 =====

// registerBuiltInHooks 注册默认的安装后扩展动作。
func registerBuiltInHooks(ctx *InstallContext) {
	if ctx == nil {
		return
	}
	if ctx.Hooks == nil {
		ctx.Hooks = NewHookRegistry()
	}
	ctx.Hooks.Add(HookAfterApplyImage, fixwin7drive_updata)
	ctx.Hooks.Add(HookAfterRepairBoot, fixwin7uefi)
	ctx.Hooks.Add(HookBeforeEnterPE, backupDriversBeforeEnterPE)
	ctx.Hooks.Add(HookAfterRepairBoot, restoreBackedUpDrivers)
	ctx.Hooks.Add(HookAfterInstall, autoinstools)
	ctx.Hooks.Add(HookAfterInstall, adddrivexe)
	ctx.Hooks.Add(HookAfterInstall, cleanupPreparedPEAfterInstall)
}

// fixwin7drive_updata 为 Win7 离线系统预注入驱动和更新。
func fixwin7drive_updata(ctx *InstallContext) error {
	if ctx == nil || ctx.Plan == nil {
		return fmt.Errorf("install context is nil")
	}
	if !strings.EqualFold(ctx.Plan.TargetOS, TargetWin7) {
		return nil
	}
	if strings.TrimSpace(ctx.Plan.TargetRoot) == "" {
		return fmt.Errorf("install target root is empty")
	}

	selfExe, err := os.Executable()
	if err != nil {
		return err
	}
	baseDir := filepath.Dir(selfExe)
	usb3Dir := filepath.Join(baseDir, "tools", "w7", "drivers", "usb3")
	storageDir := filepath.Join(baseDir, "tools", "w7", "drivers", "storage_controller")
	nvmeDir := filepath.Join(baseDir, "tools", "w7", "drivers", "nvme")

	dismSvc := dism.NewDism()

	if err := fixwin7Driver(dismSvc, ctx.Plan.TargetRoot, usb3Dir, "Win7 USB3 drivers"); err != nil {
		return err
	}
	if err := fixwin7Driver(dismSvc, ctx.Plan.TargetRoot, storageDir, "Win7 storage controller drivers"); err != nil {
		return err
	}
	if err := fixwin7NVMe(dismSvc, ctx.Plan, nvmeDir); err != nil {
		return err
	}

	return nil
}

// fixwin7uefi 在修复引导后为 Win7 的 UEFI 引导打补丁。
func fixwin7uefi(ctx *InstallContext) error {
	if ctx == nil || ctx.Plan == nil {
		return fmt.Errorf("install context is nil")
	}
	if !strings.EqualFold(ctx.Plan.TargetOS, TargetWin7) {
		return nil
	}
	if strings.TrimSpace(ctx.Plan.ImageArch) == "32" {
		log.LogWrite(0, "[fixwin7uefi] skip Win7 UEFI patch for 32-bit image")
		return nil
	}
	if strings.TrimSpace(ctx.Plan.TargetRoot) == "" {
		return fmt.Errorf("install target root is empty")
	}

	espRoot, cleanupESP, err := boot.FindESP(ctx.Plan.TargetRoot)
	if err != nil {
		log.LogWrite(0, "[fixwin7uefi] FindESP failed, skip UEFI patch: %v", err)
		return nil
	}
	if cleanupESP != nil {
		defer cleanupESP()
	}

	selfExe, err := os.Executable()
	if err != nil {
		return err
	}
	baseDir := filepath.Dir(selfExe)
	uefiDir := filepath.Join(baseDir, "tools", "w7", "uefi")
	bootShim := filepath.Join(uefiDir, "bootx64.efi")
	uefiINI := filepath.Join(uefiDir, "UefiSeven.ini")
	if !utils.FileExists(bootShim) {
		return fmt.Errorf("Win7 UEFI shim not found: %s", bootShim)
	}
	if !utils.FileExists(uefiINI) {
		return fmt.Errorf("Win7 UEFI config not found: %s", uefiINI)
	}

	bootDir := filepath.Join(espRoot, "EFI", "Microsoft", "Boot")
	origBootmgfw := filepath.Join(bootDir, "bootmgfw.efi")
	backupBootmgfw := filepath.Join(bootDir, "bootmgfw.original.efi")
	if !utils.FileExists(origBootmgfw) {
		return fmt.Errorf("Win7 UEFI boot file not found after boot repair: %s", origBootmgfw)
	}

	log.LogWrite(0, "[fixwin7uefi] patching Win7 UEFI boot: esp=%s", espRoot)
	if err := file.Copy(origBootmgfw, backupBootmgfw, true, true); err != nil {
		return fmt.Errorf("backup bootmgfw.efi failed: %w", err)
	}
	if err := file.Copy(bootShim, origBootmgfw, true, true); err != nil {
		return fmt.Errorf("deploy UefiSeven bootx64.efi failed: %w", err)
	}
	if err := file.Copy(uefiINI, filepath.Join(bootDir, "UefiSeven.ini"), true, true); err != nil {
		return fmt.Errorf("deploy UefiSeven.ini failed: %w", err)
	}

	log.LogWrite(0, "[fixwin7uefi] Win7 UEFI boot patched")
	return nil
}

func fixwin7Driver(dismSvc *dism.Dism, imagePath, driverDir, label string) error {
	if st, err := os.Stat(driverDir); err != nil || !st.IsDir() {
		return fmt.Errorf("%s directory not found: %s", label, driverDir)
	}

	log.LogWrite(0, "[fixwin7Driver] injecting %s: image=%s drivers=%s", label, imagePath, driverDir)
	if err := dismSvc.AddDriverOfflineCmd(imagePath, driverDir, true, true, nil); err != nil {
		return fmt.Errorf("inject %s failed: %w", label, err)
	}

	log.LogWrite(0, "[fixwin7Driver] %s injected", label)
	return nil
}

func fixwin7NVMe(dismSvc *dism.Dism, plan *InstallPlan, nvmeDir string) error {
	if plan == nil {
		return fmt.Errorf("install plan is nil")
	}
	if st, err := os.Stat(nvmeDir); err != nil || !st.IsDir() {
		return fmt.Errorf("Win7 NVMe driver directory not found: %s", nvmeDir)
	}

	arch := strings.TrimSpace(plan.ImageArch)
	if arch != "32" {
		packages := []string{
			filepath.Join(nvmeDir, "Windows6.1-KB2990941-v3-x64.cab"),
			filepath.Join(nvmeDir, "Windows6.1-KB3087873-v2-x64.cab"),
		}
		for _, pkg := range packages {
			if !utils.FileExists(pkg) {
				return fmt.Errorf("Win7 NVMe package not found: %s", pkg)
			}
			log.LogWrite(0, "[fixwin7NVMe] installing Win7 NVMe package: image=%s package=%s", plan.TargetRoot, pkg)
			if err := dismSvc.AddPackageOfflineSimpleCmd(plan.TargetRoot, pkg, nil); err != nil {
				return fmt.Errorf("install Win7 NVMe package failed: %s: %w", filepath.Base(pkg), err)
			}
		}
	} else {
		log.LogWrite(0, "[fixwin7NVMe] skip NVMe CAB packages for 32-bit Win7: image=%s", plan.TargetRoot)
	}

	stornvmeINF := filepath.Join(nvmeDir, "stornvme.inf")
	if !utils.FileExists(stornvmeINF) {
		return fmt.Errorf("Win7 NVMe INF not found: %s", stornvmeINF)
	}

	log.LogWrite(0, "[fixwin7NVMe] injecting Win7 NVMe INF: image=%s inf=%s", plan.TargetRoot, stornvmeINF)
	if err := dismSvc.AddDriverOfflineCmd(plan.TargetRoot, stornvmeINF, false, true, nil); err != nil {
		return fmt.Errorf("inject Win7 NVMe INF failed: %w", err)
	}

	log.LogWrite(0, "[fixwin7NVMe] Win7 NVMe support injected")
	return nil
}

// autoinstools 复制无人值守文件和安装后工具。
func autoinstools(ctx *InstallContext) error {
	if ctx == nil || ctx.Plan == nil {
		return fmt.Errorf("install context is nil")
	}
	if !ctx.Plan.Flags.NeedCopyXMLAfterBoot {
		return nil
	}

	selfExe, err := os.Executable()
	if err != nil {
		return err
	}
	baseDir := filepath.Dir(selfExe)

	unattend := filepath.Join(baseDir, "tools", "win10.xml")
	if strings.EqualFold(ctx.Plan.TargetOS, TargetWin7) {
		unattend = filepath.Join(baseDir, "tools", "win7.xml")
	}
	_ = file.Copy(unattend, filepath.Join(ctx.Plan.TargetRoot, "Windows", "Panther", "Unattend.xml"), true, true)
	_ = file.Copy(filepath.Join(baseDir, "tools", "HEU_KMS_Activator.exe"), filepath.Join(ctx.Plan.TargetRoot, "HEU_KMS_Activator.exe"), true, true)
	_, _ = tools.CreateShortcut(filepath.Join(ctx.Plan.TargetRoot, "Users", "Public", "Desktop")+`\`, "应用商店", "https://store.ttraw.com")
	log.LogWrite(0, "[postInstallTasks] copied answer file, activator, and shortcut")
	return nil
}

// adddrivexe 预置驱动安装工具。
func adddrivexe(ctx *InstallContext) error {
	if ctx == nil || ctx.Plan == nil {
		return fmt.Errorf("install context is nil")
	}

	selfExe, err := os.Executable()
	if err != nil {
		return err
	}
	baseDir := filepath.Dir(selfExe)
	driveExe := filepath.Join(baseDir, "tools", "drive.exe")
	if utils.FileExists(driveExe) {
		_ = file.Copy(driveExe, filepath.Join(ctx.Plan.TargetRoot, "drive.exe"), true, true)
	}
	log.LogWrite(0, "[postInstallTasks] driver setup tool is ready")
	return nil
}

// ===== 兼容包装 =====

// WriteResFile 保留旧入口并改为写入安装计划。
func WriteResFile(imagePath string, target, arch string, index int) error {
	return SaveInstallPlan(&InstallPlan{
		Mode:       ReinstallModeAuto,
		TargetOS:   target,
		ImageArch:  arch,
		ImagePath:  imagePath,
		ImageIndex: index,
	})
}

// LoadResData 保留旧读取入口并展开安装计划字段。
func LoadResData() (targetRoot string, diskPath string, imagePath string, volumeGuid string, diskUniqueID string, imageRel string, targetOS string, arch string, index int, err error) {
	plan, err := LoadInstallPlan()
	if err != nil {
		return "", "", "", "", "", "", "", "", 0, err
	}
	return plan.TargetRoot, plan.DiskPath, plan.ImagePath, plan.VolumeGUID, plan.DiskUniqueID, plan.ImageRel, plan.TargetOS, plan.ImageArch, plan.ImageIndex, nil
}

// ResolveImagePath 保留旧入口并恢复镜像路径。
func ResolveImagePath(diskPath, volumeGuid, diskUniqueID, imagePath, imageRel string) (string, error) {
	return RecoverInstallImagePath(&InstallPlan{
		DiskPath:     diskPath,
		VolumeGUID:   volumeGuid,
		DiskUniqueID: diskUniqueID,
		ImagePath:    imagePath,
		ImageRel:     imageRel,
	})
}

// postInstallTasks 保留旧入口并执行安装后钩子。
func postInstallTasks(targetRoot, targetOS string) error {
	ctx := NewInstallContext(&InstallPlan{
		Mode:       ReinstallModeAuto,
		TargetRoot: targetRoot,
		TargetOS:   targetOS,
	})
	return ctx.RunHooks(HookAfterInstall)
}
