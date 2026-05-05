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
	"ReSys/src/wimlib"
	"ReSys/src/windows"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	espFixMarkerFile = "ESP_FIX_WIN.DAT"
)

var findPartitionByRef = disk.FindPartitionByRef
var applyImageWithWimlib = wimlib.ApplyImageProgress
var applyImageWithDism = func(imageFile, applyDir string, index uint32, progressCh chan<- dism.DismProgress) error {
	return dism.NewDism().ApplyImageCmd(imageFile, applyDir, index, progressCh)
}
var createShortcut = tools.CreateShortcut
var addWin7Dir = fixWin7Dir
var addWin7NVMe = fixWin7NVMe

// ===== 领域类型 =====

type ReinstallMode string

const (
	ReinstallModeAuto   ReinstallMode = "auto"
	ReinstallModeManual ReinstallMode = "manual"
)

type BootRepairMode string

const (
	BootRepairModeAuto BootRepairMode = "auto"
	BootRepairModeSkip BootRepairMode = "skip"
	BootRepairModeUEFI BootRepairMode = "uefi"
	BootRepairModeBIOS BootRepairMode = "bios"
)

type InstallFlags struct {
	NeedBitLockerHandling bool `json:"need_bitlocker"`
	NeedBackupBeforePE    bool `json:"need_backup_before_pe"`
	NeedOfflineDrivers    bool `json:"need_offline_drivers"`
}

// InstallFile 描述安装完成后的单个复制项。
// InstallFile 描述安装完成后的单个文件或目录复制项。
type InstallFile struct {
	Src       string `json:"src"`
	Dst       string `json:"dst"`
	Overwrite bool   `json:"overwrite"`
	Required  bool   `json:"required"`
}

type InstallShortcut struct {
	Target string `json:"target"`
	Name   string `json:"name"`
	Dir    string `json:"dir"`
}

type InstallWin7Fix struct {
	NVMe              string `json:"nvme"`
	StorageController string `json:"storage_controller"`
	USB3              string `json:"usb3"`
	UEFI              string `json:"uefi"`
}

type InstallPlan struct {
	Mode          ReinstallMode     `json:"mode"`
	TargetOS      string            `json:"target"`
	ImageArch     string            `json:"arch"`
	PEArch        string            `json:"pe_arch"`
	PreparedPEWIM string            `json:"prepared_pe_wim"`
	ImagePath     string            `json:"image"`
	ImageIndex    int               `json:"index"`
	TargetRoot    string            `json:"target_root"`
	TargetPartRef string            `json:"target_part_ref"`
	DiskPath      string            `json:"disk"`
	DiskUniqueID  string            `json:"disk_unique_id"`
	ImageRel      string            `json:"image_rel"`
	AutoPE        bool              `json:"auto_pe"`
	ManualPEWIM   string            `json:"manual_pe_wim"`
	FormatTarget  bool              `json:"format_target"`
	FormatFS      string            `json:"format_fs"`
	FormatLabel   string            `json:"format_label"`
	FormatQuick   bool              `json:"format_quick"`
	AutoReboot    bool              `json:"auto_reboot"`
	BootRepair    BootRepairMode    `json:"boot_repair"`
	BootPartRef   string            `json:"boot_part_ref"`
	DriverFiles   []string          `json:"driver_files"`
	DriverGUIDs   []string          `json:"driver_guids"`
	Files         []InstallFile     `json:"files"`
	Shortcuts     []InstallShortcut `json:"shortcuts"`
	Win7Fix       InstallWin7Fix    `json:"win7fix"`
	Flags         InstallFlags      `json:"flags"`
}

type InstallContext struct {
	Plan  *InstallPlan
	Hooks HookRegistry
	State map[string]any
}

type HookPoint string

const (
	HookBeforeEnterPE      HookPoint = "before_enter_pe"
	HookBeforeResolveDisk  HookPoint = "before_resolve_disk"
	HookBeforeFormatTarget HookPoint = "before_format_target"
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
	if strings.TrimSpace(plan.FormatFS) == "" {
		plan.FormatFS = "NTFS"
	}
	if plan.Mode == ReinstallModeAuto {
		if strings.TrimSpace(plan.FormatLabel) == "" {
			plan.FormatLabel = "Windows"
		}
		if !plan.FormatQuick {
			plan.FormatQuick = true
		}
	}
	if plan.DriverFiles == nil {
		plan.DriverFiles = []string{}
	}
	if plan.DriverGUIDs == nil {
		plan.DriverGUIDs = []string{}
	}
	if plan.Files == nil {
		plan.Files = []InstallFile{}
	}
	if plan.Shortcuts == nil {
		plan.Shortcuts = []InstallShortcut{}
	}
	if !plan.Flags.NeedBitLockerHandling &&
		!plan.Flags.NeedBackupBeforePE &&
		!plan.Flags.NeedOfflineDrivers {
		plan.Flags.NeedBitLockerHandling = true
		plan.Flags.NeedBackupBeforePE = true
		plan.Flags.NeedOfflineDrivers = true
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

	if err := ResolveInstallTarget(plan); err != nil {
		return err
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

	data, err := encodePlan(plan)
	if err != nil {
		return err
	}

	planPath := installPlanPathForPlan(plan)
	if planPath == "" {
		return fmt.Errorf("install plan path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(planPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(planPath, data, 0o644); err != nil {
		return err
	}
	cleanupInstallPlanFiles(planPath)
	if err := prepareBootFixMarker(plan); err != nil {
		return err
	}

	imageRoot, _ := utils.NormalizeDrive(plan.ImagePath, 2)
	if plan.DiskPath == "" && imageRoot != "" {
		imgDat := imageHintPath(imageRoot)
		_ = os.MkdirAll(filepath.Dir(imgDat), 0o755)
		_ = os.WriteFile(imgDat, []byte("image="+plan.ImagePath+"\n"), 0o644)
	}

	return nil
}

// encodePlan 将安装计划序列化为 JSON 文本。
//
// `restall_win.dat` 现在直接保存完整的安装计划对象，
// 后续流程再统一走 NormalizeInstallPlan 与 ResolveInstallTarget。
func encodePlan(plan *InstallPlan) ([]byte, error) {
	if plan == nil {
		return nil, fmt.Errorf("install plan is nil")
	}
	if strings.TrimSpace(plan.ImagePath) == "" {
		return nil, fmt.Errorf("install image path is empty")
	}

	data, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// installPlanPath 返回当前系统卷上的安装计划文件路径。
//
// 安装计划始终放在当前系统卷根目录，便于重启进 PE 后重新扫描并恢复。
func installPlanFallbackPath() string {
	systemDrive := os.Getenv("SystemDrive")
	if systemDrive == "" {
		systemDrive = "C:"
	}
	sysRoot, _ := utils.NormalizeDrive(systemDrive, 0)
	if sysRoot == "" {
		sysRoot = systemDrive + `\`
	}
	return filepath.Join(sysRoot, appInstallPlanFileName())
}

func installPlanPathForTargetRoot(targetRoot string) string {
	root, err := utils.NormalizeDrive(targetRoot, 0)
	if err != nil || root == "" {
		return ""
	}
	return filepath.Join(root, appInstallPlanFileName())
}

func installPlanPathForPlan(plan *InstallPlan) string {
	if plan != nil {
		if path := installPlanPathForTargetRoot(plan.TargetRoot); path != "" {
			return path
		}
	}
	return installPlanFallbackPath()
}

func cleanupInstallPlanFiles(activePath string) {
	activePath = strings.TrimSpace(activePath)
	if activePath == "" {
		return
	}

	drives, err := disk.ListDrive()
	if err != nil {
		return
	}
	for _, d := range drives {
		root, _ := utils.NormalizeDrive(d, 0)
		if root == "" || strings.HasPrefix(strings.ToUpper(root), "X:") {
			continue
		}
		path := filepath.Join(root, appInstallPlanFileName())
		if strings.EqualFold(path, activePath) {
			continue
		}
		_ = os.Remove(path)
	}
}

func prepareBootFixMarker(plan *InstallPlan) error {
	if plan == nil || strings.TrimSpace(plan.BootPartRef) == "" {
		return nil
	}

	part, err := findBootPartition(plan.BootPartRef)
	if err != nil {
		return err
	}
	if !strings.EqualFold(strings.TrimSpace(part.Type), "EFI") {
		return nil
	}

	clearAllESPFixMarkers()

	espRoot, cleanup, err := disk.EnsureESPRoot(part)
	if err != nil {
		return fmt.Errorf("mount EFI partition for marker failed: %w", err)
	}
	if cleanup != nil {
		defer cleanup()
	}

	markerPath := filepath.Join(espRoot, espFixMarkerFile)
	if err := os.WriteFile(markerPath, []byte("marker=esp_fix_win\n"), 0o644); err != nil {
		return fmt.Errorf("write %s failed: %w", markerPath, err)
	}
	return nil
}

func clearAllESPFixMarkers() {
	disks, err := disk.ListPhysicalDisks()
	if err != nil {
		return
	}

	for _, d := range disks {
		parts, err := disk.ListDiskPartitions(d.DiskNumber)
		if err != nil {
			continue
		}
		for _, part := range parts {
			if !strings.EqualFold(strings.TrimSpace(part.Type), "EFI") {
				continue
			}
			espRoot, cleanup, err := disk.EnsureESPRoot(part)
			if err != nil {
				continue
			}
			_ = os.Remove(filepath.Join(espRoot, espFixMarkerFile))
			if cleanup != nil {
				cleanup()
			}
		}
	}
}

func findBootPartitionByMarker(plan *InstallPlan) (disk.PartitionInfo, error) {
	disks, err := disk.ListPhysicalDisks()
	if err != nil {
		return disk.PartitionInfo{}, err
	}

	targetDisk := -1
	if plan != nil {
		if root, err := utils.NormalizeDrive(plan.TargetRoot, 0); err == nil && root != "" {
			if num, err := disk.GetDiskNum(root); err == nil {
				targetDisk = int(num)
			}
		}
	}

	candidates := make([]disk.PartitionInfo, 0, 2)
	for _, d := range disks {
		parts, err := disk.ListDiskPartitions(d.DiskNumber)
		if err != nil {
			continue
		}
		for _, part := range parts {
			if !strings.EqualFold(strings.TrimSpace(part.Type), "EFI") {
				continue
			}

			espRoot, cleanup, err := disk.EnsureESPRoot(part)
			if err != nil {
				continue
			}
			_, statErr := os.Stat(filepath.Join(espRoot, espFixMarkerFile))
			if cleanup != nil {
				cleanup()
			}
			if statErr == nil {
				candidates = append(candidates, part)
			}
		}
	}
	if len(candidates) == 0 {
		return disk.PartitionInfo{}, fmt.Errorf("%s not found", espFixMarkerFile)
	}
	if targetDisk >= 0 {
		for _, part := range candidates {
			if part.DiskNumber == targetDisk {
				return part, nil
			}
		}
	}
	return candidates[0], nil
}

// captureInstallImageLocation 记录镜像所在磁盘与卷的元数据。
func captureInstallImageLocation(plan *InstallPlan) error {
	if plan == nil {
		return fmt.Errorf("install plan is nil")
	}

	plan.DiskPath = ""
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
		modAt time.Time
	}

	var hits []hit
	for _, d := range drives {
		root, _ := utils.NormalizeDrive(d, 0)
		if root == "" || strings.HasPrefix(strings.ToUpper(root), "X:") {
			continue
		}

		cand := filepath.Join(root, appInstallPlanFileName())
		info, err := os.Stat(cand)
		if err != nil {
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
		hits = append(hits, hit{
			root:  root,
			path:  cand,
			score: score,
			modAt: info.ModTime(),
		})
	}

	if len(hits) == 0 {
		return nil, fmt.Errorf("未找到 %s", appInstallPlanFileName())
	}

	for len(hits) > 0 {
		bestIdx := -1
		var bestMod time.Time
		bestScore := -1
		for i := range hits {
			if bestIdx < 0 ||
				hits[i].modAt.After(bestMod) ||
				(hits[i].modAt.Equal(bestMod) && hits[i].score > bestScore) {
				bestMod = hits[i].modAt
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

		plan, err := decodePlan(b, h.root)
		if err != nil {
			log.LogWrite(0, "[LoadInstallPlan] failed to parse %s: %v", h.path, err)
			if len(hits) == 0 {
				return nil, err
			}
			continue
		}

		if err := NormalizeInstallPlan(plan); err != nil {
			return nil, err
		}
		if root, err := utils.NormalizeDrive(plan.TargetRoot, 0); err == nil {
			plan.TargetRoot = root
		}
		return plan, nil
	}

	return nil, fmt.Errorf("读取 %s 失败", appInstallPlanFileName())
}

// ===== 目标分区解析与格式化 =====

// decodePlan 解析 JSON 格式的安装计划。
//
// 当计划文件缺少 target_root 时，继续沿用扫描到该文件的卷根作为默认值，
// 这样可以保持原先的恢复路径选择语义。
func decodePlan(data []byte, defRoot string) (*InstallPlan, error) {
	plan := &InstallPlan{}
	if err := json.Unmarshal(data, plan); err != nil {
		return nil, err
	}
	if strings.TrimSpace(plan.TargetRoot) == "" {
		plan.TargetRoot = defRoot
	}
	return plan, nil
}

func FindTempRootByMarker() string {
	drives, _ := disk.ListDrive()
	for _, d := range drives {
		root, _ := utils.NormalizeDrive(d, 0)
		if root == "" || strings.HasPrefix(strings.ToUpper(root), "X:") {
			continue
		}
		marker := tempMarkerPath(root)
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

	if plan.Mode == ReinstallModeAuto && !windows.IsWinPE() {
		plan.TargetRoot = `C:\`
		log.LogWrite(0, "[ResolveInstallTarget] auto mode on Windows, force target root: %s", plan.TargetRoot)
	}

	if strings.TrimSpace(plan.TargetPartRef) != "" {
		_, part, err := findPartitionByRef(plan.TargetPartRef)
		if err != nil {
			log.LogWrite(0, "[ResolveInstallTarget] ignore invalid target_part_ref=%s err=%v", plan.TargetPartRef, err)
		} else {
			root, err := partitionRootFromInfo(part)
			if err != nil {
				if strings.TrimSpace(plan.TargetRoot) == "" {
					return err
				}
				log.LogWrite(0, "[ResolveInstallTarget] keep existing target_root=%s because target_part_ref=%s cannot resolve a drive letter: %v", plan.TargetRoot, plan.TargetPartRef, err)
			} else {
				plan.TargetRoot = root
			}
		}
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

// captureInstallTargetLocation 根据当前 TargetRoot 反查并记录稳定分区引用。
//
// 这个步骤发生在进入 PE 之前，用于把当前在线环境中的盘符转换成
// 重启后依然可识别的分区身份，避免后续流程依赖变化的盘符。
func captureInstallTargetLocation(plan *InstallPlan) error {
	if plan == nil {
		return fmt.Errorf("install plan is nil")
	}
	if strings.TrimSpace(plan.TargetRoot) == "" {
		return fmt.Errorf("install target root is empty")
	}

	diskInfo, part, err := disk.FindPartitionByRoot(plan.TargetRoot)
	if err != nil {
		return err
	}
	partRef, err := disk.BuildPartitionRef(diskInfo, part)
	if err != nil {
		return err
	}
	root, err := partitionRootFromInfo(part)
	if err != nil {
		return err
	}

	plan.TargetRoot = root
	plan.TargetPartRef = partRef
	return nil
}

// partitionRootFromInfo 从分区枚举结果中提取可直接访问的卷根路径。
//
// 当前安装和格式化流程仍然需要一个实际可访问的根路径，因此这里要求
// 分区已经有盘符；若目标分区尚未分配盘符，则上层应先处理挂载问题。
func partitionRootFromInfo(part disk.PartitionInfo) (string, error) {
	if part.DriveLetter != "" {
		root, err := utils.NormalizeDrive(part.DriveLetter, 0)
		if err == nil && root != "" {
			return root, nil
		}
	}
	return "", fmt.Errorf(
		"partition has no drive letter: disk=%d part=%d",
		part.DiskNumber,
		part.PartitionNumber,
	)
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
	return disk.Format(letter, plan.FormatFS, plan.FormatLabel, plan.FormatQuick)
}

// chooseInstallTargetRoot 选择优先用于安装的目标分区。
func chooseInstallTargetRoot() string {
	parts := disk.Findpart()
	if len(parts) > 0 {
		for idx, part := range parts {
			root, _ := utils.NormalizeDrive(part, 0)
			log.LogWrite(
				0,
				"[chooseInstallTargetRoot] candidate partition[%d]=%s normalized=%s",
				idx,
				part,
				root,
			)
		}
		log.LogWrite(0, "[chooseInstallTargetRoot] selected uninstalled system partition: %s", parts[0])
		root, _ := utils.NormalizeDrive(parts[0], 0)
		return root
	}

	drives, _ := disk.ListDrive()
	for _, d := range drives {
		if strings.HasPrefix(strings.ToUpper(d), "X:") {
			log.LogWrite(0, "[chooseInstallTargetRoot] skip PE ramdisk: %s", d)
			continue
		}
		driveType := disk.GetDriveType(d)
		log.LogWrite(0, "[chooseInstallTargetRoot] probe fallback drive=%s type=%d", d, driveType)
		if driveType == 3 {
			log.LogWrite(0, "[chooseInstallTargetRoot] fallback selected fixed drive partition: %s", d)
			root, _ := utils.NormalizeDrive(d, 0)
			return root
		}
	}
	log.LogWrite(0, "[chooseInstallTargetRoot] no suitable partition found")
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
	return applyImage(applyPath, targetRoot, plan.ImageIndex, progress)
}

func applyImage(
	applyPath string,
	targetRoot string,
	imageIndex int,
	progress func(string, float64, string),
) error {
	if imageIndex <= 0 {
		return fmt.Errorf("invalid image index: %d", imageIndex)
	}

	wimlibErr := applyImageWithWimlib(applyPath, imageIndex, targetRoot, func(pct uint8, status string) {
		if progress != nil {
			progress("apply", float64(pct), status)
		}
	})
	if wimlibErr == nil {
		return nil
	}

	log.LogWrite(-1, "[ApplyInstallImage] wimlib apply failed, fallback to DISM: image=%s target=%s index=%d err=%v", applyPath, targetRoot, imageIndex, wimlibErr)
	if progress == nil {
		return applyImageWithDism(applyPath, targetRoot, uint32(imageIndex), nil)
	}

	progressCh := make(chan dism.DismProgress, 16)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for p := range progressCh {
			progress("apply", float64(p.Percentage), p.Status)
		}
	}()

	err := applyImageWithDism(applyPath, targetRoot, uint32(imageIndex), progressCh)
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
	case BootRepairModeUEFI:
		if strings.TrimSpace(plan.BootPartRef) != "" {
			return repairInstallBootManual(plan)
		}
		return boot.FixUEFI(plan.TargetRoot, "", "zh-cn")
	case BootRepairModeBIOS:
		if strings.TrimSpace(plan.BootPartRef) != "" {
			return repairInstallBootManual(plan)
		}
		return boot.FixBIOS(plan.TargetRoot, "", "zh-cn")
	default:
		if strings.TrimSpace(plan.BootPartRef) != "" {
			return repairInstallBootManual(plan)
		}
		return boot.FixBoot(plan.TargetRoot, "", "zh-cn")
	}
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
	ctx.Hooks.Add(HookAfterApplyImage, fixWin7)
	ctx.Hooks.Add(HookAfterRepairBoot, fixWin7UEFI)
	ctx.Hooks.Add(HookBeforeEnterPE, backupDrivers)
	ctx.Hooks.Add(HookAfterRepairBoot, restoreBackedUpDrivers)
	ctx.Hooks.Add(HookAfterInstall, afterInstall)
	ctx.Hooks.Add(HookAfterInstall, cleanupPreparedPE)
}

// fixwin7drive_updata 为 Win7 离线系统预注入驱动和更新。
func fixWin7(ctx *InstallContext) error {
	if ctx == nil || ctx.Plan == nil {
		return fmt.Errorf("install context is nil")
	}
	if !strings.EqualFold(ctx.Plan.TargetOS, TargetWin7) {
		return nil
	}
	if strings.TrimSpace(ctx.Plan.TargetRoot) == "" {
		return fmt.Errorf("install target root is empty")
	}
	if ctx.Plan.Win7Fix.empty() {
		return nil
	}

	dismSvc := dism.NewDism()
	if dir := strings.TrimSpace(ctx.Plan.Win7Fix.USB3); dir != "" {
		if err := addWin7Dir(dismSvc, ctx.Plan.TargetRoot, dir, "Win7 USB3 drivers"); err != nil {
			return err
		}
	}
	if dir := strings.TrimSpace(ctx.Plan.Win7Fix.StorageController); dir != "" {
		if err := addWin7Dir(dismSvc, ctx.Plan.TargetRoot, dir, "Win7 storage controller drivers"); err != nil {
			return err
		}
	}
	if dir := strings.TrimSpace(ctx.Plan.Win7Fix.NVMe); dir != "" {
		if err := addWin7NVMe(dismSvc, ctx.Plan, dir); err != nil {
			return err
		}
	}

	return nil
}

// fixwin7uefi 在修复引导后为 Win7 的 UEFI 引导打补丁。
func fixWin7UEFI(ctx *InstallContext) error {
	if ctx == nil || ctx.Plan == nil {
		return fmt.Errorf("install context is nil")
	}
	if !strings.EqualFold(ctx.Plan.TargetOS, TargetWin7) {
		return nil
	}
	uefiDir := strings.TrimSpace(ctx.Plan.Win7Fix.UEFI)
	if uefiDir == "" {
		return nil
	}
	if strings.TrimSpace(ctx.Plan.ImageArch) == "32" {
		log.LogWrite(0, "[fixWin7UEFI] skip Win7 UEFI patch for 32-bit image")
		return nil
	}
	if strings.TrimSpace(ctx.Plan.TargetRoot) == "" {
		return fmt.Errorf("install target root is empty")
	}

	espRoot, cleanupESP, err := boot.FindESP(ctx.Plan.TargetRoot)
	if err != nil {
		log.LogWrite(0, "[fixWin7UEFI] FindESP failed, skip UEFI patch: %v", err)
		return nil
	}
	if cleanupESP != nil {
		defer cleanupESP()
	}
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

	log.LogWrite(0, "[fixWin7UEFI] patching Win7 UEFI boot: esp=%s", espRoot)
	if err := file.Copy(origBootmgfw, backupBootmgfw, true, true); err != nil {
		return fmt.Errorf("backup bootmgfw.efi failed: %w", err)
	}
	if err := file.Copy(bootShim, origBootmgfw, true, true); err != nil {
		return fmt.Errorf("deploy UefiSeven bootx64.efi failed: %w", err)
	}
	if err := file.Copy(uefiINI, filepath.Join(bootDir, "UefiSeven.ini"), true, true); err != nil {
		return fmt.Errorf("deploy UefiSeven.ini failed: %w", err)
	}

	log.LogWrite(0, "[fixWin7UEFI] Win7 UEFI boot patched")
	return nil
}

func (w InstallWin7Fix) empty() bool {
	return strings.TrimSpace(w.NVMe) == "" &&
		strings.TrimSpace(w.StorageController) == "" &&
		strings.TrimSpace(w.USB3) == "" &&
		strings.TrimSpace(w.UEFI) == ""
}

func fixWin7Dir(dismSvc *dism.Dism, imagePath, driverDir, label string) error {
	if st, err := os.Stat(driverDir); err != nil || !st.IsDir() {
		return fmt.Errorf("%s directory not found: %s", label, driverDir)
	}

	log.LogWrite(0, "[fixWin7Dir] injecting %s: image=%s drivers=%s", label, imagePath, driverDir)
	if err := dismSvc.AddDriverOfflineCmd(imagePath, driverDir, true, true, nil); err != nil {
		return fmt.Errorf("inject %s failed: %w", label, err)
	}

	log.LogWrite(0, "[fixWin7Dir] %s injected", label)
	return nil
}

func fixWin7NVMe(dismSvc *dism.Dism, plan *InstallPlan, nvmeDir string) error {
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
// afterInstall 按安装计划执行安装后的文件复制和快捷方式创建。
func afterInstall(ctx *InstallContext) error {
	if ctx == nil || ctx.Plan == nil {
		return fmt.Errorf("install context is nil")
	}
	if len(ctx.Plan.Files) == 0 && len(ctx.Plan.Shortcuts) == 0 {
		return nil
	}

	selfExe, err := os.Executable()
	if err != nil {
		return err
	}
	baseDir := filepath.Dir(selfExe)
	if err := copyPlanFiles(ctx.Plan.TargetRoot, baseDir, ctx.Plan.Files); err != nil {
		return err
	}
	if err := makeShortcuts(ctx.Plan.TargetRoot, ctx.Plan.Shortcuts); err != nil {
		return err
	}
	log.LogWrite(0, "[afterInstall] copied files and created shortcuts")
	return nil
}

// copyPlanFiles 把配置中的文件或目录复制到新系统。
func copyPlanFiles(targetRoot, baseDir string, files []InstallFile) error {
	targetRoot = strings.TrimSpace(targetRoot)
	baseDir = strings.TrimSpace(baseDir)
	if targetRoot == "" {
		return fmt.Errorf("install target root is empty")
	}
	for _, item := range files {
		src, err := planFileSrc(baseDir, item.Src)
		if err != nil {
			return err
		}
		dst, err := planFileDst(targetRoot, item.Dst)
		if err != nil {
			return err
		}

		if _, err := os.Stat(src); err != nil {
			if os.IsNotExist(err) && !item.Required {
				log.LogWrite(0, "[copyPlanFiles] skip missing optional path: %s", src)
				continue
			}
			return fmt.Errorf("copy %s failed: %w", src, err)
		}
		if err := file.Copy(src, dst, item.Overwrite, true); err != nil {
			return err
		}
	}
	return nil
}

// makeShortcuts 把配置中的快捷方式落到新系统。
func makeShortcuts(targetRoot string, items []InstallShortcut) error {
	targetRoot = strings.TrimSpace(targetRoot)
	if targetRoot == "" {
		return fmt.Errorf("install target root is empty")
	}
	for _, item := range items {
		dir, err := shortcutDir(targetRoot, item.Dir)
		if err != nil {
			return err
		}
		target, err := shortcutTarget(targetRoot, item.Target)
		if err != nil {
			return err
		}
		if _, err := createShortcut(dir, item.Name, target); err != nil {
			return err
		}
	}
	return nil
}

// planFileSrc 解析安装后复制文件的源路径。
func planFileSrc(baseDir, src string) (string, error) {
	src = strings.TrimSpace(src)
	if src == "" {
		return "", fmt.Errorf("file src is empty")
	}
	if filepath.IsAbs(src) {
		return filepath.Clean(src), nil
	}
	if baseDir == "" {
		return "", fmt.Errorf("base dir is empty")
	}
	return filepath.Join(baseDir, filepath.FromSlash(strings.ReplaceAll(src, `\`, "/"))), nil
}

// planFileDst 解析安装后复制文件的目标路径。
func planFileDst(targetRoot, dst string) (string, error) {
	dst = strings.TrimSpace(dst)
	dst = strings.TrimLeft(dst, `\/`)
	if dst == "" {
		return "", fmt.Errorf("file dst is empty")
	}
	return filepath.Join(targetRoot, filepath.FromSlash(strings.ReplaceAll(dst, `\`, "/"))), nil
}

func shortcutDir(targetRoot, dir string) (string, error) {
	return planFileDst(targetRoot, dir)
}

// shortcutTarget 解析快捷方式目标，支持目标系统内路径和 URL。
func shortcutTarget(targetRoot, target string) (string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", fmt.Errorf("shortcut target is empty")
	}

	lower := strings.ToLower(target)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return target, nil
	}
	if filepath.IsAbs(target) {
		return filepath.Clean(target), nil
	}
	return planFileDst(targetRoot, target)
}

// adddrivexe 预置驱动安装工具。

// ===== 兼容包装 =====

// WriteResFile 保留旧入口并改为写入安装计划。

// LoadResData 保留旧读取入口并展开安装计划字段。

// postInstallTasks 保留旧入口并执行安装后钩子。
