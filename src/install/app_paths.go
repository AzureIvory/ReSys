package install

import (
	"path/filepath"
	"strings"

	"ReSys/src/config"
	"ReSys/src/utils"
)

var loadInstallAppConfig = config.LoadAppConfig

type installPathPolicy struct {
	downloadDirName     string
	peDirName           string
	driverBackupDirName string
	installPlanName     string
	imageHintName       string
	tempMarkerRel       string
}

// PathConfigSnapshot 描述当前 paths 配置及其派生结果，供探针与回归验证使用。
type PathConfigSnapshot struct {
	DownloadDirName     string `json:"download_dir_name"`
	PEDirName           string `json:"pe_dir_name"`
	DriverBackupDirName string `json:"driver_backup_dir_name"`
	InstallPlanName     string `json:"install_plan_name"`
	ImageHintName       string `json:"image_hint_name"`
	TempMarkerRel       string `json:"temp_marker_rel"`
	DownloadDirPath     string `json:"download_dir_path"`
	PEDirPath           string `json:"pe_dir_path"`
	InstallPlanPath     string `json:"install_plan_path"`
	ImageHintPath       string `json:"image_hint_path"`
	TempMarkerPath      string `json:"temp_marker_path"`
	DriverBackupRoot    string `json:"driver_backup_root"`
}

func currentInstallPathPolicy() installPathPolicy {
	def := config.DefaultAppConfig().Paths
	policy := installPathPolicy{
		downloadDirName:     def.DownloadDirName,
		peDirName:           def.PEDirName,
		driverBackupDirName: def.DriverBackupDirName,
		installPlanName:     def.InstallPlan,
		imageHintName:       def.ImageHint,
		tempMarkerRel:       def.TempMarker,
	}

	cfg, err := loadInstallAppConfig()
	if err != nil {
		return policy
	}
	if cfg.Paths.DownloadDirName != "" {
		policy.downloadDirName = cfg.Paths.DownloadDirName
	}
	if cfg.Paths.PEDirName != "" {
		policy.peDirName = cfg.Paths.PEDirName
	}
	if cfg.Paths.DriverBackupDirName != "" {
		policy.driverBackupDirName = cfg.Paths.DriverBackupDirName
	}
	if cfg.Paths.InstallPlan != "" {
		policy.installPlanName = cfg.Paths.InstallPlan
	}
	if cfg.Paths.ImageHint != "" {
		policy.imageHintName = cfg.Paths.ImageHint
	}
	if cfg.Paths.TempMarker != "" {
		policy.tempMarkerRel = cfg.Paths.TempMarker
	}
	return policy
}

func appDownloadDirName() string {
	return currentInstallPathPolicy().downloadDirName
}

// AppDownloadDirName 返回下载目录配置的当前生效值。
func AppDownloadDirName() string {
	return appDownloadDirName()
}

func appPEDirName() string {
	return currentInstallPathPolicy().peDirName
}

// AppPEDirName 返回 PE 工作目录配置的当前生效值。
func AppPEDirName() string {
	return appPEDirName()
}

func appDriverBackupDirName() string {
	return currentInstallPathPolicy().driverBackupDirName
}

// AppDriverBackupDirName 返回驱动备份目录配置的当前生效值。
func AppDriverBackupDirName() string {
	return appDriverBackupDirName()
}

func appInstallPlanFileName() string {
	return currentInstallPathPolicy().installPlanName
}

// AppInstallPlanFileName 返回安装计划文件配置的当前生效值。
func AppInstallPlanFileName() string {
	return appInstallPlanFileName()
}

func appImageHintFileName() string {
	return currentInstallPathPolicy().imageHintName
}

// AppImageHintFileName 返回镜像提示文件配置的当前生效值。
func AppImageHintFileName() string {
	return appImageHintFileName()
}

func appTempMarkerRelativePath() string {
	return currentInstallPathPolicy().tempMarkerRel
}

// AppTempMarkerRelativePath 返回临时分区标记文件配置的当前生效值。
func AppTempMarkerRelativePath() string {
	return appTempMarkerRelativePath()
}

func peWorkspaceDir(root string) string {
	return filepath.Join(root, appPEDirName())
}

func downloadWorkspaceDir(root string) string {
	return filepath.Join(root, appDownloadDirName())
}

func tempMarkerPath(root string) string {
	return filepath.Join(root, appTempMarkerRelativePath())
}

func imageHintPath(root string) string {
	return filepath.Join(root, appImageHintFileName())
}

func pathUsesPEDir(path string) bool {
	path = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(path), "/", `\`))
	if path == "" {
		return false
	}

	rel := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(appPEDirName()), "/", `\`))
	rel = strings.Trim(rel, `\`)
	if rel == "" {
		return false
	}

	token := `\` + rel + `\`
	if strings.Contains(path, token) {
		return true
	}
	return strings.HasSuffix(path, token[:len(token)-1])
}

// CollectPathConfigSnapshot 返回当前 paths 配置及常见派生路径。
func CollectPathConfigSnapshot(imagePath, root string) (PathConfigSnapshot, error) {
	policy := currentInstallPathPolicy()
	snapshot := PathConfigSnapshot{
		DownloadDirName:     policy.downloadDirName,
		PEDirName:           policy.peDirName,
		DriverBackupDirName: policy.driverBackupDirName,
		InstallPlanName:     policy.installPlanName,
		ImageHintName:       policy.imageHintName,
		TempMarkerRel:       policy.tempMarkerRel,
	}

	if nr, err := utils.NormalizeDrive(root, 0); err == nil && nr != "" {
		root = nr
	}
	if strings.TrimSpace(root) != "" {
		snapshot.DownloadDirPath = downloadWorkspaceDir(root)
		snapshot.PEDirPath = peWorkspaceDir(root)
		snapshot.InstallPlanPath = filepath.Join(root, policy.installPlanName)
		snapshot.ImageHintPath = filepath.Join(root, policy.imageHintName)
		snapshot.TempMarkerPath = filepath.Join(root, policy.tempMarkerRel)
	}

	if strings.TrimSpace(imagePath) != "" {
		plan := &InstallPlan{ImagePath: imagePath}
		backupRoot, err := driverBackupRoot(plan)
		if err != nil {
			return PathConfigSnapshot{}, err
		}
		snapshot.DriverBackupRoot = backupRoot
	}

	return snapshot, nil
}
