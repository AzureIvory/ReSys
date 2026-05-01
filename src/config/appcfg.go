//go:build windows

package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"ReSys/src/utils"
)

const (
	// AppConfigRelative 是应用级配置文件的默认相对路径。
	AppConfigRelative = `rules\config\app.json`
)

const (
	// DefaultAppUILanguage 是 app.json 中 ui_language 的默认值。
	DefaultAppUILanguage = "auto"
	// DefaultAppImageLanguage 是 app.json 中 image_default_language 的默认值。
	DefaultAppImageLanguage = "zh-CN"
	// DefaultUIBundleLanguage 是 UI 语言文件的基础回退语言。
	DefaultUIBundleLanguage = "zh_CN"
	// DefaultLanguageDirRelative 是语言文件目录的默认相对路径。
	DefaultLanguageDirRelative = `rules\lang`
	// DefaultUIThemeRelativePath 是 UI 布局文件的默认相对路径。
	DefaultUIThemeRelativePath = `rules\ui\default\default.json`
	// DefaultDownloadDirName 是下载镜像工作目录的默认相对路径。
	DefaultDownloadDirName = "tempimg"
	// DefaultPEDirName 是 PE 工作目录的默认相对路径。
	DefaultPEDirName = "PETEMP"
	// DefaultDriverBackupDirName 是驱动备份目录的默认相对路径。
	DefaultDriverBackupDirName = "driverbackup"
	// DefaultInstallPlanFileName 是安装计划文件的默认相对路径。
	DefaultInstallPlanFileName = "restall_win.dat"
	// DefaultImageHintFileName 是镜像提示文件的默认相对路径。
	DefaultImageHintFileName = "restall_img.dat"
	// DefaultTempMarkerRelativePath 是临时分区标记文件的默认相对路径。
	DefaultTempMarkerRelativePath = `RESTALL\temp.marker`
	// DefaultImageScanDepth 是本地镜像扫描深度的默认值。
	DefaultImageScanDepth = 2
	// DefaultMinLocalImageGiB 是本地镜像最小体积的默认值，单位 GiB。
	DefaultMinLocalImageGiB = 1.0

	defaultMinFreeSpace  uint64 = 7516192768
	defaultNeedFreeSpace uint64 = 10737418240
)

// AppConfig 描述 rules/config/app.json 的统一结构。
type AppConfig struct {
	Language AppLanguageConfig `json:"language"`
	Paths    AppPathsConfig    `json:"paths"`
	Image    AppImageConfig    `json:"image"`
	Disk     AppDiskConfig     `json:"disk"`
	PE       []AppPEEntry      `json:"pe"`
	UI       AppUIConfig       `json:"ui"`
}

// AppLanguageConfig 描述语言相关配置。
type AppLanguageConfig struct {
	UILanguage           string `json:"ui_language"`
	ImageDefaultLanguage string `json:"image_default_language"`
}

// AppPathsConfig 描述目录与文件名配置。
type AppPathsConfig struct {
	DownloadDirName     string `json:"Download_Dir_Name"`
	PEDirName           string `json:"PE_Dir_Name"`
	DriverBackupDirName string `json:"Driver_Backup_Dir_Name"`
	InstallPlan         string `json:"Install_Plan"`
	ImageHint           string `json:"Image_Hint"`
	TempMarker          string `json:"Temp_Marker"`
}

// AppImageConfig 描述镜像扫描相关配置。
type AppImageConfig struct {
	ScanDepth     int      `json:"Scan_Depth"`
	MinLocalImage float64  `json:"Min_Local_Image"`
	SkipNames     []string `json:"Skip_Names"`
}

// AppDiskConfig 描述磁盘筛选相关配置。
type AppDiskConfig struct {
	MinFreeSpace  uint64   `json:"Min_Free_Space"`
	NeedFreeSpace uint64   `json:"Need_Free_Space"`
	ExcludeDrive  []string `json:"Exclude_Drive"`
}

// AppPEEntry 描述单个 PE 候选项。
type AppPEEntry struct {
	Group      string `json:"group"`
	SDIPattern string `json:"sdi"`
	WIMPattern string `json:"wim"`
	Arch       string `json:"arch"`
	Label      string `json:"label"`
}

// AppUIConfig 描述界面相关配置。
type AppUIConfig struct {
	Theme  string `json:"Theme"`
	Advert bool   `json:"Advert"`
}

// DefaultAppConfig 返回一份完整的默认应用配置。
func DefaultAppConfig() AppConfig {
	return AppConfig{
		Language: AppLanguageConfig{
			UILanguage:           DefaultAppUILanguage,
			ImageDefaultLanguage: DefaultAppImageLanguage,
		},
		Paths: AppPathsConfig{
			DownloadDirName:     DefaultDownloadDirName,
			PEDirName:           DefaultPEDirName,
			DriverBackupDirName: DefaultDriverBackupDirName,
			InstallPlan:         DefaultInstallPlanFileName,
			ImageHint:           DefaultImageHintFileName,
			TempMarker:          DefaultTempMarkerRelativePath,
		},
		Image: AppImageConfig{
			ScanDepth:     DefaultImageScanDepth,
			MinLocalImage: DefaultMinLocalImageGiB,
			SkipNames:     DefaultImageSkipNames(),
		},
		Disk: AppDiskConfig{
			MinFreeSpace:  defaultMinFreeSpace,
			NeedFreeSpace: defaultNeedFreeSpace,
			ExcludeDrive:  []string{"A", "B", "X"},
		},
		PE: DefaultAppPEEntries(),
		UI: AppUIConfig{
			Theme:  fixPath(DefaultUIThemeRelativePath),
			Advert: false,
		},
	}
}

// DefaultAppPEEntries 返回一份默认 PE 候选列表副本。
func DefaultAppPEEntries() []AppPEEntry {
	return append([]AppPEEntry(nil), defaultPEEntries()...)
}

// DefaultImageSkipNames 返回默认跳过的本地镜像文件名副本。
func DefaultImageSkipNames() []string {
	return []string{"03pe.wim", "11pex64.wim"}
}

// LoadAppConfig 从默认 app.json 位置加载配置。
func LoadAppConfig() (AppConfig, error) {
	path, err := utils.ProjectFile(AppConfigRelative)
	if err != nil {
		return AppConfig{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return AppConfig{}, err
	}
	return parseAppData(data)
}

// ParseAppSource 自动识别 JSON 文本或 JSON 绝对路径，并完成归一化。
func ParseAppSource(src string) (AppConfig, error) {
	text, err := readSource(src)
	if err != nil {
		return AppConfig{}, err
	}
	return parseAppData([]byte(text))
}

// Normalize 补齐默认值，并校验 app 配置的关键字段。
func (cfg *AppConfig) Normalize() error {
	if cfg == nil {
		return fmt.Errorf("app config is nil")
	}

	def := DefaultAppConfig()

	cfg.Language.normalize(def.Language)
	if err := cfg.Paths.normalize(def.Paths); err != nil {
		return err
	}
	cfg.Image.normalize(def.Image)
	if err := cfg.Disk.normalize(def.Disk); err != nil {
		return err
	}
	if err := normalizePEEntries(cfg, def.PE); err != nil {
		return err
	}
	cfg.UI.normalize(def.UI)
	return nil
}

// UnmarshalJSON 兼容当前数组形式和后续对象形式的 PE 配置。
func (e *AppPEEntry) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return nil
	}

	type raw AppPEEntry
	var obj raw
	if err := json.Unmarshal(data, &obj); err == nil {
		if obj.Group != "" || obj.SDIPattern != "" || obj.WIMPattern != "" || obj.Arch != "" || obj.Label != "" {
			*e = AppPEEntry(obj)
			return nil
		}
	}

	var arr []string
	if err := json.Unmarshal(data, &arr); err != nil {
		return err
	}
	if len(arr) != 4 && len(arr) != 5 {
		return fmt.Errorf("pe entry expects 4 or 5 items, got %d", len(arr))
	}

	e.Group = arr[0]
	e.SDIPattern = arr[1]
	e.WIMPattern = arr[2]
	e.Arch = arr[3]
	if len(arr) == 5 {
		e.Label = arr[4]
	}
	return nil
}

// UnmarshalJSON 兼容旧版 `"language":"en_US"` 和新版对象结构。
func (c *AppLanguageConfig) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return nil
	}

	var legacy string
	if err := json.Unmarshal(data, &legacy); err == nil {
		c.UILanguage = legacy
		return nil
	}

	type raw AppLanguageConfig
	var decoded raw
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*c = AppLanguageConfig(decoded)
	return nil
}

func parseAppData(data []byte) (AppConfig, error) {
	cfg := DefaultAppConfig()
	if len(bytes.TrimSpace(data)) == 0 {
		return cfg, nil
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return AppConfig{}, err
	}
	if err := cfg.Normalize(); err != nil {
		return AppConfig{}, err
	}
	return cfg, nil
}

func (c *AppLanguageConfig) normalize(def AppLanguageConfig) {
	if c == nil {
		return
	}
	c.UILanguage = strings.TrimSpace(c.UILanguage)
	if c.UILanguage == "" {
		c.UILanguage = def.UILanguage
	}
	c.ImageDefaultLanguage = strings.TrimSpace(c.ImageDefaultLanguage)
	if c.ImageDefaultLanguage == "" {
		c.ImageDefaultLanguage = def.ImageDefaultLanguage
	}
}

func (c *AppPathsConfig) normalize(def AppPathsConfig) error {
	if c == nil {
		return nil
	}

	var err error
	if c.DownloadDirName, err = normalizeRelativePath(c.DownloadDirName, def.DownloadDirName); err != nil {
		return fmt.Errorf("paths.Download_Dir_Name: %w", err)
	}
	if c.PEDirName, err = normalizeRelativePath(c.PEDirName, def.PEDirName); err != nil {
		return fmt.Errorf("paths.PE_Dir_Name: %w", err)
	}
	if c.DriverBackupDirName, err = normalizeRelativePath(c.DriverBackupDirName, def.DriverBackupDirName); err != nil {
		return fmt.Errorf("paths.Driver_Backup_Dir_Name: %w", err)
	}
	if c.InstallPlan, err = normalizeRelativePath(c.InstallPlan, def.InstallPlan); err != nil {
		return fmt.Errorf("paths.Install_Plan: %w", err)
	}
	if c.ImageHint, err = normalizeRelativePath(c.ImageHint, def.ImageHint); err != nil {
		return fmt.Errorf("paths.Image_Hint: %w", err)
	}
	if c.TempMarker, err = normalizeRelativePath(c.TempMarker, def.TempMarker); err != nil {
		return fmt.Errorf("paths.Temp_Marker: %w", err)
	}
	return nil
}

func (c *AppImageConfig) normalize(def AppImageConfig) {
	if c == nil {
		return
	}

	if c.ScanDepth <= 0 {
		c.ScanDepth = def.ScanDepth
	}
	if c.MinLocalImage <= 0 {
		c.MinLocalImage = def.MinLocalImage
	}
	c.SkipNames = normalizeStringList(c.SkipNames, def.SkipNames, false)
}

func (c *AppDiskConfig) normalize(def AppDiskConfig) error {
	if c == nil {
		return nil
	}

	if c.MinFreeSpace == 0 {
		c.MinFreeSpace = def.MinFreeSpace
	}
	if c.NeedFreeSpace == 0 {
		c.NeedFreeSpace = def.NeedFreeSpace
	}
	if c.ExcludeDrive == nil || len(c.ExcludeDrive) == 0 {
		c.ExcludeDrive = append([]string(nil), def.ExcludeDrive...)
	} else {
		drives := make([]string, 0, len(c.ExcludeDrive))
		seen := map[string]struct{}{}
		for i, item := range c.ExcludeDrive {
			drv, err := normalizeDriveToken(item)
			if err != nil {
				return fmt.Errorf("disk.Exclude_Drive[%d]: %w", i, err)
			}
			if _, ok := seen[drv]; ok {
				continue
			}
			seen[drv] = struct{}{}
			drives = append(drives, drv)
		}
		c.ExcludeDrive = drives
	}
	return nil
}

func (c *AppUIConfig) normalize(def AppUIConfig) {
	if c == nil {
		return
	}
	c.Theme = strings.TrimSpace(c.Theme)
	if c.Theme == "" {
		c.Theme = def.Theme
		return
	}
	c.Theme = fixPath(c.Theme)
}

func normalizePEEntries(cfg *AppConfig, def []AppPEEntry) error {
	if len(cfg.PE) == 0 {
		cfg.PE = append([]AppPEEntry(nil), def...)
		return nil
	}

	items := make([]AppPEEntry, 0, len(cfg.PE))
	for i := range cfg.PE {
		item, ok, err := cfg.PE[i].normalize()
		if err != nil {
			return fmt.Errorf("pe[%d]: %w", i, err)
		}
		if ok {
			items = append(items, item)
		}
	}
	if len(items) == 0 {
		cfg.PE = append([]AppPEEntry(nil), def...)
		return nil
	}
	cfg.PE = items
	return nil
}

func (e AppPEEntry) normalize() (AppPEEntry, bool, error) {
	e.Group = strings.TrimSpace(e.Group)
	e.SDIPattern = normalizePERootPattern(e.SDIPattern)
	e.WIMPattern = normalizePERootPattern(e.WIMPattern)
	e.Label = strings.TrimSpace(e.Label)

	if e.Group == "" && e.SDIPattern == "" && e.WIMPattern == "" && strings.TrimSpace(e.Arch) == "" && e.Label == "" {
		return AppPEEntry{}, false, nil
	}
	if e.Group == "" {
		return AppPEEntry{}, false, fmt.Errorf("group is required")
	}
	if e.SDIPattern == "" {
		return AppPEEntry{}, false, fmt.Errorf("sdi is required")
	}
	if e.WIMPattern == "" {
		return AppPEEntry{}, false, fmt.Errorf("wim is required")
	}

	arch := strings.TrimSpace(e.Arch)
	if arch != "" {
		arch = utils.NormalizeArch(arch)
		switch arch {
		case "32", "64", "arm":
		default:
			return AppPEEntry{}, false, fmt.Errorf("unsupported arch: %s", e.Arch)
		}
	}
	e.Arch = arch
	return e, true, nil
}

func normalizeRelativePath(value, def string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		value = def
	}
	value = strings.ReplaceAll(value, "/", `\`)
	if filepath.IsAbs(value) {
		return "", fmt.Errorf("must be relative: %s", value)
	}
	value = filepath.Clean(value)
	if value == "." || value == `\` || value == "" {
		return "", fmt.Errorf("must not be empty")
	}
	return value, nil
}

func normalizeDriveToken(value string) (string, error) {
	value = strings.TrimSpace(value)
	value = strings.TrimSuffix(value, `\`)
	value = strings.TrimSuffix(value, ":")
	value = strings.ToUpper(value)
	if len(value) != 1 || value[0] < 'A' || value[0] > 'Z' {
		return "", fmt.Errorf("invalid drive letter: %s", value)
	}
	return value, nil
}

func normalizePERootPattern(value string) string {
	value = strings.TrimSpace(strings.ReplaceAll(value, "/", `\`))
	if value == "" {
		return ""
	}
	if !strings.HasPrefix(value, `\`) {
		value = `\` + value
	}
	return filepath.Clean(value)
}

func normalizeStringList(items, def []string, upper bool) []string {
	if len(items) == 0 {
		return append([]string(nil), def...)
	}
	out := make([]string, 0, len(items))
	seen := map[string]struct{}{}
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if upper {
			item = strings.ToUpper(item)
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	if len(out) == 0 {
		return append([]string(nil), def...)
	}
	return out
}

func defaultPEEntries() []AppPEEntry {
	return []AppPEEntry{
		{Group: "WEPE", SDIPattern: `\WEPE\WEPE.SDI`, WIMPattern: `\WEPE\WEPE64.WIM`, Arch: "64", Label: "微PE"},
		{Group: "WEPE", SDIPattern: `\WEPE\WEPE.SDI`, WIMPattern: `\WEPE\WEPE32.WIM`, Arch: "32", Label: "微PE"},
		{Group: "FIR", SDIPattern: `\FirPE\BOOT.SDI`, WIMPattern: `\FirPE\11PEX64.WIM`, Arch: "64", Label: "FirPE"},
		{Group: "FIR", SDIPattern: `\FirPE\BOOT.SDI`, WIMPattern: `\FirPE\11PEX86.WIM`, Arch: "32", Label: "FirPE"},
		{Group: "FirPE1", SDIPattern: `\boot\boot.sdi`, WIMPattern: `\boot\11pex64.wim`, Arch: "64", Label: "FirPE1"},
		{Group: "FirPE1", SDIPattern: `\boot\boot.sdi`, WIMPattern: `\boot\11pex86.wim`, Arch: "32", Label: "FirPE1"},
		{Group: "HOT", SDIPattern: `\HotPE\boot.sdi`, WIMPattern: `\HotPE\Boot.wim`, Arch: "64", Label: "HotPE"},
		{Group: "PETEMP", SDIPattern: `\PETEMP\*.sdi`, WIMPattern: `\PETEMP\*.wim`},
		{Group: "PETEMP", SDIPattern: `\PETEMP\*.SDI`, WIMPattern: `\PETEMP\*.WIM`},
	}
}
