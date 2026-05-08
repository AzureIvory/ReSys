//go:build windows

// 这个go文件定义手动重装使用的 JSON 配置模型。
//
// 这个go文件只负责两件事：
// 1. 在 UI 侧把当前选择序列化为 JSON 文本。
// 2. 在安装侧把 JSON 文本或 JSON 绝对路径解析为结构化配置。
package config

import (
	"ReSys/src/utils"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var cfgDir = func() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Dir(exe)
}

const (
	// BootAuto 表示自动修复引导。
	BootAuto = "auto"
	// BootUEFI 表示强制按 UEFI 修复引导。
	BootUEFI = "uefi"
	// BootBIOS 表示强制按 BIOS 修复引导。
	BootBIOS = "bios"
	// BootSkip 表示跳过引导修复。
	BootSkip = "skip"

	// Auto 表示使用默认自动行为。
	Auto = "AUTO"
)

// Config 是手动重装 JSON 的顶层结构。
type Config struct {
	Mode         string       `json:"mode"`
	TargetOS     string       `json:"target_os"`
	ImageArch    string       `json:"image_arch"`
	PEArch       string       `json:"pe_arch"`
	ImagePath    string       `json:"image_path"`
	Index        int          `json:"index"`
	Partition    string       `json:"partition"`
	PEWIM        string       `json:"PEwim"`
	Boot         Boot         `json:"boot"`
	Restart      bool         `json:"restart"`
	BackupDriver BackupDriver `json:"backup_driver"`
	Format       Format       `json:"format"`
	File         FileConfig   `json:"file"`
	Shortcut     Shortcut     `json:"shortcut"`
	Win7Fix      Win7Fix      `json:"win7fix"`
}

// Boot 是引导修复相关配置。
type Boot struct {
	Method        string `json:"method"`
	BootPartition string `json:"boot_partition"`
}

// BackupDriver 是驱动备份相关配置。
type BackupDriver struct {
	State bool     `json:"state"`
	File  []string `json:"file"`
	GUID  []string `json:"guid"`
}

// Format 是格式化相关配置。
type Format struct {
	State  bool   `json:"state"`
	FS     string `json:"fs"`
	Quick  bool   `json:"quick"`
	Letter string `json:"letter"`
	Label  string `json:"label"`
}

// FileConfig 定义安装后复制到新系统中的文件列表。
type FileConfig struct {
	State bool       `json:"state"`
	Items []FileItem `json:"items"`
}

// 启动方式常量。
const (
	LaunchNone       = "none"
	LaunchFirstLogon = "firstLogon"
	LaunchSpecialize = "specialize"
)

// FileItem 描述单个复制规则。
type FileItem struct {
	Src       string `json:"src"`
	Dst       string `json:"dst"`
	Overwrite bool   `json:"overwrite"`
	Required  bool   `json:"required"`
	Launch    string `json:"launch,omitempty"` // 启动方式：none / firstLogon / specialize
}

// Shortcut 定义安装后创建的快捷方式。
type Shortcut struct {
	State bool           `json:"state"`
	Items []ShortcutItem `json:"items"`
}

// ShortcutItem 描述单个快捷方式。
type ShortcutItem struct {
	Target string `json:"target"`
	Name   string `json:"name"`
	Dir    string `json:"dir"`
}

// Win7Fix 定义 Win7 修复资源路径。
type Win7Fix struct {
	NVMe              string `json:"nvme"`
	StorageController string `json:"storage_controller"`
	USB3              string `json:"usb3"`
	UEFI              string `json:"uefi"`
}

// ParseSource 自动识别 JSON 文本或 JSON 绝对路径，并完成归一化。
func ParseSource(src string) (Config, error) {
	text, err := readSource(src)
	if err != nil {
		return Config{}, err
	}

	cfg := Config{}
	if err := json.Unmarshal([]byte(text), &cfg); err != nil {
		return Config{}, err
	}
	if err := cfg.Normalize(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Marshal 将配置写为格式化 JSON 文本。
func Marshal(cfg Config) (string, error) {
	if err := cfg.Normalize(); err != nil {
		return "", err
	}
	buf, err := json.MarshalIndent(cfg, "", "\t")
	if err != nil {
		return "", err
	}
	return string(buf), nil
}

// Normalize 补齐默认值，并把大小写与别名转换为内部统一形式。
func (cfg *Config) Normalize() error {
	if cfg == nil {
		return fmt.Errorf("install config is nil")
	}

	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	switch mode {
	case "", "manual", "auto":
		cfg.Mode = mode
	default:
		return fmt.Errorf("unsupported install mode: %s", cfg.Mode)
	}

	target := strings.ToLower(strings.TrimSpace(cfg.TargetOS))
	switch target {
	case "", "win7", "win10", "win11":
		cfg.TargetOS = target
	default:
		return fmt.Errorf("unsupported target os: %s", cfg.TargetOS)
	}

	arch, err := normalizeArch(cfg.ImageArch)
	if err != nil {
		return fmt.Errorf("image_arch: %w", err)
	}
	cfg.ImageArch = arch

	peArch, err := normalizeArch(cfg.PEArch)
	if err != nil {
		return fmt.Errorf("pe_arch: %w", err)
	}
	cfg.PEArch = peArch

	cfg.ImagePath = fixPath(cfg.ImagePath)
	cfg.Partition = strings.TrimSpace(cfg.Partition)
	cfg.PEWIM = fixPath(cfg.PEWIM)

	if cfg.Index == 0 {
		cfg.Index = -1
	}

	if err := cfg.Boot.normalize(); err != nil {
		return err
	}
	cfg.BackupDriver.normalize()
	if err := cfg.Format.normalize(); err != nil {
		return err
	}
	if err := cfg.File.normalize(); err != nil {
		return err
	}
	if err := cfg.Shortcut.normalize(); err != nil {
		return err
	}
	cfg.Win7Fix.normalize()

	return nil
}

func (b *Boot) normalize() error {
	if b == nil {
		return nil
	}

	method := strings.ToLower(strings.TrimSpace(b.Method))
	switch method {
	case "", BootAuto:
		b.Method = BootAuto
	case "none", BootSkip:
		b.Method = BootSkip
	case BootUEFI:
		b.Method = BootUEFI
	case BootBIOS:
		b.Method = BootBIOS
	default:
		return fmt.Errorf("unsupported boot method: %s", b.Method)
	}

	b.BootPartition = strings.TrimSpace(b.BootPartition)
	if b.BootPartition == "" {
		b.BootPartition = Auto
	}
	if strings.EqualFold(b.BootPartition, Auto) {
		b.BootPartition = Auto
	}

	return nil
}

func (b *BackupDriver) normalize() {
	if b == nil {
		return
	}

	if b.File == nil {
		b.File = []string{}
	}
	if b.GUID == nil {
		b.GUID = []string{}
	}

	files := make([]string, 0, len(b.File))
	for _, item := range b.File {
		item = strings.TrimSpace(item)
		if item != "" {
			files = append(files, item)
		}
	}
	b.File = files

	guids := make([]string, 0, len(b.GUID))
	for _, item := range b.GUID {
		item = strings.TrimSpace(item)
		if item != "" {
			guids = append(guids, item)
		}
	}
	b.GUID = guids
}

func (f *Format) normalize() error {
	if f == nil {
		return nil
	}

	f.FS = strings.TrimSpace(f.FS)
	f.Label = strings.TrimSpace(f.Label)
	f.Letter = strings.TrimSpace(f.Letter)
	if f.Letter == "" {
		f.Letter = Auto
	}
	if !strings.EqualFold(f.Letter, Auto) {
		return fmt.Errorf("format.letter only supports AUTO")
	}
	f.Letter = Auto
	return nil
}

func (f *FileConfig) normalize() error {
	if f == nil {
		return nil
	}
	if f.Items == nil {
		f.Items = []FileItem{}
	}

	items := make([]FileItem, 0, len(f.Items))
	for i := range f.Items {
		item, ok, err := f.Items[i].normalize()
		if err != nil {
			return fmt.Errorf("file.items[%d]: %w", i, err)
		}
		if ok {
			items = append(items, item)
		}
	}
	f.Items = items
	return nil
}

func (s *Shortcut) normalize() error {
	if s == nil {
		return nil
	}
	if s.Items == nil {
		s.Items = []ShortcutItem{}
	}

	items := make([]ShortcutItem, 0, len(s.Items))
	for i := range s.Items {
		item, ok, err := s.Items[i].normalize()
		if err != nil {
			return fmt.Errorf("shortcut.items[%d]: %w", i, err)
		}
		if ok {
			items = append(items, item)
		}
	}
	s.Items = items
	return nil
}

func (f FileItem) normalize() (FileItem, bool, error) {
	f.Src = strings.TrimSpace(f.Src)
	f.Dst = strings.TrimSpace(f.Dst)
	if f.Src == "" && f.Dst == "" {
		return FileItem{}, false, nil
	}
	if f.Src == "" {
		return FileItem{}, false, fmt.Errorf("src is required")
	}
	if f.Dst == "" {
		return FileItem{}, false, fmt.Errorf("dst is required")
	}
	return f, true, nil
}

func (s ShortcutItem) normalize() (ShortcutItem, bool, error) {
	s.Target = strings.TrimSpace(s.Target)
	s.Name = strings.TrimSpace(s.Name)
	s.Dir = strings.TrimSpace(s.Dir)
	if s.Target == "" && s.Name == "" && s.Dir == "" {
		return ShortcutItem{}, false, nil
	}
	if s.Target == "" {
		return ShortcutItem{}, false, fmt.Errorf("target is required")
	}
	if s.Name == "" {
		return ShortcutItem{}, false, fmt.Errorf("name is required")
	}
	if s.Dir == "" {
		return ShortcutItem{}, false, fmt.Errorf("dir is required")
	}
	return s, true, nil
}

func (w *Win7Fix) normalize() {
	if w == nil {
		return
	}
	w.NVMe = fixPath(w.NVMe)
	w.StorageController = fixPath(w.StorageController)
	w.USB3 = fixPath(w.USB3)
	w.UEFI = fixPath(w.UEFI)
}

func normalizeArch(arch string) (string, error) {
	arch = strings.TrimSpace(arch)
	if arch == "" {
		return "", nil
	}
	if strings.EqualFold(arch, Auto) {
		return "auto", nil
	}

	arch = utils.NormalizeArch(arch)
	switch arch {
	case "32", "64", "arm":
		return arch, nil
	default:
		return "", fmt.Errorf("unsupported arch: %s", arch)
	}
}

// fixPath 把相对路径转换为相对程序目录的绝对路径。
func fixPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}

	dir := strings.TrimSpace(cfgDir())
	if dir == "" {
		return path
	}
	return filepath.Join(dir, filepath.FromSlash(strings.ReplaceAll(path, `\`, "/")))
}

func readSource(src string) (string, error) {
	src = strings.TrimSpace(src)
	if src == "" {
		return "", fmt.Errorf("empty install config source")
	}
	if isJSON(src) {
		return src, nil
	}

	if text, ok, err := readFile(src); ok || err != nil {
		return text, err
	}

	return src, nil
}

// readFile 尝试把 source 当作文件路径读取，兼容绝对路径与当前目录下的相对路径。
func readFile(src string) (string, bool, error) {
	if !filepath.IsAbs(src) {
		if _, err := os.Stat(src); err != nil {
			if os.IsNotExist(err) {
				return "", false, nil
			}
			return "", true, err
		}
	}

	data, err := os.ReadFile(src)
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", true, err
	}
	return string(data), true, nil
}

func isJSON(src string) bool {
	if src == "" {
		return false
	}
	switch src[0] {
	case '{', '[':
		return true
	default:
		return false
	}
}
