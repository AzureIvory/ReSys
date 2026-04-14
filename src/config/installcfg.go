//go:build windows

// Package config 定义手动重装使用的 JSON 配置模型。
//
// 这个包只负责两件事：
// 1. 在 UI 侧把当前选择序列化为 JSON 文本。
// 2. 在安装侧把 JSON 文本或 JSON 绝对路径解析为结构化配置。
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

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
	ImagePath    string       `json:"image_path"`
	Index        int          `json:"index"`
	Partition    string       `json:"partition"`
	PEWIM        string       `json:"PEwim"`
	Boot         Boot         `json:"boot"`
	Restart      bool         `json:"restart"`
	Unattended   Unattended   `json:"unattended"`
	BackupDriver BackupDriver `json:"backup_driver"`
	Format       Format       `json:"format"`
}

// Boot 是引导修复相关配置。
type Boot struct {
	Method        string `json:"method"`
	BootPartition string `json:"boot_partition"`
}

// Unattended 是无人值守相关配置。
type Unattended struct {
	State bool   `json:"state"`
	File  string `json:"unattended_file"`
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
	buf, err := json.MarshalIndent(cfg, "", "    ")
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

	cfg.ImagePath = strings.TrimSpace(cfg.ImagePath)
	cfg.Partition = strings.TrimSpace(cfg.Partition)
	cfg.PEWIM = strings.TrimSpace(cfg.PEWIM)

	if cfg.Index == 0 {
		cfg.Index = -1
	}

	if err := cfg.Boot.normalize(); err != nil {
		return err
	}
	cfg.Unattended.normalize()
	cfg.BackupDriver.normalize()
	if err := cfg.Format.normalize(); err != nil {
		return err
	}

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

func (u *Unattended) normalize() {
	if u == nil {
		return
	}
	u.File = strings.TrimSpace(u.File)
	if u.File == "" || strings.EqualFold(u.File, Auto) {
		u.File = Auto
	}
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

func readSource(src string) (string, error) {
	src = strings.TrimSpace(src)
	if src == "" {
		return "", fmt.Errorf("empty install config source")
	}

	if filepath.IsAbs(src) {
		if data, err := os.ReadFile(src); err == nil {
			return string(data), nil
		}
	}

	return src, nil
}
