//go:build windows

package ui

import (
	"ReSys/src/utils"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/AzureIvory/winui/widgets"
)

const (
	defaultLanguageCode = "zh_CN"
	autoLanguageCode    = "auto"
	uiConfigRelative    = "rules/config/app.json"
	langDirRelative     = "rules/lang"
)

type uiAppConfig struct {
	Language uiLanguageConfig `json:"language"`
}

type uiLanguageConfig struct {
	UILanguage string `json:"ui_language"`
}

// UnmarshalJSON 兼容旧版 `"language":"en_US"` 和新版对象结构。
func (c *uiLanguageConfig) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return nil
	}

	var legacy string
	if err := json.Unmarshal(data, &legacy); err == nil {
		c.UILanguage = legacy
		return nil
	}

	type raw uiLanguageConfig
	var decoded raw
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*c = uiLanguageConfig(decoded)
	return nil
}

var (
	i18nInitOnce sync.Once
	i18nInitErr  error

	i18nLanguage = defaultLanguageCode
	i18nTable    = map[string]any{}

	kernel32DLL                  = syscall.NewLazyDLL("kernel32.dll")
	procGetUserDefaultLocaleName = kernel32DLL.NewProc("GetUserDefaultLocaleName")
)

// initI18n 在窗口初始化前加载语言配置与语言包。
func initI18n() error {
	i18nInitOnce.Do(func() {
		cfg := loadUIConfig()
		i18nLanguage = resolveStartupLanguage(cfg.Language.UILanguage)

		table, err := loadLanguageTable(i18nLanguage)
		if err != nil {
			i18nInitErr = err
			return
		}
		i18nTable = table
	})
	return i18nInitErr
}

// Tr 提供给 ui 包外部调用的本地化文本读取函数。
func Tr(key string) string {
	return T(key)
}

// Trf 读取本地化格式串并执行 Sprintf。
func Trf(key string, args ...any) string {
	return fmt.Sprintf(T(key), args...)
}

// T 读取 ui 包内部使用的本地化文本。
func T(key string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return ""
	}

	current := any(i18nTable)
	for _, segment := range strings.Split(key, ".") {
		node, ok := current.(map[string]any)
		if !ok {
			return key
		}
		current, ok = node[segment]
		if !ok {
			return key
		}
	}

	text, ok := current.(string)
	if !ok || strings.TrimSpace(text) == "" {
		return key
	}
	return text
}

func i18nSnapshot() map[string]any {
	return cloneMap(i18nTable)
}

func localizedBootModeItems() []widgets.ListItem {
	return []widgets.ListItem{
		{Value: manualBootRepairAuto, Text: T("manual.boot.mode.auto")},
		{Value: manualBootRepairUEFI, Text: T("manual.boot.mode.uefi")},
		{Value: manualBootRepairBIOS, Text: T("manual.boot.mode.bios")},
		{Value: manualBootRepairSkip, Text: T("manual.boot.mode.skip")},
	}
}

func loadUIConfig() uiAppConfig {
	config := uiAppConfig{}
	config.Language.UILanguage = autoLanguageCode

	path, err := utils.ProjectFile(uiConfigRelative)
	if err != nil {
		return config
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return config
	}

	return parseUIConfig(data)
}

func parseUIConfig(data []byte) uiAppConfig {
	config := uiAppConfig{}
	config.Language.UILanguage = autoLanguageCode
	_ = json.Unmarshal(data, &config)
	if strings.TrimSpace(config.Language.UILanguage) == "" {
		config.Language.UILanguage = autoLanguageCode
	}
	return config
}

func resolveStartupLanguage(configured string) string {
	language := normLangCode(configured)
	if language != "" && language != autoLanguageCode {
		return language
	}

	systemLanguage := detectSystemLanguage()
	if systemLanguage == "" {
		return defaultLanguageCode
	}
	return systemLanguage
}

func normLangCode(value string) string {
	text := strings.TrimSpace(strings.ReplaceAll(value, "-", "_"))
	if text == "" {
		return ""
	}

	switch strings.ToLower(text) {
	case "auto":
		return autoLanguageCode
	case "zh_cn", "zh_hans", "zh_hans_cn", "zh":
		return "zh_CN"
	case "zh_tw", "zh_hk", "zh_mo", "zh_hant", "zh_hant_tw", "zh_hant_hk":
		return "zh_TW"
	case "en", "en_us":
		return "en_US"
	default:
		return ""
	}
}

func detectSystemLanguage() string {
	const localeNameMax = 85

	buf := make([]uint16, localeNameMax)
	ret, _, _ := procGetUserDefaultLocaleName.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if ret == 0 {
		return defaultLanguageCode
	}

	localeName := syscall.UTF16ToString(buf)
	if localeName == "" {
		return defaultLanguageCode
	}

	language := strings.ToLower(localeName)
	switch {
	case strings.HasPrefix(language, "zh-tw"),
		strings.HasPrefix(language, "zh-hk"),
		strings.HasPrefix(language, "zh-mo"),
		strings.Contains(language, "hant"):
		return "zh_TW"
	case strings.HasPrefix(language, "zh"):
		return "zh_CN"
	default:
		return "en_US"
	}
}

func loadLanguageTable(language string) (map[string]any, error) {
	base, err := readLanguageFile(defaultLanguageCode)
	if err != nil {
		return nil, err
	}

	if language == "" || language == defaultLanguageCode {
		return base, nil
	}

	override, err := readLanguageFile(language)
	if err != nil {
		return base, nil
	}
	mergeMaps(base, override)
	return base, nil
}

func readLanguageFile(language string) (map[string]any, error) {
	path, err := utils.ProjectFile(filepath.Join(langDirRelative, language+".json"))
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	table := map[string]any{}
	if err := json.Unmarshal(data, &table); err != nil {
		return nil, err
	}
	return table, nil
}

func mergeMaps(base, override map[string]any) {
	for key, value := range override {
		overrideMap, ok := value.(map[string]any)
		if !ok {
			base[key] = value
			continue
		}

		baseMap, ok := base[key].(map[string]any)
		if !ok {
			base[key] = cloneMap(overrideMap)
			continue
		}
		mergeMaps(baseMap, overrideMap)
	}
}

func cloneMap(source map[string]any) map[string]any {
	if len(source) == 0 {
		return map[string]any{}
	}

	cloned := make(map[string]any, len(source))
	for key, value := range source {
		switch typed := value.(type) {
		case map[string]any:
			cloned[key] = cloneMap(typed)
		case []any:
			cloned[key] = append([]any(nil), typed...)
		default:
			cloned[key] = typed
		}
	}
	return cloned
}
