//go:build windows

package ui

import (
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
	Language string `json:"language"`
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
		i18nLanguage = resolveStartupLanguage(cfg.Language)

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
		{Value: manualBootRepairManualUEFI, Text: T("manual.boot.mode.uefi")},
		{Value: manualBootRepairManualBIOS, Text: T("manual.boot.mode.bios")},
		{Value: manualBootRepairSkip, Text: T("manual.boot.mode.skip")},
	}
}

func loadUIConfig() uiAppConfig {
	config := uiAppConfig{Language: autoLanguageCode}

	path, err := projectFilePath(uiConfigRelative)
	if err != nil {
		return config
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return config
	}

	_ = json.Unmarshal(data, &config)
	if strings.TrimSpace(config.Language) == "" {
		config.Language = autoLanguageCode
	}
	return config
}

func resolveStartupLanguage(configured string) string {
	language := normalizeLanguageCode(configured)
	if language != "" && language != autoLanguageCode {
		return language
	}

	systemLanguage := detectSystemLanguage()
	if systemLanguage == "" {
		return defaultLanguageCode
	}
	return systemLanguage
}

func normalizeLanguageCode(value string) string {
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
	path, err := projectFilePath(filepath.Join(langDirRelative, language+".json"))
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

func projectFilePath(relativePath string) (string, error) {
	candidates := make([]string, 0, 10)
	suffix := filepath.FromSlash(relativePath)

	if wd, err := os.Getwd(); err == nil && strings.TrimSpace(wd) != "" {
		candidates = appendSearchRoots(candidates, wd, suffix)
	}
	if exe, err := os.Executable(); err == nil && strings.TrimSpace(exe) != "" {
		candidates = appendSearchRoots(candidates, filepath.Dir(exe), suffix)
	}

	seen := map[string]struct{}{}
	for _, candidate := range candidates {
		candidate = filepath.Clean(candidate)
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("%w: %s", os.ErrNotExist, suffix)
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
