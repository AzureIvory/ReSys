//go:build windows

package ui

import (
	"ReSys/src/config"
	"ReSys/src/utils"
	"ReSys/src/windows"
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

var (
	i18nInitOnce sync.Once
	i18nInitErr  error

	i18nLanguage            = config.DefaultUIBundleLanguage
	i18nTable               = map[string]any{}
	loadI18nAppConfig       = config.LoadAppConfig
	getPreferredUILanguages = windows.GetUserPreferredUILanguages
	detectLocaleLanguage    = detectLocaleLanguageFromSystem
	uiLanguageBundleExists  = func(language string) bool {
		_, err := readLanguageFile(language)
		return err == nil
	}

	kernel32DLL                  = syscall.NewLazyDLL("kernel32.dll")
	procGetUserDefaultLocaleName = kernel32DLL.NewProc("GetUserDefaultLocaleName")
)

// initI18n 在窗口初始化前加载语言配置与语言包。
func initI18n() error {
	i18nInitOnce.Do(func() {
		i18nLanguage = resolveStartupLanguage(configuredUILanguage())

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

func localizedTargetSystemItems() []widgets.ListItem {
	return []widgets.ListItem{
		// 说明：
		// - Text 仍然走现有 i18n（主要标题）。
		// - Subtitle 只需要给 “其他” 做多语言；win7/win10/win11 用固定短标识即可。
		// - ImagePath 走 JSONUI 的 AssetsDir（见 host.go 的 ensureUIAssets 写盘资源）。
		{Value: targetWin7, Text: T("manual.system.option.win7"), Subtitle: "win7", ImagePath: "win7.png"},
		{Value: targetWin10, Text: T("manual.system.option.win10"), Subtitle: "win10", ImagePath: "win10.png"},
		{Value: targetWin11, Text: T("manual.system.option.win11"), Subtitle: "win11", ImagePath: "win11.png"},
		{Value: targetOther, Text: T("manual.system.option.other"), Subtitle: T("manual.system.subtitle.other"), ImagePath: "icon.png"},
	}
}

// configuredUILanguage 返回 app 配置里的 UI 语言，失败时回退到配置默认值。
func configuredUILanguage() string {
	def := config.DefaultAppUILanguage
	cfg, err := loadI18nAppConfig()
	if err != nil {
		return def
	}
	if value := strings.TrimSpace(cfg.Language.UILanguage); value != "" {
		return value
	}
	return def
}

func resolveStartupLanguage(configured string) string {
	language := normLangCode(configured)
	if language != "" && language != config.DefaultAppUILanguage {
		return language
	}

	if langs, err := getPreferredUILanguages(); err == nil {
		seen := map[string]struct{}{}
		for _, lang := range langs {
			normalized := normLangCode(lang)
			if normalized == "" {
				continue
			}
			if _, ok := seen[normalized]; ok {
				continue
			}
			seen[normalized] = struct{}{}
			if uiLanguageBundleExists(normalized) {
				return normalized
			}
		}
	}

	localeLanguage := normLangCode(detectLocaleLanguage())
	if localeLanguage != "" && uiLanguageBundleExists(localeLanguage) {
		return localeLanguage
	}

	return config.DefaultUIBundleLanguage
}

func normLangCode(value string) string {
	text := strings.TrimSpace(strings.ReplaceAll(value, "-", "_"))
	if text == "" {
		return ""
	}

	switch strings.ToLower(text) {
	case "auto":
		return config.DefaultAppUILanguage
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

func detectLocaleLanguageFromSystem() string {
	const localeNameMax = 85

	buf := make([]uint16, localeNameMax)
	ret, _, _ := procGetUserDefaultLocaleName.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if ret == 0 {
		return config.DefaultUIBundleLanguage
	}

	localeName := syscall.UTF16ToString(buf)
	if localeName == "" {
		return config.DefaultUIBundleLanguage
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
	base, err := readLanguageFile(config.DefaultUIBundleLanguage)
	if err != nil {
		return nil, err
	}

	if language == "" || language == config.DefaultUIBundleLanguage {
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
	path, err := utils.ProjectFile(filepath.Join(config.DefaultLanguageDirRelative, language+".json"))
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

// availableLanguages 枚举 rules/lang 内的 JSON 文件，返回组合框用的语言列表。
func availableLanguages() []widgets.ListItem {
	dir, err := utils.ProjectDir("rules", "lang")
	if err != nil {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	items := make([]widgets.ListItem, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		code := strings.TrimSuffix(name, ".json")
		items = append(items, widgets.ListItem{Value: code, Text: code})
	}
	return items
}

// setUILanguage 切换 UI 语言：重新加载语言包并刷新界面文本。
func setUILanguage(language string) error {
	prevPromptTitle := T("prompt.title")
	prevDialogPrompt := T("dialog.prompt")
	prevPreparing := T("progress.preparing")
	prevPreparingInstall := T("progress.preparingInstall")

	table, err := loadLanguageTable(language)
	if err != nil {
		return err
	}
	i18nLanguage = language
	i18nTable = table
	refreshLocalizedRuntimeState(language, prevPromptTitle, prevDialogPrompt, prevPreparing, prevPreparingInstall)
	return nil
}

// refreshLocalizedRuntimeState 在切换语言后重建依赖文本缓存的 UI 状态。
// 这一步不能只更新 i18n 树，因为部分控件的 placeholder、组合框选项和摘要文案
// 是以普通 store 字段或 Go 缓存形式保存的，需要一起重算。
func refreshLocalizedRuntimeState(
	language string,
	prevPromptTitle string,
	prevDialogPrompt string,
	prevPreparing string,
	prevPreparingInstall string,
) {
	if ui.store == nil {
		return
	}

	patch := map[string]any{
		"i18n":                                      i18nSnapshot(),
		"window.title":                              T("window.title"),
		"manual.language.selected":                  language,
		"manual.language.items":                     availableLanguages(),
		"manual.image.placeholder":                  T("manual.image.placeholder"),
		"manual.image.indexPlaceholder":             localizedImageIndexPlaceholder(),
		"manual.system.items":                       localizedTargetSystemItems(),
		"manual.boot.modeItems":                     localizedBootModeItems(),
		"manual.partitions.loadingText":             T("manual.loading.disks"),
		"manual.postprocess.files.form.launchItems": postProcessLaunchItems(),
		"prompt.title":                              T("prompt.title"),
		"msgbox.okText":                             T("common.ok"),
		"msgbox.cancelText":                         T("common.cancel"),
		"msgbox.yesText":                            T("common.yes"),
		"msgbox.noText":                             T("common.no"),
		"msgbox.retryText":                          T("common.retry"),
	}

	if current := manualStoreString("progress.status", ""); current == prevPreparing {
		patch["progress.status"] = T("progress.preparing")
	} else if current == prevPreparingInstall {
		patch["progress.status"] = T("progress.preparingInstall")
	}

	if current := manualStoreString("msgbox.title", ""); current == prevDialogPrompt || current == prevPromptTitle {
		patch["msgbox.title"] = T("dialog.prompt")
	}

	manualPatchState(patch)
	if ui.app != nil {
		ui.app.SetTitle(T("window.title"))
	}

	relocalizeDriverGUIDOptions()
	manualSyncPostProcessStore()
	RefreshBootTargets()
	manualUpdatePEInputState()
	manualUpdateDetail()
	UpdateDriverDialogSummary()
	manualUpdateSummary()
}

func localizedImageIndexPlaceholder() string {
	switch {
	case strings.TrimSpace(manual.imagePath) == "":
		return T("manual.image.indexPlaceholder")
	case manual.imageParseErr != "":
		return T("manual.image.parseFailedShort")
	case len(manual.imageInfos) == 0:
		return T("manual.image.noIndex")
	default:
		return T("manual.image.selectIndex")
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
