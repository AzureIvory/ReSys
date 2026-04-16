//go:build windows

package ui

import (
	"ReSys/src/utils"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/AzureIvory/winui/core"
	"github.com/AzureIvory/winui/widgets"
)

const (
	driverGUIDDocRelativePath = "docs/driver-guid.md"
	manualInstallExportName   = "manual.generated.json"
)

var (
	driverGUIDMatchExpr = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	driverGUIDExactExpr = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

type manualDriverGUIDOption struct {
	Name    string
	GUID    string
	CheckID string
}

func parseDriverGUID(markdown string) ([]manualDriverGUIDOption, error) {
	lines := strings.Split(markdown, "\n")
	items := make([]manualDriverGUIDOption, 0, len(lines))
	seen := map[string]struct{}{}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "|") {
			continue
		}

		cells := markdownCells(line)
		if len(cells) == 0 || isMarkdownSeparatorRow(cells) {
			continue
		}

		match := driverGUIDMatchExpr.FindString(line)
		guid, ok := normalizeDriverGUID(match)
		if !ok {
			continue
		}
		if _, exists := seen[guid]; exists {
			continue
		}

		name := strings.TrimSpace(cells[0])
		if name == "" && len(cells) > 1 {
			name = strings.TrimSpace(cells[1])
		}
		if name == "" {
			name = guid
		}

		seen[guid] = struct{}{}
		items = append(items, manualDriverGUIDOption{
			Name:    name,
			GUID:    guid,
			CheckID: driverGUIDCheckID(guid),
		})
	}

	if len(items) == 0 {
		return nil, fmt.Errorf("no valid driver GUID found in %s", driverGUIDDocRelativePath)
	}
	return items, nil
}

func parseDriverFilePatterns(raw string) []string {
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ',' || r == ';'
	})
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}

	for _, item := range parts {
		pattern := strings.ToLower(strings.TrimSpace(item))
		if pattern == "" {
			continue
		}
		if _, exists := seen[pattern]; exists {
			continue
		}
		seen[pattern] = struct{}{}
		out = append(out, pattern)
	}
	return out
}

func markdownCells(line string) []string {
	trimmed := strings.TrimSpace(line)
	trimmed = strings.TrimPrefix(trimmed, "|")
	trimmed = strings.TrimSuffix(trimmed, "|")
	if strings.TrimSpace(trimmed) == "" {
		return nil
	}

	parts := strings.Split(trimmed, "|")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		out = append(out, strings.TrimSpace(part))
	}
	return out
}

func isMarkdownSeparatorRow(cells []string) bool {
	if len(cells) == 0 {
		return true
	}
	for _, cell := range cells {
		if strings.Trim(cell, "-: ") != "" {
			return false
		}
	}
	return true
}

func normalizeDriverGUID(raw string) (string, bool) {
	text := strings.TrimSpace(strings.Trim(raw, "{}"))
	if !driverGUIDExactExpr.MatchString(text) {
		return "", false
	}
	return "{" + strings.ToUpper(text) + "}", true
}

func driverGUIDCheckID(guid string) string {
	replacer := strings.NewReplacer("{", "", "}", "", "-", "_")
	return "manual-driver-guid-" + strings.ToLower(replacer.Replace(guid))
}

func loadDriverGUIDOptions() ([]manualDriverGUIDOption, error) {
	path, err := utils.ProjectFile(driverGUIDDocRelativePath)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseDriverGUID(string(data))
}

func EnsureDriverDialogInit() {
	if manual.driverGUIDSelected == nil {
		manual.driverGUIDSelected = map[string]bool{}
	}
	if len(manual.driverGUIDOptions) == 0 {
		items, err := loadDriverGUIDOptions()
		if err != nil {
			if guid, ok := normalizeDriverGUID("88BAE032-5A81-49F0-BC3D-A4FF138216D6"); ok {
				items = []manualDriverGUIDOption{{
					Name:    "USBDevice",
					GUID:    guid,
					CheckID: driverGUIDCheckID(guid),
				}}
			}
		}
		manual.driverGUIDOptions = items
	}
	manualSetState("manual.driver.infPatterns", manual.driverINFPatterns)
	RenderDriverGUIDOptions()
	UpdateDriverDialogSummary()
}

func RenderDriverGUIDOptions() {
	if ui.window == nil {
		return
	}
	widget := ui.window.FindWidget("manual-driver-guid-list")
	panel, ok := widget.(*widgets.Panel)
	if !ok || panel == nil {
		return
	}

	for _, child := range panel.Children() {
		panel.Remove(child.ID())
	}

	for _, item := range manual.driverGUIDOptions {
		guid := item.GUID
		check := NewDriverGUIDCheckBox(item, manual.driverGUIDSelected[item.GUID], func(checked bool) {
			if manual.driverGUIDSelected == nil {
				manual.driverGUIDSelected = map[string]bool{}
			}
			if checked {
				manual.driverGUIDSelected[guid] = true
			} else {
				delete(manual.driverGUIDSelected, guid)
			}
			UpdateDriverDialogSummary()
		})
		panel.Add(check)
	}
}

func NewDriverGUIDCheckBox(
	item manualDriverGUIDOption,
	checked bool,
	onChange func(bool),
) *widgets.CheckBox {
	check := widgets.NewCheckBox(item.CheckID, item.Name, widgets.ModeCustom)
	check.SetStyle(widgets.ChoiceStyle{IndicatorStyle: widgets.ChoiceIndicatorCheck})
	widgets.SetPreferredSize(check, core.Size{Width: 0, Height: 28})
	check.SetChecked(checked)
	check.SetOnChange(onChange)
	return check
}

func HandleBackupDriversChange(checked bool) {
	manualSetState("manual.options.backupDrivers", checked)
	if checked {
		manualOpenDriverDialog()
	} else {
		manualSetState("manual.driver.visible", false)
	}
	manualUpdateSummary()
}

func manualOpenDriverDialog() {
	EnsureDriverDialogInit()
	manualSetState("manual.driver.visible", true)
}

func HandleDriverPatternChange(value string) {
	manual.driverINFPatterns = value
	manualSetState("manual.driver.infPatterns", value)
	UpdateDriverDialogSummary()
}

func HandleDriverDialogConfirm() {
	CloseDriverDialog()
}

func HandleDriverDialogCancel() {
	CloseDriverDialog()
}

func CloseDriverDialog() {
	manualSetState("manual.driver.visible", false)
	if !HasDriverSelection() {
		manualSetState("manual.options.backupDrivers", false)
	}
	manualUpdateSummary()
}

func SelectedDriverFileRules() []string {
	return parseDriverFilePatterns(manual.driverINFPatterns)
}

func SelectedDriverGUIDs() []string {
	if len(manual.driverGUIDOptions) == 0 || len(manual.driverGUIDSelected) == 0 {
		return []string{}
	}

	out := make([]string, 0, len(manual.driverGUIDSelected))
	for _, item := range manual.driverGUIDOptions {
		if manual.driverGUIDSelected[item.GUID] {
			out = append(out, item.GUID)
		}
	}
	return out
}

func HasDriverSelection() bool {
	return len(SelectedDriverFileRules()) > 0 || len(SelectedDriverGUIDs()) > 0
}

func UpdateDriverDialogSummary() {
	fileCount := len(SelectedDriverFileRules())
	guidCount := len(SelectedDriverGUIDs())
	summary := T("manual.driver.summary.empty")
	if fileCount > 0 || guidCount > 0 {
		summary = fmt.Sprintf(T("manual.driver.summary.selected"), fileCount, guidCount)
	}
	manualSetState("manual.driver.summary", summary)
}

func ExportInstallJSON(text string) (string, error) {
	dir, err := utils.ProjectDir("rules", "install")
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, manualInstallExportName)
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		return "", err
	}
	return path, nil
}
