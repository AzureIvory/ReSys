//go:build windows

package ui

import (
	driversvc "ReSys/src/driver"
	"ReSys/src/utils"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/AzureIvory/winui/core"
	"github.com/AzureIvory/winui/widgets"
)

const manualInstallExportName = "manual.generated.json"

type manualDriverGUIDOption struct {
	Name    string
	GUID    string
	CheckID string
	Enabled bool
}

func driverGUIDCheckID(guid string) string {
	replacer := strings.NewReplacer("{", "", "}", "", "-", "_")
	return "manual-driver-guid-" + strings.ToLower(replacer.Replace(guid))
}

func EnsureDriverDialogInit() {
	if manual.driverGUIDSelected == nil {
		manual.driverGUIDSelected = map[string]bool{}
	}
	if len(manual.driverGUIDOptions) == 0 {
		items, err := loadDriverGUIDOptions()
		if err == nil {
			manual.driverGUIDOptions = items
		}
	}
	manualDropDisabledDriverGUIDSelections()
	manualSetState("manual.driver.infPatterns", manual.driverINFPatterns)
	RenderDriverGUIDOptions()
	UpdateDriverDialogSummary()
}

func RenderDriverGUIDOptions() {
	if ui.window == nil {
		return
	}
	widget := ui.window.FindWidget("manual-driver-guid-scroll")
	scroll, ok := widget.(*widgets.ScrollView)
	if !ok || scroll == nil {
		return
	}

	panel := widgets.NewPanel("manual-driver-guid-list")
	panel.SetLayout(widgets.ColumnLayout{
		Gap:        6,
		Padding:    widgets.UniformInsets(8),
		CrossAlign: widgets.AlignStretch,
	})

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
	scroll.SetContent(panel)
}

func NewDriverGUIDCheckBox(
	item manualDriverGUIDOption,
	checked bool,
	onChange func(bool),
) *widgets.CheckBox {
	check := widgets.NewCheckBox(item.CheckID, item.Name, widgets.ModeCustom)
	check.SetStyle(widgets.ChoiceStyle{IndicatorStyle: widgets.ChoiceIndicatorCheck})
	widgets.SetPreferredSize(check, core.Size{Width: 500, Height: 28})
	check.SetLayoutData(widgets.FlexLayoutData{Align: widgets.AlignStretch})
	check.SetChecked(item.Enabled && checked)
	check.SetEnabled(item.Enabled)
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
	return driversvc.ParseFilePatterns(manual.driverINFPatterns)
}

func SelectedDriverGUIDs() []string {
	if len(manual.driverGUIDOptions) == 0 || len(manual.driverGUIDSelected) == 0 {
		return []string{}
	}

	out := make([]string, 0, len(manual.driverGUIDSelected))
	for _, item := range manual.driverGUIDOptions {
		if item.Enabled && manual.driverGUIDSelected[item.GUID] {
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

func manualDropDisabledDriverGUIDSelections() {
	if len(manual.driverGUIDOptions) == 0 || len(manual.driverGUIDSelected) == 0 {
		return
	}

	enabled := make(map[string]struct{}, len(manual.driverGUIDOptions))
	for _, item := range manual.driverGUIDOptions {
		if item.Enabled {
			enabled[item.GUID] = struct{}{}
		}
	}
	for guid := range manual.driverGUIDSelected {
		if _, ok := enabled[guid]; !ok {
			delete(manual.driverGUIDSelected, guid)
		}
	}
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
