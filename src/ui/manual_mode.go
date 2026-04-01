//go:build windows

package ui

import (
	"ReSys/res"
	bl "ReSys/src/bitlocker"
	"ReSys/src/disk"
	"ReSys/src/dism"
	imgsvc "ReSys/src/image"
	"ReSys/src/utils"
	winos "ReSys/src/windows"
	"fmt"
	"sort"
	"strings"

	"github.com/AzureIvory/winui/core"
	"github.com/AzureIvory/winui/widgets"
)

var StartManualInstall = func(cfg ManualInstallConfig) {}

type ManualInstallConfig struct {
	TargetOS      string
	ImageArch     string
	ImagePath     string
	ImageIndex    int
	TargetRoot    string
	AutoPE        bool
	ManualPEWIM   string
	FormatTarget  bool
	AutoReboot    bool
	BootRepair    string
	BootTargetRef string
	AutoDeploy    bool
}

type manualUIState struct {
	panel           *widgets.Panel
	titleLabel      *widgets.Label
	imageLabel      *widgets.Label
	indexLabel      *widgets.Label
	targetLabel     *widgets.Label
	detailTitle     *widgets.Label
	summaryLabel    *widgets.Label
	bootRepairLabel *widgets.Label

	detailPanel *widgets.Panel
	detailLabel *widgets.Label

	loadingPanel *widgets.Panel
	loadingImage *widgets.AnimatedImage
	loadingLabel *widgets.Label

	backBtn        *widgets.Button
	imageEdit      *widgets.EditBox
	imageBrowseBtn *widgets.Button
	indexCombo     *widgets.ComboBox
	partitionList  *widgets.ListBox

	autoPECheck *widgets.CheckBox
	peEdit      *widgets.EditBox
	peBrowseBtn *widgets.Button

	bootModeCombo   *widgets.ComboBox
	bootTargetCombo *widgets.ComboBox

	formatCheck     *widgets.CheckBox
	deployCheck     *widgets.CheckBox
	autoRebootCheck *widgets.CheckBox
	startBtn        *widgets.Button

	imagePath      string
	imageInfos     []dism.ImageMeta
	imageParseErr  string
	partitionRows  []manualPartitionRow
	bootRows       []manualPartitionRow
	partitionError string
	bootTargets    []manualBootTargetOption

	partitionLoading bool
	partitionLoadID  uint64
}

type manualPartitionRow struct {
	DiskNumber       int
	PartitionNumber  int
	PartitionType    string
	DiskStyle        string
	DiskKind         string
	FileSystem       string
	VolumeLabel      string
	VolumeGuidPath   string
	DriveLetter      string
	TargetRoot       string
	SizeBytes        uint64
	FreeBytes        uint64
	BitLocker        string
	TargetSelectable bool
	CurrentSystem    bool
	Ref              string
	Summary          string
	Detail           string
}

type manualBootTargetOption struct {
	Ref  string
	Text string
}

const (
	manualBootRepairAuto       = "auto"
	manualBootRepairSkip       = "skip"
	manualBootRepairLegacy     = "manual"
	manualBootRepairManualUEFI = "manual_uefi"
	manualBootRepairManualBIOS = "manual_bios"
)

var manual manualUIState

func initManualMode(theme *widgets.Theme, root *widgets.Panel) {
	if theme == nil || root == nil {
		return
	}

	manual.panel = widgets.NewPanel("manual-mode")
	manual.panel.SetVisible(false)

	manual.titleLabel = widgets.NewLabel("manual-title", "手动重装")
	manual.titleLabel.SetStyle(widgets.TextStyle{
		Font: widgets.FontSpec{
			Face:   "Microsoft YaHei UI",
			SizeDP: 18,
			Weight: 700,
		},
		Color:  core.RGB(15, 23, 42),
		Format: core.DTVCenter | core.DTSingleLine,
	})

	labelStyle := widgets.TextStyle{
		Font: widgets.FontSpec{
			Face:   "Microsoft YaHei UI",
			SizeDP: 13,
			Weight: 700,
		},
		Color:  core.RGB(51, 65, 85),
		Format: core.DTVCenter | core.DTSingleLine,
	}
	summaryStyle := widgets.TextStyle{
		Font: widgets.FontSpec{
			Face:   "Microsoft YaHei UI",
			SizeDP: 12,
		},
		Color:  core.RGB(71, 85, 105),
		Format: core.DTVCenter | core.DTSingleLine | core.DTEndEllipsis,
	}
	detailStyle := widgets.TextStyle{
		Font: widgets.FontSpec{
			Face:   "Microsoft YaHei UI",
			SizeDP: 12,
		},
		Color:  core.RGB(30, 41, 59),
		Format: 0x00000010,
	}
	loadingStyle := widgets.TextStyle{
		Font: widgets.FontSpec{
			Face:   "Microsoft YaHei UI",
			SizeDP: 12,
			Weight: 700,
		},
		Color:  core.RGB(71, 85, 105),
		Format: core.DTCenter | core.DTVCenter | core.DTSingleLine,
	}

	listStyle := theme.ListBox
	listStyle.Font = widgets.FontSpec{Face: "Microsoft YaHei UI", SizeDP: 12}
	listStyle.ItemHeightDP = 28
	listStyle.PaddingDP = 6
	listStyle.CornerRadius = 10
	listStyle.BorderColor = core.RGB(203, 213, 225)
	listStyle.HoverBorder = core.RGB(59, 130, 246)
	listStyle.FocusBorder = core.RGB(37, 99, 235)
	listStyle.ItemSelectedColor = core.RGB(37, 99, 235)
	listStyle.ItemTextColor = core.RGB(255, 255, 255)

	comboStyle := theme.ComboBox
	comboStyle.Font = widgets.FontSpec{Face: "Microsoft YaHei UI", SizeDP: 12}
	comboStyle.PaddingDP = 8
	comboStyle.CornerRadius = 10
	comboStyle.MaxVisibleItems = 8
	comboStyle.BorderColor = core.RGB(203, 213, 225)
	comboStyle.HoverBorder = core.RGB(59, 130, 246)
	comboStyle.FocusBorder = core.RGB(37, 99, 235)
	comboStyle.ItemSelectedColor = core.RGB(37, 99, 235)
	comboStyle.ItemTextColor = core.RGB(255, 255, 255)

	editStyle := theme.Edit
	editStyle.Font = widgets.FontSpec{Face: "Microsoft YaHei UI", SizeDP: 12}
	editStyle.PaddingDP = 8
	editStyle.CornerRadius = 10
	editStyle.BorderColor = core.RGB(203, 213, 225)
	editStyle.HoverBorder = core.RGB(59, 130, 246)
	editStyle.FocusBorder = core.RGB(37, 99, 235)
	editStyle.DisabledBg = core.RGB(248, 250, 252)

	checkStyle := theme.CheckBox
	checkStyle.Font = widgets.FontSpec{Face: "Microsoft YaHei UI", SizeDP: 12}
	checkStyle.IndicatorSizeDP = 16
	checkStyle.IndicatorGapDP = 8

	manual.backBtn = widgets.NewButton("manual-back", "返回", widgets.ModeCustom)
	manual.backBtn.SetStyle(secondaryButtonStyle())
	manual.backBtn.SetOnClick(func() {
		applyMode(modeSelect)
	})

	manual.imageLabel = widgets.NewLabel("manual-image-label", "镜像")
	manual.imageLabel.SetStyle(labelStyle)
	manual.indexLabel = widgets.NewLabel("manual-index-label", "索引")
	manual.indexLabel.SetStyle(labelStyle)
	manual.targetLabel = widgets.NewLabel("manual-target-label", "安装分区")
	manual.targetLabel.SetStyle(labelStyle)
	manual.detailTitle = widgets.NewLabel("manual-detail-title", "分区详情")
	manual.detailTitle.SetStyle(labelStyle)
	manual.summaryLabel = widgets.NewLabel("manual-summary", "请选择本地安装镜像和目标分区。")
	manual.summaryLabel.SetStyle(summaryStyle)

	manual.imageEdit = widgets.NewEditBox("manual-image-edit", widgets.ModeCustom)
	manual.imageEdit.SetStyle(editStyle)
	manual.imageEdit.SetReadOnly(true)
	manual.imageEdit.SetPlaceholder("选择本地 ISO / WIM / ESD 镜像")

	manual.imageBrowseBtn = widgets.NewButton("manual-image-browse", "浏览", widgets.ModeCustom)
	manual.imageBrowseBtn.SetStyle(secondaryButtonStyle())
	manual.imageBrowseBtn.SetOnClick(func() {
		path, err := openImageFileDialog(manual.imagePath)
		if err != nil {
			UiShowError("错误", err.Error())
			return
		}
		if strings.TrimSpace(path) == "" {
			return
		}
		manualLoadImage(path)
	})

	manual.indexCombo = widgets.NewComboBox("manual-index-combo", widgets.ModeCustom)
	manual.indexCombo.SetStyle(comboStyle)
	manual.indexCombo.SetPlaceholder("先选择镜像")
	manual.indexCombo.SetOnChange(func(_ int, _ widgets.ListItem) {
		manualRefreshBootTargets()
		manualUpdateDetail()
		manualUpdateSummary()
	})

	manual.partitionList = widgets.NewListBox("manual-partition-list")
	manual.partitionList.SetStyle(listStyle)
	manual.partitionList.SetOnChange(func(index int, _ widgets.ListItem) {
		manualApplyPartitionSelection(index)
	})

	manual.loadingPanel = widgets.NewPanel("manual-loading-panel")
	manual.loadingPanel.SetVisible(false)
	manual.loadingPanel.SetStyle(widgets.PanelStyle{
		Background:   core.RGB(255, 255, 255),
		BorderColor:  core.RGB(203, 213, 225),
		CornerRadius: 12,
		BorderWidth:  1,
	})

	manual.loadingImage = widgets.NewAnimatedImage("manual-loading-image")
	manual.loadingImage.SetScaleMode(widgets.ImageScaleContain)
	manual.loadingImage.SetVisible(false)
	_ = manual.loadingImage.LoadGIF(res.WaitGIF)
	manual.loadingPanel.Add(manual.loadingImage)

	manual.loadingLabel = widgets.NewLabel("manual-loading-label", "正在检测硬盘中...")
	manual.loadingLabel.SetStyle(loadingStyle)
	manual.loadingLabel.SetVisible(false)
	manual.loadingPanel.Add(manual.loadingLabel)

	manual.detailPanel = widgets.NewPanel("manual-detail-panel")
	manual.detailPanel.SetStyle(widgets.PanelStyle{
		Background:   core.RGB(255, 255, 255),
		BorderColor:  core.RGB(203, 213, 225),
		CornerRadius: 12,
		BorderWidth:  1,
	})

	manual.detailLabel = widgets.NewLabel("manual-detail-label", "请选择一个分区查看详情。")
	manual.detailLabel.SetStyle(detailStyle)
	manual.detailPanel.Add(manual.detailLabel)

	manual.autoPECheck = widgets.NewCheckBox("manual-auto-pe", "自动处理 PE", widgets.ModeCustom)
	manual.autoPECheck.SetStyle(checkStyle)
	manual.autoPECheck.SetChecked(true)
	manual.autoPECheck.SetOnChange(func(bool) {
		manualUpdatePEInputState()
		manualUpdateSummary()
	})

	manual.peEdit = widgets.NewEditBox("manual-pe-edit", widgets.ModeCustom)
	manual.peEdit.SetStyle(editStyle)
	manual.peEdit.SetPlaceholder("自动处理 PE 关闭后，可手动指定 PE WIM")
	manual.peEdit.SetOnChange(func(string) {
		manualUpdateSummary()
	})

	manual.peBrowseBtn = widgets.NewButton("manual-pe-browse", "浏览", widgets.ModeCustom)
	manual.peBrowseBtn.SetStyle(secondaryButtonStyle())
	manual.peBrowseBtn.SetOnClick(func() {
		path, err := openPEFileDialog(manual.peEdit.TextValue())
		if err != nil {
			UiShowError("错误", err.Error())
			return
		}
		if strings.TrimSpace(path) == "" {
			return
		}
		manual.peEdit.SetText(path)
		manualUpdateSummary()
	})

	manual.bootRepairLabel = widgets.NewLabel("manual-boot-repair-label", "修复引导")
	manual.bootRepairLabel.SetStyle(labelStyle)

	manual.bootModeCombo = widgets.NewComboBox("manual-boot-mode", widgets.ModeCustom)
	manual.bootModeCombo.SetStyle(comboStyle)
	manual.bootModeCombo.SetItems([]widgets.ListItem{
		{Value: "auto", Text: "自动修复"},
		{Value: "skip", Text: "不修复"},
		{Value: "manual", Text: "手动指定"},
	})
	manual.bootModeCombo.SetSelected(0)
	manual.bootModeCombo.SetOnChange(func(_ int, _ widgets.ListItem) {
		manualUpdateBootTargetState()
		manualUpdateSummary()
	})
	manual.bootModeCombo.SetItems([]widgets.ListItem{
		{Value: manualBootRepairAuto, Text: "自动修复"},
		{Value: manualBootRepairSkip, Text: "不修复"},
		{Value: manualBootRepairManualUEFI, Text: "手动修复 UEFI"},
		{Value: manualBootRepairManualBIOS, Text: "手动修复 BIOS"},
	})
	manual.bootModeCombo.SetSelected(0)
	manual.bootModeCombo.SetOnChange(func(_ int, _ widgets.ListItem) {
		manualRefreshBootTargets()
		manualUpdateSummary()
	})
	manual.bootModeCombo.SetItems([]widgets.ListItem{
		{Value: manualBootRepairAuto, Text: "自动"},
		{Value: manualBootRepairManualUEFI, Text: "UEFI"},
		{Value: manualBootRepairManualBIOS, Text: "BIOS"},
		{Value: manualBootRepairSkip, Text: "不修复"},
	})
	manual.bootModeCombo.SetSelected(0)
	manual.bootModeCombo.SetOnChange(func(_ int, _ widgets.ListItem) {
		manualRefreshBootTargets()
		manualUpdateSummary()
	})

	manual.bootTargetCombo = widgets.NewComboBox("manual-boot-target", widgets.ModeCustom)
	manual.bootTargetCombo.SetStyle(comboStyle)
	manual.bootTargetCombo.SetPlaceholder("引导分区将随目标分区更新")
	manual.bootTargetCombo.SetOnChange(func(_ int, _ widgets.ListItem) {
		manualUpdateSummary()
	})

	manual.formatCheck = widgets.NewCheckBox("manual-format", "格式化目标分区", widgets.ModeCustom)
	manual.formatCheck.SetStyle(checkStyle)
	manual.formatCheck.SetChecked(true)
	manual.formatCheck.SetOnChange(func(bool) {
		manualUpdateSummary()
	})

	manual.deployCheck = widgets.NewCheckBox("manual-deploy", "安装后自动部署", widgets.ModeCustom)
	manual.deployCheck.SetStyle(checkStyle)
	manual.deployCheck.SetChecked(true)
	manual.deployCheck.SetOnChange(func(bool) {
		manualUpdateSummary()
	})

	manual.autoRebootCheck = widgets.NewCheckBox("manual-auto-reboot", "自动重启", widgets.ModeCustom)
	manual.autoRebootCheck.SetStyle(checkStyle)
	manual.autoRebootCheck.SetChecked(true)
	manual.autoRebootCheck.SetOnChange(func(bool) {
		manualUpdateSummary()
	})

	manual.startBtn = widgets.NewButton("manual-start", "开始重装", widgets.ModeCustom)
	manual.startBtn.SetStyle(dialogPrimaryButtonStyle())
	manual.startBtn.SetOnClick(func() {
		cfg, err := manualBuildConfig()
		if err != nil {
			UiShowError("错误", err.Error())
			return
		}
		if !Message("提示", "手动重装将按当前选项覆盖目标分区，是否继续？") {
			return
		}
		applyMode(modeProgress)
		go StartManualInstall(cfg)
	})

	manual.panel.AddAll(
		manual.backBtn,
		manual.titleLabel,
		manual.imageLabel,
		manual.indexLabel,
		manual.targetLabel,
		manual.detailTitle,
		manual.bootRepairLabel,
		manual.summaryLabel,
		manual.imageEdit,
		manual.imageBrowseBtn,
		manual.indexCombo,
		manual.partitionList,
		manual.loadingPanel,
		manual.detailPanel,
		manual.autoPECheck,
		manual.peEdit,
		manual.peBrowseBtn,
		manual.bootModeCombo,
		manual.bootTargetCombo,
		manual.formatCheck,
		manual.deployCheck,
		manual.autoRebootCheck,
		manual.startBtn,
	)
	root.Add(manual.panel)

	manualUpdatePEInputState()
	manualUpdateBootTargetState()
	manualUpdateSummary()
}

func destroyManualMode() {
	if manual.loadingImage != nil {
		_ = manual.loadingImage.Close()
	}
	manual = manualUIState{}
}

func UiShowManualMode() {
	if ui.app == nil {
		return
	}
	_ = ui.app.Post(func() {
		applyMode(modeManual)
		manualRefreshPartitionsAsync()
	})
}

func manualSetVisible(visible bool) {
	if manual.panel == nil {
		return
	}
	manual.panel.SetVisible(visible)
}

func layoutManual(w, h int32) {
	if manual.panel == nil || ui.app == nil {
		return
	}

	margin := ui.app.DP(14)
	gap := ui.app.DP(12)
	rowH := ui.app.DP(28)
	headerH := ui.app.DP(30)
	labelW := ui.app.DP(42)
	browseW := ui.app.DP(70)
	leftW := ui.app.DP(274)
	rightX := margin + leftW + gap
	rightW := w - rightX - margin
	detailH := ui.app.DP(104)
	bottomY := h - margin - rowH

	manual.panel.SetBounds(core.Rect{X: 0, Y: 0, W: w, H: h})

	manual.backBtn.SetBounds(core.Rect{X: margin, Y: margin, W: ui.app.DP(70), H: headerH})
	manual.titleLabel.SetBounds(core.Rect{
		X: margin + ui.app.DP(82),
		Y: margin,
		W: w - margin*2 - ui.app.DP(82),
		H: headerH,
	})

	y := margin + headerH + ui.app.DP(8)

	manual.imageLabel.SetBounds(core.Rect{X: margin, Y: y, W: labelW, H: rowH})
	manual.imageEdit.SetBounds(core.Rect{
		X: margin + labelW + ui.app.DP(6),
		Y: y,
		W: w - margin*2 - labelW - ui.app.DP(6) - browseW - ui.app.DP(6),
		H: rowH,
	})
	manual.imageBrowseBtn.SetBounds(core.Rect{X: w - margin - browseW, Y: y, W: browseW, H: rowH})

	y += rowH + ui.app.DP(6)

	manual.indexLabel.SetBounds(core.Rect{X: margin, Y: y, W: labelW, H: rowH})
	manual.indexCombo.SetBounds(core.Rect{
		X: margin + labelW + ui.app.DP(6),
		Y: y,
		W: ui.app.DP(250),
		H: rowH,
	})
	manual.summaryLabel.SetBounds(core.Rect{
		X: margin + labelW + ui.app.DP(266),
		Y: y,
		W: w - margin*2 - labelW - ui.app.DP(266),
		H: rowH,
	})

	y += rowH + ui.app.DP(6)

	manual.targetLabel.SetBounds(core.Rect{X: margin, Y: y, W: leftW, H: ui.app.DP(20)})
	manual.detailTitle.SetBounds(core.Rect{X: rightX, Y: y, W: rightW, H: ui.app.DP(20)})

	y += ui.app.DP(22)

	listH := bottomY - y - ui.app.DP(10)
	if listH < ui.app.DP(160) {
		listH = ui.app.DP(160)
	}
	manual.partitionList.SetBounds(core.Rect{X: margin, Y: y, W: leftW, H: listH})
	manual.loadingPanel.SetBounds(core.Rect{X: margin, Y: y, W: leftW, H: listH})
	loadingImageSize := ui.app.DP(68)
	loadingImageY := y + (listH-ui.app.DP(84))/2
	if loadingImageY < y+ui.app.DP(24) {
		loadingImageY = y + ui.app.DP(24)
	}
	manual.loadingImage.SetBounds(core.Rect{
		X: margin + (leftW-loadingImageSize)/2,
		Y: loadingImageY,
		W: loadingImageSize,
		H: loadingImageSize,
	})
	manual.loadingLabel.SetBounds(core.Rect{
		X: margin + ui.app.DP(12),
		Y: loadingImageY + loadingImageSize + ui.app.DP(8),
		W: leftW - ui.app.DP(24),
		H: rowH,
	})
	manual.detailPanel.SetBounds(core.Rect{X: rightX, Y: y, W: rightW, H: detailH})
	manual.detailLabel.SetBounds(core.Rect{
		X: rightX + ui.app.DP(10),
		Y: y + ui.app.DP(10),
		W: rightW - ui.app.DP(20),
		H: detailH - ui.app.DP(20),
	})

	optY := y + detailH + ui.app.DP(6)
	manual.autoPECheck.SetBounds(core.Rect{X: rightX, Y: optY, W: rightW, H: rowH})

	optY += rowH + ui.app.DP(4)
	manual.peEdit.SetBounds(core.Rect{X: rightX, Y: optY, W: rightW - browseW - ui.app.DP(6), H: rowH})
	manual.peBrowseBtn.SetBounds(core.Rect{X: rightX + rightW - browseW, Y: optY, W: browseW, H: rowH})

	optY += rowH + ui.app.DP(6)
	bootLabelW := ui.app.DP(64)
	bootModeW := ui.app.DP(132)
	bootGap := ui.app.DP(6)
	manual.bootRepairLabel.SetBounds(core.Rect{X: rightX, Y: optY, W: bootLabelW, H: rowH})
	manual.bootModeCombo.SetBounds(core.Rect{
		X: rightX + bootLabelW + bootGap,
		Y: optY,
		W: bootModeW,
		H: rowH,
	})
	manual.bootTargetCombo.SetBounds(core.Rect{
		X: rightX + bootLabelW + bootGap + bootModeW + bootGap,
		Y: optY,
		W: rightW - bootLabelW - bootGap - bootModeW - bootGap,
		H: rowH,
	})

	manual.formatCheck.SetBounds(core.Rect{X: margin, Y: bottomY, W: ui.app.DP(162), H: rowH})
	manual.deployCheck.SetBounds(core.Rect{X: margin + ui.app.DP(168), Y: bottomY, W: ui.app.DP(186), H: rowH})
	manual.autoRebootCheck.SetBounds(core.Rect{X: margin + ui.app.DP(360), Y: bottomY, W: ui.app.DP(110), H: rowH})
	manual.startBtn.SetBounds(core.Rect{
		X: w - margin - ui.app.DP(108),
		Y: bottomY - ui.app.DP(2),
		W: ui.app.DP(108),
		H: rowH + ui.app.DP(4),
	})
}

func manualLoadImage(path string) {
	path = strings.TrimSpace(path)
	manual.imagePath = path
	manual.imageEdit.SetText(path)
	manual.imageInfos = nil
	manual.imageParseErr = ""
	manual.indexCombo.SetItems(nil)
	manual.indexCombo.SetPlaceholder("先选择镜像")

	if path == "" {
		manualUpdateSummary()
		return
	}

	infos, err := imgsvc.DetectImageInfos(path)
	if err != nil {
		manual.imageParseErr = fmt.Sprintf("镜像解析失败: %v", err)
		manual.indexCombo.SetPlaceholder("镜像解析失败")
		manualUpdateSummary()
		return
	}

	manual.imageInfos = infos
	items := make([]widgets.ListItem, 0, len(infos))
	selectedIndex := 0
	preferredIndex := imgsvc.SelectInstallIndex(infos)
	for i, info := range infos {
		items = append(items, widgets.ListItem{
			Value: fmt.Sprintf("%d", info.Index),
			Text:  manualImageInfoText(info),
		})
		if info.Index == preferredIndex {
			selectedIndex = i
		}
	}
	manual.indexCombo.SetItems(items)
	if len(items) > 0 {
		manual.indexCombo.SetSelected(selectedIndex)
	}
	manualRefreshBootTargets()
	manualUpdateDetail()
	manualUpdateSummary()
}

func manualRefreshPartitionsAsync() {
	if manual.partitionList == nil || ui.app == nil {
		return
	}

	prevRef := manualSelectedPartitionRef()
	manual.partitionLoadID++
	loadID := manual.partitionLoadID
	manual.partitionError = ""
	manualSetLoading(true, "正在检测硬盘中...")

	go func(prevRef string, loadID uint64) {
		rows, bootRows, err := manualCollectPartitionRows()
		if ui.app == nil {
			return
		}
		_ = ui.app.Post(func() {
			if loadID != manual.partitionLoadID {
				return
			}
			manualApplyPartitionRows(prevRef, rows, bootRows, err)
		})
	}(prevRef, loadID)
}

func manualSetLoading(loading bool, text string) {
	manual.partitionLoading = loading

	if manual.loadingLabel != nil {
		if strings.TrimSpace(text) == "" {
			text = "正在检测硬盘中..."
		}
		manual.loadingLabel.SetText(text)
		manual.loadingLabel.SetVisible(loading)
	}
	if manual.loadingImage != nil {
		manual.loadingImage.SetVisible(loading)
		manual.loadingImage.SetPlaying(loading)
	}
	if manual.loadingPanel != nil {
		manual.loadingPanel.SetVisible(loading)
	}
	if manual.partitionList != nil {
		manual.partitionList.SetEnabled(!loading)
		if loading {
			manual.partitionList.ClearSelection()
		}
	}
	if loading {
		manual.bootTargets = nil
		if manual.bootTargetCombo != nil {
			manual.bootTargetCombo.SetItems(nil)
			manual.bootTargetCombo.SetPlaceholder("正在检测硬盘中...")
		}
		if manual.detailLabel != nil {
			manual.detailLabel.SetText("正在后台检测分区信息，请稍候。")
		}
	}
	manualUpdatePEInputState()
	manualUpdateBootTargetState()
	manualUpdateSummary()
}

func manualApplyPartitionRows(prevRef string, rows, bootRows []manualPartitionRow, err error) {
	manual.partitionRows = rows
	manual.bootRows = bootRows
	manual.partitionError = ""
	manualSetLoading(false, "")

	if err != nil {
		manual.partitionRows = nil
		manual.bootRows = nil
		manual.partitionError = err.Error()
		manual.partitionList.SetItems(nil)
		manual.partitionList.ClearSelection()
		manual.detailLabel.SetText("未能读取分区信息，请检查磁盘枚举接口。")
		manualRefreshBootTargets()
		manualUpdatePEInputState()
		manualUpdateSummary()
		return
	}

	items := make([]widgets.ListItem, 0, len(rows))
	for _, row := range rows {
		items = append(items, widgets.ListItem{
			Value: row.Ref,
			Text:  row.Summary,
		})
	}
	manual.partitionList.SetItems(items)

	selected := manualFindPartitionIndex(prevRef)
	if selected < 0 {
		selected = manualDefaultPartitionIndex()
	}
	if selected >= 0 {
		manual.partitionList.SetSelected(selected)
		manualApplyPartitionSelection(selected)
		return
	}

	manual.partitionList.ClearSelection()
	manual.detailLabel.SetText("未发现可用分区。")
	manualRefreshBootTargets()
	manualUpdatePEInputState()
	manualUpdateSummary()
}

func manualApplyPartitionSelection(index int) {
	if index < 0 || index >= len(manual.partitionRows) {
		manual.detailLabel.SetText("请选择一个分区查看详情。")
		manualRefreshBootTargets()
		manualUpdatePEInputState()
		manualUpdateSummary()
		return
	}
	manualUpdateDetail()
	manualRefreshBootTargets()
	manualUpdatePEInputState()
	manualUpdateSummary()
}

func manualUpdateDetail() {
	if manual.partitionLoading {
		manual.detailLabel.SetText("正在后台检测分区信息，请稍候。")
		return
	}
	row, ok := manualSelectedPartition()
	if !ok {
		manual.detailLabel.SetText("请选择一个分区查看详情。")
		return
	}

	detail := row.Detail
	if info, ok := manualSelectedImageInfo(); ok {
		detail += fmt.Sprintf(
			"\n镜像: %s  索引: %d  架构: %s",
			manualFriendlyTarget(manualSelectedTargetOS()),
			info.Index,
			manualFriendlyArch(utils.NormalizeArch(info.Arch)),
		)
	}
	manual.detailLabel.SetText(detail)
}

func manualRefreshBootTargets() {
	if manual.partitionLoading {
		manual.bootTargets = nil
		manual.bootTargetCombo.SetItems(nil)
		manual.bootTargetCombo.SetPlaceholder("正在检测硬盘中...")
		manualUpdateBootTargetState()
		return
	}
	row, ok := manualSelectedPartition()
	mode := manualSelectedBootMode()
	if !ok {
		manual.bootTargets = nil
		manual.bootTargetCombo.SetItems(nil)
		manual.bootTargetCombo.SetPlaceholder("先选择目标分区")
		manualUpdateBootTargetState()
		return
	}

	if mode == manualBootRepairSkip {
		manual.bootTargets = nil
		manual.bootTargetCombo.SetItems(nil)
		manual.bootTargetCombo.SetPlaceholder("已关闭引导修复")
		manualUpdateBootTargetState()
		return
	}
	if mode == manualBootRepairAuto {
		manual.bootTargets = nil
		manual.bootTargetCombo.SetItems(nil)
		if strings.EqualFold(row.DiskStyle, "GPT") {
			manual.bootTargetCombo.SetPlaceholder("自动修复将自动选择 EFI 引导分区")
		} else {
			manual.bootTargetCombo.SetPlaceholder("自动修复将自动选择 BIOS 引导分区")
		}
		manualUpdateBootTargetState()
		return
	}

	prevRef := manualSelectedBootTargetRef()
	manual.bootTargets = manualCollectBootTargets(row, mode)
	items := make([]widgets.ListItem, 0, len(manual.bootTargets))
	selected := -1
	for i, option := range manual.bootTargets {
		items = append(items, widgets.ListItem{
			Value: option.Ref,
			Text:  option.Text,
		})
		if option.Ref == prevRef {
			selected = i
		}
	}
	manual.bootTargetCombo.SetItems(items)
	if len(items) == 0 {
		if strings.EqualFold(row.DiskStyle, "GPT") {
			manual.bootTargetCombo.SetPlaceholder("未找到可用 EFI 分区")
		} else {
			manual.bootTargetCombo.SetPlaceholder("未找到可用 BIOS 引导分区")
		}
	} else if strings.EqualFold(row.DiskStyle, "GPT") {
		manual.bootTargetCombo.SetPlaceholder("选择 EFI 分区")
	} else {
		manual.bootTargetCombo.SetPlaceholder("选择 BIOS 引导分区")
	}
	bootType := manualBootRepairType(row, mode)
	if len(items) == 0 {
		if bootType == "UEFI" {
			manual.bootTargetCombo.SetPlaceholder("未找到可用 EFI 分区")
		} else {
			manual.bootTargetCombo.SetPlaceholder("未找到可用 BIOS 引导分区")
		}
	} else if bootType == "UEFI" {
		manual.bootTargetCombo.SetPlaceholder("选择 EFI 引导分区")
	} else {
		manual.bootTargetCombo.SetPlaceholder("选择 BIOS 引导分区")
	}
	if selected < 0 && len(items) > 0 {
		selected = 0
	}
	if selected >= 0 {
		manual.bootTargetCombo.SetSelected(selected)
	}
	manualUpdateBootTargetState()
}

func manualUpdatePEInputState() {
	if manual.partitionLoading {
		if manual.autoPECheck != nil {
			manual.autoPECheck.SetEnabled(false)
		}
		if manual.peEdit != nil {
			manual.peEdit.SetEnabled(false)
		}
		if manual.peBrowseBtn != nil {
			manual.peBrowseBtn.SetEnabled(false)
		}
		return
	}
	row, ok := manualSelectedPartition()
	needsPE := ok && row.CurrentSystem
	autoPE := manual.autoPECheck != nil && manual.autoPECheck.IsChecked()

	if manual.autoPECheck != nil {
		manual.autoPECheck.SetEnabled(needsPE)
	}
	if manual.peEdit != nil {
		manual.peEdit.SetEnabled(needsPE && !autoPE)
	}
	if manual.peBrowseBtn != nil {
		manual.peBrowseBtn.SetEnabled(needsPE && !autoPE)
	}
}

func manualUpdateBootTargetState() {
	if manual.bootTargetCombo == nil {
		return
	}
	manual.bootTargetCombo.SetEnabled(!manual.partitionLoading && manualBootModeNeedsTarget() && len(manual.bootTargets) > 0)
	manualUpdateActionState()
}

func manualUpdateActionState() {
	if manual.startBtn == nil {
		return
	}
	manual.startBtn.SetEnabled(manualValidationReason() == "")
}

func manualUpdateSummary() {
	if manual.summaryLabel == nil {
		return
	}

	parts := make([]string, 0, 4)
	if manual.partitionLoading {
		parts = append(parts, "正在检测硬盘中...")
	}
	if strings.TrimSpace(manual.imagePath) == "" {
		parts = append(parts, "未选择安装镜像")
	} else if manual.imageParseErr != "" {
		parts = append(parts, manual.imageParseErr)
	} else if info, ok := manualSelectedImageInfo(); ok {
		parts = append(parts, fmt.Sprintf(
			"镜像: %s / 索引 %d / %s",
			manualFriendlyTarget(manualSelectedTargetOS()),
			info.Index,
			manualFriendlyArch(utils.NormalizeArch(info.Arch)),
		))
	} else {
		parts = append(parts, "镜像已选择，等待索引")
	}

	if row, ok := manualSelectedPartition(); ok {
		if row.TargetSelectable {
			parts = append(parts, fmt.Sprintf("目标: %s", manualPartitionDisplayName(row)))
			if row.CurrentSystem {
				if manual.autoPECheck.IsChecked() {
					parts = append(parts, "当前系统分区，将自动处理 PE")
				} else {
					parts = append(parts, "当前系统分区，将手动指定 PE")
				}
			} else {
				parts = append(parts, "非当前系统分区，将直接离线安装")
			}
		} else {
			parts = append(parts, fmt.Sprintf("当前选中 %s，仅供查看", manualPartitionDisplayName(row)))
		}
	} else if manual.partitionError != "" {
		parts = append(parts, manual.partitionError)
	} else {
		parts = append(parts, "未选择目标分区")
	}
	if bootSummary := manualBootRepairSummary(); bootSummary != "" {
		parts = append(parts, bootSummary)
	}

	if reason := manualValidationReason(); reason != "" {
		parts = append(parts, "未就绪: "+reason)
	}

	manual.summaryLabel.SetText(strings.Join(parts, " | "))
	manualUpdateActionState()
}

func manualBuildConfig() (ManualInstallConfig, error) {
	if reason := manualValidationReason(); reason != "" {
		return ManualInstallConfig{}, fmt.Errorf(reason)
	}

	row, _ := manualSelectedPartition()
	info, _ := manualSelectedImageInfo()
	cfg := ManualInstallConfig{
		TargetOS:     manualSelectedTargetOS(),
		ImageArch:    utils.NormalizeArch(info.Arch),
		ImagePath:    strings.TrimSpace(manual.imagePath),
		ImageIndex:   info.Index,
		TargetRoot:   row.TargetRoot,
		AutoPE:       manual.autoPECheck.IsChecked(),
		ManualPEWIM:  strings.TrimSpace(manual.peEdit.TextValue()),
		FormatTarget: manual.formatCheck.IsChecked(),
		AutoReboot:   manual.autoRebootCheck.IsChecked(),
		BootRepair:   manualSelectedBootMode(),
		AutoDeploy:   manual.deployCheck.IsChecked(),
	}
	if cfg.ImageArch == "" {
		cfg.ImageArch = winos.DesiredArch()
	}
	if cfg.TargetOS == "" {
		cfg.TargetOS = targetWin10
	}
	if manualBootModeNeedsTarget() {
		cfg.BootTargetRef = manualSelectedBootTargetRef()
	}
	return cfg, nil
}

func manualSelectedImageInfo() (dism.ImageMeta, bool) {
	index := -1
	if manual.indexCombo != nil {
		index = manual.indexCombo.SelectedIndex()
	}
	if index < 0 || index >= len(manual.imageInfos) {
		return dism.ImageMeta{}, false
	}
	return manual.imageInfos[index], true
}

func manualSelectedPartition() (manualPartitionRow, bool) {
	index := -1
	if manual.partitionList != nil {
		index = manual.partitionList.SelectedIndex()
	}
	if index < 0 || index >= len(manual.partitionRows) {
		return manualPartitionRow{}, false
	}
	return manual.partitionRows[index], true
}

func manualSelectedPartitionRef() string {
	row, ok := manualSelectedPartition()
	if !ok {
		return ""
	}
	return row.Ref
}

func manualSelectedBootMode() string {
	if manual.bootModeCombo == nil {
		return manualBootRepairAuto
	}
	item, ok := manual.bootModeCombo.SelectedItem()
	if !ok || strings.TrimSpace(item.Value) == "" {
		return manualBootRepairAuto
	}
	return strings.TrimSpace(item.Value)
}

func manualBootModeNeedsTarget() bool {
	switch manualSelectedBootMode() {
	case manualBootRepairLegacy, manualBootRepairManualUEFI, manualBootRepairManualBIOS:
		return true
	default:
		return false
	}
}

func manualBootRepairSummary() string {
	switch manualSelectedBootMode() {
	case manualBootRepairSkip:
		return "引导修复: 已关闭"
	case manualBootRepairManualUEFI:
		if text := manualSelectedBootTargetText(); text != "" {
			return "引导修复: UEFI -> " + text
		}
		return "引导修复: UEFI"
	case manualBootRepairManualBIOS:
		if text := manualSelectedBootTargetText(); text != "" {
			return "引导修复: BIOS -> " + text
		}
		return "引导修复: BIOS"
	default:
		row, ok := manualSelectedPartition()
		if ok {
			return "引导修复: 自动 (" + manualBootRepairType(row, manualBootRepairAuto) + ")"
		}
		return "引导修复: 自动"
	}
}

func manualSelectedBootTargetText() string {
	ref := strings.TrimSpace(manualSelectedBootTargetRef())
	if ref == "" {
		return ""
	}
	for _, option := range manual.bootTargets {
		if strings.EqualFold(option.Ref, ref) {
			return option.Text
		}
	}
	return ""
}

func manualSelectedBootTargetRef() string {
	if manual.bootTargetCombo == nil {
		return ""
	}
	item, ok := manual.bootTargetCombo.SelectedItem()
	if !ok {
		return ""
	}
	return strings.TrimSpace(item.Value)
}

func manualSelectedTargetOS() string {
	if target := imgsvc.DetectTargetFromInfos(manual.imageInfos); target != "" {
		return target
	}
	info, ok := manualSelectedImageInfo()
	if !ok {
		return ""
	}
	s := strings.ToLower(strings.TrimSpace(info.Name + " " + info.Description + " " + info.Edition + " " + info.Flags))
	switch {
	case strings.Contains(s, "windows 7"), strings.Contains(s, "win7"):
		return targetWin7
	case strings.Contains(s, "windows 11"), strings.Contains(s, "win11"):
		return targetWin11
	case strings.Contains(s, "windows 10"), strings.Contains(s, "win10"):
		return targetWin10
	default:
		return ""
	}
}

func manualValidationReason() string {
	if manual.partitionLoading {
		return "正在检测硬盘信息"
	}
	if strings.TrimSpace(manual.imagePath) == "" {
		return "请选择安装镜像"
	}
	if manual.imageParseErr != "" {
		return manual.imageParseErr
	}
	info, ok := manualSelectedImageInfo()
	if !ok || info.Index <= 0 {
		return "请选择镜像索引"
	}
	row, ok := manualSelectedPartition()
	if !ok {
		return "请选择目标分区"
	}
	if !row.TargetSelectable {
		return "当前分区不能作为安装目标"
	}
	if row.CurrentSystem && !manual.autoPECheck.IsChecked() && strings.TrimSpace(manual.peEdit.TextValue()) == "" {
		return "当前系统分区需要手动指定 PE WIM"
	}
	if manualBootModeNeedsTarget() && strings.TrimSpace(manualSelectedBootTargetRef()) == "" {
		return "请选择引导分区"
	}
	return ""
}

func manualCollectPartitionRows() ([]manualPartitionRow, []manualPartitionRow, error) {
	volumes, err := disk.ListVolumes()
	if err != nil {
		return nil, nil, err
	}

	diskStyleByDisk := map[int]string{}
	if disks, err := disk.ListPhysicalDisks(); err == nil {
		for _, info := range disks {
			diskStyleByDisk[info.DiskNumber] = strings.TrimSpace(info.PartitionStyle)
		}
	}

	kindByDisk := map[int]string{}
	for _, vol := range volumes {
		root := strings.TrimSpace(vol.RootPath)
		if root == "" && vol.DriveLetter != "" {
			root = vol.DriveLetter
		}
		if root == "" {
			continue
		}
		if _, ok := kindByDisk[vol.DiskNumber]; ok {
			continue
		}
		norm, err := utils.NormalizeDrive(root, 0)
		if err != nil || norm == "" {
			continue
		}
		if kind, err := disk.GetDiskKind(norm); err == nil {
			kindByDisk[vol.DiskNumber] = kind
		}
	}

	diskNumbers := map[int]struct{}{}
	for _, vol := range volumes {
		diskNumbers[vol.DiskNumber] = struct{}{}
	}
	for diskNumber := range diskStyleByDisk {
		diskNumbers[diskNumber] = struct{}{}
	}

	manager := bl.New()
	bitlockerReady := manager.IsAvailable()

	orderedDisks := make([]int, 0, len(diskNumbers))
	for diskNumber := range diskNumbers {
		orderedDisks = append(orderedDisks, diskNumber)
	}
	sort.Ints(orderedDisks)

	bootRows := manualBuildBootRows(orderedDisks, volumes, diskStyleByDisk, kindByDisk, manager, bitlockerReady)
	partByGUID := make(map[string]manualPartitionRow, len(bootRows))
	partByLetter := make(map[string]manualPartitionRow, len(bootRows))
	for _, row := range bootRows {
		if key := manualNormalizeGUID(row.VolumeGuidPath); key != "" {
			partByGUID[key] = row
		}
		if key := manualNormalizeDriveLetter(row.DriveLetter); key != "" {
			partByLetter[key] = row
		}
	}

	rows := make([]manualPartitionRow, 0, len(volumes))
	for _, vol := range volumes {
		letter := manualNormalizeDriveLetter(vol.DriveLetter)
		if letter == "" {
			continue
		}
		targetRoot, err := utils.NormalizeDrive(letter, 0)
		if err != nil || targetRoot == "" {
			continue
		}

		row := manualPartitionRow{
			DiskNumber:     vol.DiskNumber,
			PartitionType:  "未识别",
			DiskStyle:      strings.TrimSpace(diskStyleByDisk[vol.DiskNumber]),
			DiskKind:       manualFirstNonEmpty(kindByDisk[vol.DiskNumber], "Unknown"),
			FileSystem:     strings.TrimSpace(vol.FileSystem),
			VolumeLabel:    strings.TrimSpace(vol.Label),
			VolumeGuidPath: strings.TrimSpace(vol.VolumeGuidPath),
			DriveLetter:    letter,
			TargetRoot:     targetRoot,
			SizeBytes:      vol.SizeBytes,
			FreeBytes:      vol.FreeBytes,
			Ref:            strings.ToUpper(targetRoot),
		}

		if part, ok := partByGUID[manualNormalizeGUID(vol.VolumeGuidPath)]; ok {
			row.PartitionNumber = part.PartitionNumber
			row.PartitionType = manualFirstNonEmpty(part.PartitionType, row.PartitionType)
			row.Ref = part.Ref
		} else if part, ok := partByLetter[letter]; ok {
			row.PartitionNumber = part.PartitionNumber
			row.PartitionType = manualFirstNonEmpty(part.PartitionType, row.PartitionType)
			row.Ref = part.Ref
		}

		if row.DiskStyle == "" {
			if style, _, err := disk.GetDiskInfo(row.TargetRoot); err == nil {
				row.DiskStyle = style
			}
		}
		if row.DiskKind == "Unknown" {
			if kind, err := disk.GetDiskKind(row.TargetRoot); err == nil {
				row.DiskKind = kind
			}
		}

		row.CurrentSystem = manualIsCurrentSystemRoot(row.TargetRoot)
		row.BitLocker = manualBitLockerText(manager, bitlockerReady, row.TargetRoot)
		row.TargetSelectable = manualIsInstallTarget(row)
		row.Summary = manualPartitionSummary(row)
		row.Detail = manualPartitionDetail(row)
		rows = append(rows, row)
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].CurrentSystem != rows[j].CurrentSystem {
			return rows[i].CurrentSystem
		}
		if rows[i].DriveLetter != rows[j].DriveLetter {
			if rows[i].DriveLetter == "" {
				return false
			}
			if rows[j].DriveLetter == "" {
				return true
			}
			return rows[i].DriveLetter < rows[j].DriveLetter
		}
		if rows[i].DiskNumber != rows[j].DiskNumber {
			return rows[i].DiskNumber < rows[j].DiskNumber
		}
		if rows[i].PartitionNumber != rows[j].PartitionNumber {
			return rows[i].PartitionNumber < rows[j].PartitionNumber
		}
		return rows[i].TargetRoot < rows[j].TargetRoot
	})

	if len(rows) == 0 {
		return nil, bootRows, fmt.Errorf("未发现任何可用分区")
	}
	return rows, bootRows, nil
}

func manualBuildBootRows(
	orderedDisks []int,
	volumes []disk.VolumeInfo,
	diskStyleByDisk map[int]string,
	kindByDisk map[int]string,
	manager *bl.BitLockerManager,
	bitlockerReady bool,
) []manualPartitionRow {
	volByGUID := map[string]disk.VolumeInfo{}
	volByLetter := map[string]disk.VolumeInfo{}
	for _, vol := range volumes {
		if key := manualNormalizeGUID(vol.VolumeGuidPath); key != "" {
			volByGUID[key] = vol
		}
		if key := manualNormalizeDriveLetter(vol.DriveLetter); key != "" {
			volByLetter[key] = vol
		}
	}

	rows := make([]manualPartitionRow, 0, len(orderedDisks)*4)
	for _, diskNumber := range orderedDisks {
		parts, err := disk.ListDiskPartitions(diskNumber)
		if err != nil {
			continue
		}
		for _, part := range parts {
			row := manualPartitionRow{
				DiskNumber:      diskNumber,
				PartitionNumber: part.PartitionNumber,
				PartitionType:   manualFirstNonEmpty(strings.TrimSpace(part.Type), "未识别"),
				DiskStyle:       strings.TrimSpace(diskStyleByDisk[diskNumber]),
				DiskKind:        manualFirstNonEmpty(kindByDisk[diskNumber], "Unknown"),
				VolumeGuidPath:  strings.TrimSpace(part.VolumeGuidPath),
				DriveLetter:     manualNormalizeDriveLetter(part.DriveLetter),
				SizeBytes:       part.SizeBytes,
				Ref:             fmt.Sprintf("%d:%d", diskNumber, part.PartitionNumber),
			}

			vol, ok := volByGUID[manualNormalizeGUID(part.VolumeGuidPath)]
			if !ok && row.DriveLetter != "" {
				vol, ok = volByLetter[row.DriveLetter]
			}
			if ok {
				if vol.SizeBytes > 0 {
					row.SizeBytes = vol.SizeBytes
					row.FreeBytes = vol.FreeBytes
				}
				row.FileSystem = strings.TrimSpace(vol.FileSystem)
				row.VolumeLabel = strings.TrimSpace(vol.Label)
				if row.VolumeGuidPath == "" {
					row.VolumeGuidPath = strings.TrimSpace(vol.VolumeGuidPath)
				}
			}

			root := ""
			if ok && strings.TrimSpace(vol.RootPath) != "" {
				root = strings.TrimSpace(vol.RootPath)
			} else if row.DriveLetter != "" {
				root = row.DriveLetter
			}
			if norm, err := utils.NormalizeDrive(root, 0); err == nil {
				row.TargetRoot = norm
			}

			if row.DiskStyle == "" && row.TargetRoot != "" {
				if style, _, err := disk.GetDiskInfo(row.TargetRoot); err == nil {
					row.DiskStyle = style
				}
			}
			if row.DiskKind == "Unknown" && row.TargetRoot != "" {
				if kind, err := disk.GetDiskKind(row.TargetRoot); err == nil {
					row.DiskKind = kind
				}
			}

			row.CurrentSystem = manualIsCurrentSystemRoot(row.TargetRoot)
			row.BitLocker = manualBitLockerText(manager, bitlockerReady, row.TargetRoot)
			row.TargetSelectable = manualIsInstallTarget(row)
			row.Summary = manualPartitionSummary(row)
			row.Detail = manualPartitionDetail(row)
			rows = append(rows, row)
		}
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].DiskNumber != rows[j].DiskNumber {
			return rows[i].DiskNumber < rows[j].DiskNumber
		}
		return rows[i].PartitionNumber < rows[j].PartitionNumber
	})
	return rows
}

func manualCollectBootTargets(target manualPartitionRow, mode string) []manualBootTargetOption {
	options := make([]manualBootTargetOption, 0, 4)
	if manualBootRepairType(target, mode) == "UEFI" {
		for _, row := range manual.bootRows {
			if !manualIsUEFIBootPartition(row) {
				continue
			}
			options = append(options, manualBootTargetOption{
				Ref:  row.Ref,
				Text: manualBootTargetText(row),
			})
		}
		sort.Slice(options, func(i, j int) bool {
			di, pi := manualParsePartitionRef(options[i].Ref)
			dj, pj := manualParsePartitionRef(options[j].Ref)
			if di != dj {
				if di == target.DiskNumber {
					return true
				}
				if dj == target.DiskNumber {
					return false
				}
				return di < dj
			}
			return pi < pj
		})
		return options
	}

	for _, row := range manual.bootRows {
		if !manualIsBIOSBootPartition(row) {
			continue
		}
		options = append(options, manualBootTargetOption{
			Ref:  row.Ref,
			Text: manualBootTargetText(row),
		})
	}
	sort.Slice(options, func(i, j int) bool {
		di, pi := manualParsePartitionRef(options[i].Ref)
		dj, pj := manualParsePartitionRef(options[j].Ref)
		if di != dj {
			if di == target.DiskNumber {
				return true
			}
			if dj == target.DiskNumber {
				return false
			}
			return di < dj
		}
		if options[i].Ref == target.Ref {
			return true
		}
		if options[j].Ref == target.Ref {
			return false
		}
		return pi < pj
	})
	return options
}

func manualBootRepairType(target manualPartitionRow, mode string) string {
	switch strings.TrimSpace(mode) {
	case manualBootRepairManualUEFI:
		return "UEFI"
	case manualBootRepairManualBIOS:
		return "BIOS"
	case manualBootRepairLegacy:
		if strings.EqualFold(target.DiskStyle, "GPT") {
			return "UEFI"
		}
		return "BIOS"
	default:
		if strings.EqualFold(target.DiskStyle, "GPT") {
			return "UEFI"
		}
		return "BIOS"
	}
}

func manualIsUEFIBootPartition(row manualPartitionRow) bool {
	if !strings.EqualFold(strings.TrimSpace(row.DiskStyle), "GPT") {
		return false
	}

	partType := strings.ToUpper(strings.TrimSpace(row.PartitionType))
	if partType == "EFI" {
		return true
	}

	if !strings.EqualFold(strings.TrimSpace(row.FileSystem), "FAT32") {
		return false
	}

	label := strings.ToLower(strings.TrimSpace(row.VolumeLabel))
	if strings.Contains(label, "efi") || strings.Contains(label, "esp") {
		return true
	}

	if row.SizeBytes > 0 && row.SizeBytes <= 2*1024*1024*1024 && !row.TargetSelectable {
		return true
	}

	return false
}

func manualIsBIOSBootPartition(row manualPartitionRow) bool {
	if !strings.EqualFold(strings.TrimSpace(row.DiskStyle), "MBR") {
		return false
	}
	if strings.TrimSpace(row.TargetRoot) == "" {
		return false
	}
	partType := strings.ToUpper(strings.TrimSpace(row.PartitionType))
	return partType != "EFI" && partType != "MSR"
}

func manualDefaultPartitionIndex() int {
	for i, row := range manual.partitionRows {
		if row.CurrentSystem && row.TargetSelectable {
			return i
		}
	}
	for i, row := range manual.partitionRows {
		if row.TargetSelectable {
			return i
		}
	}
	if len(manual.partitionRows) > 0 {
		return 0
	}
	return -1
}

func manualFindPartitionIndex(ref string) int {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return -1
	}
	for i, row := range manual.partitionRows {
		if strings.EqualFold(row.Ref, ref) {
			return i
		}
	}
	return -1
}

func manualIsInstallTarget(row manualPartitionRow) bool {
	if strings.TrimSpace(row.TargetRoot) == "" {
		return false
	}
	if strings.EqualFold(row.TargetRoot, "X:\\") {
		return false
	}
	switch strings.ToUpper(strings.TrimSpace(row.PartitionType)) {
	case "EFI", "MSR", "RECOVERY":
		return false
	}
	if strings.EqualFold(strings.TrimSpace(row.FileSystem), "FAT32") {
		return false
	}
	return true
}

func manualIsCurrentSystemRoot(root string) bool {
	if strings.TrimSpace(root) == "" {
		return false
	}
	systemRoot := winos.SystemDriveRoot()
	if norm, err := utils.NormalizeDrive(systemRoot, 0); err == nil {
		systemRoot = norm
	}
	normRoot, err := utils.NormalizeDrive(root, 0)
	if err != nil {
		return false
	}
	return strings.EqualFold(normRoot, systemRoot)
}

func manualBitLockerText(manager *bl.BitLockerManager, ready bool, root string) string {
	if strings.TrimSpace(root) == "" {
		return "未挂载"
	}
	if !ready || manager == nil {
		return "未知"
	}
	letter := strings.TrimSpace(root)
	if len(letter) == 0 {
		return "未知"
	}
	status := manager.GetStatus(letter[0])
	switch status {
	case bl.VolNotEncrypted:
		return "未加密"
	case bl.VolEncryptedUnlocked:
		return "已解锁"
	case bl.VolEncryptedLocked:
		return "已锁定"
	case bl.VolEncrypting:
		return "加密中"
	case bl.VolDecrypting:
		return "解密中"
	default:
		return "未知"
	}
}

func manualImageInfoText(info dism.ImageMeta) string {
	parts := []string{fmt.Sprintf("%d", info.Index)}
	if name := strings.TrimSpace(info.Name); name != "" {
		//parts = append(parts, name)
	} else if edition := strings.TrimSpace(info.Edition); edition != "" {
		//parts = append(parts, edition)
	}
	if desc := strings.TrimSpace(info.Description); desc != "" && !strings.EqualFold(desc, info.Name) {
		parts = append(parts, desc)
	}
	return strings.Join(parts, " | ")
}

func manualPartitionSummary(row manualPartitionRow) string {
	parts := make([]string, 0, 5)
	if drive := strings.TrimRight(strings.TrimSpace(row.TargetRoot), `\`); drive != "" {
		parts = append(parts, drive)
	} else {
		parts = append(parts, fmt.Sprintf("磁盘%d分区%d", row.DiskNumber, row.PartitionNumber))
	}
	if label := strings.TrimSpace(row.VolumeLabel); label != "" {
		parts = append(parts, label)
	}
	if size := manualSizeText(row.SizeBytes); size != "-" {
		parts = append(parts, size)
	}
	if style := strings.TrimSpace(row.DiskStyle); style != "" {
		parts = append(parts, style)
	}
	if kind := strings.TrimSpace(row.DiskKind); kind != "" && !strings.EqualFold(kind, "Unknown") {
		parts = append(parts, kind)
	}
	return strings.Join(parts, " ")
}

func manualPartitionDetail(row manualPartitionRow) string {
	modeText := "可作为安装目标"
	if !row.TargetSelectable {
		modeText = "仅供查看，不能作为安装目标"
	}
	currentText := "否"
	if row.CurrentSystem {
		currentText = "是"
	}
	return fmt.Sprintf(
		"卷: %s    卷标: %s\n容量: %s    文件系统: %s\n磁盘%d 分区%d    类型: %s / %s\n硬盘: %s    BitLocker: %s\n当前系统: %s    %s",
		manualFirstNonEmpty(strings.TrimRight(row.TargetRoot, `\`), "未挂载"),
		manualFirstNonEmpty(row.VolumeLabel, "-"),
		manualSizeDetailText(row.SizeBytes, row.FreeBytes),
		manualFirstNonEmpty(row.FileSystem, "-"),
		row.DiskNumber,
		row.PartitionNumber,
		manualFirstNonEmpty(row.PartitionType, "-"),
		manualFirstNonEmpty(row.DiskStyle, "-"),
		manualFirstNonEmpty(row.DiskKind, "-"),
		manualFirstNonEmpty(row.BitLocker, "-"),
		currentText,
		modeText,
	)
}

func manualPartitionDisplayName(row manualPartitionRow) string {
	base := strings.TrimRight(row.TargetRoot, `\`)
	if base == "" {
		base = fmt.Sprintf("磁盘%d 分区%d", row.DiskNumber, row.PartitionNumber)
	}
	if row.VolumeLabel != "" {
		base += " " + row.VolumeLabel
	}
	return base
}

func manualBootTargetText(row manualPartitionRow) string {
	name := strings.TrimRight(strings.TrimSpace(row.TargetRoot), `\`)
	if name == "" {
		name = fmt.Sprintf("磁盘%d分区%d", row.DiskNumber, row.PartitionNumber)
	}
	if label := strings.TrimSpace(row.VolumeLabel); label != "" {
		name += " " + label
	}
	return fmt.Sprintf("%s [磁盘%d分区%d]", name, row.DiskNumber, row.PartitionNumber)
}

func manualFriendlyTarget(target string) string {
	switch strings.ToLower(strings.TrimSpace(target)) {
	case targetWin7:
		return "Windows 7"
	case targetWin11:
		return "Windows 11"
	case targetWin10:
		return "Windows 10"
	default:
		return "未知系统"
	}
}

func manualFriendlyArch(arch string) string {
	switch strings.TrimSpace(arch) {
	case "32":
		return "32 位"
	case "64":
		return "64 位"
	default:
		if arch == "" {
			return "未知架构"
		}
		return arch
	}
}

func manualSizeText(size uint64) string {
	if size == 0 {
		return "-"
	}
	return dism.BytesToMBGBStr(size)
}

func manualSizePairText(sizeBytes, freeBytes uint64) string {
	if sizeBytes == 0 {
		return "-"
	}
	if freeBytes == 0 {
		return manualSizeText(sizeBytes)
	}
	return fmt.Sprintf("%s/%s", manualSizeText(sizeBytes), manualSizeText(freeBytes))
}

func manualSizeDetailText(sizeBytes, freeBytes uint64) string {
	if sizeBytes == 0 {
		return "-"
	}
	if freeBytes == 0 {
		return fmt.Sprintf("总 %s", manualSizeText(sizeBytes))
	}
	return fmt.Sprintf("总 %s / 可用 %s", manualSizeText(sizeBytes), manualSizeText(freeBytes))
}

func manualNormalizeGUID(path string) string {
	return strings.ToUpper(strings.TrimSpace(path))
}

func manualNormalizeDriveLetter(letter string) string {
	letter = strings.ToUpper(strings.TrimSpace(letter))
	letter = strings.TrimRight(letter, `:\`)
	if len(letter) == 1 {
		return letter
	}
	return ""
}

func manualFirstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func manualParsePartitionRef(ref string) (int, int) {
	parts := strings.Split(strings.TrimSpace(ref), ":")
	if len(parts) != 2 {
		return 0, 0
	}
	var diskNumber, partNumber int
	fmt.Sscanf(parts[0], "%d", &diskNumber)
	fmt.Sscanf(parts[1], "%d", &partNumber)
	return diskNumber, partNumber
}
