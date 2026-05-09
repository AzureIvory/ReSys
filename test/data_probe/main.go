//go:build windows

package main

import (
	"ReSys/src/data"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/AzureIvory/winui/core"
	"github.com/AzureIvory/winui/sysapi"
	"github.com/AzureIvory/winui/widgets"
)

// loadRes 保存一次解析得到的全部结果。
type loadRes struct {
	res   *data.RuleParseResult
	items []data.RuleItem
	pes   []data.WinPEImg
}

// probeUI 管理测试窗口和交互。
type probeUI struct {
	app   *core.App
	scene *widgets.Scene

	root *widgets.Panel
	top  *widgets.Panel
	mid  *widgets.Panel
	bot  *widgets.Panel
	left *widgets.Panel
	right *widgets.Panel

	pathLab *widgets.Label
	statLab *widgets.Label
	itemLab *widgets.Label
	peLab   *widgets.Label

	pathBox *widgets.EditBox
	sumBox  *widgets.EditBox
	itemBox *widgets.EditBox
	peBox   *widgets.EditBox

	pickBtn *widgets.Button
	loadBtn *widgets.Button
}

func main() {
	ui := &probeUI{}
	opts := core.Options{
		ClassName:      "DataProbeWin",
		Title:          "JSON 解析测试",
		Width:          1320,
		Height:         920,
		MinWidth:       1080,
		MinHeight:      760,
		Style:          core.DefaultWindowStyle,
		ExStyle:        core.DefaultWindowExStyle,
		Cursor:         core.CursorArrow,
		Background:     core.RGB(246, 248, 251),
		DoubleBuffered: true,
		RenderMode:     core.RenderModeAuto,
	}

	widgets.BindScene(&opts, widgets.SceneHooks{
		OnCreate: func(app *core.App, scene *widgets.Scene) error {
			return ui.onMake(app, scene)
		},
		OnResize: func(_ *core.App, _ *widgets.Scene, size core.Size) {
			ui.onSize(size)
		},
	})

	app, err := core.NewApp(opts)
	if err != nil {
		panic(err)
	}
	if err := app.Init(); err != nil {
		panic(err)
	}
	app.Run()
}

// onMake 创建窗口控件。
func (u *probeUI) onMake(app *core.App, scene *widgets.Scene) error {
	u.app = app
	u.scene = scene
	u.makeUI()
	u.fillInit()
	u.onSize(app.ClientSize())
	return nil
}

// makeUI 组装页面结构。
func (u *probeUI) makeUI() {
	u.root = widgets.NewPanel("root")
	u.root.SetStyle(widgets.PanelStyle{Background: core.RGB(246, 248, 251)})
	u.root.SetLayout(widgets.AbsoluteLayout{})

	u.top = u.makeTop()
	u.mid = u.makeMid()
	u.bot = u.makeBot()

	u.root.AddAll(u.top, u.mid, u.bot)
	u.scene.Root().Add(u.root)
}

// makeTop 创建顶部操作区。
func (u *probeUI) makeTop() *widgets.Panel {
	pan := widgets.NewPanel("top")
	pan.SetStyle(u.boxSty())
	pan.SetLayout(widgets.ColumnLayout{
		Gap:        10,
		Padding:    widgets.UniformInsets(16),
		CrossAlign: widgets.AlignStretch,
	})

	title := u.newLab("title", "JSON 解析测试工具", 22, 700)
	tip := u.newLab("tip", "选择一个规则 JSON，查看摘要、RuleItem 和 WinPEImg 明细。", 13, 400)
	tip.SetStyle(widgets.TextStyle{
		Font:   widgets.FontSpec{Face: "Microsoft YaHei UI", SizeDP: 13},
		Color:  core.RGB(90, 102, 120),
		Format: core.DTWordBreak,
	})
	widgets.SetPreferredSize(tip, core.Size{Height: 40})

	row := widgets.NewPanel("pathRow")
	row.SetLayout(widgets.RowLayout{
		Gap:        10,
		CrossAlign: widgets.AlignStretch,
	})

	u.pathBox = u.newBox("pathBox", false)
	u.pathBox.SetReadOnly(true)
	widgets.SetPreferredSize(u.pathBox, core.Size{Width: 780, Height: 42})

	u.pickBtn = widgets.NewButton("pickBtn", "选择文件", widgets.ModeCustom)
	u.pickBtn.SetStyle(u.btnSty())
	u.pickBtn.SetOnClick(func() {
		u.pickFile()
	})
	widgets.SetPreferredSize(u.pickBtn, core.Size{Width: 120, Height: 42})

	u.loadBtn = widgets.NewButton("loadBtn", "开始解析", widgets.ModeCustom)
	u.loadBtn.SetStyle(u.btnSty())
	u.loadBtn.SetOnClick(func() {
		u.startLoad()
	})
	widgets.SetPreferredSize(u.loadBtn, core.Size{Width: 120, Height: 42})

	row.AddAll(u.pathBox, u.pickBtn, u.loadBtn)

	pan.AddAll(title, tip, row)
	return pan
}

// makeMid 创建摘要区。
func (u *probeUI) makeMid() *widgets.Panel {
	pan := widgets.NewPanel("mid")
	pan.SetStyle(u.boxSty())
	pan.SetLayout(widgets.ColumnLayout{
		Gap:        10,
		Padding:    widgets.UniformInsets(16),
		CrossAlign: widgets.AlignStretch,
	})

	u.pathLab = u.newLab("pathLab", "当前文件：", 14, 700)
	u.statLab = u.newLab("statLab", "状态：未解析", 14, 700)
	u.sumBox = u.newBox("sumBox", true)
	widgets.SetPreferredSize(u.sumBox, core.Size{Height: 170})

	pan.AddAll(u.pathLab, u.statLab, u.sumBox)
	return pan
}

// makeBot 创建底部明细区。
func (u *probeUI) makeBot() *widgets.Panel {
	pan := widgets.NewPanel("bot")
	pan.SetLayout(widgets.AbsoluteLayout{})

	u.left = widgets.NewPanel("left")
	u.left.SetStyle(u.boxSty())
	u.left.SetLayout(widgets.ColumnLayout{
		Gap:        10,
		Padding:    widgets.UniformInsets(16),
		CrossAlign: widgets.AlignStretch,
	})

	u.right = widgets.NewPanel("right")
	u.right.SetStyle(u.boxSty())
	u.right.SetLayout(widgets.ColumnLayout{
		Gap:        10,
		Padding:    widgets.UniformInsets(16),
		CrossAlign: widgets.AlignStretch,
	})

	u.itemLab = u.newLab("itemLab", "RuleItem 明细", 15, 700)
	u.peLab = u.newLab("peLab", "WinPEImg 明细", 15, 700)

	u.itemBox = u.newBox("itemBox", true)
	u.peBox = u.newBox("peBox", true)
	widgets.SetPreferredSize(u.itemBox, core.Size{Height: 420})
	widgets.SetPreferredSize(u.peBox, core.Size{Height: 420})

	u.left.AddAll(u.itemLab, u.itemBox)
	u.right.AddAll(u.peLab, u.peBox)
	pan.AddAll(u.left, u.right)
	return pan
}

// fillInit 填充初始文本。
func (u *probeUI) fillInit() {
	dir := pickDir()
	u.pathBox.SetText(dir)
	u.pathLab.SetText("当前文件：" + dir)
	u.sumBox.SetText("请先选择一个 JSON 文件，然后点击“开始解析”。")
	u.itemBox.SetText("暂无 RuleItem 数据。")
	u.peBox.SetText("暂无 WinPEImg 数据。")
}

// onSize 处理窗口布局。
func (u *probeUI) onSize(size core.Size) {
	if u.root == nil || u.app == nil {
		return
	}

	gap := u.app.DP(14)
	mar := u.app.DP(18)
	topH := u.app.DP(150)
	midH := u.app.DP(230)

	u.root.SetBounds(widgets.Rect{W: size.Width, H: size.Height})
	u.top.SetBounds(widgets.Rect{
		X: mar, Y: mar, W: size.Width - mar*2, H: topH,
	})
	u.mid.SetBounds(widgets.Rect{
		X: mar, Y: mar + topH + gap, W: size.Width - mar*2, H: midH,
	})

	botY := mar + topH + gap + midH + gap
	botH := size.Height - botY - mar
	if botH < u.app.DP(260) {
		botH = u.app.DP(260)
	}
	u.bot.SetBounds(widgets.Rect{
		X: mar, Y: botY, W: size.Width - mar*2, H: botH,
	})

	left, right := calcBot(size, mar, gap, topH, midH)
	u.left.SetBounds(left)
	u.right.SetBounds(right)
}

// calcBot 计算底部左右两栏的绝对位置。
func calcBot(size core.Size, mar, gap, topH, midH int32) (widgets.Rect, widgets.Rect) {
	botY := mar + topH + gap + midH + gap
	botH := size.Height - botY - mar
	if botH < 260 {
		botH = 260
	}
	botW := size.Width - mar*2
	leftW := (botW - gap) / 2
	rightW := botW - gap - leftW

	left := widgets.Rect{
		X: mar,
		Y: botY,
		W: leftW,
		H: botH,
	}
	right := widgets.Rect{
		X: mar + leftW + gap,
		Y: botY,
		W: rightW,
		H: botH,
	}
	return left, right
}

// pickFile 打开原生文件选择器。
func (u *probeUI) pickFile() {
	path, err := sysapi.OpenFile(u.app, sysapi.Options{
		Title:       "选择要测试的 JSON 文件",
		ButtonLabel: "选择",
		InitialPath: pickDir(),
		Filters: []sysapi.FileFilter{
			{Name: "JSON Files", Pattern: "*.json"},
			{Name: "All Files", Pattern: "*.*"},
		},
	})
	if err != nil {
		u.showErr(err)
		return
	}
	if strings.TrimSpace(path) == "" {
		return
	}
	u.pathBox.SetText(path)
	u.pathLab.SetText("当前文件：" + path)
	u.statLab.SetText("状态：已选择，等待解析")
}

// startLoad 异步启动解析。
func (u *probeUI) startLoad() {
	path := strings.TrimSpace(u.pathBox.TextValue())
	if path == "" {
		u.statLab.SetText("状态：请先选择文件")
		return
	}
	u.setBusy(true)
	go func() {
		out, err := parseFile(path)
		if err != nil {
			_ = u.app.Post(func() {
				u.setBusy(false)
				u.showErr(err)
			})
			return
		}
		_ = u.app.Post(func() {
			u.setBusy(false)
			u.showRes(path, out)
		})
	}()
}

// setBusy 更新按钮状态和提示。
func (u *probeUI) setBusy(busy bool) {
	u.pickBtn.SetEnabled(!busy)
	u.loadBtn.SetEnabled(!busy)
	if busy {
		u.statLab.SetText("状态：解析中，请稍候...")
	}
}

// showErr 显示失败结果。
func (u *probeUI) showErr(err error) {
	msg := strings.TrimSpace(err.Error())
	u.statLab.SetText("状态：解析失败")
	u.sumBox.SetText("解析失败：\r\n" + msg)
	u.itemBox.SetText("无 RuleItem 结果。")
	u.peBox.SetText("无 WinPEImg 结果。")
}

// showRes 显示成功结果。
func (u *probeUI) showRes(path string, out *loadRes) {
	u.pathLab.SetText("当前文件：" + path)
	u.statLab.SetText(fmt.Sprintf("状态：解析成功，RuleItem %d 条，WinPEImg %d 条", len(out.items), len(out.pes)))
	u.sumBox.SetText(buildSum(out.res))
	u.itemBox.SetText(buildRule(out.items))
	u.peBox.SetText(buildPE(out.pes))
}

// parseFile 调用 data 包解析指定文件。
func parseFile(path string) (*loadRes, error) {
	res, err := data.ParseRuleFile(path)
	if err != nil {
		return nil, err
	}
	items, err := data.ParseRuleItems(path)
	if err != nil {
		return nil, err
	}
	pes, err := data.ParseRuleWinPEs(path)
	if err != nil {
		return nil, err
	}
	return &loadRes{
		res:   res,
		items: items,
		pes:   pes,
	}, nil
}

// buildSum 渲染解析摘要。
func buildSum(res *data.RuleParseResult) string {
	if res == nil {
		return "无摘要数据。"
	}
	var sb strings.Builder
	sb.WriteString("摘要\r\n")
	sb.WriteString("----\r\n")
	sb.WriteString("RulePath: " + res.RulePath + "\r\n")
	sb.WriteString("Source: " + res.Source + "\r\n")
	sb.WriteString(fmt.Sprintf("Rank: %d\r\n", res.Rank))
	sb.WriteString(fmt.Sprintf("Enabled: %t\r\n", res.Enabled))
	sb.WriteString("Mode: " + res.Mode + "\r\n")
	sb.WriteString("System: " + res.System + "\r\n")
	sb.WriteString("SizeUnit: " + res.SizeUnit + "\r\n")
	sb.WriteString(fmt.Sprintf("Items: %d\r\n", len(res.Items)))
	return sb.String()
}

// buildRule 渲染 RuleItem 列表。
func buildRule(items []data.RuleItem) string {
	if len(items) == 0 {
		return "无 RuleItem 数据。"
	}
	var sb strings.Builder
	for i, it := range items {
		sb.WriteString(fmt.Sprintf("[%d]\r\n", i+1))
		sb.WriteString("ID: " + it.ID + "\r\n")
		sb.WriteString("Source: " + it.Source + "\r\n")
		sb.WriteString("System: " + it.System + "\r\n")
		sb.WriteString("Name: " + it.Name + "\r\n")
		sb.WriteString("FileName: " + it.FileName + "\r\n")
		sb.WriteString("Desc: " + it.Description + "\r\n")
		sb.WriteString("Date: " + it.PublishDate + "\r\n")
		sb.WriteString("Language: " + it.Language + "\r\n")
		sb.WriteString("Arch: " + it.Arch + "\r\n")
		sb.WriteString("Edition: " + it.Edition + "\r\n")
		sb.WriteString("Ver: " + it.Ver + "\r\n")
		sb.WriteString(fmt.Sprintf("Index: %d\r\n", it.Index))
		sb.WriteString("Size: " + fmtSize(it.Size, it.SizeUnit) + "\r\n")
		sb.WriteString("SHA1: " + it.Hash.Sha1 + "\r\n")
		sb.WriteString("SHA256: " + it.Hash.Sha256 + "\r\n")
		sb.WriteString("MD5: " + it.Hash.MD5 + "\r\n")
		sb.WriteString("LinkType: " + it.Link.Type + "\r\n")
		sb.WriteString("Links:\r\n" + fmtLinks(it.Link.Links))
		if strings.TrimSpace(it.Offset) != "" {
			sb.WriteString("Offset: " + it.Offset + "\r\n")
		}
		if i < len(items)-1 {
			sb.WriteString("\r\n")
		}
	}
	return sb.String()
}

// buildPE 渲染 WinPEImg 列表。
func buildPE(items []data.WinPEImg) string {
	if len(items) == 0 {
		return "无 WinPEImg 数据。"
	}
	var sb strings.Builder
	for i, it := range items {
		sb.WriteString(fmt.Sprintf("[%d]\r\n", i+1))
		sb.WriteString("Name: " + it.Name + "\r\n")
		sb.WriteString("Arch: " + it.Arch + "\r\n")
		sb.WriteString("Group: " + it.Grp + "\r\n")
		sb.WriteString("Ver: " + it.Ver + "\r\n")
		sb.WriteString(fmt.Sprintf("Size: %.2f\r\n", it.Sz))
		sb.WriteString("MD5: " + it.MD5 + "\r\n")
		sb.WriteString("Offset: " + fmtOff(it.OffsetStart, it.OffsetEnd) + "\r\n")
		sb.WriteString("Links:\r\n" + fmtLinks(it.Links))
		if i < len(items)-1 {
			sb.WriteString("\r\n")
		}
	}
	return sb.String()
}

// fmtSize 统一格式化大小文本。
func fmtSize(size float64, unit string) string {
	unit = strings.TrimSpace(unit)
	if unit == "" {
		return fmt.Sprintf("%.2f", size)
	}
	return fmt.Sprintf("%.2f %s", size, unit)
}

// fmtOff 格式化偏移范围。
func fmtOff(start, end int64) string {
	if start == 0 && end == 0 {
		return "-"
	}
	return fmt.Sprintf("0x%X | 0x%X", start, end)
}

// fmtLinks 把链接列表渲染成多行文本。
func fmtLinks(links []string) string {
	if len(links) == 0 {
		return "-\r\n"
	}
	var sb strings.Builder
	for i, one := range links {
		sb.WriteString(fmt.Sprintf("  %d. %s\r\n", i+1, one))
	}
	return sb.String()
}

// newLab 创建一个基础标签。
func (u *probeUI) newLab(id, txt string, size int32, weight int32) *widgets.Label {
	lab := widgets.NewLabel(id, txt)
	lab.SetStyle(widgets.TextStyle{
		Font:   widgets.FontSpec{Face: "Microsoft YaHei UI", SizeDP: size, Weight: weight},
		Color:  core.RGB(20, 28, 44),
		Format: core.DTWordBreak,
	})
	return lab
}

// newBox 创建一个只读文本框。
func (u *probeUI) newBox(id string, multi bool) *widgets.EditBox {
	box := widgets.NewEditBox(id, widgets.ModeCustom)
	box.SetReadOnly(true)
	box.SetMultiline(multi)
	box.SetWordWrap(true)
	box.SetVerticalScroll(multi)
	box.SetHorizontalScroll(false)
	box.SetAcceptReturn(true)
	box.SetStyle(widgets.EditStyle{
		Background:      core.RGB(255, 255, 255),
		BorderColor:     core.RGB(205, 214, 226),
		FocusBorder:     core.RGB(64, 120, 242),
		TextColor:       core.RGB(34, 43, 59),
		PlaceholderColor: core.RGB(130, 140, 156),
		CornerRadius:    12,
	})
	return box
}

// btnSty 返回统一按钮样式。
func (u *probeUI) btnSty() widgets.ButtonStyle {
	return widgets.ButtonStyle{
		Shape:        widgets.ButtonShapePill,
		Background:   core.RGB(245, 249, 255),
		Hover:        core.RGB(226, 239, 255),
		Pressed:      core.RGB(82, 126, 230),
		Border:       core.RGB(181, 201, 236),
		TextColor:    core.RGB(27, 42, 71),
		DownText:     core.RGB(255, 255, 255),
		CornerRadius: 20,
	}
}

// boxSty 返回统一面板样式。
func (u *probeUI) boxSty() widgets.PanelStyle {
	return widgets.PanelStyle{
		Background:   core.RGB(255, 255, 255),
		BorderColor:  core.RGB(216, 224, 235),
		BorderWidth:  1,
		CornerRadius: 16,
	}
}

// pickDir 返回默认打开目录。
func pickDir() string {
	_, cur, _, ok := runtime.Caller(0)
	if ok {
		base := filepath.Dir(cur)
		root := filepath.Clean(filepath.Join(base, "..", "..", "rules", "core"))
		return root
	}
	return "."
}
