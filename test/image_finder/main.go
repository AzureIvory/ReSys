//go:build windows

package main

import (
	"ReSys/src/dism"
	"ReSys/src/image"
	"fmt"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/AzureIvory/winui/core"
	"github.com/AzureIvory/winui/widgets"
)

type imgRow struct {
	path string
	file string
	sys  string
}

type imgWin struct {
	app   *core.App
	scene *widgets.Scene
	root  *widgets.Panel

	scanBtn *widgets.Button
	statLb  *widgets.Label
	listLb  *widgets.ListBox
	idxCb   *widgets.ComboBox
	idxLb   *widgets.Label
	pathLb  *widgets.Label
	fileLb  *widgets.Label
	sysLb   *widgets.Label
	nameLb  *widgets.Label
	edtnLb  *widgets.Label
	archLb  *widgets.Label
	flagLb  *widgets.Label
	sizeLb  *widgets.Label
	metaLb  *widgets.Label
	descLb  *widgets.Label

	pathEd *widgets.EditBox
	fileEd *widgets.EditBox
	sysEd  *widgets.EditBox
	nameEd *widgets.EditBox
	edtnEd *widgets.EditBox
	archEd *widgets.EditBox
	flagEd *widgets.EditBox
	sizeEd *widgets.EditBox
	descEd *widgets.EditBox
	metaEd *widgets.EditBox

	rows []imgRow
	info []dism.ImageMeta

	busy atomic.Bool
	tok  atomic.Uint64
}

func main() {
	ui := &imgWin{}

	opts := core.Options{
		ClassName:      "ReSysImgFind",
		Title:          "ReSys 本地镜像测试",
		Width:          1380,
		Height:         860,
		MinWidth:       1100,
		MinHeight:      700,
		Style:          core.DefaultWindowStyle,
		ExStyle:        core.DefaultWindowExStyle,
		Cursor:         core.CursorArrow,
		Background:     core.RGB(245, 248, 252),
		DoubleBuffered: true,
		RenderMode:     core.RenderModeAuto,
	}

	widgets.BindScene(&opts, widgets.SceneHooks{
		OnCreate: ui.onMake,
		OnResize: ui.onSize,
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

// onMake 初始化窗口控件。
func (u *imgWin) onMake(app *core.App, scene *widgets.Scene) error {
	u.app = app
	u.scene = scene
	u.buildUI()
	u.onSize(app, scene, app.ClientSize())
	u.setStat("点击“开始寻找”扫描本地镜像。列表支持 ISO/WIM/ESD。")
	return nil
}

// onSize 根据窗口大小重排布局。
func (u *imgWin) onSize(_ *core.App, _ *widgets.Scene, sz core.Size) {
	if u.root == nil {
		return
	}
	u.root.SetBounds(core.Rect{X: 0, Y: 0, W: sz.Width, H: sz.Height})

	m := int32(18)
	g := int32(12)
	btnW := int32(132)
	btnH := int32(38)

	topY := m
	u.scanBtn.SetBounds(core.Rect{X: m, Y: topY, W: btnW, H: btnH})
	u.statLb.SetBounds(core.Rect{
		X: m + btnW + g,
		Y: topY + 2,
		W: sz.Width - (m + btnW + g) - m,
		H: btnH + 14,
	})

	areaY := topY + btnH + g
	areaH := sz.Height - areaY - m
	if areaH < 0 {
		areaH = 0
	}

	leftW := (sz.Width - m*2 - g) / 2
	if leftW < 440 {
		leftW = 440
	}
	if leftW > 700 {
		leftW = 700
	}
	rightX := m + leftW + g
	rightW := sz.Width - rightX - m
	if rightW < 320 {
		rightW = 320
	}

	u.listLb.SetBounds(core.Rect{X: m, Y: areaY, W: leftW, H: areaH})

	lw := int32(66)
	eh := int32(34)
	ey := areaY

	// 右侧标签由独立 Label 控件承载，这里只摆放输入框。
	u.idxCb.SetBounds(core.Rect{X: rightX + lw + g, Y: ey, W: rightW - lw - g, H: eh + 4})
	ey += eh + 12
	u.pathEd.SetBounds(core.Rect{X: rightX + lw + g, Y: ey, W: rightW - lw - g, H: eh})
	ey += eh + 8
	u.fileEd.SetBounds(core.Rect{X: rightX + lw + g, Y: ey, W: rightW - lw - g, H: eh})
	ey += eh + 8
	u.sysEd.SetBounds(core.Rect{X: rightX + lw + g, Y: ey, W: rightW - lw - g, H: eh})
	ey += eh + 8
	u.nameEd.SetBounds(core.Rect{X: rightX + lw + g, Y: ey, W: rightW - lw - g, H: eh})
	ey += eh + 8
	u.edtnEd.SetBounds(core.Rect{X: rightX + lw + g, Y: ey, W: rightW - lw - g, H: eh})
	ey += eh + 8
	u.archEd.SetBounds(core.Rect{X: rightX + lw + g, Y: ey, W: rightW - lw - g, H: eh})
	ey += eh + 8
	u.flagEd.SetBounds(core.Rect{X: rightX + lw + g, Y: ey, W: rightW - lw - g, H: eh})
	ey += eh + 8
	u.sizeEd.SetBounds(core.Rect{X: rightX + lw + g, Y: ey, W: rightW - lw - g, H: eh})
	ey += eh + 8

	descH := int32(90)
	metaH := areaY + areaH - ey - 8 - descH
	if metaH < 80 {
		metaH = 80
	}
	u.metaEd.SetBounds(core.Rect{X: rightX + lw + g, Y: ey, W: rightW - lw - g, H: metaH})
	ey += metaH + 8
	u.descEd.SetBounds(core.Rect{X: rightX + lw + g, Y: ey, W: rightW - lw - g, H: descH})

	// 右侧标签位置
	u.idxLb.SetBounds(core.Rect{X: rightX, Y: areaY + 8, W: lw, H: 24})
	u.pathLb.SetBounds(core.Rect{X: rightX, Y: areaY + (eh + 12) + 8, W: lw, H: 24})
	u.fileLb.SetBounds(core.Rect{X: rightX, Y: areaY + (eh + 12) + (eh + 8) + 8, W: lw, H: 24})
	u.sysLb.SetBounds(core.Rect{X: rightX, Y: areaY + (eh + 12) + (eh+8)*2 + 8, W: lw, H: 24})
	u.nameLb.SetBounds(core.Rect{X: rightX, Y: areaY + (eh + 12) + (eh+8)*3 + 8, W: lw, H: 24})
	u.edtnLb.SetBounds(core.Rect{X: rightX, Y: areaY + (eh + 12) + (eh+8)*4 + 8, W: lw, H: 24})
	u.archLb.SetBounds(core.Rect{X: rightX, Y: areaY + (eh + 12) + (eh+8)*5 + 8, W: lw, H: 24})
	u.flagLb.SetBounds(core.Rect{X: rightX, Y: areaY + (eh + 12) + (eh+8)*6 + 8, W: lw, H: 24})
	u.sizeLb.SetBounds(core.Rect{X: rightX, Y: areaY + (eh + 12) + (eh+8)*7 + 8, W: lw, H: 24})
	u.metaLb.SetBounds(core.Rect{X: rightX, Y: areaY + (eh + 12) + (eh+8)*8 + 8, W: lw, H: 24})
	u.descLb.SetBounds(core.Rect{X: rightX, Y: ey + 8, W: lw, H: 24})
}

func (u *imgWin) buildUI() {
	root := widgets.NewPanel("root")
	root.SetStyle(widgets.PanelStyle{Background: core.RGB(245, 248, 252)})
	root.SetLayout(widgets.AbsoluteLayout{})

	u.scanBtn = widgets.NewButton("scanBtn", "开始寻找", widgets.ModeNative)
	u.scanBtn.SetOnClick(u.onScan)

	u.statLb = widgets.NewLabel("statLb", "")
	u.statLb.SetMultiline(true)
	u.statLb.SetWordWrap(true)
	u.statLb.SetStyle(widgets.TextStyle{
		Font:   widgets.FontSpec{Face: "Microsoft YaHei UI", SizeDP: 13},
		Color:  core.RGB(71, 85, 105),
		Format: core.DTWordBreak,
	})

	u.listLb = widgets.NewListBox("imgList")
	u.listLb.SetOnChange(u.onPick)
	u.listLb.SetStyle(widgets.ListStyle{ItemHeightDP: 30})

	u.idxCb = widgets.NewComboBox("idxCb", widgets.ModeNative)
	u.idxCb.SetOnChange(u.onIdx)
	u.idxLb = mkLb("idxLb", "索引")
	u.pathLb = mkLb("pathLb", "路径")
	u.fileLb = mkLb("fileLb", "文件")
	u.sysLb = mkLb("sysLb", "系统")
	u.nameLb = mkLb("nameLb", "名称")
	u.edtnLb = mkLb("edtnLb", "版本")
	u.archLb = mkLb("archLb", "架构")
	u.flagLb = mkLb("flagLb", "标识")
	u.sizeLb = mkLb("sizeLb", "大小")
	u.metaLb = mkLb("metaLb", "扩展")
	u.descLb = mkLb("descLb", "描述")

	u.pathEd = roBox("pathEd", false)
	u.fileEd = roBox("fileEd", false)
	u.sysEd = roBox("sysEd", false)
	u.nameEd = roBox("nameEd", false)
	u.edtnEd = roBox("edtnEd", false)
	u.archEd = roBox("archEd", false)
	u.flagEd = roBox("flagEd", false)
	u.sizeEd = roBox("sizeEd", false)
	u.metaEd = roBox("metaEd", true)
	u.descEd = roBox("descEd", true)

	root.AddAll(
		u.scanBtn,
		u.statLb,
		u.listLb,
		u.idxCb,
		u.idxLb,
		u.pathLb,
		u.fileLb,
		u.sysLb,
		u.nameLb,
		u.edtnLb,
		u.archLb,
		u.flagLb,
		u.sizeLb,
		u.metaLb,
		u.descLb,
		u.pathEd,
		u.fileEd,
		u.sysEd,
		u.nameEd,
		u.edtnEd,
		u.archEd,
		u.flagEd,
		u.sizeEd,
		u.metaEd,
		u.descEd,
	)

	u.root = root
	u.scene.Root().Add(root)
}

func roBox(id string, mul bool) *widgets.EditBox {
	ed := widgets.NewEditBox(id, widgets.ModeNative)
	ed.SetReadOnly(true)
	if mul {
		ed.SetMultiline(true)
	}
	return ed
}

func mkLb(id, txt string) *widgets.Label {
	lb := widgets.NewLabel(id, txt)
	lb.SetStyle(widgets.TextStyle{
		Font:   widgets.FontSpec{Face: "Microsoft YaHei UI", SizeDP: 13, Weight: 600},
		Color:  core.RGB(30, 41, 59),
		Format: core.DTVCenter | core.DTSingleLine,
	})
	return lb
}

// onScan 扫描本地镜像并填充列表。
func (u *imgWin) onScan() {
	if !u.busy.CompareAndSwap(false, true) {
		return
	}
	u.scanBtn.SetEnabled(false)
	u.listLb.SetItems(nil)
	u.idxCb.SetItems(nil)
	u.rows = nil
	u.info = nil
	u.setInfo(nil)
	u.setStat("正在扫描本地镜像...")

	go func() {
		paths, err := image.Findimg()
		rows := make([]imgRow, 0, len(paths))
		for _, p := range paths {
			sys := "未知系统"
			if infos, e := image.DetectImageInfos(p); e == nil {
				sys = sysName(image.DetectTargetFromInfos(infos))
			}
			rows = append(rows, imgRow{
				path: p,
				file: filepath.Base(p),
				sys:  sys,
			})
		}

		u.post(func() {
			u.busy.Store(false)
			u.scanBtn.SetEnabled(true)
			u.rows = rows
			u.fillList(rows)

			switch {
			case err != nil && len(rows) == 0:
				u.setStat("扫描失败: " + err.Error())
			case err != nil && len(rows) > 0:
				u.setStat(fmt.Sprintf("扫描完成，共 %d 个镜像（部分卷访问失败: %v）", len(rows), err))
			default:
				u.setStat(fmt.Sprintf("扫描完成，共找到 %d 个镜像。", len(rows)))
			}
		})
	}()
}

func (u *imgWin) fillList(rows []imgRow) {
	items := make([]widgets.ListItem, 0, len(rows))
	for _, r := range rows {
		txt := fmt.Sprintf("%s | %s | %s", r.file, r.sys, r.path)
		items = append(items, widgets.ListItem{
			Value: r.path,
			Text:  txt,
		})
	}
	u.listLb.SetItems(items)
	if len(items) > 0 {
		u.listLb.SetSelected(0)
	}
}

// onPick 点选镜像后自动解析索引和详情。
func (u *imgWin) onPick(idx int, it widgets.ListItem) {
	if idx < 0 || idx >= len(u.rows) {
		return
	}
	row := u.rows[idx]
	u.pathEd.SetText(row.path)
	u.fileEd.SetText(row.file)
	u.sysEd.SetText(row.sys)
	u.idxCb.SetItems(nil)
	u.info = nil
	u.setInfo(nil)
	u.setStat("正在解析镜像索引...")

	tk := u.tok.Add(1)
	path := it.Value
	go func() {
		infos, err := image.DetectImageInfos(path)
		u.post(func() {
			if tk != u.tok.Load() {
				return
			}
			if err != nil {
				u.setStat("解析失败: " + err.Error())
				return
			}
			u.info = infos
			u.fillIdx(infos)
			u.setStat(fmt.Sprintf("解析完成，共 %d 个索引。", len(infos)))
		})
	}()
}

func (u *imgWin) fillIdx(infos []dism.ImageMeta) {
	items := make([]widgets.ListItem, 0, len(infos))
	for i := range infos {
		inf := infos[i]
		txt := fmt.Sprintf(
			"Index %d | %s | %s | %s | %s",
			inf.Index,
			nz(inf.Name),
			nz(inf.Arch),
			nz(inf.Edition),
			nz(inf.Flags),
		)
		items = append(items, widgets.ListItem{
			Value: fmt.Sprintf("%d", inf.Index),
			Text:  txt,
		})
	}
	u.idxCb.SetItems(items)
	if len(items) > 0 {
		u.idxCb.SetSelected(0)
	}
}

func (u *imgWin) onIdx(idx int, _ widgets.ListItem) {
	if idx < 0 || idx >= len(u.info) {
		u.setInfo(nil)
		return
	}
	u.setInfo(&u.info[idx])
}

func (u *imgWin) setInfo(inf *dism.ImageMeta) {
	if inf == nil {
		u.nameEd.SetText("")
		u.edtnEd.SetText("")
		u.archEd.SetText("")
		u.flagEd.SetText("")
		u.sizeEd.SetText("")
		u.descEd.SetText("")
		u.metaEd.SetText("")
		return
	}
	u.nameEd.SetText(inf.Name)
	u.edtnEd.SetText(inf.Edition)
	u.archEd.SetText(inf.Arch)
	u.flagEd.SetText(inf.Flags)
	if strings.TrimSpace(inf.Size) != "" {
		u.sizeEd.SetText(inf.Size)
	} else {
		u.sizeEd.SetText(fmt.Sprintf("%d", inf.SizeBytes))
	}
	u.descEd.SetText(inf.Description)
	u.metaEd.SetText(fmt.Sprintf(
		"Index: %d\r\nInstallation: %s\r\nSystemRoot: %s\r\nIsOS: %t",
		inf.Index,
		inf.Installation,
		inf.SystemRoot,
		inf.IsOS,
	))
}

func (u *imgWin) post(fn func()) {
	if u.app == nil || fn == nil {
		return
	}
	_ = u.app.Post(fn)
}

func (u *imgWin) setStat(s string) {
	u.statLb.SetText(strings.TrimSpace(s))
}

func nz(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "-"
	}
	return s
}

func sysName(code string) string {
	switch strings.ToLower(strings.TrimSpace(code)) {
	case "win7":
		return "Windows 7"
	case "win10":
		return "Windows 10"
	case "win11":
		return "Windows 11"
	default:
		return "未知系统"
	}
}
