//go:build windows

package main

import (
	"ReSys/src/download"
	"context"
	"fmt"
	neturl "net/url"
	"path"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/AzureIvory/winui/core"
	"github.com/AzureIvory/winui/widgets"
)

type dlKind uint8

const (
	kindBad dlKind = iota
	kindURL
	kindBT
)

type dlJob struct {
	kind dlKind
	link string
	dst  string
}

type dlUI struct {
	app   *core.App
	scene *widgets.Scene
	root  *widgets.Panel

	linkLb *widgets.Label
	linkEd *widgets.EditBox
	dirLb  *widgets.Label
	dirEd  *widgets.EditBox
	statLb *widgets.Label
	prog   *widgets.ProgressBar
	goBtn  *widgets.Button

	busy atomic.Bool
}

type progCut struct {
	pct int32
	at  time.Time
}

func main() {
	ui := &dlUI{}

	opts := core.Options{
		ClassName:      "ReSysTestDL",
		Title:          "ReSys 下载测试",
		Width:          860,
		Height:         230,
		MinWidth:       720,
		MinHeight:      230,
		Style:          core.DefaultWindowStyle,
		ExStyle:        core.DefaultWindowExStyle,
		Cursor:         core.CursorArrow,
		Background:     core.RGB(246, 248, 251),
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
func (u *dlUI) onMake(app *core.App, scene *widgets.Scene) error {
	u.app = app
	u.scene = scene
	u.buildUI()
	u.onSize(app, scene, app.ClientSize())
	u.setStat("支持 HTTP/HTTPS 和 magnet。下载路径只填目录，URL 会自动使用链接文件名。")
	return nil
}

// onSize 负责窗口重排版。
func (u *dlUI) onSize(_ *core.App, _ *widgets.Scene, size core.Size) {
	if u.root == nil {
		return
	}

	u.root.SetBounds(core.Rect{X: 0, Y: 0, W: size.Width, H: size.Height})

	m := int32(24)
	g := int32(12)
	lw := int32(92)
	bh := int32(36)
	bw := int32(118)
	pw := size.Width - m*2
	if pw < 0 {
		pw = 0
	}
	ew := pw - lw - g
	if ew < 0 {
		ew = 0
	}

	y := m
	u.linkLb.SetBounds(core.Rect{X: m, Y: y, W: lw, H: bh})
	u.linkEd.SetBounds(core.Rect{X: m + lw + g, Y: y, W: ew, H: bh})

	y += bh + g
	u.dirLb.SetBounds(core.Rect{X: m, Y: y, W: lw, H: bh})
	u.dirEd.SetBounds(core.Rect{X: m + lw + g, Y: y, W: ew, H: bh})

	y += bh + g
	u.goBtn.SetBounds(core.Rect{X: size.Width - m - bw, Y: y, W: bw, H: bh})
	u.prog.SetBounds(core.Rect{X: m, Y: y + 12, W: size.Width - m*3 - bw, H: 24})

	y += bh + g
	u.statLb.SetBounds(core.Rect{
		X: m,
		Y: y,
		W: size.Width - m*2,
		H: size.Height - y - m,
	})
}

// buildUI 创建界面控件。
func (u *dlUI) buildUI() {
	root := widgets.NewPanel("root")
	root.SetStyle(widgets.PanelStyle{Background: core.RGB(246, 248, 251)})
	root.SetLayout(widgets.AbsoluteLayout{})

	u.linkLb = widgets.NewLabel("linkLb", "镜像链接")
	u.linkLb.SetStyle(textSty())

	u.linkEd = widgets.NewEditBox("linkEd", widgets.ModeNative)
	u.linkEd.SetPlaceholder("输入 HTTP/HTTPS 或 magnet 链接")

	u.dirLb = widgets.NewLabel("dirLb", "下载目录")
	u.dirLb.SetStyle(textSty())

	u.dirEd = widgets.NewEditBox("dirEd", widgets.ModeNative)
	u.dirEd.SetPlaceholder("只输入下载目录")

	u.goBtn = widgets.NewButton("goBtn", "开始下载", widgets.ModeNative)
	u.goBtn.SetOnClick(u.onGo)

	u.prog = widgets.NewProgressBar("prog")
	u.prog.SetStyle(widgets.ProgressStyle{ShowPercent: true})
	u.prog.SetValue(0)

	u.statLb = widgets.NewLabel("statLb", "")
	u.statLb.SetMultiline(true)
	u.statLb.SetWordWrap(true)
	u.statLb.SetStyle(widgets.TextStyle{
		Font:   widgets.FontSpec{Face: "Microsoft YaHei UI", SizeDP: 13},
		Color:  core.RGB(71, 85, 105),
		Format: 0,
	})

	root.AddAll(
		u.linkLb,
		u.linkEd,
		u.dirLb,
		u.dirEd,
		u.goBtn,
		u.prog,
		u.statLb,
	)

	u.root = root
	u.scene.Root().Add(root)
}

// onGo 收集参数并启动下载。
func (u *dlUI) onGo() {
	if !u.busy.CompareAndSwap(false, true) {
		return
	}

	job, err := mkJob(
		u.linkEd.TextValue(),
		u.dirEd.TextValue(),
	)
	if err != nil {
		u.busy.Store(false)
		u.showErr(err.Error())
		return
	}

	u.lockUI(true)
	u.setProg(0)
	u.setStat(startMsg(job))

	go u.runJob(job)
}

// runJob 在后台执行下载任务。
func (u *dlUI) runJob(job dlJob) {
	var (
		dst string
		err error
	)

	switch job.kind {
	case kindURL:
		dst, err = u.runURL(job)
	case kindBT:
		dst, err = u.runBT(job)
	default:
		err = fmt.Errorf("不支持的下载类型")
	}

	u.post(func() {
		u.lockUI(false)
		u.busy.Store(false)
		if err != nil {
			u.setStat("下载失败: " + err.Error())
			u.showErr(err.Error())
			return
		}
		u.setProg(100)
		u.setStat("下载完成: " + dst)
	})
}

// runURL 复用现有直链下载器。
func (u *dlUI) runURL(job dlJob) (string, error) {
	var cut progCut

	opt := download.NewNativeDownloadOptions(
		job.link,
		job.dst,
		func(pct float64, speed int64) {
			pp := clampPct(pct)
			msg := fmt.Sprintf(
				"直链下载 %d%%  %s",
				pp,
				fmtRate(speed),
			)
			u.push(&cut, pp, msg)
		},
	)

	res, err := download.Download(context.Background(), opt)
	if err != nil {
		return "", err
	}
	if res != nil && strings.TrimSpace(res.Destination) != "" {
		return res.Destination, nil
	}
	return job.dst, nil
}

// runBT 复用现有 BT 下载器。
func (u *dlUI) runBT(job dlJob) (string, error) {
	var cut progCut

	dst, err := download.DownloadBT(job.link, job.dst, func(
		pct int,
		speed, done, total int64,
	) {
		pp := clampInt(pct, 0, 100)
		msg := fmt.Sprintf(
			"BT 下载 %d%%  %s  %s/%s",
			pp,
			fmtRate(speed),
			fmtSize(done),
			fmtSize(total),
		)
		u.push(&cut, int32(pp), msg)
	})
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(dst) == "" {
		return job.dst, nil
	}
	return dst, nil
}

// lockUI 控制下载中的输入状态。
func (u *dlUI) lockUI(busy bool) {
	u.linkEd.SetEnabled(!busy)
	u.dirEd.SetEnabled(!busy)
	u.goBtn.SetEnabled(!busy)
	if busy {
		u.goBtn.SetText("下载中")
		return
	}
	u.goBtn.SetText("开始下载")
}

// setProg 更新进度条。
func (u *dlUI) setProg(pct int32) {
	u.prog.SetValue(pct)
}

// setStat 更新状态文本。
func (u *dlUI) setStat(msg string) {
	u.statLb.SetText(strings.TrimSpace(msg))
}

// showErr 弹出错误提示。
func (u *dlUI) showErr(msg string) {
	u.setStat("错误: " + strings.TrimSpace(msg))
	if u.app == nil {
		return
	}
	_, _ = u.app.MessageBox(
		"下载失败",
		msg,
		core.MessageBoxOK|core.MessageBoxIconError,
		0,
	)
}

// post 把回调切回 UI 线程。
func (u *dlUI) post(fn func()) {
	if u.app == nil || fn == nil {
		return
	}
	_ = u.app.Post(fn)
}

// push 节流进度刷新，避免刷屏过密。
func (u *dlUI) push(cut *progCut, pct int32, msg string) {
	if cut == nil {
		return
	}

	now := time.Now()
	if pct != 100 && cut.pct == pct && now.Sub(cut.at) < 150*time.Millisecond {
		return
	}

	cut.pct = pct
	cut.at = now
	u.post(func() {
		u.setProg(pct)
		u.setStat(msg)
	})
}

func textSty() widgets.TextStyle {
	return widgets.TextStyle{
		Font:   widgets.FontSpec{Face: "Microsoft YaHei UI", SizeDP: 14, Weight: 600},
		Color:  core.RGB(15, 23, 42),
		Format: core.DTVCenter | core.DTSingleLine,
	}
}

func startMsg(job dlJob) string {
	if job.kind == kindBT {
		return "准备开始 BT 下载: " + job.dst
	}
	return "准备开始直链下载: " + job.dst
}

func mkJob(link, dir string) (dlJob, error) {
	link = strings.TrimSpace(link)
	if link == "" {
		return dlJob{}, fmt.Errorf("镜像链接不能为空")
	}

	kind := pickKind(link)
	if kind == kindBad {
		return dlJob{}, fmt.Errorf("只支持 HTTP/HTTPS 或 magnet 链接")
	}

	dst, err := fixDst(kind, link, dir)
	if err != nil {
		return dlJob{}, err
	}

	return dlJob{
		kind: kind,
		link: link,
		dst:  dst,
	}, nil
}

func pickKind(src string) dlKind {
	src = strings.ToLower(strings.TrimSpace(src))
	switch {
	case strings.HasPrefix(src, "http://"), strings.HasPrefix(src, "https://"):
		return kindURL
	case strings.HasPrefix(src, "magnet:?xt=urn:btih:"):
		return kindBT
	default:
		return kindBad
	}
}

// fixDst 把目录输入转换成实际下载目标。
func fixDst(kind dlKind, link, dir string) (string, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return "", fmt.Errorf("下载目录不能为空")
	}

	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("解析下载目录失败: %w", err)
	}
	abs = filepath.Clean(abs)

	if kind == kindBT {
		return abs, nil
	}

	name, err := urlName(link)
	if err != nil {
		return "", err
	}
	return filepath.Join(abs, name), nil
}

// urlName 从下载链接里提取文件名。
func urlName(link string) (string, error) {
	u, err := neturl.Parse(strings.TrimSpace(link))
	if err != nil {
		return "", fmt.Errorf("解析下载链接失败: %w", err)
	}

	name := strings.TrimSpace(path.Base(u.EscapedPath()))
	if name == "" || name == "." || name == "/" {
		return "", fmt.Errorf("下载链接里没有可用的文件名")
	}

	name, err = neturl.PathUnescape(name)
	if err != nil {
		return "", fmt.Errorf("解析文件名失败: %w", err)
	}
	name = strings.TrimSpace(name)
	if name == "" || name == "." || name == ".." {
		return "", fmt.Errorf("下载链接里的文件名无效")
	}
	return name, nil
}

func clampPct(pct float64) int32 {
	if pct < 0 {
		return 0
	}
	if pct > 100 {
		return 100
	}
	return int32(pct + 0.5)
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func fmtRate(v int64) string {
	if v <= 0 {
		return "0 B/s"
	}
	return fmtSize(v) + "/s"
}

func fmtSize(v int64) string {
	if v <= 0 {
		return "0 B"
	}

	val := float64(v)
	unit := "B"
	switch {
	case v >= 1<<40:
		val /= 1 << 40
		unit = "TB"
	case v >= 1<<30:
		val /= 1 << 30
		unit = "GB"
	case v >= 1<<20:
		val /= 1 << 20
		unit = "MB"
	case v >= 1<<10:
		val /= 1 << 10
		unit = "KB"
	}

	if unit == "B" {
		return fmt.Sprintf("%d %s", v, unit)
	}
	return fmt.Sprintf("%.1f %s", val, unit)
}
