package main

import (
	_ "embed"
	"fmt"
	"time"

	"github.com/twgh/xcgui/app"
	"github.com/twgh/xcgui/font"
	"github.com/twgh/xcgui/imagex"
	"github.com/twgh/xcgui/widget"
	"github.com/twgh/xcgui/window"
	"github.com/twgh/xcgui/xc"
	"github.com/twgh/xcgui/xcc"
)

//go:embed icon.ico
var icon []byte

const win7s = `<svg t="1764743418381" class="icon" viewBox="0 0 1126 1024" version="1.1" xmlns="http://www.w3.org/2000/svg" p-id="9920" width="64" height="64"><path d="M495.702538 486.212409H0.30719V175.233561c-1.638348-15.359508 3.071902-30.719017 13.311574-42.597037a60.106877 60.106877 0 0 1 40.856293-20.684138L495.600141 61.163611v425.048798z" fill="#FF4722" p-id="9921"></path><path d="M1126.26156 486.212409H570.759336V52.971873L1057.758152 0.544751c17.407443-2.150331 35.019679 3.071902 48.12646 14.437938 13.311574 11.366036 20.581741 27.647115 20.376948 44.747368v426.482352z" fill="#7FC619" p-id="9922"></path><path d="M495.702538 952.629484L54.37266 901.123932a57.546958 57.546958 0 0 1-40.549102-18.943394 53.655883 53.655883 0 0 1-13.516368-41.573069V558.709289h495.395348v393.920195z" fill="#167FF5" p-id="9923"></path><path d="M1058.577326 1023.180826l-487.81799-62.052414v-402.419123h555.502224v405.491025a54.884644 54.884644 0 0 1-18.943394 45.361748 59.185306 59.185306 0 0 1-48.74084 13.618764z" fill="#FFAC1D" p-id="9924"></path></svg>`
const win10s = `<svg t="1764742911348" class="icon" viewBox="0 0 1024 1024" version="1.1" xmlns="http://www.w3.org/2000/svg" p-id="4725" width="64" height="64"><path d="M982.366 490.72V34.869L458.75 111.205V490.72zM421.873 116.68l-380.24 55.47v318.57h380.24zM41.633 527.597V850.3l380.24 56.09V527.599zM458.75 911.866l523.616 77.266V527.598H458.75z" fill="#00A0E9" p-id="4726"></path></svg>`
const win11s = `<svg t="1764743229360" class="icon" viewBox="0 0 1024 1024" version="1.1" xmlns="http://www.w3.org/2000/svg" p-id="8563" width="64" height="64"><path d="M74.873 70.383h416.025q4.424 0 4.424 4.424v416.025q0 4.423-4.424 4.423H74.873q-4.424 0-4.424-4.423V74.807q0-4.424 4.424-4.424z" fill="#0099FF" p-id="8564"></path><path d="M530.536 70.383h421.157q1.858 0 1.858 1.858v421.156q0 1.858-1.858 1.858H530.536q-1.858 0-1.858-1.858V72.241q0-1.858 1.858-1.858z" fill="#00D9FC" p-id="8565"></path><path d="M74.873 528.745h416.025q4.424 0 4.424 4.423v416.025q0 4.424-4.424 4.424H74.873q-4.424 0-4.424-4.424V533.168q0-4.423 4.424-4.423z" fill="#0053FF" p-id="8566"></path><path d="M530.536 528.745h421.157q1.858 0 1.858 1.858v421.156q0 1.858-1.858 1.858H530.536q-1.858 0-1.858-1.858V530.603q0-1.858 1.858-1.858z" fill="#00B1EF" p-id="8567"></path></svg>`

var (
	a *app.App
	w *window.Window
	//按钮
	btn_win7  *widget.Button
	btn_win10 *widget.Button
	btn_win11 *widget.Button
	btn_win   *widget.Button

	//文本
	text_win7  *widget.ShapeText
	text_win10 *widget.ShapeText
	text_win11 *widget.ShapeText
	text_mes   *widget.ShapeText

	//gif
	gif_wait *widget.ShapeGif
	//进度条
	progbar *widget.ProgressBar
)

func Uiinit() {
	// 初始化
	app.Init()
	a = app.New(true)
	// 启用自适应DPI
	a.EnableAutoDPI(true).EnableDPI(true)
	w = window.New(0, 0, 600, 400, "ReSys", 0, xcc.Window_Style_Caption|xcc.Window_Style_Btn_Close|xcc.Window_Style_Btn_Min|xcc.Window_Style_Title|xcc.Window_Style_Icon|xcc.Window_Style_Center|xcc.Window_Style_Border|xcc.Window_Style_Drag_Border)
	w.SetBorderSize(0, 34, 0, 0)                        //边框
	w.SetTransparentType(xcc.Window_Transparent_Shadow) //透明类型
	w.SetTransparentAlpha(240)                          //透明度
	w.SetShadowInfo(8, 255, 10, false, 0)               //阴影
	windowIcon := imagex.NewByMemAdaptive(icon, 0, 0, 0, 0)
	a.SetWindowIcon(windowIcon.Handle)
	//按钮
	btn_win7 = widget.NewButton(50, 200, 100, 100, "", w.Handle)
	btn_win10 = widget.NewButton(250, 200, 100, 100, "", w.Handle)
	btn_win11 = widget.NewButton(450, 200, 100, 100, "", w.Handle)
	widget.NewButton(10, 43, 60, 30, "高级模式", w.Handle)
	btn_win7.SetIcon(imagex.NewBySvgString(win7s).EnableAutoDestroy(true).Handle)
	btn_win10.SetIcon(imagex.NewBySvgString(win10s).EnableAutoDestroy(true).Handle)
	btn_win11.SetIcon(imagex.NewBySvgString(win11s).EnableAutoDestroy(true).Handle)

	//文本
	text_win7 = widget.NewShapeText(50, 150, 100, 50, "重装 win7", w.Handle)
	text_win10 = widget.NewShapeText(250, 150, 100, 50, "重装win10", w.Handle)
	text_win11 = widget.NewShapeText(450, 150, 100, 50, "重装win11", w.Handle)
	text_mes = widget.NewShapeText(150, 50, 500, 50, "请在下方选一个系统安装", w.Handle)
	text_win7.SetFont(font.New(15).Handle)
	text_win10.SetFont(font.New(15).Handle)
	text_win11.SetFont(font.New(15).Handle)
	text_mes.SetFont(font.New(20).Handle)

	//gif
	gif_wait = widget.NewShapeGif(30, 50, 215, 80, w.Handle)
	gif_wait.SetImage(imagex.NewByFile("wait.gif").Handle)
	//进度条
	progbar = widget.NewProgressBar(300, 50, 300, 30, w.Handle)
	go test(progbar)

}

// 简单消息框
func Message(w *window.Window, title, text string) bool {
	isOK := false
	//创建消息窗口
	md := w.Msg_Create(title, text,
		xcc.MessageBox_Flag_Ok|xcc.MessageBox_Flag_Cancel,
		xcc.Window_Style_Modal)
	md.SetBorderSize(0, 34, 0, 0)                        //边框
	md.SetTransparentType(xcc.Window_Transparent_Shadow) //透明类型
	md.SetTransparentAlpha(240)                          //透明度
	md.SetShadowInfo(4, 255, 6, false, 0)                //阴影
	// 找到 确定 并返回
	for i := int32(0); i < md.GetChildCount(); i++ {
		hEle := md.GetChildByIndex(i)
		if xc.XC_IsHXCGUI(hEle, xcc.XC_BUTTON) {
			if xc.XBtn_GetText(hEle) == "确 定" {
				btn := widget.NewButtonByHandle(hEle)
				btn.AddEvent_BnClick(func(hEle int, pbHandled *bool) int {
					isOK = true
					return 0
				})
				break
			}
		}
	}

	md.DoModal()

	return isOK
}
func test(p *widget.ProgressBar) {

	s := 0
	for i := 0; i <= 100; i++ {
		q := s + i
		fmt.Println(q)
		time.Sleep(100 * time.Millisecond)
		p.SetPos(int32(q))
		p.Redraw(false)
	}

}
func Click_w7() {
	// 注册按钮事件
	btn_win7.AddEvent_BnClick(func(hEle int, pbHandled *bool) int {
		if Message(w, "提示", "重装系统将会清除C盘数据,是否继续?") {
			//点了确定后

			btn_win7.Enable(false)                                         //禁用
			btn_win7.Show(false)                                           //隐藏(无用)
			btn_win7.SetPosition(2048, 2048, true, xcc.AdjustLayout_No, 0) //移动

			btn_win7.SetPosition(50, 200, true, xcc.AdjustLayout_No, 0) //移回
		}
		return 0
	})
}
