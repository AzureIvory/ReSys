package main

import (
	_ "embed"

	"github.com/twgh/xcgui/app"
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
	win7ico  *imagex.Image
	win10ico *imagex.Image
	win11ico *imagex.Image
)

func main() {
	// 初始化
	app.Init()
	a := app.New(true)
	// 启用自适应DPI
	a.EnableAutoDPI(true).EnableDPI(true)
	// 创建窗口
	w := window.New(0, 0, 600, 400, "xcgui", 0, xcc.Window_Style_Default|xcc.Window_Style_Drag_Window)

	// 设置窗口边框大小：标题栏高度34
	w.SetBorderSize(0, 34, 0, 0)
	// 设置窗口透明类型：阴影窗口, 带透明通道, 边框阴影, 窗口透明或半透明
	w.SetTransparentType(xcc.Window_Transparent_Shadow)
	// 设置窗口透明度：255就是不透明
	w.SetTransparentAlpha(240)
	// 设置窗口阴影：阴影大小8, 深度255, 圆角内收大小10, 是否强制直角false, 阴影颜色0也就是黑色
	w.SetShadowInfo(8, 255, 10, false, 0)

	// 从内存加载图片自适应大小
	windowIcon := imagex.NewByMemAdaptive(icon, 0, 0, 0, 0)
	// 设置程序默认窗口图标
	a.SetWindowIcon(windowIcon.Handle)

	// 创建按钮
	btn := widget.NewButton(50, 100, 100, 100, "", w.Handle)
	// 设置按钮图标
	btn.SetIcon(imagex.NewBySvgString(win7s).EnableAutoDestroy(true).Handle)
	btn1 := widget.NewButton(250, 100, 100, 100, "", w.Handle)
	btn1.SetIcon(imagex.NewBySvgString(win10s).EnableAutoDestroy(true).Handle)
	btn2 := widget.NewButton(450, 100, 100, 100, "", w.Handle)
	btn2.SetIcon(imagex.NewBySvgString(win11s).EnableAutoDestroy(true).Handle)
	widget.NewShapeText(50, 50, 100, 50, "重装win7", w.Handle)
	// 注册按钮事件
	btn.AddEvent_BnClick(func(hEle int, pbHandled *bool) int {
		// 是否点了确定按钮
		var isOK bool
		// 创建可自定义的信息框
		md := w.Msg_Create("标题", "内容", xcc.MessageBox_Flag_Ok|xcc.MessageBox_Flag_Cancel, xcc.Window_Style_Modal)
		// 设置窗口边框大小
		md.SetBorderSize(0, 34, 0, 0)
		// 设置窗口透明类型：阴影窗口, 带透明通道, 边框阴影, 窗口透明或半透明
		md.SetTransparentType(xcc.Window_Transparent_Shadow)
		// 设置窗口透明度：255就是不透明
		md.SetTransparentAlpha(255)
		// 设置窗口阴影：阴影大小4, 深度255, 圆角内收大小6, 是否强制直角false, 阴影颜色0也就是黑色
		md.SetShadowInfo(4, 255, 6, false, 0)
		// 遍历子控件, 找到确定按钮
		for i := int32(0); i < md.GetChildCount(); i++ {
			hEle := md.GetChildByIndex(i)
			if xc.XC_IsHXCGUI(hEle, xcc.XC_BUTTON) && xc.XBtn_GetText(hEle) == "确 定" { // 是确定按钮
				btn := widget.NewButtonByHandle(hEle)
				btn.AddEvent_BnClick(func(hEle int, pbHandled *bool) int {
					isOK = true
					return 0
				})
				break
			}
		}
		// 显示模态窗口
		md.DoModal()
		if isOK {
			w.MessageBox("提示", "你点击了确定按钮", xcc.MessageBox_Flag_Ok, xcc.Window_Style_Default)
		}
		return 0
	})

	// 显示窗口
	w.Show(true)
	// 运行消息循环
	a.Run()
	// 退出界面库释放资源
	a.Exit()
}
