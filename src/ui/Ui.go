package ui

import (
	"ReSys/res"
	"ReSys/src/log"
	"ReSys/src/tools"
	"bytes"
	_ "embed"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/gif"
	"runtime"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)
const (
	targetWin7  = "win7"
	targetWin10 = "win10"
	targetWin11 = "win11"
)

var StartInstall = func(target string) {}

const drawTextAutoLen = uintptr(^uint32(0)) // 0xFFFFFFFF，相当于 int32(-1)
const LOGPIXELSY = 90                       // 用于获取垂直方向的逻辑 DPI
// 全局缩放比例
var dpiScale float64 = 1.0
var (
	user32  = windows.NewLazySystemDLL("user32.dll")
	gdi32   = windows.NewLazySystemDLL("gdi32.dll")
	msimg32 = windows.NewLazySystemDLL("msimg32.dll")
	shlwapi = windows.NewLazySystemDLL("shlwapi.dll")

	procRegisterClassExW        = user32.NewProc("RegisterClassExW")
	procCreateWindowExW         = user32.NewProc("CreateWindowExW")
	procDefWindowProcW          = user32.NewProc("DefWindowProcW")
	procShowWindow              = user32.NewProc("ShowWindow")
	procUpdateWindow            = user32.NewProc("UpdateWindow")
	procGetMessageW             = user32.NewProc("GetMessageW")
	procTranslateMessage        = user32.NewProc("TranslateMessage")
	procDispatchMessageW        = user32.NewProc("DispatchMessageW")
	procPostQuitMessage         = user32.NewProc("PostQuitMessage")
	procPostMessageW            = user32.NewProc("PostMessageW")
	procSendMessageW            = user32.NewProc("SendMessageW")
	procInvalidateRect          = user32.NewProc("InvalidateRect")
	procBeginPaint              = user32.NewProc("BeginPaint")
	procEndPaint                = user32.NewProc("EndPaint")
	procGetClientRect           = user32.NewProc("GetClientRect")
	procSetTimer                = user32.NewProc("SetTimer")
	procKillTimer               = user32.NewProc("KillTimer")
	procTrackMouseEvent         = user32.NewProc("TrackMouseEvent")
	procSetCapture              = user32.NewProc("SetCapture")
	procReleaseCapture          = user32.NewProc("ReleaseCapture")
	procSetLayeredWindowAttribs = user32.NewProc("SetLayeredWindowAttributes")
	procMessageBeep             = user32.NewProc("MessageBeep")
	procLoadCursorW             = user32.NewProc("LoadCursorW")
	procSetCursor               = user32.NewProc("SetCursor")
	procGetDC                   = user32.NewProc("GetDC")
	procReleaseDC               = user32.NewProc("ReleaseDC")
	procSetWindowPos            = user32.NewProc("SetWindowPos")
	procSetWindowTextW          = user32.NewProc("SetWindowTextW")
	procMessageBoxW             = user32.NewProc("MessageBoxW")
	procMessageBoxTimeoutW      = user32.NewProc("MessageBoxTimeoutW")
	procAdjustWindowRectEx      = user32.NewProc("AdjustWindowRectEx")

	procCreateSolidBrush    = gdi32.NewProc("CreateSolidBrush")
	procDeleteObject        = gdi32.NewProc("DeleteObject")
	procCreatePen           = gdi32.NewProc("CreatePen")
	procSelectObject        = gdi32.NewProc("SelectObject")
	procRectangle           = gdi32.NewProc("Rectangle")
	procRoundRect           = gdi32.NewProc("RoundRect")
	procSetBkMode           = gdi32.NewProc("SetBkMode")
	procSetTextColor        = gdi32.NewProc("SetTextColor")
	procDrawTextW           = user32.NewProc("DrawTextW")
	procCreateFontIndirectW = gdi32.NewProc("CreateFontIndirectW")

	procCreateCompatibleDC = gdi32.NewProc("CreateCompatibleDC")
	procDeleteDC           = gdi32.NewProc("DeleteDC")
	procCreateDIBSection   = gdi32.NewProc("CreateDIBSection")
	procBitBlt             = gdi32.NewProc("BitBlt")

	procAlphaBlend   = msimg32.NewProc("AlphaBlend")
	procGradientFill = msimg32.NewProc("GradientFill")

	procDrawIconEx = user32.NewProc("DrawIconEx")

	procSetProcessDPIAware = user32.NewProc("SetProcessDPIAware")

	procLocalAlloc         = tools.Kernel32.NewProc("LocalAlloc")
	procLocalFree          = tools.Kernel32.NewProc("LocalFree")
	procGetModuleHandleW   = tools.Kernel32.NewProc("GetModuleHandleW")
	procGetModuleHandleExW = tools.Kernel32.NewProc("GetModuleHandleExW")

	procSystemParametersInfoW = user32.NewProc("SystemParametersInfoW")

	//dpi
	shcore                            = windows.NewLazySystemDLL("shcore.dll")          // 设置显示 Dpi
	procSetProcessDpiAwarenessContext = user32.NewProc("SetProcessDpiAwarenessContext") // Win10 1607+
	procSetProcessDpiAwareness        = shcore.NewProc("SetProcessDpiAwareness")        // Win8.1+
	procGetDeviceCaps                 = gdi32.NewProc("GetDeviceCaps")
)

const (
	WS_VISIBLE      = 0x10000000
	WS_CLIPSIBLINGS = 0x04000000
	WS_CLIPCHILDREN = 0x02000000

	// 原生标题栏相关
	WS_CAPTION     = 0x00C00000
	WS_SYSMENU     = 0x00080000
	WS_MINIMIZEBOX = 0x00020000
	WS_THICKFRAME  = 0x00040000
	WS_MAXIMIZEBOX = 0x00010000

	WS_EX_APPWINDOW = 0x00040000
	WS_EX_LAYERED   = 0x00080000

	SW_SHOW = 5

	WM_DESTROY     = 0x0002
	WM_PAINT       = 0x000F
	WM_SIZE        = 0x0005
	WM_TIMER       = 0x0113
	WM_MOUSEMOVE   = 0x0200
	WM_MOUSELEAVE  = 0x02A3
	WM_LBUTTONDOWN = 0x0201
	WM_LBUTTONUP   = 0x0202

	WM_APP = 0x8000

	WM_APP_SET_PROGRESS = WM_APP + 1
	WM_APP_SET_STATUS   = WM_APP + 2
	WM_APP_SWITCH_MODE  = WM_APP + 3

	LWA_ALPHA = 0x00000002

	BKMODE_TRANSPARENT = 1

	DT_CENTER       = 0x00000001
	DT_VCENTER      = 0x00000004
	DT_SINGLELINE   = 0x00000020
	DT_END_ELLIPSIS = 0x00008000

	PS_SOLID = 0

	SRCCOPY = 0x00CC0020

	TME_LEAVE = 0x00000002

	DI_NORMAL = 0x0003

	IDC_HAND  = 32649
	IDC_ARROW = 32512

	MB_OKCANCEL    = 0x00000001
	MB_RETRYCANCEL = 0x00000005
	IDOK           = 1
	IDRETRY        = 4

	SWP_NOMOVE                                   = 0x0002
	SWP_NOSIZE                                   = 0x0001
	SWP_NOZORDER                                 = 0x0004
	GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT = 0x00000002
	GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS       = 0x00000004
)

// 原自绘标题栏高度（现在由系统标题栏负责了），用于把旧布局整体上移保持观感一致
const oldTitleBarH int32 = 44

var gScale float32 = 1.0 // 全局缩放系数
// 初始化 DPI 缩放比例
func initScale() {
	hdc, _, _ := user32.NewProc("GetDC").Call(0)
	// LOGPIXELSX = 88
	logPixelsX, _, _ := gdi32.NewProc("GetDeviceCaps").Call(hdc, 88)
	user32.NewProc("ReleaseDC").Call(0, hdc)

	if logPixelsX > 0 {
		gScale = float32(logPixelsX) / 96.0
	}
}

// dp (Density-independent Pixel) 辅助函数
// 将设计稿的像素值转换为当前屏幕的实际像素值
func dp(v int32) int32 {
	return int32(float32(v) * gScale)
}

// yFromOld 函数。
func yFromOld(oldY int32) int32 { return oldY - oldTitleBarH }

// 辅助函数：Win32 COLORREF 是 0x00BBGGRR，和通常的 RGB 相反
func RGB(r, g, b byte) uintptr {
	return uintptr(r) | (uintptr(g) << 8) | (uintptr(b) << 16)
}

var (
	// 现代简约浅色主题（干净、留白、低对比）
	ColorBgDark   = RGB(255, 255, 255) // 整体背景（雾白/浅灰）
	ColorTitleBar = RGB(248, 249, 251) // 现在不会再用于自绘标题栏（保留不影响）
	ColorText     = RGB(16, 16, 16)    // 主文字（深灰，非纯黑更柔和）
	ColorTextHint = RGB(16, 16, 16)    // 提示文字（中灰）

	// 按钮
	ColorBtnNormal = RGB(255, 255, 255) // 白按钮
	ColorBtnHover  = RGB(242, 244, 247) // hover 轻微变灰
	ColorBtnDown   = RGB(0, 120, 215)
	ColorBtnBorder = RGB(200, 206, 214) // 边框更清晰一点
	ColorHighlight = RGB(0, 120, 215)   // 高亮
)

var gFontQuality byte = ANTIALIASED_QUALITY

const (
	// SystemParametersInfo - Font smoothing / ClearType
	SPI_GETFONTSMOOTHING     = 0x004A
	SPI_SETFONTSMOOTHING     = 0x004B
	SPI_GETFONTSMOOTHINGTYPE = 0x200A
	SPI_SETFONTSMOOTHINGTYPE = 0x200B
	//（可选）对比度
	SPI_SETFONTSMOOTHINGCONTRAST = 0x200D

	FE_FONTSMOOTHINGSTANDARD  = 0x0001
	FE_FONTSMOOTHINGCLEARTYPE = 0x0002

	SPIF_UPDATEINIFILE = 0x01
	SPIF_SENDCHANGE    = 0x02

	// LOGFONT.Quality
	ANTIALIASED_QUALITY = 4
	CLEARTYPE_QUALITY   = 5
)

type WNDCLASSEX struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     windows.Handle
	HIcon         windows.Handle
	HCursor       windows.Handle
	HbrBackground windows.Handle
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       windows.Handle
}

type MSG struct {
	HWnd    windows.Handle
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      struct{ X, Y int32 }
}

type RECT struct{ Left, Top, Right, Bottom int32 }

type POINT struct{ X, Y int32 }

type PAINTSTRUCT struct {
	Hdc         windows.Handle
	FErase      int32
	RcPaint     RECT
	FRestore    int32
	FIncUpdate  int32
	RgbReserved [32]byte
}

type LOGFONTW struct {
	Height         int32
	Width          int32
	Escapement     int32
	Orientation    int32
	Weight         int32
	Italic         byte
	Underline      byte
	StrikeOut      byte
	CharSet        byte
	OutPrecision   byte
	ClipPrecision  byte
	Quality        byte
	PitchAndFamily byte
	FaceName       [32]uint16
}

type TRACKMOUSEEVENT struct {
	CbSize      uint32
	DwFlags     uint32
	HWndTrack   windows.Handle
	DwHoverTime uint32
}

// AlphaBlend
type BLENDFUNCTION struct {
	BlendOp             byte
	BlendFlags          byte
	SourceConstantAlpha byte
	AlphaFormat         byte
}

const (
	AC_SRC_OVER  = 0x00
	AC_SRC_ALPHA = 0x01
)

// GradientFill
type TRIVERTEX struct {
	X, Y                    int32
	Red, Green, Blue, Alpha uint16
}
type GRADIENT_RECT struct {
	UpperLeft, LowerRight uint32
}

const GRADIENT_FILL_RECT_V = 0x00000001

// 系统层：能开 ClearType 就开；否则至少打开“字体平滑”。
// 字体层：设置全局 gFontQuality：优先 CLEARTYPE_QUALITY，否则 ANTIALIASED_QUALITY。
func initFontSmoothing() {
	// 1) 开启字体平滑（Font Smoothing）
	procSystemParametersInfoW.Call(
		SPI_SETFONTSMOOTHING,
		1,
		0,
		SPIF_UPDATEINIFILE|SPIF_SENDCHANGE,
	)

	// 2) 尝试设置为 ClearType
	want := uint32(FE_FONTSMOOTHINGCLEARTYPE)
	rSet, _, _ := procSystemParametersInfoW.Call(
		SPI_SETFONTSMOOTHINGTYPE,
		0,
		uintptr(unsafe.Pointer(&want)),
		SPIF_UPDATEINIFILE|SPIF_SENDCHANGE,
	)

	// 3) 读取回系统实际值，确认是否真的启用
	var cur uint32
	rGet, _, _ := procSystemParametersInfoW.Call(
		SPI_GETFONTSMOOTHINGTYPE,
		0,
		uintptr(unsafe.Pointer(&cur)),
		0,
	)

	if rSet != 0 && rGet != 0 && cur == FE_FONTSMOOTHINGCLEARTYPE {
		gFontQuality = CLEARTYPE_QUALITY
		return
	}

	// 4) ClearType 不可用：退回标准灰阶平滑
	std := uint32(FE_FONTSMOOTHINGSTANDARD)
	procSystemParametersInfoW.Call(
		SPI_SETFONTSMOOTHINGTYPE,
		0,
		uintptr(unsafe.Pointer(&std)),
		SPIF_UPDATEINIFILE|SPIF_SENDCHANGE,
	)
	gFontQuality = ANTIALIASED_QUALITY
}

// DPI
func initDPI() {
	// 不要强制拉伸界面导致模糊
	procSetProcessDPIAware.Call()

	// 获取屏幕设备上下文
	hdc, _, _ := procGetDC.Call(0)
	if hdc != 0 {
		// 获取当前系统的 DPI 值（标准为 96，175% 时为 168）
		dpi, _, _ := procGetDeviceCaps.Call(hdc, uintptr(LOGPIXELSY))
		if dpi > 0 {
			dpiScale = float64(dpi) / 96.0
		}
		// 释放设备上下文
		procReleaseDC.Call(0, hdc)
	}
}

// 将设计像素转换为实际物理像素
func scale(v int) int {
	return int(float64(v) * dpiScale)
}

// int32
func scale32(v int32) int32 {
	return int32(float64(v) * dpiScale)
}

// getHInstance 函数。
func getHInstance() windows.Handle {
	var h windows.Handle
	r, _, _ := procGetModuleHandleExW.Call(
		GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
		wndProc,
		uintptr(unsafe.Pointer(&h)),
	)
	if r == 0 || h == 0 {
		le := windows.GetLastError()
		if le == windows.ERROR_SUCCESS {
			panic("GetModuleHandleExW failed (ret=0, GetLastError=0)")
		}
		panic(le)
	}
	return h
}

type Mode int32

const (
	ModeSelect Mode = iota
	ModeProgress
)

type Rect struct{ X, Y, W, H int32 }

// contains 函数。
func (r Rect) contains(x, y int32) bool {
	return x >= r.X && y >= r.Y && x < r.X+r.W && y < r.Y+r.H
}

type Button struct {
	R       Rect
	Text    string
	Icon    windows.Handle // HICON
	Visible bool
	Enabled bool
	Hover   bool
	Down    bool
	OnClick func()
}

type Frame struct {
	Bmp     windows.Handle // HBITMAP (32bpp)
	W, H    int32
	DelayMs uint32
}

type UI struct {
	hwnd windows.Handle

	mode      atomic.Int32
	statusPtr atomic.Uintptr
	progress  atomic.Int32

	btn7, btn10, btn11, btnAdv Button

	frames   []Frame
	frameIdx int
	timerOn  bool

	font16 windows.Handle
	font20 windows.Handle

	iconApp windows.Handle
	icon7   windows.Handle
	icon10  windows.Handle
	icon11  windows.Handle
}

var ui UI

// uiSetProgress 函数。
func UiSetProgress(pos int32) {
	if ui.hwnd == 0 {
		return
	}
	ui.progress.Store(pos)
	procPostMessageW.Call(uintptr(ui.hwnd), WM_APP_SET_PROGRESS, uintptr(pos), 0)
}

// uiSetStatus 函数。
func UiSetStatus(s string) {
	if ui.hwnd == 0 {
		return
	}
	p := allocUTF16(s)
	procPostMessageW.Call(uintptr(ui.hwnd), WM_APP_SET_STATUS, p, 0)
}

// uiShowError 函数。
func UiShowError(title, text string) {
	procMessageBeep.Call(0)
	Message(title, text)
}

// uiSwitchToProgress 函数。
func uiSwitchToProgress() {
	if ui.hwnd == 0 {
		return
	}
	procPostMessageW.Call(uintptr(ui.hwnd), WM_APP_SWITCH_MODE, uintptr(ModeProgress), 0)
}

// win2 函数。
func Win2() {
	uiSwitchToProgress()
}

// 简单消息框
func Message(title, text string) bool {
	if ui.hwnd == 0 {
		return false
	}

	// 优先尝试 MessageBoxTimeoutW（10秒）
	if err := procMessageBoxTimeoutW.Find(); err == nil {
		ret, _, _ := procMessageBoxTimeoutW.Call(
			uintptr(ui.hwnd),
			uintptr(unsafe.Pointer(mustUTF16(text))),
			uintptr(unsafe.Pointer(mustUTF16(title))),
			MB_OKCANCEL,
			0,      // wLanguageId
			10_000, // dwMilliseconds
		)
		return ret == IDOK // 超时/Cancel 都会返回 false
	}

	// 回退到普通 MessageBoxW
	ret, _, _ := procMessageBoxW.Call(
		uintptr(ui.hwnd),
		uintptr(unsafe.Pointer(mustUTF16(text))),
		uintptr(unsafe.Pointer(mustUTF16(title))),
		MB_OKCANCEL,
	)
	return ret == IDOK
}

// 重试/退出消息框，返回 true 表示重试。
func MessageRetryExit(title, text string) bool {
	if ui.hwnd == 0 {
		return false
	}
	ret, _, _ := procMessageBoxW.Call(
		uintptr(ui.hwnd),
		uintptr(unsafe.Pointer(mustUTF16(text))),
		uintptr(unsafe.Pointer(mustUTF16(title))),
		MB_RETRYCANCEL,
	)
	return ret == IDRETRY
}

// icoToHICON 函数。
func icoToHICON(ico []byte, want int32) (windows.Handle, error) {
	if len(ico) < 6 {
		log.LogWrite(0, "[icoToHICON]icoToHICON ico长度不足: len=%d", len(ico))
		return 0, syscall.EINVAL
	}
	count := int(*(*uint16)(unsafe.Pointer(&ico[4])))
	if count <= 0 {
		log.LogWrite(0, "[icoToHICON]icoToHICON 图标数量异常: count=%d", count)
		return 0, syscall.EINVAL
	}
	type entry struct {
		W, H        byte
		ColorCount  byte
		Reserved    byte
		Planes      uint16
		BitCount    uint16
		BytesInRes  uint32
		ImageOffset uint32
	}
	best := -1
	bestScore := int32(1 << 30)
	entriesOff := 6
	for i := 0; i < count; i++ {
		off := entriesOff + i*16
		if off+16 > len(ico) {
			break
		}
		e := (*entry)(unsafe.Pointer(&ico[off]))
		w := int32(e.W)
		h := int32(e.H)
		if w == 0 {
			w = 256
		}
		if h == 0 {
			h = 256
		}
		dw := w - want
		if dw < 0 {
			dw = -dw
		}
		dh := h - want
		if dh < 0 {
			dh = -dh
		}
		score := dw + dh
		if score < bestScore {
			bestScore = score
			best = i
		}
	}
	if best < 0 {
		log.LogWrite(0, "[icoToHICON]icoToHICON 未找到合适的图标尺寸")
		return 0, syscall.EINVAL
	}
	e := (*entry)(unsafe.Pointer(&ico[entriesOff+best*16]))
	start := int(e.ImageOffset)
	end := start + int(e.BytesInRes)
	if start < 0 || end > len(ico) || start >= end {
		log.LogWrite(0, "[icoToHICON]icoToHICON 图标数据越界: start=%d end=%d len=%d", start, end, len(ico))
		return 0, syscall.EINVAL
	}
	imgBits := ico[start:end]

	createIcon := user32.NewProc("CreateIconFromResourceEx")
	const LR_DEFAULTCOLOR = 0x0000
	h, _, err := createIcon.Call(
		uintptr(unsafe.Pointer(&imgBits[0])),
		uintptr(len(imgBits)),
		1,
		0x00030000,
		uintptr(want),
		uintptr(want),
		LR_DEFAULTCOLOR,
	)
	if h == 0 {
		log.LogWrite(0, "[icoToHICON]icoToHICON CreateIconFromResourceEx失败: err=%v", err)
		return 0, err
	}
	return windows.Handle(h), nil
}

// decodeGIFFrames 函数。
func decodeGIFFrames(gifBytes []byte) ([]Frame, error) {
	g, err := gif.DecodeAll(bytes.NewReader(gifBytes))
	if err != nil {
		log.LogWrite(0, "[decodeGIFFrames]decodeGIFFrames 解析GIF失败: err=%v", err)
		return nil, err
	}

	W, H := g.Config.Width, g.Config.Height
	canvas := image.NewRGBA(image.Rect(0, 0, W, H))

	var frames []Frame
	for i, pimg := range g.Image {
		draw.Draw(canvas, pimg.Bounds(), pimg, pimg.Bounds().Min, draw.Over)

		// 拷贝出当前完整画面作为一帧
		out := image.NewRGBA(canvas.Bounds())
		copy(out.Pix, canvas.Pix)

		hbmp, w, h, err := rgbaToDIB(out)
		if err != nil {
			log.LogWrite(0, "[decodeGIFFrames]decodeGIFFrames 转换DIB失败: err=%v", err)
			return nil, err
		}

		delay := uint32(100)
		if i < len(g.Delay) && g.Delay[i] > 0 {
			delay = uint32(g.Delay[i]) * 10
		}
		if delay < 10 {
			delay = 10
		}

		frames = append(frames, Frame{Bmp: hbmp, W: w, H: h, DelayMs: delay})
	}
	return frames, nil
}

// rgbaToDIB 函数。
func rgbaToDIB(img *image.RGBA) (windows.Handle, int32, int32, error) {
	type BITMAPINFOHEADER struct {
		Size          uint32
		Width         int32
		Height        int32
		Planes        uint16
		BitCount      uint16
		Compression   uint32
		SizeImage     uint32
		XPelsPerMeter int32
		YPelsPerMeter int32
		ClrUsed       uint32
		ClrImportant  uint32
	}
	type BITMAPINFO struct {
		Header BITMAPINFOHEADER
		Colors [1]uint32
	}
	const BI_RGB = 0
	w := int32(img.Bounds().Dx())
	h := int32(img.Bounds().Dy())
	if w <= 0 || h <= 0 {
		log.LogWrite(0, "[rgbaToDIB]rgbaToDIB 图像尺寸异常: w=%d h=%d", w, h)
		return 0, 0, 0, fmt.Errorf("invalid image size")
	}

	var bi BITMAPINFO
	bi.Header.Size = uint32(unsafe.Sizeof(bi.Header))
	bi.Header.Width = w
	bi.Header.Height = -h
	bi.Header.Planes = 1
	bi.Header.BitCount = 32
	bi.Header.Compression = BI_RGB

	var bits unsafe.Pointer
	hdc, _, _ := procGetDC.Call(0)
	defer procReleaseDC.Call(0, hdc)

	hbmp, _, err := procCreateDIBSection.Call(
		hdc,
		uintptr(unsafe.Pointer(&bi)),
		0,
		uintptr(unsafe.Pointer(&bits)),
		0,
		0,
	)
	if hbmp == 0 {
		log.LogWrite(0, "[rgbaToDIB]rgbaToDIB CreateDIBSection失败: err=%v", err)
		return 0, 0, 0, err
	}

	dst := unsafe.Slice((*byte)(bits), int(w*h*4))
	src := img.Pix
	for i := 0; i < len(src); i += 4 {
		r, g, b, a := src[i], src[i+1], src[i+2], src[i+3]

		// premultiply: c' = c * a / 255
		rr := uint16(r) * uint16(a) / 255
		gg := uint16(g) * uint16(a) / 255
		bb := uint16(b) * uint16(a) / 255

		dst[i+0] = byte(bb) // B
		dst[i+1] = byte(gg) // G
		dst[i+2] = byte(rr) // R
		dst[i+3] = a        // A
	}
	return windows.Handle(hbmp), w, h, nil
}

// mustUTF16 函数。
func mustUTF16(s string) *uint16 {
	p, _ := windows.UTF16PtrFromString(s)
	return p
}

// allocUTF16 函数。
func allocUTF16(s string) uintptr {
	u16, _ := windows.UTF16FromString(s)
	nbytes := uintptr(len(u16) * 2)
	const LMEM_FIXED = 0x0000
	mem, _, _ := procLocalAlloc.Call(LMEM_FIXED, nbytes)
	if mem == 0 {
		return 0
	}
	dst := unsafe.Slice((*uint16)(unsafe.Pointer(mem)), len(u16))
	copy(dst, u16)
	return mem
}

// freeUTF16 函数。
func freeUTF16(p uintptr) {
	if p != 0 {
		procLocalFree.Call(p)
	}
}

// makeFont 函数。
func makeFont(height int32, weight int32, _ string) windows.Handle {
	faceName := "Microsoft YaHei UI"

	var lf LOGFONTW
	lf.Height = -scale32(height)
	lf.Weight = weight
	lf.CharSet = 1 // DEFAULT_CHARSET

	lf.Quality = 5

	f := windows.StringToUTF16(faceName)
	copy(lf.FaceName[:], f)

	h, _, _ := procCreateFontIndirectW.Call(uintptr(unsafe.Pointer(&lf)))
	return windows.Handle(h)
}

// setLayerAlpha 函数。
func setLayerAlpha(hwnd windows.Handle, alpha byte) {
	procSetLayeredWindowAttribs.Call(uintptr(hwnd), 0, uintptr(alpha), LWA_ALPHA)
}

// paint 函数。
func paint() {
	var ps PAINTSTRUCT
	hdc, _, _ := procBeginPaint.Call(uintptr(ui.hwnd), uintptr(unsafe.Pointer(&ps)))
	defer procEndPaint.Call(uintptr(ui.hwnd), uintptr(unsafe.Pointer(&ps)))

	var rc RECT
	procGetClientRect.Call(uintptr(ui.hwnd), uintptr(unsafe.Pointer(&rc)))
	w := rc.Right - rc.Left
	h := rc.Bottom - rc.Top

	memDC, _, _ := procCreateCompatibleDC.Call(hdc)
	defer procDeleteDC.Call(memDC)

	bmi := BITMAPINFOHEADER{
		Size:        uint32(unsafe.Sizeof(BITMAPINFOHEADER{})),
		Width:       w,
		Height:      -h,
		Planes:      1,
		BitCount:    32,
		Compression: 0,
	}
	var bits unsafe.Pointer
	hbmp, _, _ := procCreateDIBSection.Call(memDC, uintptr(unsafe.Pointer(&bmi)), 0, uintptr(unsafe.Pointer(&bits)), 0, 0)
	defer procDeleteObject.Call(hbmp)

	oldBmp, _, _ := procSelectObject.Call(memDC, hbmp)
	defer procSelectObject.Call(memDC, oldBmp)

	bgBrush, _, _ := procCreateSolidBrush.Call(uintptr(ColorBgDark))
	fillRc := RECT{0, 0, w, h}
	fillRect(windows.Handle(memDC), &fillRc, windows.Handle(bgBrush))
	procDeleteObject.Call(bgBrush)

	mode := Mode(ui.mode.Load())
	if mode == ModeSelect {
		paintSelect(windows.Handle(memDC), w, h)
	} else {
		paintProgress(windows.Handle(memDC), w, h)
	}

	procBitBlt.Call(hdc, 0, 0, uintptr(w), uintptr(h), memDC, 0, 0, SRCCOPY)
}

type BITMAPINFOHEADER struct {
	Size          uint32
	Width         int32
	Height        int32
	Planes        uint16
	BitCount      uint16
	Compression   uint32
	SizeImage     uint32
	XPelsPerMeter int32
	YPelsPerMeter int32
	ClrUsed       uint32
	ClrImportant  uint32
}

type RGBA struct{ R, G, B, A byte }

// colorRGBA 函数。
func colorRGBA(r, g, b, a byte) *image.Uniform { return image.NewUniform(imageRGBA(r, g, b, a)) }

// imageRGBA 函数。
func imageRGBA(r, g, b, a byte) color.RGBA { return color.RGBA{R: r, G: g, B: b, A: a} }

// drawButton 函数。
func drawButton(hdc windows.Handle, b *Button, font windows.Handle) {
	if !b.Visible {
		return
	}

	bgColor := ColorBtnNormal
	textColor := ColorText

	if !b.Enabled {
		bgColor = RGB(35, 35, 35)
		textColor = RGB(100, 100, 100)
	} else if b.Down {
		bgColor = ColorBtnDown
		textColor = RGB(255, 255, 255)
	} else if b.Hover {
		bgColor = ColorBtnHover
	}

	brush, _, _ := procCreateSolidBrush.Call(bgColor)
	pen, _, _ := procCreatePen.Call(PS_SOLID, 1, bgColor)

	oldBrush, _, _ := procSelectObject.Call(uintptr(hdc), brush)
	oldPen, _, _ := procSelectObject.Call(uintptr(hdc), pen)

	radius := dp(8)
	procRoundRect.Call(uintptr(hdc),
		uintptr(b.R.X), uintptr(b.R.Y),
		uintptr(b.R.X+b.R.W), uintptr(b.R.Y+b.R.H),
		uintptr(radius), uintptr(radius)) // 使用缩放后的圆角

	procSelectObject.Call(uintptr(hdc), oldBrush)
	procSelectObject.Call(uintptr(hdc), oldPen)
	procDeleteObject.Call(brush)
	procDeleteObject.Call(pen)

	if b.Icon != 0 {
		iconSize := dp(48) // 图标显示大小也需要缩放

		// 重新计算居中位置
		ix := b.R.X + (b.R.W-iconSize)/2
		// 图标稍微往上提一点，给文字留位置
		iy := b.R.Y + (b.R.H-iconSize)/2 - dp(10)

		if b.Text == "" {
			iy = b.R.Y + (b.R.H-iconSize)/2
		}

		if b.Down {
			iy += 1
			ix += 1
		}

		procDrawIconEx.Call(uintptr(hdc), uintptr(ix), uintptr(iy), uintptr(b.Icon),
			uintptr(iconSize), uintptr(iconSize), 0, 0, DI_NORMAL)
	}

	if b.Text != "" {
		procSetBkMode.Call(uintptr(hdc), BKMODE_TRANSPARENT)
		procSetTextColor.Call(uintptr(hdc), textColor)

		oldF, _, _ := procSelectObject.Call(uintptr(hdc), uintptr(font))

		rectText := RECT{b.R.X, b.R.Y, b.R.X + b.R.W, b.R.Y + b.R.H}
		if b.Icon != 0 {
			rectText.Top = b.R.Y + b.R.H - dp(35)
		}

		if b.Down {
			rectText.Top += 1
			rectText.Bottom += 1
			rectText.Left += 1
			rectText.Right += 1
		}

		procDrawTextW.Call(
			uintptr(hdc),
			uintptr(unsafe.Pointer(mustUTF16(b.Text))),
			drawTextAutoLen,
			uintptr(unsafe.Pointer(&rectText)),
			uintptr(DT_CENTER|DT_VCENTER|DT_SINGLELINE),
		)
		procSelectObject.Call(uintptr(hdc), oldF)
	}
}

// fillRect 函数。
func fillRect(hdc windows.Handle, rc *RECT, hbr windows.Handle) {
	fill := user32.NewProc("FillRect")
	fill.Call(uintptr(hdc), uintptr(unsafe.Pointer(rc)), uintptr(hbr))
}

// getAllButtons 函数。
func getAllButtons() []*Button {
	if ui.mode.Load() == int32(ModeSelect) {
		return []*Button{&ui.btn7, &ui.btn10, &ui.btn11, &ui.btnAdv}
	}
	return nil
}

// paintSelect 函数。
func paintSelect(hdc windows.Handle, w, h int32) {
	procSetBkMode.Call(uintptr(hdc), BKMODE_TRANSPARENT)
	procSetTextColor.Call(uintptr(hdc), uintptr(ColorTextHint))
	oldF, _, _ := procSelectObject.Call(uintptr(hdc), uintptr(ui.font20))
	defer procSelectObject.Call(uintptr(hdc), oldF)

	// 计算标题位置：在按钮上方
	// 按钮中心大概在 h/2，文字放在 h/2 - dp(100) 的位置
	titleH := dp(40)
	titleY := h/2 - dp(120)

	rt := RECT{0, titleY, w, titleY + titleH}
	text := "请选择要安装的操作系统"

	procDrawTextW.Call(
		uintptr(hdc),
		uintptr(unsafe.Pointer(mustUTF16(text))),
		drawTextAutoLen,
		uintptr(unsafe.Pointer(&rt)),
		uintptr(DT_CENTER|DT_VCENTER|DT_SINGLELINE),
	)

	drawButton(hdc, &ui.btn7, ui.font16)
	drawButton(hdc, &ui.btn10, ui.font16)
	drawButton(hdc, &ui.btn11, ui.font16)
	drawButton(hdc, &ui.btnAdv, ui.font16)
}

// paintProgress 绘制进度界面
func paintProgress(hdc windows.Handle, w, h int32) {
	// 1. 获取当前状态文字和进度
	p := ui.statusPtr.Load()
	status := "正在准备..."
	if p != 0 {
		status = windows.UTF16PtrToString((*uint16)(unsafe.Pointer(p)))
	}

	pct := ui.progress.Load()
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}

	// 2. 准备绘制环境
	procSetBkMode.Call(uintptr(hdc), BKMODE_TRANSPARENT)
	procSetTextColor.Call(uintptr(hdc), uintptr(ColorText))

	// 使用大号字体绘制状态
	oldF, _, _ := procSelectObject.Call(uintptr(hdc), uintptr(ui.font20))
	defer procSelectObject.Call(uintptr(hdc), oldF)

	// 3. 绘制 GIF 动画 (保持原逻辑，位置微调)
	gifBottomY := int32(0) // 用于记录GIF底部位置，方便下面布局
	if len(ui.frames) > 0 {
		f := ui.frames[ui.frameIdx%len(ui.frames)]
		gifW := dp(f.W)
		gifH := dp(f.H)

		// 居中显示 GIF (使用缩放后的尺寸计算)
		x := (w - gifW) / 2
		// 将 GIF 放在垂直中心偏上一点的位置
		y := h/2 - gifH/2 - dp(40)
		gifBottomY = y + gifH

		srcDC, _, _ := procCreateCompatibleDC.Call(uintptr(hdc))
		defer procDeleteDC.Call(srcDC)
		old, _, _ := procSelectObject.Call(srcDC, uintptr(f.Bmp))
		defer procSelectObject.Call(srcDC, old)

		blend := BLENDFUNCTION{BlendOp: AC_SRC_OVER, BlendFlags: 0, SourceConstantAlpha: 255, AlphaFormat: AC_SRC_ALPHA}
		blendVal := *(*uint32)(unsafe.Pointer(&blend))

		procAlphaBlend.Call(
			uintptr(hdc),
			uintptr(x), uintptr(y), uintptr(gifW), uintptr(gifH), // 目标区域：使用缩放后的宽高
			srcDC,
			0, 0, uintptr(f.W), uintptr(f.H), // 源区域：保持原始图片宽高
			uintptr(blendVal),
		)
	} else {
		gifBottomY = h / 2 // 如果没有GIF，基准线在中间
	}

	// 4. 绘制状态文字 (在 GIF 下方)
	textY := gifBottomY + 20
	rt := RECT{20, textY, w - 20, textY + 30}
	procDrawTextW.Call(
		uintptr(hdc),
		uintptr(unsafe.Pointer(mustUTF16(status))),
		drawTextAutoLen,
		uintptr(unsafe.Pointer(&rt)),
		uintptr(DT_CENTER|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS),
	)

	// 5. 绘制现代化进度条
	// 参数设定
	barH := int32(10)               // 高度增加到 10px (看起来更精致)
	barW := int32(float64(w) * 0.7) // 宽度占窗口 70%
	barX := (w - barW) / 2
	barY := textY + 45 // 在文字下方 45px 处

	// 5.1 绘制进度条背景 (浅灰色)
	// 颜色注意：Win32 是 BGR 格式。0xEBEBEB 是很淡的灰色
	bgColor := uintptr(0x00EBEBEB)
	bgBr, _, _ := procCreateSolidBrush.Call(bgColor)
	bgPen, _, _ := procCreatePen.Call(PS_SOLID, 1, bgColor) // 边框同色，消除锯齿感

	oldBr, _, _ := procSelectObject.Call(uintptr(hdc), bgBr)
	oldPen, _, _ := procSelectObject.Call(uintptr(hdc), bgPen)

	// 使用圆角矩形，圆角半径为高度的一半，形成胶囊状
	procRoundRect.Call(uintptr(hdc),
		uintptr(barX), uintptr(barY),
		uintptr(barX+barW), uintptr(barY+barH),
		uintptr(barH), uintptr(barH)) // 圆角半径

	procSelectObject.Call(uintptr(hdc), oldBr)
	procSelectObject.Call(uintptr(hdc), oldPen)
	procDeleteObject.Call(bgBr)
	procDeleteObject.Call(bgPen)

	// 5.2 绘制进度条前景 (高亮色)
	fillW := barW * pct / 100
	// 只有进度大于0才绘制，避免绘制出奇怪的圆点
	if fillW > 0 {
		// 最小绘制宽度要保证圆角不畸形，至少等于高度
		if fillW < barH {
			fillW = barH
		}

		// 你的 ColorHighlight (0x0078D7) 是很好的Win10蓝
		fBr, _, _ := procCreateSolidBrush.Call(uintptr(ColorHighlight))
		fPen, _, _ := procCreatePen.Call(PS_SOLID, 1, uintptr(ColorHighlight))

		oldBr2, _, _ := procSelectObject.Call(uintptr(hdc), fBr)
		oldPen2, _, _ := procSelectObject.Call(uintptr(hdc), fPen)

		procRoundRect.Call(uintptr(hdc),
			uintptr(barX), uintptr(barY),
			uintptr(barX+fillW), uintptr(barY+barH),
			uintptr(barH), uintptr(barH))

		procSelectObject.Call(uintptr(hdc), oldBr2)
		procSelectObject.Call(uintptr(hdc), oldPen2)
		procDeleteObject.Call(fBr)
		procDeleteObject.Call(fPen)
	}

	// 6. 绘制百分比文字 (在进度条右侧 或者 居中悬浮)
	// 方案：在进度条右侧显示一个小小的百分比，显得比较精致
	pctText := fmt.Sprintf("%d%%", pct)

	// 切换回小字体
	oldF2, _, _ := procSelectObject.Call(uintptr(hdc), uintptr(ui.font16))
	defer procSelectObject.Call(uintptr(hdc), oldF2)

	// 设置灰色字体用于显示百分比
	procSetTextColor.Call(uintptr(hdc), uintptr(0x00999999))

	// 计算位置：进度条右边 + 10px
	pctX := barX + barW + 10
	tr := RECT{pctX, barY - 5, pctX + 50, barY + barH + 5} // 稍微加宽高度以便垂直居中

	procDrawTextW.Call(
		uintptr(hdc),
		uintptr(unsafe.Pointer(mustUTF16(pctText))),
		drawTextAutoLen,
		uintptr(unsafe.Pointer(&tr)),
		uintptr(DT_VCENTER|DT_SINGLELINE), // 左对齐+垂直居中
	)
}

// -------------------- layout --------------------

func layoutSelect(w, h int32) {
	// 1. 定义基础尺寸 (使用 dp 函数进行缩放)
	btnSize := dp(120)               // 按钮大小
	gap := dp(50)                    // 按钮间距
	btnY := h/2 - btnSize/2 + dp(20) // 垂直居中稍微偏下一点

	// 2. 计算三个按钮的总宽度，用于水平居中
	// 3个按钮 + 2个间距
	totalWidth := btnSize*3 + gap*2

	// 起始 X 坐标 = (窗口宽 - 总宽) / 2
	startX := (w - totalWidth) / 2

	// 3. 布局按钮 (动态计算 X 坐标)
	ui.btn7 = Button{
		R:    Rect{X: startX, Y: btnY, W: btnSize, H: btnSize},
		Text: "重装 win7", Icon: ui.icon7, Visible: true, Enabled: true,
		OnClick: func() {
			if Message("提示", "重装系统将会清除C盘数据,是否继续?") {
				uiSwitchToProgress()
				go StartInstall(targetWin7)
			}
		},
	}

	ui.btn10 = Button{
		R:    Rect{X: startX + btnSize + gap, Y: btnY, W: btnSize, H: btnSize},
		Text: "重装 win10", Icon: ui.icon10, Visible: true, Enabled: true,
		OnClick: func() {
			if Message("提示", "重装系统将会清除C盘数据,是否继续?") {
				uiSwitchToProgress()
				go StartInstall(targetWin10)
			}
		},
	}

	ui.btn11 = Button{
		R:    Rect{X: startX + (btnSize+gap)*2, Y: btnY, W: btnSize, H: btnSize},
		Text: "重装 win11", Icon: ui.icon11, Visible: true, Enabled: true,
		OnClick: func() {
			if Message("提示", "重装系统将会清除C盘数据,是否继续?") {
				uiSwitchToProgress()
				go StartInstall(targetWin11)
			}
		},
	}

	// 4. 高级模式按钮 (右上角定位)
	advW, advH := dp(90), dp(34)
	ui.btnAdv = Button{
		R:    Rect{X: w - advW - dp(20), Y: dp(20), W: advW, H: advH},
		Text: "高级模式", Icon: 0, Visible: true, Enabled: true,
		OnClick: func() { UiSetStatus("高级模式：TODO") },
	}
}

// layoutProgress 函数。
func layoutProgress() {
	ui.btn7.Visible, ui.btn10.Visible, ui.btn11.Visible, ui.btnAdv.Visible = false, false, false, false
}

// updateHover 函数。
func updateHover(x, y int32) bool {
	changed := false
	for _, b := range getAllButtons() {
		if !b.Visible || !b.Enabled {
			if b.Hover {
				b.Hover = false
				changed = true
			}
			continue
		}
		h := b.R.contains(x, y)
		if h != b.Hover {
			b.Hover = h
			changed = true
		}
	}
	return changed
}

// hitButton 函数。
func hitButton(x, y int32) *Button {
	for _, b := range getAllButtons() {
		if b.Visible && b.Enabled && b.R.contains(x, y) {
			return b
		}
	}
	return nil
}

// trackLeave 函数。
func trackLeave() {
	var t TRACKMOUSEEVENT
	t.CbSize = uint32(unsafe.Sizeof(t))
	t.DwFlags = TME_LEAVE
	t.HWndTrack = ui.hwnd
	procTrackMouseEvent.Call(uintptr(unsafe.Pointer(&t)))
}

var wndProc = windows.NewCallback(func(hwnd uintptr, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {

	case WM_PAINT:
		paint()
		return 0

	case WM_SIZE:
		var rc RECT
		procGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&rc)))
		w := rc.Right - rc.Left
		h := rc.Bottom - rc.Top
		if ui.mode.Load() == int32(ModeSelect) {
			layoutSelect(w, h)
		} else {
			layoutProgress()
		}
		return 0

	case WM_MOUSEMOVE:
		x := int32(int16(uint16(lParam & 0xFFFF)))
		y := int32(int16(uint16((lParam >> 16) & 0xFFFF)))
		trackLeave()
		if updateHover(x, y) {
			procInvalidateRect.Call(hwnd, 0, 0)
		}
		if hitButton(x, y) != nil {
			hc, _, _ := procLoadCursorW.Call(0, uintptr(IDC_HAND))
			procSetCursor.Call(hc)
		} else {
			hc, _, _ := procLoadCursorW.Call(0, uintptr(IDC_ARROW))
			procSetCursor.Call(hc)
		}
		return 0

	case WM_MOUSELEAVE:
		if updateHover(-1, -1) {
			procInvalidateRect.Call(hwnd, 0, 0)
		}
		return 0

	case WM_LBUTTONDOWN:
		x := int32(int16(uint16(lParam & 0xFFFF)))
		y := int32(int16(uint16((lParam >> 16) & 0xFFFF)))
		if b := hitButton(x, y); b != nil {
			b.Down = true
			procSetCapture.Call(hwnd)
			procInvalidateRect.Call(hwnd, 0, 0)
		}
		return 0

	case WM_LBUTTONUP:
		x := int32(int16(uint16(lParam & 0xFFFF)))
		y := int32(int16(uint16((lParam >> 16) & 0xFFFF)))
		procReleaseCapture.Call()
		for _, b := range getAllButtons() {
			if b.Down {
				b.Down = false
				if b.Visible && b.Enabled && b.R.contains(x, y) && b.OnClick != nil {
					b.OnClick()
				}
			}
		}
		procInvalidateRect.Call(hwnd, 0, 0)
		return 0

	case WM_TIMER:
		if ui.mode.Load() == int32(ModeProgress) && len(ui.frames) > 0 {
			ui.frameIdx = (ui.frameIdx + 1) % len(ui.frames)

			next := ui.frames[ui.frameIdx].DelayMs
			if next < 10 {
				next = 10
			}
			procSetTimer.Call(hwnd, 1, uintptr(next), 0)

			procInvalidateRect.Call(hwnd, 0, 0)
		}
		return 0

	case WM_APP_SET_PROGRESS:
		procInvalidateRect.Call(hwnd, 0, 0)
		return 0

	case WM_APP_SET_STATUS:
		old := ui.statusPtr.Swap(wParam)
		freeUTF16(old)
		procInvalidateRect.Call(hwnd, 0, 0)
		return 0

	case WM_APP_SWITCH_MODE:
		m := Mode(wParam)
		ui.mode.Store(int32(m))
		if m == ModeProgress {
			layoutProgress()
			if !ui.timerOn && len(ui.frames) > 0 {
				procSetTimer.Call(hwnd, 1, uintptr(ui.frames[0].DelayMs), 0)
				ui.timerOn = true
			}
			UiSetProgress(0)
			UiSetStatus("正在寻找镜像...")
		} else {
			if ui.timerOn {
				procKillTimer.Call(hwnd, 1)
				ui.timerOn = false
			}
		}
		procInvalidateRect.Call(hwnd, 0, 1)
		return 0

	case WM_DESTROY:
		old := ui.statusPtr.Swap(0)
		freeUTF16(old)
		if ui.timerOn {
			procKillTimer.Call(hwnd, 1)
		}
		for _, f := range ui.frames {
			if f.Bmp != 0 {
				procDeleteObject.Call(uintptr(f.Bmp))
			}
		}
		procPostQuitMessage.Call(0)
		return 0
	}

	ret, _, _ := procDefWindowProcW.Call(hwnd, uintptr(msg), wParam, lParam)
	return ret
})

// Uiinit 函数。
func Uiinit() {
	runtime.LockOSThread()
	initDPI()
	initFontSmoothing()

	var err error
	ui.iconApp, err = icoToHICON(res.IcoApp, scale32(32))
	if err != nil {
		ui.iconApp = 0
	}
	ui.icon7, _ = icoToHICON(res.IcoWin7, scale32(48))
	ui.icon10, _ = icoToHICON(res.IcoWin10, scale32(48))
	ui.icon11, _ = icoToHICON(res.IcoWin11, scale32(48))

	ui.frames, _ = decodeGIFFrames(res.WaitGIF)

	ui.font16 = makeFont(0, 0, "Microsoft YaHei UI")
	ui.font20 = makeFont(0, 0, "Microsoft YaHei UI")

	cls := mustUTF16("ReSysCanvasWnd")
	var wc WNDCLASSEX
	hInst0, _, err := procGetModuleHandleW.Call(0)
	if hInst0 == 0 {
		panic(err)
	}
	hInst := getHInstance()
	wc.HInstance = hInst

	hInst = windows.Handle(hInst0)

	wc.CbSize = uint32(unsafe.Sizeof(wc))
	wc.LpfnWndProc = wndProc
	wc.HInstance = hInst
	wc.LpszClassName = cls
	hc, _, _ := procLoadCursorW.Call(0, uintptr(IDC_ARROW))
	wc.HCursor = windows.Handle(hc)

	atom, _, err2 := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
	if atom == 0 {
		panic(err2)
	}

	style := uintptr(WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_CLIPCHILDREN | WS_CLIPSIBLINGS)
	exStyle := uintptr(WS_EX_APPWINDOW)

	// 获取工作区
	const SPI_GETWORKAREA = 0x0030
	var wa RECT
	procSystemParametersInfoW.Call(SPI_GETWORKAREA, 0, uintptr(unsafe.Pointer(&wa)), 0)

	clientW, clientH := scale32(600), scale32(400)

	// 把客户区尺寸换算成窗口外框尺寸（包含标题栏/边框）
	rc := RECT{Left: 0, Top: 0, Right: clientW, Bottom: clientH}
	procAdjustWindowRectEx.Call(uintptr(unsafe.Pointer(&rc)), style, 0, exStyle)
	winW := rc.Right - rc.Left
	winH := rc.Bottom - rc.Top

	// 屏幕居中计算
	x := wa.Left + (wa.Right-wa.Left-winW)/2
	y := wa.Top + (wa.Bottom-wa.Top-winH)/2

	hwnd, _, err3 := procCreateWindowExW.Call(
		exStyle,
		uintptr(unsafe.Pointer(cls)),
		uintptr(unsafe.Pointer(mustUTF16("ReSys"))),
		style,
		uintptr(x), uintptr(y), uintptr(winW), uintptr(winH),
		0, 0, uintptr(hInst), 0,
	)
	if hwnd == 0 {
		panic(err3)
	}
	ui.hwnd = windows.Handle(hwnd)

	// 设置透明度
	// setLayerAlpha(ui.hwnd, 240)

	const WM_SETICON = 0x0080
	const ICON_SMALL = 0
	const ICON_BIG = 1
	if ui.iconApp != 0 {
		procSendMessageW.Call(hwnd, WM_SETICON, ICON_SMALL, uintptr(ui.iconApp))
		procSendMessageW.Call(hwnd, WM_SETICON, ICON_BIG, uintptr(ui.iconApp))
	}

	ui.mode.Store(int32(ModeSelect))

	layoutSelect(clientW, clientH)

	procShowWindow.Call(hwnd, SW_SHOW)
	procUpdateWindow.Call(hwnd)
}

// UiRun 函数。
func UiRun() {
	var msg MSG
	for {
		r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
	}

	if ui.font16 != 0 {
		procDeleteObject.Call(uintptr(ui.font16))
	}
	if ui.font20 != 0 {
		procDeleteObject.Call(uintptr(ui.font20))
	}
}
