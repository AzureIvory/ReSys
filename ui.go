package main

import (
	"bytes"
	_ "embed"
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

//go:embed icon.ico
var icoApp []byte

//go:embed win7.ico
var icoWin7 []byte

//go:embed win10.ico
var icoWin10 []byte

//go:embed win11.ico
var icoWin11 []byte

//go:embed wait.gif
var waitGIF []byte

const drawTextAutoLen = uintptr(^uint32(0)) // 0xFFFFFFFF，相当于 int32(-1)

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	gdi32    = windows.NewLazySystemDLL("gdi32.dll")
	msimg32  = windows.NewLazySystemDLL("msimg32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")
	shlwapi  = windows.NewLazySystemDLL("shlwapi.dll")

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

	procLocalAlloc         = kernel32.NewProc("LocalAlloc")
	procLocalFree          = kernel32.NewProc("LocalFree")
	procGetModuleHandleW   = kernel32.NewProc("GetModuleHandleW")
	procGetModuleHandleExW = kernel32.NewProc("GetModuleHandleExW")
)

const (
	WS_POPUP        = 0x80000000
	WS_VISIBLE      = 0x10000000
	WS_CLIPSIBLINGS = 0x04000000
	WS_CLIPCHILDREN = 0x02000000

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
	WM_NCHITTEST   = 0x0084
	WM_SETCURSOR   = 0x0020

	HTCAPTION = 2
	HTCLIENT  = 1

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

const (
	ColorBgDark   = 0x00FFFFFF // 主背景
	ColorTitleBar = 0x00228B22 // 标题栏
	ColorText     = 0x00333333 // 主要文字
	ColorTextHint = 0x00888888 // 提示文字

	// 按钮颜色
	ColorBtnNormal = 0x00F7F7F7 // 按钮背景
	ColorBtnHover  = 0x00E0F0E0 // 悬停背景
	ColorBtnDown   = 0x00D0E0D0 // 按下背景
	ColorBtnBorder = 0x00CCCCCC // 默认边框
	ColorHighlight = 0x003CB371 // 高亮色

	// 标题栏按钮颜色
	ColorBtnCloseHover = 0xFFADFF2F // 关闭
	ColorBtnMinHover   = 0x00D0E0D0 // 最小化
	ColorBtnDown1      = 0x003E3E3E

	// 按钮尺寸
	TitleBtnW = 46
	TitleBtnH = 32
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

// -------------------- UI model --------------------

type Mode int32

const (
	ModeSelect Mode = iota
	ModeProgress
)

type Rect struct{ X, Y, W, H int32 }

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

	btnMin   Button
	btnClose Button
}

var ui UI

// -------------------- thread-safe UI APIs (给业务层用) --------------------

func uiSetProgress(pos int32) {
	if ui.hwnd == 0 {
		return
	}
	ui.progress.Store(pos)
	procPostMessageW.Call(uintptr(ui.hwnd), WM_APP_SET_PROGRESS, uintptr(pos), 0)
}

func uiSetStatus(s string) {
	if ui.hwnd == 0 {
		return
	}
	p := allocUTF16(s)
	procPostMessageW.Call(uintptr(ui.hwnd), WM_APP_SET_STATUS, p, 0)
}

func uiShowError(title, text string) {
	procMessageBeep.Call(0)
	Message(title, text)
}

func uiSwitchToProgress() {
	if ui.hwnd == 0 {
		return
	}
	procPostMessageW.Call(uintptr(ui.hwnd), WM_APP_SWITCH_MODE, uintptr(ModeProgress), 0)
}

// -------------------- compat API --------------------

func win2() {
	uiSwitchToProgress()
}

// 简单消息框
func Message(title, text string) bool {
	if ui.hwnd == 0 {
		return false
	}
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

// -------------------- icon loader (.ico bytes -> HICON) --------------------

func icoToHICON(ico []byte, want int32) (windows.Handle, error) {
	if len(ico) < 6 {
		return 0, syscall.EINVAL
	}
	count := int(*(*uint16)(unsafe.Pointer(&ico[4])))
	if count <= 0 {
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
		return 0, syscall.EINVAL
	}
	e := (*entry)(unsafe.Pointer(&ico[entriesOff+best*16]))
	start := int(e.ImageOffset)
	end := start + int(e.BytesInRes)
	if start < 0 || end > len(ico) || start >= end {
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
		return 0, err
	}
	return windows.Handle(h), nil
}
func decodeGIFFrames(gifBytes []byte) ([]Frame, error) {
	g, err := gif.DecodeAll(bytes.NewReader(gifBytes))
	if err != nil {
		return nil, err
	}
	var frames []Frame
	for i, pimg := range g.Image {
		rgba := image.NewRGBA(pimg.Bounds())
		draw.Draw(rgba, rgba.Bounds(), pimg, pimg.Bounds().Min, draw.Src)
		hbmp, w, h, err := rgbaToDIB(rgba)
		if err != nil {
			return nil, err
		}
		delay := uint32(100)
		if i < len(g.Delay) && g.Delay[i] > 0 {
			delay = uint32(g.Delay[i]) * 10
		}
		frames = append(frames, Frame{Bmp: hbmp, W: w, H: h, DelayMs: delay})
	}
	return frames, nil
}

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
		return 0, 0, 0, err
	}

	dst := unsafe.Slice((*byte)(bits), int(w*h*4))
	src := img.Pix
	for i := 0; i < len(src); i += 4 {
		r, g, b, a := src[i], src[i+1], src[i+2], src[i+3]
		dst[i+0] = b
		dst[i+1] = g
		dst[i+2] = r
		dst[i+3] = a
	}
	return windows.Handle(hbmp), w, h, nil
}

// -------------------- helpers --------------------

func mustUTF16(s string) *uint16 {
	p, _ := windows.UTF16PtrFromString(s)
	return p
}

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
func freeUTF16(p uintptr) {
	if p != 0 {
		procLocalFree.Call(p)
	}
}

func makeFont(height int32, weight int32, face string) windows.Handle {
	var lf LOGFONTW
	lf.Height = -height
	lf.Weight = weight
	f := windows.StringToUTF16(face)
	copy(lf.FaceName[:], f)
	h, _, _ := procCreateFontIndirectW.Call(uintptr(unsafe.Pointer(&lf)))
	return windows.Handle(h)
}

func setLayerAlpha(hwnd windows.Handle, alpha byte) {
	procSetLayeredWindowAttribs.Call(uintptr(hwnd), 0, uintptr(alpha), LWA_ALPHA)
}

// -------------------- painting --------------------

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
		Size:  uint32(unsafe.Sizeof(BITMAPINFOHEADER{})),
		Width: w, Height: -h, Planes: 1, BitCount: 32, Compression: 0,
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

func colorRGBA(r, g, b, a byte) *image.Uniform { return image.NewUniform(imageRGBA(r, g, b, a)) }
func imageRGBA(r, g, b, a byte) color.RGBA     { return color.RGBA{R: r, G: g, B: b, A: a} }

func drawButton(hdc windows.Handle, b *Button, font windows.Handle) {
	if !b.Visible {
		return
	}

	bgColor := ColorBtnNormal
	borderColor := ColorBtnBorder

	if !b.Enabled {
		bgColor = 0x002A2A2A
		borderColor = 0x00333333
	} else if b.Down {
		bgColor = ColorBtnDown
		borderColor = ColorHighlight
	} else if b.Hover {
		bgColor = ColorBtnHover
		borderColor = ColorHighlight
	}

	brush, _, _ := procCreateSolidBrush.Call(uintptr(bgColor))
	pen, _, _ := procCreatePen.Call(PS_SOLID, 1, uintptr(borderColor))
	if b.Hover && b.Enabled {
		procDeleteObject.Call(pen)
		pen, _, _ = procCreatePen.Call(PS_SOLID, 2, uintptr(borderColor))
	}

	oldBrush, _, _ := procSelectObject.Call(uintptr(hdc), brush)
	oldPen, _, _ := procSelectObject.Call(uintptr(hdc), pen)

	procRoundRect.Call(uintptr(hdc),
		uintptr(b.R.X), uintptr(b.R.Y),
		uintptr(b.R.X+b.R.W), uintptr(b.R.Y+b.R.H),
		10, 10)

	procSelectObject.Call(uintptr(hdc), oldBrush)
	procSelectObject.Call(uintptr(hdc), oldPen)
	procDeleteObject.Call(brush)
	procDeleteObject.Call(pen)

	if b.Icon != 0 {
		ix := b.R.X + (b.R.W-48)/2
		iy := b.R.Y + 16
		if b.Down {
			iy += 1
		}
		procDrawIconEx.Call(uintptr(hdc), uintptr(ix), uintptr(iy), uintptr(b.Icon), 48, 48, 0, 0, DI_NORMAL)
	}

	procSetBkMode.Call(uintptr(hdc), BKMODE_TRANSPARENT)
	if b.Enabled {
		procSetTextColor.Call(uintptr(hdc), uintptr(ColorText))
	} else {
		procSetTextColor.Call(uintptr(hdc), 0x00666666)
	}

	oldF, _, _ := procSelectObject.Call(uintptr(hdc), uintptr(font))
	defer procSelectObject.Call(uintptr(hdc), oldF)

	rectText := RECT{b.R.X, b.R.Y + b.R.H - 40, b.R.X + b.R.W, b.R.Y + b.R.H - 5}
	if b.Down {
		rectText.Top += 1
		rectText.Bottom += 1
	}

	procDrawTextW.Call(
		uintptr(hdc),
		uintptr(unsafe.Pointer(mustUTF16(b.Text))),
		drawTextAutoLen,
		uintptr(unsafe.Pointer(&rectText)),
		uintptr(DT_CENTER|DT_VCENTER|DT_SINGLELINE),
	)
}

func fillRect(hdc windows.Handle, rc *RECT, hbr windows.Handle) {
	fill := user32.NewProc("FillRect")
	fill.Call(uintptr(hdc), uintptr(unsafe.Pointer(rc)), uintptr(hbr))
}

func paintTitle(hdc windows.Handle, w, h int32) {
	var r RECT = RECT{0, 0, w, 44}
	br, _, _ := procCreateSolidBrush.Call(uintptr(ColorTitleBar))
	fillRect(hdc, &r, windows.Handle(br))
	procDeleteObject.Call(br)

	if ui.iconApp != 0 {
		procDrawIconEx.Call(uintptr(hdc), 12, 6, uintptr(ui.iconApp), 32, 32, 0, 0, DI_NORMAL)
	}

	procSetBkMode.Call(uintptr(hdc), BKMODE_TRANSPARENT)
	procSetTextColor.Call(uintptr(hdc), uintptr(ColorText))
	oldF, _, _ := procSelectObject.Call(uintptr(hdc), uintptr(ui.font20))
	defer procSelectObject.Call(uintptr(hdc), oldF)

	rt := RECT{54, 0, w - 100, 44}
	titleText := "系统重装工具"
	procDrawTextW.Call(
		uintptr(hdc),
		uintptr(unsafe.Pointer(mustUTF16(titleText))),
		drawTextAutoLen,
		uintptr(unsafe.Pointer(&rt)),
		uintptr(DT_VCENTER|DT_SINGLELINE),
	)
	drawTitleBtn(hdc, &ui.btnMin, false)
	drawTitleBtn(hdc, &ui.btnClose, true)
}

func getAllButtons() []*Button {
	base := []*Button{&ui.btnMin, &ui.btnClose}

	if ui.mode.Load() == int32(ModeSelect) {
		return append(base, &ui.btn7, &ui.btn10, &ui.btn11, &ui.btnAdv)
	}
	return base
}

func paintSelect(hdc windows.Handle, w, h int32) {
	paintTitle(hdc, w, h)

	procSetBkMode.Call(uintptr(hdc), BKMODE_TRANSPARENT)
	procSetTextColor.Call(uintptr(hdc), uintptr(ColorTextHint))
	oldF, _, _ := procSelectObject.Call(uintptr(hdc), uintptr(ui.font20))
	defer procSelectObject.Call(uintptr(hdc), oldF)

	rt := RECT{0, 60, w, 100}
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

func paintProgress(hdc windows.Handle, w, h int32) {
	paintTitle(hdc, w, h)

	p := ui.statusPtr.Load()
	status := "正在准备..."
	if p != 0 {
		status = windows.UTF16PtrToString((*uint16)(unsafe.Pointer(p)))
	}
	procSetBkMode.Call(uintptr(hdc), BKMODE_TRANSPARENT)
	procSetTextColor.Call(uintptr(hdc), uintptr(ColorText))
	oldF, _, _ := procSelectObject.Call(uintptr(hdc), uintptr(ui.font20))
	defer procSelectObject.Call(uintptr(hdc), oldF)

	rt := RECT{20, 60, w - 20, 96}
	procDrawTextW.Call(
		uintptr(hdc),
		uintptr(unsafe.Pointer(mustUTF16(status))),
		drawTextAutoLen,
		uintptr(unsafe.Pointer(&rt)),
		uintptr(DT_CENTER|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS),
	)

	if len(ui.frames) > 0 {
		f := ui.frames[ui.frameIdx%len(ui.frames)]
		x := (w - f.W) / 2
		y := int32(110)

		srcDC, _, _ := procCreateCompatibleDC.Call(uintptr(hdc))
		defer procDeleteDC.Call(srcDC)
		old, _, _ := procSelectObject.Call(srcDC, uintptr(f.Bmp))
		defer procSelectObject.Call(srcDC, old)

		blend := BLENDFUNCTION{BlendOp: AC_SRC_OVER, SourceConstantAlpha: 255, AlphaFormat: AC_SRC_ALPHA}
		blendVal := *(*uint32)(unsafe.Pointer(&blend))
		procAlphaBlend.Call(uintptr(hdc),
			uintptr(x), uintptr(y), uintptr(f.W), uintptr(f.H),
			srcDC, 0, 0, uintptr(f.W), uintptr(f.H),
			*(*uintptr)(unsafe.Pointer(&blend)),
			uintptr(blendVal),
		)
	}

	pct := ui.progress.Load()
	barW := int32(300)
	barH := int32(6)
	barX := (w - barW) / 2
	barY := int32(280)

	bgBr, _, _ := procCreateSolidBrush.Call(0x00333333)
	procRoundRect.Call(uintptr(hdc), uintptr(barX), uintptr(barY), uintptr(barX+barW), uintptr(barY+barH), 3, 3)
	procDeleteObject.Call(bgBr)

	fillW := barW * pct / 100
	if fillW > 0 {
		fBr, _, _ := procCreateSolidBrush.Call(uintptr(ColorHighlight))
		procRoundRect.Call(uintptr(hdc), uintptr(barX), uintptr(barY), uintptr(barX+fillW), uintptr(barY+barH), 3, 3)
		procDeleteObject.Call(fBr)
	}

	oldF2, _, _ := procSelectObject.Call(uintptr(hdc), uintptr(ui.font16))
	defer procSelectObject.Call(uintptr(hdc), oldF2)
	procSetTextColor.Call(uintptr(hdc), 0x00FFFFFF)
	tr := RECT{barX, barY - 28, barX + barW, barY}
	procDrawTextW.Call(
		uintptr(hdc),
		uintptr(unsafe.Pointer(mustUTF16("进度说明"))),
		drawTextAutoLen,
		uintptr(unsafe.Pointer(&tr)),
		uintptr(DT_CENTER|DT_VCENTER|DT_SINGLELINE),
	)
}

// -------------------- layout --------------------

func layoutTitleBar(w, h int32) {
	ui.btnClose = Button{
		R:       Rect{X: w - TitleBtnW, Y: 0, W: TitleBtnW, H: 44},
		Text:    "✕",
		Visible: true, Enabled: true,
		OnClick: func() {
			procPostQuitMessage.Call(0)
		},
	}

	ui.btnMin = Button{
		R:       Rect{X: w - TitleBtnW*2, Y: 0, W: TitleBtnW, H: 44},
		Text:    "─",
		Visible: true, Enabled: true,
		OnClick: func() {
			procShowWindow.Call(uintptr(ui.hwnd), 6)
		},
	}
}

func layoutSelect(w, h int32) {
	layoutTitleBar(w, h)

	ui.btn7 = Button{
		R:    Rect{X: 50, Y: 200, W: 120, H: 120},
		Text: "重装 win7", Icon: ui.icon7, Visible: true, Enabled: true,
		OnClick: func() {
			if Message("提示", "重装系统将会清除C盘数据,是否继续?") {
				uiSwitchToProgress()
				go StartInstall(targetWin7)
			}
		},
	}
	ui.btn10 = Button{
		R:    Rect{X: 240, Y: 200, W: 120, H: 120},
		Text: "重装 win10", Icon: ui.icon10, Visible: true, Enabled: true,
		OnClick: func() {
			if Message("提示", "重装系统将会清除C盘数据,是否继续?") {
				uiSwitchToProgress()
				go StartInstall(targetWin10)
			}
		},
	}
	ui.btn11 = Button{
		R:    Rect{X: 430, Y: 200, W: 120, H: 120},
		Text: "重装 win11", Icon: ui.icon11, Visible: true, Enabled: true,
		OnClick: func() {
			if Message("提示", "重装系统将会清除C盘数据,是否继续?") {
				uiSwitchToProgress()
				go StartInstall(targetWin11)
			}
		},
	}
	ui.btnAdv = Button{
		R:    Rect{X: 10, Y: 50, W: 90, H: 34},
		Text: "高级模式", Icon: 0, Visible: true, Enabled: true,
		OnClick: func() { uiSetStatus("高级模式：TODO") },
	}
}

func layoutProgress() {
	ui.btn7.Visible, ui.btn10.Visible, ui.btn11.Visible, ui.btnAdv.Visible = false, false, false, false
}

func drawTitleBtn(hdc windows.Handle, b *Button, isClose bool) {
	var bgHex uintptr = ColorTitleBar

	if b.Down {
		if isClose {
			bgHex = 0x001A0B99
		} else {
			bgHex = 0x00333333
		}
	} else if b.Hover {
		if isClose {
			bgHex = ColorBtnCloseHover
		} else {
			bgHex = ColorBtnMinHover
		}
	}
	if bgHex != ColorTitleBar {
		brush, _, _ := procCreateSolidBrush.Call(bgHex)
		r := RECT{b.R.X, b.R.Y, b.R.X + b.R.W, b.R.Y + b.R.H}
		fillRect(hdc, &r, windows.Handle(brush))
		procDeleteObject.Call(brush)
	}

	pen, _, _ := procCreatePen.Call(PS_SOLID, 1, 0x00FFFFFF)
	oldPen, _, _ := procSelectObject.Call(uintptr(hdc), pen)

	cx := b.R.X + b.R.W/2
	cy := b.R.Y + b.R.H/2

	if isClose {
		moveToEx(hdc, cx-5, cy-5)
		lineTo(hdc, cx+5, cy+5)
		moveToEx(hdc, cx+5, cy-5)
		lineTo(hdc, cx-5, cy+5)
	} else {
		moveToEx(hdc, cx-5, cy)
		lineTo(hdc, cx+5, cy)
	}
	procSelectObject.Call(uintptr(hdc), oldPen)
	procDeleteObject.Call(pen)
}
func moveToEx(hdc windows.Handle, x, y int32) {
	gdi32.NewProc("MoveToEx").Call(uintptr(hdc), uintptr(x), uintptr(y), 0)
}

func lineTo(hdc windows.Handle, x, y int32) {
	gdi32.NewProc("LineTo").Call(uintptr(hdc), uintptr(x), uintptr(y))
}

// -------------------- input / hit-test --------------------

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
func hitButton(x, y int32) *Button {
	for _, b := range getAllButtons() {
		if b.Visible && b.Enabled && b.R.contains(x, y) {
			return b
		}
	}
	return nil
}

func trackLeave() {
	var t TRACKMOUSEEVENT
	t.CbSize = uint32(unsafe.Sizeof(t))
	t.DwFlags = TME_LEAVE
	t.HWndTrack = ui.hwnd
	procTrackMouseEvent.Call(uintptr(unsafe.Pointer(&t)))
}

// -------------------- WndProc --------------------

var wndProc = windows.NewCallback(func(hwnd uintptr, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {

	case WM_PAINT:
		paint()
		return 0

	case WM_SIZE:
		var rc RECT
		procGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&rc)))
		layoutSelect(rc.Right-rc.Left, rc.Bottom-rc.Top)
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

	case WM_NCHITTEST:
		x := int32(int16(uint16(lParam & 0xFFFF)))
		y := int32(int16(uint16((lParam >> 16) & 0xFFFF)))

		pt := POINT{X: x, Y: y}
		user32.NewProc("ScreenToClient").Call(hwnd, uintptr(unsafe.Pointer(&pt)))

		if hitButton(pt.X, pt.Y) != nil {
			return HTCLIENT
		}

		if pt.Y < 44 {
			return HTCAPTION
		}

		return HTCLIENT

	case WM_TIMER:
		if ui.mode.Load() == int32(ModeProgress) && len(ui.frames) > 0 {
			ui.frameIdx = (ui.frameIdx + 1) % len(ui.frames)
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
			uiSetProgress(0)
			uiSetStatus("正在寻找镜像...")
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

// -------------------- entry points --------------------

func Uiinit() {
	runtime.LockOSThread()

	procSetProcessDPIAware.Call()

	var err error
	ui.iconApp, err = icoToHICON(icoApp, 32)
	if err != nil {
		ui.iconApp = 0
	}
	ui.icon7, _ = icoToHICON(icoWin7, 48)
	ui.icon10, _ = icoToHICON(icoWin10, 48)
	ui.icon11, _ = icoToHICON(icoWin11, 48)

	ui.frames, _ = decodeGIFFrames(waitGIF)

	ui.font16 = makeFont(16, 400, "Microsoft YaHei")
	ui.font20 = makeFont(20, 600, "Segoe UI Semibold")

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

	style := uintptr(WS_POPUP | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS)
	exStyle := uintptr(WS_EX_APPWINDOW | WS_EX_LAYERED)

	hwnd, _, err3 := procCreateWindowExW.Call(
		exStyle,
		uintptr(unsafe.Pointer(cls)),
		uintptr(unsafe.Pointer(mustUTF16("ReSys"))),
		style,
		100, 100, 600, 400,
		0, 0, uintptr(hInst), 0,
	)
	if hwnd == 0 {
		panic(err3)
	}
	ui.hwnd = windows.Handle(hwnd)
	setLayerAlpha(ui.hwnd, 240)

	const WM_SETICON = 0x0080
	const ICON_SMALL = 0
	const ICON_BIG = 1
	if ui.iconApp != 0 {
		procSendMessageW.Call(hwnd, WM_SETICON, ICON_SMALL, uintptr(ui.iconApp))
		procSendMessageW.Call(hwnd, WM_SETICON, ICON_BIG, uintptr(ui.iconApp))
	}

	ui.mode.Store(int32(ModeSelect))
	layoutSelect(600, 400)

	procShowWindow.Call(hwnd, SW_SHOW)
	procUpdateWindow.Call(hwnd)
}

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
