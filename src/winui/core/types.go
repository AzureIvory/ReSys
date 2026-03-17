package core

import "golang.org/x/sys/windows"

type Color uint32

type CursorID uintptr

type FontQuality byte

type DPIAwareness int

type MouseButton uint8

type Point struct {
	X int32
	Y int32
}

type Size struct {
	Width  int32
	Height int32
}

type Rect struct {
	X int32
	Y int32
	W int32
	H int32
}

type DPIInfo struct {
	X         int32
	Y         int32
	Scale     float64
	Awareness DPIAwareness
}

type MouseEvent struct {
	Point  Point
	Button MouseButton
	Flags  uintptr
}

type KeyEvent struct {
	Key   uint32
	Flags uintptr
}

type Options struct {
	ClassName      string
	Title          string
	Width          int32
	Height         int32
	Style          uint32
	ExStyle        uint32
	Cursor         CursorID
	Icon           *Icon
	Background     Color
	DoubleBuffered bool

	OnCreate     func(*App) error
	OnPaint      func(*App, *Canvas)
	OnResize     func(*App, Size)
	OnMouseMove  func(*App, MouseEvent)
	OnMouseLeave func(*App)
	OnMouseDown  func(*App, MouseEvent)
	OnMouseUp    func(*App, MouseEvent)
	OnKeyDown    func(*App, KeyEvent)
	OnChar       func(*App, rune)
	OnFocus      func(*App, bool)
	OnTimer      func(*App, uintptr)
	OnDPIChanged func(*App, DPIInfo)
	OnDestroy    func(*App)
}

const (
	DPIAwarenessUnknown DPIAwareness = iota
	DPIAwarenessSystem
	DPIAwarenessPerMonitor
	DPIAwarenessPerMonitorV2
)

const (
	MouseButtonLeft MouseButton = 1
)

const (
	WSCaption      uint32 = 0x00C00000
	WSSysMenu      uint32 = 0x00080000
	WSMinimizeBox  uint32 = 0x00020000
	WSThickFrame   uint32 = 0x00040000
	WSMaximizeBox  uint32 = 0x00010000
	WSClipSiblings uint32 = 0x04000000
	WSClipChildren uint32 = 0x02000000

	WSExAppWindow uint32 = 0x00040000
	WSExLayered   uint32 = 0x00080000
)

const (
	DefaultWindowStyle   = WSCaption | WSSysMenu | WSMinimizeBox | WSClipChildren | WSClipSiblings
	DefaultWindowExStyle = WSExAppWindow
)

const (
	CursorArrow CursorID = 32512
	CursorIBeam CursorID = 32513
	CursorHand  CursorID = 32649
)

const (
	DTCenter      uint32 = 0x00000001
	DTVCenter     uint32 = 0x00000004
	DTSingleLine  uint32 = 0x00000020
	DTEndEllipsis uint32 = 0x00008000
)

const (
	MessageBoxOKCancel    uint32 = 0x00000001
	MessageBoxRetryCancel uint32 = 0x00000005
)

const (
	MessageBoxResultOK    = 1
	MessageBoxResultRetry = 4
)

const (
	FontQualityAntialiased FontQuality = 4
	FontQualityClearType   FontQuality = 5
)

const (
	drawTextAutoLen = uintptr(^uint32(0))

	showWindowNormal = 5

	wmDestroy     = 0x0002
	wmSize        = 0x0005
	wmSetFocus    = 0x0007
	wmKillFocus   = 0x0008
	wmPaint       = 0x000F
	wmClose       = 0x0010
	wmSetIcon     = 0x0080
	wmKeyDown     = 0x0100
	wmChar        = 0x0102
	wmTimer       = 0x0113
	wmMouseMove   = 0x0200
	wmLButtonDown = 0x0201
	wmLButtonUp   = 0x0202
	wmMouseLeave  = 0x02A3
	wmDPICHanged  = 0x02E0
	wmApp         = 0x8000
	wmNcCreate    = 0x0081
	wmNcDestroy   = 0x0082
	wmAppInvoke   = wmApp + 0x240

	iconSmall = 0
	iconBig   = 1

	psSolid = 0

	srccopy = 0x00CC0020

	bkModeTransparent = 1

	tmeLeave = 0x00000002

	diNormal = 0x0003

	acSrcOver  = 0x00
	acSrcAlpha = 0x01

	logPixelsX = 88
	logPixelsY = 90

	swpNoZOrder   = 0x0004
	swpNoActivate = 0x0010

	spiGetWorkArea = 0x0030
)

const (
	KeyBack   uint32 = 0x08
	KeyTab    uint32 = 0x09
	KeyReturn uint32 = 0x0D
	KeyEscape uint32 = 0x1B
	KeySpace  uint32 = 0x20
	KeyHome   uint32 = 0x24
	KeyLeft   uint32 = 0x25
	KeyUp     uint32 = 0x26
	KeyRight  uint32 = 0x27
	KeyDown   uint32 = 0x28
	KeyEnd    uint32 = 0x23
	KeyDelete uint32 = 0x2E
)

type wndClassEx struct {
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

type msg struct {
	HWnd    windows.Handle
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      point
}

type point struct {
	X int32
	Y int32
}

type winRect struct {
	Left   int32
	Top    int32
	Right  int32
	Bottom int32
}

func RGB(r, g, b byte) Color {
	return Color(uint32(r) | (uint32(g) << 8) | (uint32(b) << 16))
}

func (r Rect) Contains(x, y int32) bool {
	return x >= r.X && y >= r.Y && x < r.X+r.W && y < r.Y+r.H
}

func (r Rect) Empty() bool {
	return r.W <= 0 || r.H <= 0
}

func (r Rect) toWinRect() winRect {
	return winRect{
		Left:   r.X,
		Top:    r.Y,
		Right:  r.X + r.W,
		Bottom: r.Y + r.H,
	}
}

func rectFromWinRect(r winRect) Rect {
	return Rect{
		X: r.Left,
		Y: r.Top,
		W: r.Right - r.Left,
		H: r.Bottom - r.Top,
	}
}

func pointFromLParam(lParam uintptr) Point {
	return Point{
		X: int32(int16(uint16(lParam & 0xFFFF))),
		Y: int32(int16(uint16((lParam >> 16) & 0xFFFF))),
	}
}

func dpiFromWParam(wParam uintptr) (int32, int32) {
	return int32(uint16(wParam & 0xFFFF)), int32(uint16((wParam >> 16) & 0xFFFF))
}
