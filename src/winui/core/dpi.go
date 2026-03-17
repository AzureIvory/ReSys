package core

import (
	"math"
	"sync"
	"unsafe"
)

var (
	procSetProcessDPIAware              = user32.NewProc("SetProcessDPIAware")
	procSetProcessDpiAwarenessContext   = user32.NewProc("SetProcessDpiAwarenessContext")
	procGetThreadDpiAwarenessContext    = user32.NewProc("GetThreadDpiAwarenessContext")
	procGetAwarenessFromDpiAwarenessCtx = user32.NewProc("GetAwarenessFromDpiAwarenessContext")
	procGetDpiForWindow                 = user32.NewProc("GetDpiForWindow")
	procSetProcessDpiAwareness          = shcore.NewProc("SetProcessDpiAwareness")
	procGetDeviceCaps                   = gdi32.NewProc("GetDeviceCaps")
)

var dpiInitOnce sync.Once

const (
	processDpiSystemAware = 1
	processDpiPerMonitor  = 2
)

const (
	hResultOK     uint32 = 0
	hResultDenied uint32 = 0x80070005
)

const (
	dpiAwareContextSystemAware       = ^uintptr(1)
	dpiAwareContextPerMonitorAware   = ^uintptr(2)
	dpiAwareContextPerMonitorAwareV2 = ^uintptr(3)
)

func initProcessDPIAwareness() DPIInfo {
	info := queryScreenDPI()
	info.Awareness = DPIAwarenessUnknown

	dpiInitOnce.Do(func() {
		switch {
		case trySetDpiAwarenessContext(dpiAwareContextPerMonitorAwareV2):
			info.Awareness = DPIAwarenessPerMonitorV2
		case trySetDpiAwarenessContext(dpiAwareContextPerMonitorAware):
			info.Awareness = DPIAwarenessPerMonitor
		case trySetProcessDpiAwareness(processDpiPerMonitor):
			info.Awareness = DPIAwarenessPerMonitor
		case trySetProcessDpiAwareness(processDpiSystemAware):
			info.Awareness = DPIAwarenessSystem
		case trySetProcessDPIAware():
			info.Awareness = DPIAwarenessSystem
		default:
			info.Awareness = currentDPIAwareness()
			if info.Awareness == DPIAwarenessUnknown {
				info.Awareness = DPIAwarenessSystem
			}
		}
	})

	if current := currentDPIAwareness(); current != DPIAwarenessUnknown {
		info.Awareness = current
	}
	return info
}

func trySetDpiAwarenessContext(ctx uintptr) bool {
	if err := procSetProcessDpiAwarenessContext.Find(); err != nil {
		return false
	}
	r1, _, _ := procSetProcessDpiAwarenessContext.Call(ctx)
	return r1 != 0
}

func trySetProcessDpiAwareness(level uintptr) bool {
	if err := procSetProcessDpiAwareness.Find(); err != nil {
		return false
	}
	hr, _, _ := procSetProcessDpiAwareness.Call(level)
	return uint32(hr) == hResultOK || uint32(hr) == hResultDenied
}

func trySetProcessDPIAware() bool {
	if err := procSetProcessDPIAware.Find(); err != nil {
		return false
	}
	r1, _, _ := procSetProcessDPIAware.Call()
	return r1 != 0
}

func currentDPIAwareness() DPIAwareness {
	if err := procGetThreadDpiAwarenessContext.Find(); err != nil {
		return DPIAwarenessUnknown
	}
	ctx, _, _ := procGetThreadDpiAwarenessContext.Call()
	switch ctx {
	case dpiAwareContextPerMonitorAwareV2:
		return DPIAwarenessPerMonitorV2
	case dpiAwareContextPerMonitorAware:
		return DPIAwarenessPerMonitor
	case dpiAwareContextSystemAware:
		return DPIAwarenessSystem
	}

	if err := procGetAwarenessFromDpiAwarenessCtx.Find(); err != nil {
		return DPIAwarenessUnknown
	}
	r1, _, _ := procGetAwarenessFromDpiAwarenessCtx.Call(ctx)
	switch r1 {
	case processDpiSystemAware:
		return DPIAwarenessSystem
	case processDpiPerMonitor:
		return DPIAwarenessPerMonitor
	default:
		return DPIAwarenessUnknown
	}
}

func queryScreenDPI() DPIInfo {
	info := DPIInfo{X: 96, Y: 96, Scale: 1}

	hdc, _, _ := procGetDC.Call(0)
	if hdc == 0 {
		return info
	}
	defer procReleaseDC.Call(0, hdc)

	dx, _, _ := procGetDeviceCaps.Call(hdc, logPixelsX)
	dy, _, _ := procGetDeviceCaps.Call(hdc, logPixelsY)
	if dx > 0 {
		info.X = int32(dx)
		info.Scale = float64(dx) / 96.0
	}
	if dy > 0 {
		info.Y = int32(dy)
	}
	return info
}

func (a *App) refreshWindowDPI() {
	if a == nil || a.hwnd == 0 {
		return
	}
	if err := procGetDpiForWindow.Find(); err == nil {
		dpiX, _, _ := procGetDpiForWindow.Call(uintptr(a.hwnd))
		if dpiX > 0 {
			info := a.DPI()
			info.X = int32(dpiX)
			info.Y = int32(dpiX)
			info.Scale = float64(info.X) / 96.0
			a.setDPI(info)
			return
		}
	}
	info := queryScreenDPI()
	info.Awareness = a.DPI().Awareness
	a.setDPI(info)
}

func (a *App) setDPI(info DPIInfo) {
	a.dpiMu.Lock()
	a.dpi = info
	a.dpiMu.Unlock()
}

func (a *App) DPI() DPIInfo {
	a.dpiMu.RLock()
	defer a.dpiMu.RUnlock()
	return a.dpi
}

func (a *App) DP(value int32) int32 {
	scale := a.DPI().Scale
	if scale <= 0 {
		scale = 1
	}
	return int32(math.Round(float64(value) * scale))
}

func (a *App) Scale(value int) int {
	return int(a.DP(int32(value)))
}

func dpiChangeFromMessage(wParam, lParam uintptr, current DPIInfo) (DPIInfo, *winRect) {
	x, y := dpiFromWParam(wParam)
	if x <= 0 {
		x = current.X
	}
	if y <= 0 {
		y = current.Y
	}
	if x <= 0 {
		x = 96
	}
	if y <= 0 {
		y = x
	}

	info := DPIInfo{
		X:         x,
		Y:         y,
		Scale:     float64(x) / 96.0,
		Awareness: current.Awareness,
	}
	if lParam == 0 {
		return info, nil
	}
	return info, (*winRect)(unsafe.Pointer(lParam))
}
