package core

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	gdi32    = windows.NewLazySystemDLL("gdi32.dll")
	msimg32  = windows.NewLazySystemDLL("msimg32.dll")
	shcore   = windows.NewLazySystemDLL("shcore.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")
)

var (
	procRegisterClassExW      = user32.NewProc("RegisterClassExW")
	procCreateWindowExW       = user32.NewProc("CreateWindowExW")
	procDefWindowProcW        = user32.NewProc("DefWindowProcW")
	procDestroyWindow         = user32.NewProc("DestroyWindow")
	procShowWindow            = user32.NewProc("ShowWindow")
	procUpdateWindow          = user32.NewProc("UpdateWindow")
	procGetMessageW           = user32.NewProc("GetMessageW")
	procTranslateMessage      = user32.NewProc("TranslateMessage")
	procDispatchMessageW      = user32.NewProc("DispatchMessageW")
	procPostQuitMessage       = user32.NewProc("PostQuitMessage")
	procPostMessageW          = user32.NewProc("PostMessageW")
	procSendMessageW          = user32.NewProc("SendMessageW")
	procInvalidateRect        = user32.NewProc("InvalidateRect")
	procGetClientRect         = user32.NewProc("GetClientRect")
	procAdjustWindowRectEx    = user32.NewProc("AdjustWindowRectEx")
	procSetWindowTextW        = user32.NewProc("SetWindowTextW")
	procMessageBoxW           = user32.NewProc("MessageBoxW")
	procMessageBoxTimeoutW    = user32.NewProc("MessageBoxTimeoutW")
	procMessageBeep           = user32.NewProc("MessageBeep")
	procGetDC                 = user32.NewProc("GetDC")
	procReleaseDC             = user32.NewProc("ReleaseDC")
	procSystemParametersInfoW = user32.NewProc("SystemParametersInfoW")
	procSetWindowPos          = user32.NewProc("SetWindowPos")
	procGetModuleHandleW      = kernel32.NewProc("GetModuleHandleW")
	procGetCurrentThreadID    = kernel32.NewProc("GetCurrentThreadId")
)

var (
	globalWndProc  = windows.NewCallback(appWndProc)
	classSequence  atomic.Uint64
	windowRegistry sync.Map
	createRegistry sync.Map
)

type App struct {
	opts      Options
	hwnd      windows.Handle
	threadID  uint32
	className string

	dpiMu sync.RWMutex
	dpi   DPIInfo

	sizeMu     sync.RWMutex
	clientSize Size

	initOnce sync.Once
	ready    chan struct{}
	done     chan int
	initErr  error

	closed atomic.Bool

	postMu    sync.Mutex
	postQueue []func()

	timerMu      sync.Mutex
	activeTimers map[uintptr]struct{}
}

func NewApp(opts Options) (*App, error) {
	if opts.ClassName == "" {
		opts.ClassName = fmt.Sprintf("WinUICore_%d", classSequence.Add(1))
	}
	if opts.Width <= 0 {
		opts.Width = 600
	}
	if opts.Height <= 0 {
		opts.Height = 400
	}
	if opts.Style == 0 {
		opts.Style = DefaultWindowStyle
	}
	if opts.ExStyle == 0 {
		opts.ExStyle = DefaultWindowExStyle
	}
	if opts.Cursor == 0 {
		opts.Cursor = CursorArrow
	}
	if opts.Background == 0 {
		opts.Background = RGB(255, 255, 255)
	}

	return &App{
		opts:         opts,
		className:    opts.ClassName,
		ready:        make(chan struct{}),
		done:         make(chan int, 1),
		activeTimers: make(map[uintptr]struct{}),
	}, nil
}

func (a *App) Init() error {
	if a == nil {
		return ErrNotInitialized
	}
	a.initOnce.Do(func() {
		go a.runUIThread()
		<-a.ready
	})
	return a.initErr
}

func (a *App) Run() int {
	if a == nil {
		return -1
	}
	if err := a.Init(); err != nil {
		return -1
	}
	return <-a.done
}

func (a *App) Handle() windows.Handle {
	if a == nil {
		return 0
	}
	return a.hwnd
}

func (a *App) ClientSize() Size {
	a.sizeMu.RLock()
	defer a.sizeMu.RUnlock()
	return a.clientSize
}

func (a *App) IsUIThread() bool {
	if a == nil {
		return false
	}
	return currentThreadID() == a.threadID
}

func (a *App) Post(fn func()) error {
	if a == nil || a.hwnd == 0 {
		return ErrNotInitialized
	}
	if fn == nil {
		return nil
	}
	if a.closed.Load() {
		return ErrAppClosed
	}
	if currentThreadID() == a.threadID {
		fn()
		return nil
	}

	a.postMu.Lock()
	if a.closed.Load() {
		a.postMu.Unlock()
		return ErrAppClosed
	}
	a.postQueue = append(a.postQueue, fn)
	a.postMu.Unlock()

	r1, _, err := procPostMessageW.Call(uintptr(a.hwnd), wmAppInvoke, 0, 0)
	if r1 == 0 {
		return wrapError("PostMessageW", err)
	}
	return nil
}

func (a *App) Invalidate(rect *Rect) {
	if a == nil || a.hwnd == 0 || a.closed.Load() {
		return
	}

	if rect == nil {
		procInvalidateRect.Call(uintptr(a.hwnd), 0, 0)
		return
	}

	local := rect.toWinRect()
	procInvalidateRect.Call(uintptr(a.hwnd), uintptr(unsafe.Pointer(&local)), 0)
}

func (a *App) SetTitle(title string) {
	if a == nil || a.hwnd == 0 || a.closed.Load() {
		return
	}

	text := title
	_ = a.Post(func() {
		ptr, err := windows.UTF16PtrFromString(text)
		if err != nil {
			return
		}
		procSetWindowTextW.Call(uintptr(a.hwnd), uintptr(unsafe.Pointer(ptr)))
	})
}

func (a *App) MessageBox(title, text string, flags uint32, timeout time.Duration) (int, error) {
	if a == nil || a.hwnd == 0 {
		return 0, ErrNotInitialized
	}

	titlePtr, err := windows.UTF16PtrFromString(title)
	if err != nil {
		return 0, err
	}
	textPtr, err := windows.UTF16PtrFromString(text)
	if err != nil {
		return 0, err
	}

	if timeout > 0 && procMessageBoxTimeoutW.Find() == nil {
		r1, _, _ := procMessageBoxTimeoutW.Call(
			uintptr(a.hwnd),
			uintptr(unsafe.Pointer(textPtr)),
			uintptr(unsafe.Pointer(titlePtr)),
			uintptr(flags),
			0,
			uintptr(timeout/time.Millisecond),
		)
		return int(r1), nil
	}

	r1, _, callErr := procMessageBoxW.Call(
		uintptr(a.hwnd),
		uintptr(unsafe.Pointer(textPtr)),
		uintptr(unsafe.Pointer(titlePtr)),
		uintptr(flags),
	)
	if r1 == 0 {
		return 0, wrapError("MessageBoxW", callErr)
	}
	return int(r1), nil
}

func MessageBeep() error {
	r1, _, err := procMessageBeep.Call(0)
	if r1 == 0 {
		return wrapError("MessageBeep", err)
	}
	return nil
}

func (a *App) runUIThread() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	a.threadID = currentThreadID()
	a.setDPI(initProcessDPIAwareness())

	if err := a.createWindow(); err != nil {
		a.initErr = err
		close(a.ready)
		a.done <- -1
		return
	}

	close(a.ready)
	a.done <- a.runLoop()
}

func (a *App) createWindow() error {
	hInst, _, err := procGetModuleHandleW.Call(0)
	if hInst == 0 {
		return wrapError("GetModuleHandleW", err)
	}

	classNamePtr, err := windows.UTF16PtrFromString(a.className)
	if err != nil {
		return err
	}

	cursor, err := loadCursor(a.opts.Cursor)
	if err != nil {
		return err
	}

	wc := wndClassEx{
		CbSize:        uint32(unsafe.Sizeof(wndClassEx{})),
		LpfnWndProc:   globalWndProc,
		HInstance:     windows.Handle(hInst),
		HCursor:       cursor,
		HIcon:         a.opts.Icon.Handle(),
		HIconSm:       a.opts.Icon.Handle(),
		LpszClassName: classNamePtr,
	}

	if atom, _, regErr := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc))); atom == 0 {
		if last := windows.GetLastError(); last != windows.ERROR_CLASS_ALREADY_EXISTS {
			return wrapError("RegisterClassExW", regErr)
		}
	}

	wa, err := workArea()
	if err != nil {
		return err
	}

	clientW := a.DP(a.opts.Width)
	clientH := a.DP(a.opts.Height)
	frame := winRect{Right: clientW, Bottom: clientH}
	if r1, _, adjustErr := procAdjustWindowRectEx.Call(
		uintptr(unsafe.Pointer(&frame)),
		uintptr(a.opts.Style),
		0,
		uintptr(a.opts.ExStyle),
	); r1 == 0 {
		return wrapError("AdjustWindowRectEx", adjustErr)
	}

	winW := frame.Right - frame.Left
	winH := frame.Bottom - frame.Top
	x := wa.Left + (wa.Right-wa.Left-winW)/2
	y := wa.Top + (wa.Bottom-wa.Top-winH)/2

	title := a.opts.Title
	if title == "" {
		title = a.className
	}
	titlePtr, err := windows.UTF16PtrFromString(title)
	if err != nil {
		return err
	}

	createRegistry.Store(a.threadID, a)
	hwnd, _, createErr := procCreateWindowExW.Call(
		uintptr(a.opts.ExStyle),
		uintptr(unsafe.Pointer(classNamePtr)),
		uintptr(unsafe.Pointer(titlePtr)),
		uintptr(a.opts.Style),
		uintptr(x),
		uintptr(y),
		uintptr(winW),
		uintptr(winH),
		0,
		0,
		hInst,
		0,
	)
	createRegistry.Delete(a.threadID)
	if hwnd == 0 {
		return wrapError("CreateWindowExW", createErr)
	}

	a.hwnd = windows.Handle(hwnd)
	windowRegistry.Store(a.hwnd, a)
	a.refreshWindowDPI()

	if a.opts.Icon != nil && a.opts.Icon.handle != 0 {
		procSendMessageW.Call(hwnd, wmSetIcon, iconSmall, uintptr(a.opts.Icon.handle))
		procSendMessageW.Call(hwnd, wmSetIcon, iconBig, uintptr(a.opts.Icon.handle))
	}

	if a.opts.OnCreate != nil {
		if err := a.opts.OnCreate(a); err != nil {
			procDestroyWindow.Call(hwnd)
			return err
		}
	}

	if rect, err := clientRect(a.hwnd); err == nil {
		size := Size{Width: rect.W, Height: rect.H}
		a.updateClientSize(size)
		if a.opts.OnResize != nil {
			a.opts.OnResize(a, size)
		}
	}

	procShowWindow.Call(hwnd, showWindowNormal)
	procUpdateWindow.Call(hwnd)
	return nil
}

func clientRect(hwnd windows.Handle) (Rect, error) {
	var rc winRect
	r1, _, err := procGetClientRect.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&rc)))
	if r1 == 0 {
		return Rect{}, wrapError("GetClientRect", err)
	}
	return rectFromWinRect(rc), nil
}

func workArea() (winRect, error) {
	var rc winRect
	r1, _, err := procSystemParametersInfoW.Call(
		spiGetWorkArea,
		0,
		uintptr(unsafe.Pointer(&rc)),
		0,
	)
	if r1 == 0 {
		return winRect{}, wrapError("SystemParametersInfoW", err)
	}
	return rc, nil
}

func loadCursor(cursor CursorID) (windows.Handle, error) {
	h, _, err := procLoadCursorW.Call(0, uintptr(cursor))
	if h == 0 {
		return 0, wrapError("LoadCursorW", err)
	}
	return windows.Handle(h), nil
}

func (a *App) setCursor(cursor CursorID) {
	h, err := loadCursor(cursor)
	if err != nil {
		return
	}
	procSetCursor.Call(uintptr(h))
}

func (a *App) SetCursor(cursor CursorID) {
	if a == nil || a.hwnd == 0 {
		return
	}
	if a.IsUIThread() {
		a.setCursor(cursor)
		return
	}
	_ = a.Post(func() {
		a.setCursor(cursor)
	})
}

func (a *App) captureMouse() {
	if a == nil || a.hwnd == 0 {
		return
	}
	procSetCapture.Call(uintptr(a.hwnd))
}

func (a *App) CaptureMouse() {
	if a == nil || a.hwnd == 0 {
		return
	}
	if a.IsUIThread() {
		a.captureMouse()
		return
	}
	_ = a.Post(func() {
		a.captureMouse()
	})
}

func (a *App) releaseMouse() {
	procReleaseCapture.Call()
}

func (a *App) ReleaseMouse() {
	if a == nil || a.hwnd == 0 {
		return
	}
	if a.IsUIThread() {
		a.releaseMouse()
		return
	}
	_ = a.Post(func() {
		a.releaseMouse()
	})
}

func (a *App) updateClientSize(size Size) {
	a.sizeMu.Lock()
	a.clientSize = size
	a.sizeMu.Unlock()
}

func currentThreadID() uint32 {
	r1, _, _ := procGetCurrentThreadID.Call()
	return uint32(r1)
}
