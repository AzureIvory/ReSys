package core

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

func appWndProc(hwnd uintptr, msg uint32, wParam, lParam uintptr) uintptr {
	app := lookupApp(windows.Handle(hwnd))
	if app == nil && msg == wmNcCreate {
		app = lookupCreatingApp()
		if app != nil {
			app.hwnd = windows.Handle(hwnd)
			windowRegistry.Store(app.hwnd, app)
		}
	}
	if app == nil {
		ret, _, _ := procDefWindowProcW.Call(hwnd, uintptr(msg), wParam, lParam)
		return ret
	}

	switch msg {
	case wmSetFocus:
		if app.opts.OnFocus != nil {
			app.opts.OnFocus(app, true)
		}
		return 0

	case wmKillFocus:
		if app.opts.OnFocus != nil {
			app.opts.OnFocus(app, false)
		}
		return 0

	case wmPaint:
		session, err := beginPaintSession(app.hwnd, app.opts.DoubleBuffered)
		if err == nil {
			if session.canvas != nil {
				_ = session.canvas.Clear(app.opts.Background)
				if app.opts.OnPaint != nil {
					app.opts.OnPaint(app, session.canvas)
				}
			}
			_ = session.close()
		}
		return 0

	case wmSize:
		if rect, err := clientRect(app.hwnd); err == nil {
			size := Size{Width: rect.W, Height: rect.H}
			app.updateClientSize(size)
			if app.opts.OnResize != nil {
				app.opts.OnResize(app, size)
			}
		}
		return 0

	case wmMouseMove:
		if app.opts.OnMouseMove != nil {
			app.opts.OnMouseMove(app, MouseEvent{
				Point: pointFromLParam(lParam),
				Flags: wParam,
			})
		}
		return 0

	case wmMouseLeave:
		if app.opts.OnMouseLeave != nil {
			app.opts.OnMouseLeave(app)
		}
		return 0

	case wmLButtonDown:
		if app.opts.OnMouseDown != nil {
			app.opts.OnMouseDown(app, MouseEvent{
				Point:  pointFromLParam(lParam),
				Button: MouseButtonLeft,
				Flags:  wParam,
			})
		}
		return 0

	case wmLButtonUp:
		if app.opts.OnMouseUp != nil {
			app.opts.OnMouseUp(app, MouseEvent{
				Point:  pointFromLParam(lParam),
				Button: MouseButtonLeft,
				Flags:  wParam,
			})
		}
		return 0

	case wmKeyDown:
		if app.opts.OnKeyDown != nil {
			app.opts.OnKeyDown(app, KeyEvent{
				Key:   uint32(wParam),
				Flags: lParam,
			})
		}
		return 0

	case wmChar:
		if app.opts.OnChar != nil {
			app.opts.OnChar(app, rune(wParam))
		}
		return 0

	case wmTimer:
		if app.opts.OnTimer != nil {
			app.opts.OnTimer(app, wParam)
		}
		return 0

	case wmDPICHanged:
		info, suggested := dpiChangeFromMessage(wParam, lParam, app.DPI())
		app.setDPI(info)
		if suggested != nil {
			procSetWindowPos.Call(
				uintptr(app.hwnd),
				0,
				uintptr(suggested.Left),
				uintptr(suggested.Top),
				uintptr(suggested.Right-suggested.Left),
				uintptr(suggested.Bottom-suggested.Top),
				swpNoZOrder|swpNoActivate,
			)
		}
		if app.opts.OnDPIChanged != nil {
			app.opts.OnDPIChanged(app, info)
		}
		if rect, err := clientRect(app.hwnd); err == nil {
			size := Size{Width: rect.W, Height: rect.H}
			app.updateClientSize(size)
			if app.opts.OnResize != nil {
				app.opts.OnResize(app, size)
			}
		}
		return 0

	case wmAppInvoke:
		app.drainPosted()
		return 0

	case wmClose:
		procDestroyWindow.Call(uintptr(app.hwnd))
		return 0

	case wmDestroy:
		app.closed.Store(true)
		app.killAllTimers()
		app.drainPosted()
		if app.opts.OnDestroy != nil {
			app.opts.OnDestroy(app)
		}
		procPostQuitMessage.Call(0)
		return 0

	case wmNcDestroy:
		windowRegistry.Delete(app.hwnd)
		return 0
	}

	ret, _, _ := procDefWindowProcW.Call(hwnd, uintptr(msg), wParam, lParam)
	return ret
}

func (a *App) runLoop() int {
	var message msg
	for {
		r1, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&message)), 0, 0, 0)
		switch int32(r1) {
		case -1:
			return -1
		case 0:
			return int(message.WParam)
		default:
			procTranslateMessage.Call(uintptr(unsafe.Pointer(&message)))
			procDispatchMessageW.Call(uintptr(unsafe.Pointer(&message)))
		}
	}
}

func (a *App) drainPosted() {
	a.postMu.Lock()
	queue := a.postQueue
	a.postQueue = nil
	a.postMu.Unlock()

	for _, fn := range queue {
		if fn != nil {
			fn()
		}
	}
}

func lookupApp(hwnd windows.Handle) *App {
	if hwnd == 0 {
		return nil
	}
	if value, ok := windowRegistry.Load(hwnd); ok {
		if app, ok := value.(*App); ok {
			return app
		}
	}
	return nil
}

func lookupCreatingApp() *App {
	if value, ok := createRegistry.Load(currentThreadID()); ok {
		if app, ok := value.(*App); ok {
			return app
		}
	}
	return nil
}
