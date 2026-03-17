package core

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procTrackMouseEvent = user32.NewProc("TrackMouseEvent")
	procSetCapture      = user32.NewProc("SetCapture")
	procReleaseCapture  = user32.NewProc("ReleaseCapture")
	procLoadCursorW     = user32.NewProc("LoadCursorW")
	procSetCursor       = user32.NewProc("SetCursor")
)

type trackMouseEvent struct {
	CbSize      uint32
	DwFlags     uint32
	HWndTrack   windows.Handle
	DwHoverTime uint32
}

type MouseTarget struct {
	Bounds  func() Rect
	Visible func() bool
	Enabled func() bool
	Cursor  CursorID

	OnEnter func()
	OnLeave func()
	OnMove  func(MouseEvent)
	OnDown  func(MouseEvent)
	OnUp    func(MouseEvent)
	OnClick func(MouseEvent)
}

type InputRouter struct {
	app      *App
	targets  []*MouseTarget
	hovered  *MouseTarget
	captured *MouseTarget
}

func NewInputRouter(app *App) *InputRouter {
	return &InputRouter{app: app}
}

func (r *InputRouter) SetTargets(targets ...*MouseTarget) {
	r.targets = append(r.targets[:0], targets...)
	r.hovered = nil
	r.captured = nil
}

func (r *InputRouter) HandleMove(ev MouseEvent) bool {
	if r == nil {
		return false
	}
	r.trackLeave()

	target := r.hit(ev.Point)
	changed := r.hovered != target
	if changed {
		if r.hovered != nil && r.hovered.OnLeave != nil {
			r.hovered.OnLeave()
		}
		r.hovered = target
		if r.hovered != nil && r.hovered.OnEnter != nil {
			r.hovered.OnEnter()
		}
	}
	if target != nil && target.OnMove != nil {
		target.OnMove(ev)
	}
	r.applyCursor(target)
	return changed
}

func (r *InputRouter) HandleLeave() bool {
	if r == nil || r.hovered == nil {
		r.applyCursor(nil)
		return false
	}
	if r.hovered.OnLeave != nil {
		r.hovered.OnLeave()
	}
	r.hovered = nil
	r.applyCursor(nil)
	return true
}

func (r *InputRouter) HandleDown(ev MouseEvent) bool {
	if r == nil {
		return false
	}
	target := r.hit(ev.Point)
	if target == nil {
		return false
	}
	r.captured = target
	if r.app != nil {
		r.app.captureMouse()
	}
	if target.OnDown != nil {
		target.OnDown(ev)
	}
	return true
}

func (r *InputRouter) HandleUp(ev MouseEvent) bool {
	if r == nil {
		return false
	}
	if r.app != nil {
		r.app.releaseMouse()
	}
	if r.captured == nil {
		return false
	}

	target := r.captured
	r.captured = nil
	if target.OnUp != nil {
		target.OnUp(ev)
	}
	if target == r.hit(ev.Point) && target.OnClick != nil {
		target.OnClick(ev)
	}
	return true
}

func (r *InputRouter) hit(pt Point) *MouseTarget {
	for _, target := range r.targets {
		if target == nil || target.Bounds == nil {
			continue
		}
		if target.Visible != nil && !target.Visible() {
			continue
		}
		if target.Enabled != nil && !target.Enabled() {
			continue
		}
		if target.Bounds().Contains(pt.X, pt.Y) {
			return target
		}
	}
	return nil
}

func (r *InputRouter) trackLeave() {
	if r == nil || r.app == nil || r.app.hwnd == 0 {
		return
	}
	event := trackMouseEvent{
		CbSize:    uint32(unsafe.Sizeof(trackMouseEvent{})),
		DwFlags:   tmeLeave,
		HWndTrack: r.app.hwnd,
	}
	procTrackMouseEvent.Call(uintptr(unsafe.Pointer(&event)))
}

func (r *InputRouter) applyCursor(target *MouseTarget) {
	cursor := CursorArrow
	if target != nil && target.Cursor != 0 {
		cursor = target.Cursor
	}
	if r.app != nil {
		r.app.setCursor(cursor)
	}
}
