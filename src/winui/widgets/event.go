package widgets

import "ReSys/src/winui/core"

type EventType int

const (
	EventMouseMove EventType = iota + 1
	EventMouseEnter
	EventMouseLeave
	EventMouseDown
	EventMouseUp
	EventClick
	EventFocus
	EventBlur
	EventKeyDown
	EventChar
	EventTimer
	EventPaint
	EventResize
)

type Event struct {
	Type    EventType
	Point   core.Point
	Button  core.MouseButton
	Key     core.KeyEvent
	Rune    rune
	Flags   uintptr
	TimerID uintptr
	Bounds  Rect
	Ctx     *PaintCtx
	Source  Widget
}

func eventFromMouse(t EventType, ev core.MouseEvent) Event {
	return Event{
		Type:   t,
		Point:  ev.Point,
		Button: ev.Button,
		Flags:  ev.Flags,
	}
}
