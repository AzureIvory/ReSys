package widgets

import (
	"ReSys/src/winui/core"
	"fmt"
	"sync/atomic"
)

type Rect = core.Rect
type Color = core.Color
type CursorID = core.CursorID

type Widget interface {
	ID() string
	Bounds() Rect
	SetBounds(Rect)
	Visible() bool
	SetVisible(bool)
	Enabled() bool
	SetEnabled(bool)
	HitTest(x, y int32) bool
	OnEvent(evt Event) bool
	Paint(ctx *PaintCtx)
}

type widgetNode interface {
	Widget
	setScene(*Scene)
	scene() *Scene
	setParent(Container)
	parent() Container
	cursor() CursorID
}

type focusableWidget interface {
	Widget
	acceptsFocus() bool
}

type overlayWidget interface {
	Widget
	PaintOverlay(ctx *PaintCtx)
}

var widgetSequence atomic.Uint64

func newWidgetID(prefix string) string {
	if prefix == "" {
		prefix = "widget"
	}
	return fmt.Sprintf("%s-%d", prefix, widgetSequence.Add(1))
}

type widgetBase struct {
	id        string
	bounds    Rect
	visible   bool
	enabled   bool
	sceneRef  *Scene
	parentRef Container
}

func newWidgetBase(id, prefix string) widgetBase {
	if id == "" {
		id = newWidgetID(prefix)
	}
	return widgetBase{
		id:      id,
		visible: true,
		enabled: true,
	}
}

func (b *widgetBase) ID() string {
	return b.id
}

func (b *widgetBase) Bounds() Rect {
	return b.bounds
}

func (b *widgetBase) Visible() bool {
	return b.visible
}

func (b *widgetBase) Enabled() bool {
	return b.enabled
}

func (b *widgetBase) HitTest(x, y int32) bool {
	return b.visible && b.bounds.Contains(x, y)
}

func (b *widgetBase) setScene(scene *Scene) {
	b.sceneRef = scene
}

func (b *widgetBase) scene() *Scene {
	return b.sceneRef
}

func (b *widgetBase) setParent(parent Container) {
	b.parentRef = parent
}

func (b *widgetBase) parent() Container {
	return b.parentRef
}

func (b *widgetBase) cursor() CursorID {
	return core.CursorArrow
}

func (b *widgetBase) setBounds(owner Widget, rect Rect) {
	if b.bounds == rect {
		return
	}
	b.bounds = rect
	if b.sceneRef != nil {
		b.sceneRef.Invalidate(owner)
	}
}

func (b *widgetBase) setVisible(owner Widget, visible bool) {
	if b.visible == visible {
		return
	}
	b.visible = visible
	if b.sceneRef != nil {
		b.sceneRef.Invalidate(owner)
	}
}

func (b *widgetBase) setEnabled(owner Widget, enabled bool) {
	if b.enabled == enabled {
		return
	}
	b.enabled = enabled
	if b.sceneRef != nil {
		b.sceneRef.Invalidate(owner)
	}
}

func (b *widgetBase) runOnUI(fn func()) {
	if fn == nil {
		return
	}
	if b.sceneRef == nil {
		fn()
		return
	}
	b.sceneRef.runOnUI(fn)
}

func (b *widgetBase) invalidate(owner Widget) {
	if b.sceneRef != nil {
		b.sceneRef.Invalidate(owner)
	}
}

func asWidgetNode(widget Widget) widgetNode {
	if widget == nil {
		return nil
	}
	node, _ := widget.(widgetNode)
	return node
}
