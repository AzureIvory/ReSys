package widgets

import (
	"ReSys/src/winui/core"
	"fmt"
	"sync"
	"time"
)

type PaintCtx struct {
	canvas *core.PaintCtx
	scene  *Scene
}

func newPaintCtx(scene *Scene, canvas *core.PaintCtx) *PaintCtx {
	return &PaintCtx{
		canvas: canvas,
		scene:  scene,
	}
}

func (p *PaintCtx) Canvas() *core.PaintCtx {
	if p == nil {
		return nil
	}
	return p.canvas
}

func (p *PaintCtx) Bounds() Rect {
	if p == nil || p.canvas == nil {
		return Rect{}
	}
	return p.canvas.Bounds()
}

func (p *PaintCtx) DP(value int32) int32 {
	if p == nil || p.scene == nil || p.scene.app == nil {
		return value
	}
	return p.scene.app.DP(value)
}

func (p *PaintCtx) FillRoundRect(rect Rect, radius int32, color core.Color) error {
	if p == nil || p.canvas == nil {
		return nil
	}
	return p.canvas.FillRoundRect(rect, radius, color)
}

// FillRect 绘制实心矩形。
func (p *PaintCtx) FillRect(rect Rect, color core.Color) error {
	if p == nil || p.canvas == nil {
		return nil
	}
	return p.canvas.FillRect(rect, color)
}

func (p *PaintCtx) StrokeRoundRect(rect Rect, radius int32, color core.Color, width int32) error {
	if p == nil || p.canvas == nil {
		return nil
	}
	return p.canvas.StrokeRoundRect(rect, radius, color, width)
}

func (p *PaintCtx) DrawIcon(icon *core.Icon, rect Rect) error {
	if p == nil || p.canvas == nil {
		return nil
	}
	return p.canvas.DrawIcon(icon, rect)
}

func (p *PaintCtx) DrawText(text string, rect Rect, style TextStyle) error {
	if p == nil || p.canvas == nil {
		return nil
	}
	font, err := p.scene.font(style.Font)
	if err != nil {
		return err
	}
	return p.canvas.DrawText(text, rect, font, style.Color, style.Format)
}

// MeasureText 测量文本在当前主题字体下的尺寸。
func (p *PaintCtx) MeasureText(text string, spec FontSpec) (core.Size, error) {
	if p == nil || p.canvas == nil || p.scene == nil {
		return core.Size{}, nil
	}
	font, err := p.scene.font(spec)
	if err != nil {
		return core.Size{}, err
	}
	return p.canvas.MeasureText(text, font)
}

func (p *PaintCtx) DrawProgress(rect Rect, value int32, style ProgressStyle) error {
	if p == nil || p.canvas == nil || rect.Empty() {
		return nil
	}
	value = clampValue(value, 0, 100)
	trackRadius := p.DP(style.CornerRadius)
	if trackRadius <= 0 {
		trackRadius = max32(1, rect.H/2)
	}

	if err := p.canvas.FillRoundRect(rect, trackRadius, style.TrackColor); err != nil {
		return err
	}

	fillW := rect.W * value / 100
	if fillW > 0 {
		fillW = clampValue(fillW, 1, rect.W)
		if err := p.canvas.FillRoundRect(
			Rect{X: rect.X, Y: rect.Y, W: fillW, H: rect.H},
			min32(trackRadius, max32(1, fillW)),
			style.FillColor,
		); err != nil {
			return err
		}
	}

	if !style.ShowPercent {
		return nil
	}

	bubbleColor := style.BubbleColor
	if bubbleColor == 0 {
		bubbleColor = style.FillColor
	}
	textColor := style.TextColor
	if textColor == 0 {
		textColor = core.RGB(255, 255, 255)
	}

	bubbleW := p.DP(52)
	bubbleH := p.DP(28)
	bubbleGap := p.DP(6)
	pointerH := p.DP(6)
	pointerHalfW := p.DP(6)
	pointerInset := p.DP(10)
	bubbleRadius := min32(max32(1, trackRadius), max32(1, bubbleH/2))

	anchorX := rect.X + fillW
	if anchorX < rect.X {
		anchorX = rect.X
	}
	if anchorX > rect.X+rect.W {
		anchorX = rect.X + rect.W
	}

	bubbleX := anchorX - bubbleW/2
	if rect.W > bubbleW {
		bubbleX = clampValue(bubbleX, rect.X, rect.X+rect.W-bubbleW)
	} else {
		bubbleX = rect.X + (rect.W-bubbleW)/2
	}

	tipY := rect.Y - bubbleGap
	baseY := tipY - pointerH
	bubbleRect := Rect{
		X: bubbleX,
		Y: baseY - bubbleH,
		W: bubbleW,
		H: bubbleH,
	}

	pointerX := anchorX
	minPointerX := bubbleRect.X + pointerInset
	maxPointerX := bubbleRect.X + bubbleRect.W - pointerInset
	if minPointerX > maxPointerX {
		pointerX = bubbleRect.X + bubbleRect.W/2
	} else {
		pointerX = clampValue(pointerX, minPointerX, maxPointerX)
	}

	if err := p.canvas.FillPolygon([]core.Point{
		{X: pointerX, Y: tipY},
		{X: pointerX - pointerHalfW, Y: baseY},
		{X: pointerX + pointerHalfW, Y: baseY},
	}, bubbleColor); err != nil {
		return err
	}
	if err := p.canvas.FillRoundRect(bubbleRect, bubbleRadius, bubbleColor); err != nil {
		return err
	}

	return p.DrawText(
		fmt.Sprintf("%d%%", value),
		bubbleRect,
		TextStyle{
			Font:   style.Font,
			Color:  textColor,
			Format: core.DTCenter | core.DTVCenter | core.DTSingleLine,
		},
	)
}

type Scene struct {
	app     *core.App
	root    *Panel
	theme   *Theme
	hover   Widget
	capture Widget
	focus   Widget

	fontMu sync.Mutex
	fonts  map[FontSpec]*core.Font

	timerMu     sync.Mutex
	timers      map[uintptr]Widget
	nextTimerID uintptr
}

func NewScene(coreApp *core.App) *Scene {
	root := NewPanel("scene-root")
	scene := &Scene{
		app:    coreApp,
		root:   root,
		theme:  DefaultTheme(),
		fonts:  make(map[FontSpec]*core.Font),
		timers: make(map[uintptr]Widget),
	}
	root.setScene(scene)
	root.SetBounds(Rect{W: coreApp.ClientSize().Width, H: coreApp.ClientSize().Height})
	return scene
}

func (s *Scene) Root() *Panel {
	return s.root
}

func (s *Scene) Theme() *Theme {
	return s.theme
}

func (s *Scene) SetTheme(theme *Theme) {
	if theme == nil {
		return
	}
	s.runOnUI(func() {
		s.theme = theme
		s.resetFonts()
		s.Invalidate(nil)
	})
}

func (s *Scene) ReloadResources() {
	s.runOnUI(func() {
		s.resetFonts()
		s.Invalidate(nil)
	})
}

func (s *Scene) Resize(bounds Rect) {
	s.runOnUI(func() {
		s.root.SetBounds(bounds)
		s.Dispatch(Event{Type: EventResize, Bounds: bounds, Source: s.root})
		s.Invalidate(nil)
	})
}

func (s *Scene) Paint(ctx *PaintCtx) {
	if s == nil || s.root == nil || ctx == nil {
		return
	}
	s.root.Paint(ctx)
	s.paintOverlays(s.root, ctx)
}

func (s *Scene) PaintCore(canvas *core.PaintCtx) {
	s.Paint(newPaintCtx(s, canvas))
}

func (s *Scene) Dispatch(evt Event) bool {
	if s == nil || s.root == nil {
		return false
	}

	switch evt.Type {
	case EventMouseMove:
		return s.dispatchMouseMove(evt)
	case EventMouseLeave:
		return s.dispatchMouseLeave(evt)
	case EventMouseDown:
		return s.dispatchMouseDown(evt)
	case EventMouseUp:
		return s.dispatchMouseUp(evt)
	case EventResize:
		return s.routeEvent(s.root, evt)
	case EventKeyDown, EventChar:
		return s.dispatchKeyboard(evt)
	case EventTimer, EventPaint:
		return s.routeEvent(s.root, evt)
	default:
		if evt.Source != nil {
			return s.routeEvent(evt.Source, evt)
		}
	}
	return false
}

func (s *Scene) DispatchMouseMove(ev core.MouseEvent) bool {
	return s.Dispatch(eventFromMouse(EventMouseMove, ev))
}

func (s *Scene) DispatchMouseLeave() bool {
	return s.Dispatch(Event{Type: EventMouseLeave})
}

func (s *Scene) DispatchMouseDown(ev core.MouseEvent) bool {
	return s.Dispatch(eventFromMouse(EventMouseDown, ev))
}

func (s *Scene) DispatchMouseUp(ev core.MouseEvent) bool {
	return s.Dispatch(eventFromMouse(EventMouseUp, ev))
}

// DispatchKeyDown 分发按键事件到当前焦点控件。
func (s *Scene) DispatchKeyDown(ev core.KeyEvent) bool {
	return s.Dispatch(Event{Type: EventKeyDown, Key: ev, Source: s.focus})
}

// DispatchChar 分发字符输入到当前焦点控件。
func (s *Scene) DispatchChar(ch rune) bool {
	return s.Dispatch(Event{Type: EventChar, Rune: ch, Source: s.focus})
}

// Focus 返回当前持有焦点的控件。
func (s *Scene) Focus() Widget {
	return s.focus
}

// Blur 清空当前场景焦点。
func (s *Scene) Blur() {
	if s == nil {
		return
	}
	s.runOnUI(func() {
		s.setFocus(nil)
	})
}

func (s *Scene) Invalidate(widget Widget) {
	if s == nil || s.app == nil {
		return
	}
	if widget == nil {
		s.app.Invalidate(nil)
		return
	}
	rect := widget.Bounds()
	s.app.Invalidate(&rect)
}

func (s *Scene) HandleTimer(timerID uintptr) bool {
	if s == nil || timerID == 0 {
		return false
	}

	s.timerMu.Lock()
	target := s.timers[timerID]
	s.timerMu.Unlock()
	if target == nil {
		return false
	}

	return s.routeEvent(target, Event{
		Type:    EventTimer,
		TimerID: timerID,
		Source:  target,
	})
}

func (s *Scene) Close() error {
	s.timerMu.Lock()
	timerIDs := make([]uintptr, 0, len(s.timers))
	for id := range s.timers {
		timerIDs = append(timerIDs, id)
	}
	s.timerMu.Unlock()

	for _, id := range timerIDs {
		_ = s.app.KillTimer(id)
	}

	s.disposeTree(s.root)
	s.focus = nil
	s.hover = nil
	s.capture = nil

	s.fontMu.Lock()
	defer s.fontMu.Unlock()
	for key, font := range s.fonts {
		_ = font.Close()
		delete(s.fonts, key)
	}
	return nil
}

func (s *Scene) runOnUI(fn func()) {
	if fn == nil {
		return
	}
	if s == nil || s.app == nil || s.app.IsUIThread() {
		fn()
		return
	}
	_ = s.app.Post(fn)
}

func (s *Scene) font(spec FontSpec) (*core.Font, error) {
	s.fontMu.Lock()
	defer s.fontMu.Unlock()

	if font := s.fonts[spec]; font != nil {
		return font, nil
	}
	font, err := s.app.NewFont(spec.Face, spec.SizeDP, spec.Weight)
	if err != nil {
		return nil, err
	}
	s.fonts[spec] = font
	return font, nil
}

func (s *Scene) resetFonts() {
	s.fontMu.Lock()
	defer s.fontMu.Unlock()
	for key, font := range s.fonts {
		_ = font.Close()
		delete(s.fonts, key)
	}
}

func (s *Scene) startTimer(owner Widget, timerID uintptr, interval time.Duration) (uintptr, error) {
	if s == nil || s.app == nil || owner == nil {
		return 0, nil
	}

	s.timerMu.Lock()
	if timerID == 0 {
		s.nextTimerID++
		timerID = s.nextTimerID
	}
	s.timers[timerID] = owner
	s.timerMu.Unlock()

	if err := s.app.SetTimer(timerID, interval); err != nil {
		s.timerMu.Lock()
		delete(s.timers, timerID)
		s.timerMu.Unlock()
		return 0, err
	}
	return timerID, nil
}

func (s *Scene) updateTimer(timerID uintptr, interval time.Duration) error {
	if s == nil || s.app == nil || timerID == 0 {
		return nil
	}
	return s.app.SetTimer(timerID, interval)
}

func (s *Scene) stopTimer(timerID uintptr) error {
	if s == nil || s.app == nil || timerID == 0 {
		return nil
	}
	s.timerMu.Lock()
	delete(s.timers, timerID)
	s.timerMu.Unlock()
	return s.app.KillTimer(timerID)
}

func (s *Scene) disposeTree(widget Widget) {
	if widget == nil {
		return
	}
	if container, ok := widget.(Container); ok {
		for _, child := range container.Children() {
			s.disposeTree(child)
		}
	}
	if disposable, ok := widget.(interface{ Close() error }); ok {
		_ = disposable.Close()
	}
}

func (s *Scene) routeEvent(target Widget, evt Event) bool {
	if target == nil {
		return false
	}
	path := s.pathTo(target)
	if len(path) == 0 {
		return false
	}

	for _, widget := range path {
		if widget.OnEvent(evt) {
			return true
		}
	}
	for i := len(path) - 2; i >= 0; i-- {
		if path[i].OnEvent(evt) {
			return true
		}
	}
	return false
}

// dispatchKeyboard 把键盘事件路由给焦点控件。
func (s *Scene) dispatchKeyboard(evt Event) bool {
	if s.focus == nil {
		return false
	}
	evt.Source = s.focus
	return s.routeEvent(s.focus, evt)
}

func (s *Scene) pathTo(target Widget) []Widget {
	node := asWidgetNode(target)
	if node == nil {
		return nil
	}

	var reverse []Widget
	for current := node; current != nil; {
		reverse = append(reverse, current)
		parent := current.parent()
		if parent == nil {
			break
		}
		current = asWidgetNode(parent)
	}

	path := make([]Widget, 0, len(reverse))
	for i := len(reverse) - 1; i >= 0; i-- {
		path = append(path, reverse[i])
	}
	return path
}

func (s *Scene) dispatchMouseMove(evt Event) bool {
	hit := s.hitTest(s.root, evt.Point.X, evt.Point.Y)
	eventTarget := hit
	if s.capture != nil {
		eventTarget = s.capture
	}

	if s.hover != hit {
		if s.hover != nil {
			s.routeEvent(s.hover, Event{Type: EventMouseLeave, Point: evt.Point, Source: s.hover})
		}
		s.hover = hit
		if s.hover != nil {
			s.routeEvent(s.hover, Event{Type: EventMouseEnter, Point: evt.Point, Source: s.hover})
		}
	}

	if hit != nil {
		s.app.SetCursor(cursorFor(hit))
	} else {
		s.app.SetCursor(core.CursorArrow)
	}

	if eventTarget != nil {
		return s.routeEvent(eventTarget, evt)
	}
	return false
}

func (s *Scene) dispatchMouseLeave(evt Event) bool {
	if s.hover == nil {
		s.app.SetCursor(core.CursorArrow)
		return false
	}
	target := s.hover
	s.hover = nil
	s.app.SetCursor(core.CursorArrow)
	return s.routeEvent(target, Event{Type: EventMouseLeave, Point: evt.Point, Source: target})
}

func (s *Scene) dispatchMouseDown(evt Event) bool {
	target := s.hitTest(s.root, evt.Point.X, evt.Point.Y)
	s.setFocus(target)
	if target == nil {
		return false
	}
	s.capture = target
	s.app.CaptureMouse()
	return s.routeEvent(target, evt)
}

func (s *Scene) dispatchMouseUp(evt Event) bool {
	target := s.capture
	s.capture = nil
	s.app.ReleaseMouse()

	hit := s.hitTest(s.root, evt.Point.X, evt.Point.Y)
	if target == nil {
		target = hit
	}
	if target == nil {
		return false
	}

	handled := s.routeEvent(target, evt)
	if hit != nil && target == hit {
		click := evt
		click.Type = EventClick
		click.Source = hit
		if s.routeEvent(hit, click) {
			handled = true
		}
	}
	return handled
}

func (s *Scene) hitTest(widget Widget, x, y int32) Widget {
	if widget == nil || !widget.Visible() || !widget.Enabled() {
		return nil
	}
	if container, ok := widget.(Container); ok {
		children := container.Children()
		for i := len(children) - 1; i >= 0; i-- {
			if hit := s.hitTest(children[i], x, y); hit != nil {
				return hit
			}
		}
	}
	if widget.HitTest(x, y) {
		return widget
	}
	return nil
}

// setFocus 切换场景中的焦点控件。
func (s *Scene) setFocus(target Widget) {
	if target != nil {
		focusable, ok := target.(focusableWidget)
		if !ok || !focusable.acceptsFocus() || !target.Visible() || !target.Enabled() {
			target = nil
		}
	}
	if s.focus == target {
		return
	}

	old := s.focus
	s.focus = target
	if old != nil {
		s.routeEvent(old, Event{Type: EventBlur, Source: old})
	}
	if s.focus != nil {
		s.routeEvent(s.focus, Event{Type: EventFocus, Source: s.focus})
	}
}

// paintOverlays 在普通控件之后绘制浮层。
func (s *Scene) paintOverlays(widget Widget, ctx *PaintCtx) {
	if widget == nil || !widget.Visible() {
		return
	}
	if container, ok := widget.(Container); ok {
		for _, child := range container.Children() {
			s.paintOverlays(child, ctx)
		}
	}
	if overlay, ok := widget.(overlayWidget); ok {
		overlay.PaintOverlay(ctx)
	}
}

func cursorFor(widget Widget) core.CursorID {
	if node := asWidgetNode(widget); node != nil {
		return node.cursor()
	}
	return core.CursorArrow
}

func clampValue(value, min, max int32) int32 {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func min32(a, b int32) int32 {
	if a < b {
		return a
	}
	return b
}

func max32(a, b int32) int32 {
	if a > b {
		return a
	}
	return b
}
