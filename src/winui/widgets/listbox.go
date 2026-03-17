package widgets

import "ReSys/src/winui/core"

// ListBox 表示单选列表框控件。
type ListBox struct {
	widgetBase
	items    []ListItem
	selected int
	hover    int
	pressed  int
	focused  bool
	Style    ListStyle
	OnChange func(int, ListItem)
}

// NewListBox 创建一个列表框控件。
func NewListBox(id string) *ListBox {
	return &ListBox{
		widgetBase: newWidgetBase(id, "listbox"),
		selected:   -1,
		hover:      -1,
		pressed:    -1,
	}
}

// SetBounds 设置控件区域。
func (l *ListBox) SetBounds(rect Rect) {
	l.runOnUI(func() {
		l.widgetBase.setBounds(l, rect)
	})
}

// SetVisible 设置控件可见性。
func (l *ListBox) SetVisible(visible bool) {
	l.runOnUI(func() {
		l.widgetBase.setVisible(l, visible)
	})
}

// SetEnabled 设置控件可用性。
func (l *ListBox) SetEnabled(enabled bool) {
	l.runOnUI(func() {
		l.widgetBase.setEnabled(l, enabled)
	})
}

// SetItems 设置列表项。
func (l *ListBox) SetItems(items []ListItem) {
	l.runOnUI(func() {
		l.items = cloneItems(items)
		if len(l.items) == 0 {
			l.selected = -1
			l.hover = -1
			l.pressed = -1
		} else if l.selected >= len(l.items) {
			l.selected = len(l.items) - 1
		}
		l.invalidate(l)
	})
}

// Items 返回当前列表项副本。
func (l *ListBox) Items() []ListItem {
	return cloneItems(l.items)
}

// SetSelected 设置选中项索引。
func (l *ListBox) SetSelected(index int) {
	l.runOnUI(func() {
		l.selectIndex(index, false)
	})
}

// SelectedIndex 返回当前选中索引。
func (l *ListBox) SelectedIndex() int {
	return l.selected
}

// SelectedItem 返回当前选中项。
func (l *ListBox) SelectedItem() (ListItem, bool) {
	if l.selected < 0 || l.selected >= len(l.items) {
		return ListItem{}, false
	}
	return l.items[l.selected], true
}

// SetStyle 设置控件样式。
func (l *ListBox) SetStyle(style ListStyle) {
	l.runOnUI(func() {
		l.Style = style
		l.invalidate(l)
	})
}

// SetOnChange 设置选中变更回调。
func (l *ListBox) SetOnChange(fn func(int, ListItem)) {
	l.runOnUI(func() {
		l.OnChange = fn
	})
}

// OnEvent 处理鼠标、键盘和焦点事件。
func (l *ListBox) OnEvent(evt Event) bool {
	switch evt.Type {
	case EventMouseMove:
		index := l.indexAt(evt.Point)
		if l.hover != index {
			l.hover = index
			l.invalidate(l)
		}
	case EventMouseLeave:
		if l.hover != -1 {
			l.hover = -1
			l.invalidate(l)
		}
	case EventMouseDown:
		if l.Enabled() {
			l.pressed = l.indexAt(evt.Point)
			l.invalidate(l)
			return true
		}
	case EventMouseUp:
		if l.pressed != -1 {
			l.pressed = -1
			l.invalidate(l)
			return true
		}
	case EventClick:
		if !l.Enabled() {
			return false
		}
		index := l.indexAt(evt.Point)
		if index >= 0 {
			l.selectIndex(index, true)
			return true
		}
	case EventFocus:
		if !l.focused {
			l.focused = true
			l.invalidate(l)
		}
	case EventBlur:
		if l.focused || l.hover != -1 {
			l.focused = false
			l.hover = -1
			l.pressed = -1
			l.invalidate(l)
		}
	case EventKeyDown:
		if l.handleKey(evt.Key) {
			return true
		}
	}
	return false
}

// Paint 绘制列表框外观。
func (l *ListBox) Paint(ctx *PaintCtx) {
	if !l.Visible() || ctx == nil {
		return
	}

	style := l.resolveStyle(ctx)
	bounds := l.Bounds()
	if bounds.Empty() {
		return
	}

	borderColor := style.BorderColor
	if l.focused {
		borderColor = style.FocusBorder
	} else if l.hover >= 0 {
		borderColor = style.HoverBorder
	}

	radius := ctx.DP(style.CornerRadius)
	_ = ctx.FillRoundRect(bounds, radius, style.Background)
	_ = ctx.StrokeRoundRect(bounds, radius, borderColor, 1)

	for index, item := range l.items {
		rowRect := l.rowRect(index, ctx, style)
		if rowRect.Y >= bounds.Y+bounds.H {
			break
		}
		if rowRect.Y+rowRect.H <= bounds.Y {
			continue
		}

		textColor := style.TextColor
		if item.Disabled {
			textColor = style.DisabledText
		}
		if index == l.selected {
			_ = ctx.FillRoundRect(rowRect, max32(1, radius-ctx.DP(2)), style.ItemSelectedColor)
			textColor = style.ItemTextColor
		} else if index == l.hover {
			_ = ctx.FillRoundRect(rowRect, max32(1, radius-ctx.DP(2)), style.ItemHoverColor)
		}

		textRect := Rect{
			X: rowRect.X + ctx.DP(10),
			Y: rowRect.Y,
			W: max32(0, rowRect.W-ctx.DP(20)),
			H: rowRect.H,
		}
		_ = ctx.DrawText(item.displayText(), textRect, TextStyle{
			Font:   style.Font,
			Color:  textColor,
			Format: core.DTVCenter | core.DTSingleLine | core.DTEndEllipsis,
		})
	}
}

// acceptsFocus 声明该控件支持焦点。
func (l *ListBox) acceptsFocus() bool {
	return true
}

// cursor 返回悬停时使用的光标。
func (l *ListBox) cursor() CursorID {
	if !l.Enabled() {
		return core.CursorArrow
	}
	return core.CursorHand
}

// resolveStyle 合并主题样式和控件样式。
func (l *ListBox) resolveStyle(ctx *PaintCtx) ListStyle {
	style := DefaultTheme().ListBox
	if ctx != nil && ctx.scene != nil && ctx.scene.theme != nil {
		style = ctx.scene.theme.ListBox
	}
	return mergeListStyle(style, l.Style)
}

// handleKey 处理方向键选中变化。
func (l *ListBox) handleKey(key core.KeyEvent) bool {
	if len(l.items) == 0 || !l.Enabled() {
		return false
	}

	switch key.Key {
	case core.KeyUp:
		l.selectRelative(-1)
		return true
	case core.KeyDown:
		l.selectRelative(1)
		return true
	case core.KeyHome:
		l.selectIndex(0, true)
		return true
	case core.KeyEnd:
		l.selectIndex(len(l.items)-1, true)
		return true
	case core.KeyReturn, core.KeySpace:
		if l.selected >= 0 && l.selected < len(l.items) && l.OnChange != nil {
			l.OnChange(l.selected, l.items[l.selected])
		}
		return true
	}
	return false
}

// selectRelative 按步长移动选中项。
func (l *ListBox) selectRelative(step int) {
	index := l.selected
	if index < 0 {
		if step >= 0 {
			index = -1
		} else {
			index = len(l.items)
		}
	}
	for {
		index += step
		if index < 0 || index >= len(l.items) {
			return
		}
		if !l.items[index].Disabled {
			l.selectIndex(index, true)
			return
		}
	}
}

// selectIndex 更新选中项并按需通知外部。
func (l *ListBox) selectIndex(index int, notify bool) {
	if index < 0 || index >= len(l.items) || l.items[index].Disabled {
		return
	}
	if l.selected == index {
		return
	}
	l.selected = index
	l.invalidate(l)
	if notify && l.OnChange != nil {
		l.OnChange(index, l.items[index])
	}
}

// indexAt 返回鼠标所在的列表项索引。
func (l *ListBox) indexAt(point core.Point) int {
	rect := l.Bounds()
	if !rect.Contains(point.X, point.Y) {
		return -1
	}
	style := mergeListStyle(DefaultTheme().ListBox, l.Style)
	itemHeight := max32(1, l.dp(style.ItemHeightDP))
	padding := max32(0, l.dp(style.PaddingDP))
	index := int((point.Y - rect.Y - padding) / itemHeight)
	if point.Y < rect.Y+padding || index < 0 || index >= len(l.items) {
		return -1
	}
	return index
}

// rowRect 计算某一项的绘制区域。
func (l *ListBox) rowRect(index int, ctx *PaintCtx, style ListStyle) Rect {
	padding := ctx.DP(style.PaddingDP)
	itemHeight := ctx.DP(style.ItemHeightDP)
	return Rect{
		X: l.bounds.X + padding,
		Y: l.bounds.Y + padding + int32(index)*itemHeight,
		W: max32(0, l.bounds.W-padding*2),
		H: itemHeight,
	}
}

// dp 按场景 DPI 缩放尺寸。
func (l *ListBox) dp(value int32) int32 {
	if scene := l.scene(); scene != nil && scene.app != nil {
		return scene.app.DP(value)
	}
	return value
}

// mergeListStyle 合并列表样式。
func mergeListStyle(base, override ListStyle) ListStyle {
	if override.Font.Face != "" {
		base.Font = override.Font
	}
	if override.TextColor != 0 {
		base.TextColor = override.TextColor
	}
	if override.DisabledText != 0 {
		base.DisabledText = override.DisabledText
	}
	if override.Background != 0 {
		base.Background = override.Background
	}
	if override.BorderColor != 0 {
		base.BorderColor = override.BorderColor
	}
	if override.HoverBorder != 0 {
		base.HoverBorder = override.HoverBorder
	}
	if override.FocusBorder != 0 {
		base.FocusBorder = override.FocusBorder
	}
	if override.ItemHoverColor != 0 {
		base.ItemHoverColor = override.ItemHoverColor
	}
	if override.ItemSelectedColor != 0 {
		base.ItemSelectedColor = override.ItemSelectedColor
	}
	if override.ItemTextColor != 0 {
		base.ItemTextColor = override.ItemTextColor
	}
	if override.ItemHeightDP != 0 {
		base.ItemHeightDP = override.ItemHeightDP
	}
	if override.PaddingDP != 0 {
		base.PaddingDP = override.PaddingDP
	}
	if override.CornerRadius != 0 {
		base.CornerRadius = override.CornerRadius
	}
	return base
}
