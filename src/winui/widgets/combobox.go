package widgets

import "ReSys/src/winui/core"

// ComboBox 表示带下拉列表的组合框控件。
type ComboBox struct {
	widgetBase
	items       []ListItem
	selected    int
	hover       int
	focused     bool
	open        bool
	Placeholder string
	Style       ComboStyle
	OnChange    func(int, ListItem)
}

// NewComboBox 创建一个组合框控件。
func NewComboBox(id string) *ComboBox {
	return &ComboBox{
		widgetBase: newWidgetBase(id, "combobox"),
		selected:   -1,
		hover:      -1,
	}
}

// SetBounds 设置控件区域。
func (c *ComboBox) SetBounds(rect Rect) {
	c.runOnUI(func() {
		c.widgetBase.setBounds(c, rect)
		c.invalidateAll()
	})
}

// SetVisible 设置控件可见性。
func (c *ComboBox) SetVisible(visible bool) {
	c.runOnUI(func() {
		if !visible {
			c.open = false
		}
		c.widgetBase.setVisible(c, visible)
		c.invalidateAll()
	})
}

// SetEnabled 设置控件可用性。
func (c *ComboBox) SetEnabled(enabled bool) {
	c.runOnUI(func() {
		c.widgetBase.setEnabled(c, enabled)
		c.invalidateAll()
	})
}

// SetItems 设置下拉项。
func (c *ComboBox) SetItems(items []ListItem) {
	c.runOnUI(func() {
		c.items = cloneItems(items)
		if len(c.items) == 0 {
			c.selected = -1
			c.hover = -1
			c.open = false
		} else if c.selected >= len(c.items) {
			c.selected = len(c.items) - 1
		}
		c.invalidateAll()
	})
}

// Items 返回当前下拉项副本。
func (c *ComboBox) Items() []ListItem {
	return cloneItems(c.items)
}

// SetSelected 设置选中项索引。
func (c *ComboBox) SetSelected(index int) {
	c.runOnUI(func() {
		c.selectIndex(index, false)
	})
}

// SelectedIndex 返回当前选中索引。
func (c *ComboBox) SelectedIndex() int {
	return c.selected
}

// SelectedItem 返回当前选中项。
func (c *ComboBox) SelectedItem() (ListItem, bool) {
	if c.selected < 0 || c.selected >= len(c.items) {
		return ListItem{}, false
	}
	return c.items[c.selected], true
}

// SetPlaceholder 设置占位文本。
func (c *ComboBox) SetPlaceholder(text string) {
	c.runOnUI(func() {
		if c.Placeholder == text {
			return
		}
		c.Placeholder = text
		c.invalidateAll()
	})
}

// SetStyle 设置控件样式。
func (c *ComboBox) SetStyle(style ComboStyle) {
	c.runOnUI(func() {
		c.Style = style
		c.invalidateAll()
	})
}

// SetOnChange 设置选中变更回调。
func (c *ComboBox) SetOnChange(fn func(int, ListItem)) {
	c.runOnUI(func() {
		c.OnChange = fn
	})
}

// HitTest 让打开状态也能命中下拉层。
func (c *ComboBox) HitTest(x, y int32) bool {
	if !c.Visible() {
		return false
	}
	if c.widgetBase.HitTest(x, y) {
		return true
	}
	if c.open {
		return c.popupRect().Contains(x, y)
	}
	return false
}

// OnEvent 处理鼠标、键盘和焦点事件。
func (c *ComboBox) OnEvent(evt Event) bool {
	switch evt.Type {
	case EventMouseMove:
		if c.open {
			index := c.popupIndexAt(evt.Point)
			if c.hover != index {
				c.hover = index
				c.invalidateAll()
			}
			return index >= 0
		}
	case EventMouseLeave:
		if c.hover != -1 {
			c.hover = -1
			c.invalidateAll()
		}
	case EventMouseDown:
		if c.Enabled() {
			return true
		}
	case EventMouseUp:
		if c.Enabled() {
			return true
		}
	case EventClick:
		if !c.Enabled() {
			return false
		}
		if c.bounds.Contains(evt.Point.X, evt.Point.Y) {
			c.open = !c.open && len(c.items) > 0
			if !c.open {
				c.hover = -1
			}
			c.invalidateAll()
			return true
		}
		if c.open {
			index := c.popupIndexAt(evt.Point)
			if index >= 0 {
				c.selectIndex(index, true)
				c.open = false
				c.hover = -1
				c.invalidateAll()
				return true
			}
		}
	case EventFocus:
		if !c.focused {
			c.focused = true
			c.invalidateAll()
		}
	case EventBlur:
		if c.focused || c.open || c.hover != -1 {
			c.focused = false
			c.open = false
			c.hover = -1
			c.invalidateAll()
		}
	case EventKeyDown:
		if c.handleKey(evt.Key) {
			return true
		}
	}
	return false
}

// Paint 绘制关闭状态下的组合框主体。
func (c *ComboBox) Paint(ctx *PaintCtx) {
	if !c.Visible() || ctx == nil {
		return
	}

	style := c.resolveStyle(ctx)
	bounds := c.Bounds()
	if bounds.Empty() {
		return
	}

	borderColor := style.BorderColor
	if c.focused || c.open {
		borderColor = style.FocusBorder
	} else if c.hover >= 0 {
		borderColor = style.HoverBorder
	}

	_ = ctx.FillRoundRect(bounds, ctx.DP(style.CornerRadius), style.Background)
	_ = ctx.StrokeRoundRect(bounds, ctx.DP(style.CornerRadius), borderColor, 1)

	text := c.Placeholder
	textColor := style.PlaceholderColor
	if item, ok := c.SelectedItem(); ok {
		text = item.displayText()
		textColor = style.TextColor
	}

	padding := ctx.DP(style.PaddingDP)
	arrowW := ctx.DP(28)
	textRect := Rect{
		X: bounds.X + padding,
		Y: bounds.Y,
		W: max32(0, bounds.W-padding*2-arrowW),
		H: bounds.H,
	}
	arrowRect := Rect{
		X: bounds.X + bounds.W - arrowW - padding/2,
		Y: bounds.Y,
		W: arrowW,
		H: bounds.H,
	}
	_ = ctx.DrawText(text, textRect, TextStyle{
		Font:   style.Font,
		Color:  textColor,
		Format: core.DTVCenter | core.DTSingleLine | core.DTEndEllipsis,
	})
	arrow := "▾"
	if c.open {
		arrow = "▴"
	}
	_ = ctx.DrawText(arrow, arrowRect, TextStyle{
		Font: FontSpec{
			Face:   style.Font.Face,
			SizeDP: style.Font.SizeDP,
			Weight: 700,
		},
		Color:  style.ArrowColor,
		Format: core.DTCenter | core.DTVCenter | core.DTSingleLine,
	})
}

// PaintOverlay 绘制展开后的下拉层。
func (c *ComboBox) PaintOverlay(ctx *PaintCtx) {
	if !c.Visible() || !c.open || ctx == nil {
		return
	}

	style := c.resolveStyle(ctx)
	popup := c.popupRect()
	if popup.Empty() {
		return
	}

	radius := ctx.DP(style.CornerRadius)
	_ = ctx.FillRoundRect(popup, radius, style.PopupBackground)
	_ = ctx.StrokeRoundRect(popup, radius, style.FocusBorder, 1)

	start, end := c.popupRange()
	for index := start; index < end; index++ {
		item := c.items[index]
		rowRect := c.popupRowRect(index, ctx, style)
		textColor := style.TextColor
		if item.Disabled {
			textColor = style.PlaceholderColor
		}
		if index == c.selected {
			_ = ctx.FillRoundRect(rowRect, max32(1, radius-ctx.DP(2)), style.ItemSelectedColor)
			textColor = style.ItemTextColor
		} else if index == c.hover {
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
func (c *ComboBox) acceptsFocus() bool {
	return true
}

// cursor 返回悬停时使用的光标。
func (c *ComboBox) cursor() CursorID {
	if !c.Enabled() {
		return core.CursorArrow
	}
	return core.CursorHand
}

// resolveStyle 合并主题样式和控件样式。
func (c *ComboBox) resolveStyle(ctx *PaintCtx) ComboStyle {
	style := DefaultTheme().ComboBox
	if ctx != nil && ctx.scene != nil && ctx.scene.theme != nil {
		style = ctx.scene.theme.ComboBox
	}
	return mergeComboStyle(style, c.Style)
}

// handleKey 处理方向键和开关状态。
func (c *ComboBox) handleKey(key core.KeyEvent) bool {
	if !c.Enabled() {
		return false
	}

	switch key.Key {
	case core.KeyReturn, core.KeySpace:
		if len(c.items) == 0 {
			return true
		}
		c.open = !c.open
		if !c.open {
			c.hover = -1
		}
		c.invalidateAll()
		return true
	case core.KeyEscape:
		if c.open {
			c.open = false
			c.hover = -1
			c.invalidateAll()
			return true
		}
	case core.KeyDown:
		if len(c.items) == 0 {
			return true
		}
		c.open = true
		c.selectRelative(1)
		c.hover = c.selected
		c.invalidateAll()
		return true
	case core.KeyUp:
		if len(c.items) == 0 {
			return true
		}
		c.open = true
		c.selectRelative(-1)
		c.hover = c.selected
		c.invalidateAll()
		return true
	case core.KeyHome:
		if len(c.items) == 0 {
			return true
		}
		c.selectIndex(0, true)
		c.hover = c.selected
		c.invalidateAll()
		return true
	case core.KeyEnd:
		if len(c.items) == 0 {
			return true
		}
		c.selectIndex(len(c.items)-1, true)
		c.hover = c.selected
		c.invalidateAll()
		return true
	}
	return false
}

// selectRelative 按步长移动选中项。
func (c *ComboBox) selectRelative(step int) {
	index := c.selected
	if index < 0 {
		if step >= 0 {
			index = -1
		} else {
			index = len(c.items)
		}
	}
	for {
		index += step
		if index < 0 || index >= len(c.items) {
			return
		}
		if !c.items[index].Disabled {
			c.selectIndex(index, true)
			return
		}
	}
}

// selectIndex 更新选中项并按需通知外部。
func (c *ComboBox) selectIndex(index int, notify bool) {
	if index < 0 || index >= len(c.items) || c.items[index].Disabled {
		return
	}
	if c.selected == index {
		return
	}
	c.selected = index
	c.invalidateAll()
	if notify && c.OnChange != nil {
		c.OnChange(index, c.items[index])
	}
}

// popupRect 计算下拉层区域。
func (c *ComboBox) popupRect() Rect {
	if !c.open || len(c.items) == 0 {
		return Rect{}
	}
	style := mergeComboStyle(DefaultTheme().ComboBox, c.Style)
	itemHeight := c.dp(style.ItemHeightDP)
	padding := c.dp(style.PaddingDP)
	start, end := c.popupRange()
	visibleCount := end - start
	return Rect{
		X: c.bounds.X,
		Y: c.bounds.Y + c.bounds.H + c.dp(6),
		W: c.bounds.W,
		H: padding*2 + int32(visibleCount)*itemHeight,
	}
}

// popupRange 返回当前需要展示的项范围。
func (c *ComboBox) popupRange() (int, int) {
	if len(c.items) == 0 {
		return 0, 0
	}
	style := mergeComboStyle(DefaultTheme().ComboBox, c.Style)
	visible := int(style.MaxVisibleItems)
	if visible <= 0 || visible > len(c.items) {
		visible = len(c.items)
	}
	start := 0
	if c.selected >= visible {
		start = c.selected - visible + 1
	}
	end := start + visible
	if end > len(c.items) {
		end = len(c.items)
		start = end - visible
		if start < 0 {
			start = 0
		}
	}
	return start, end
}

// popupIndexAt 返回下拉层命中的项索引。
func (c *ComboBox) popupIndexAt(point core.Point) int {
	popup := c.popupRect()
	if !popup.Contains(point.X, point.Y) {
		return -1
	}
	style := mergeComboStyle(DefaultTheme().ComboBox, c.Style)
	itemHeight := max32(1, c.dp(style.ItemHeightDP))
	padding := max32(0, c.dp(style.PaddingDP))
	start, end := c.popupRange()
	index := int((point.Y - popup.Y - padding) / itemHeight)
	if point.Y < popup.Y+padding || start+index >= end || index < 0 {
		return -1
	}
	return start + index
}

// popupRowRect 计算某一项在下拉层内的绘制区域。
func (c *ComboBox) popupRowRect(index int, ctx *PaintCtx, style ComboStyle) Rect {
	popup := c.popupRect()
	start, _ := c.popupRange()
	padding := ctx.DP(style.PaddingDP)
	itemHeight := ctx.DP(style.ItemHeightDP)
	offset := int32(index - start)
	return Rect{
		X: popup.X + padding,
		Y: popup.Y + padding + offset*itemHeight,
		W: max32(0, popup.W-padding*2),
		H: itemHeight,
	}
}

// invalidateAll 在下拉层变化时触发整窗重绘。
func (c *ComboBox) invalidateAll() {
	if scene := c.scene(); scene != nil {
		scene.Invalidate(nil)
	}
}

// dp 按场景 DPI 缩放尺寸。
func (c *ComboBox) dp(value int32) int32 {
	if scene := c.scene(); scene != nil && scene.app != nil {
		return scene.app.DP(value)
	}
	return value
}

// mergeComboStyle 合并组合框样式。
func mergeComboStyle(base, override ComboStyle) ComboStyle {
	if override.Font.Face != "" {
		base.Font = override.Font
	}
	if override.TextColor != 0 {
		base.TextColor = override.TextColor
	}
	if override.PlaceholderColor != 0 {
		base.PlaceholderColor = override.PlaceholderColor
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
	if override.ArrowColor != 0 {
		base.ArrowColor = override.ArrowColor
	}
	if override.PopupBackground != 0 {
		base.PopupBackground = override.PopupBackground
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
	if override.MaxVisibleItems != 0 {
		base.MaxVisibleItems = override.MaxVisibleItems
	}
	return base
}
