package widgets

import "ReSys/src/winui/core"

type Button struct {
	widgetBase
	Text    string
	Icon    *core.Icon
	Hover   bool
	Down    bool
	OnClick func()
	Style   ButtonStyle
}

func NewButton(id, text string) *Button {
	return &Button{
		widgetBase: newWidgetBase(id, "button"),
		Text:       text,
	}
}

func (b *Button) SetBounds(rect Rect) {
	b.widgetBase.setBounds(b, rect)
}

func (b *Button) SetVisible(visible bool) {
	b.widgetBase.setVisible(b, visible)
}

func (b *Button) SetEnabled(enabled bool) {
	b.widgetBase.setEnabled(b, enabled)
}

func (b *Button) SetText(text string) {
	b.runOnUI(func() {
		if b.Text == text {
			return
		}
		b.Text = text
		b.invalidate(b)
	})
}

func (b *Button) SetIcon(icon *core.Icon) {
	b.runOnUI(func() {
		if b.Icon == icon {
			return
		}
		b.Icon = icon
		b.invalidate(b)
	})
}

func (b *Button) SetOnClick(fn func()) {
	b.runOnUI(func() {
		b.OnClick = fn
	})
}

func (b *Button) cursor() CursorID {
	if !b.Enabled() {
		return core.CursorArrow
	}
	return core.CursorHand
}

func (b *Button) OnEvent(evt Event) bool {
	switch evt.Type {
	case EventMouseEnter:
		if !b.Hover {
			b.Hover = true
			b.invalidate(b)
		}
	case EventMouseLeave:
		changed := b.Hover
		b.Hover = false
		if changed {
			b.invalidate(b)
		}
	case EventMouseDown:
		if b.Enabled() {
			b.Down = true
			b.invalidate(b)
			return true
		}
	case EventMouseUp:
		if b.Down {
			b.Down = false
			b.invalidate(b)
			return true
		}
	case EventClick:
		if b.Enabled() && b.OnClick != nil {
			b.OnClick()
			return true
		}
	}
	return false
}

func (b *Button) Paint(ctx *PaintCtx) {
	if !b.Visible() {
		return
	}

	style := b.resolveStyle(ctx)
	bgColor := style.Background
	textColor := style.TextColor

	if !b.Enabled() {
		bgColor = style.Disabled
		textColor = style.DisabledText
	} else if b.Down {
		bgColor = style.Pressed
		textColor = core.RGB(255, 255, 255)
	} else if b.Hover {
		bgColor = style.Hover
	}

	radius := ctx.DP(style.CornerRadius)
	_ = ctx.FillRoundRect(b.Bounds(), radius, bgColor)

	if b.Icon != nil {
		iconSize := ctx.DP(style.IconSizeDP)
		iconX := b.bounds.X + (b.bounds.W-iconSize)/2
		iconY := b.bounds.Y + (b.bounds.H-iconSize)/2 - ctx.DP(10)
		if b.Text == "" {
			iconY = b.bounds.Y + (b.bounds.H-iconSize)/2
		}
		if b.Down {
			iconX++
			iconY++
		}
		_ = ctx.DrawIcon(b.Icon, Rect{X: iconX, Y: iconY, W: iconSize, H: iconSize})
	}

	if b.Text == "" {
		return
	}

	textRect := b.Bounds()
	if b.Icon != nil {
		textRect.Y = b.bounds.Y + b.bounds.H - ctx.DP(style.TextInsetDP)
		textRect.H = ctx.DP(style.TextInsetDP)
	}
	if b.Down {
		textRect.X++
		textRect.Y++
	}

	_ = ctx.DrawText(
		b.Text,
		textRect,
		TextStyle{
			Font:   style.Font,
			Color:  textColor,
			Format: core.DTCenter | core.DTVCenter | core.DTSingleLine,
		},
	)
}

func (b *Button) resolveStyle(ctx *PaintCtx) ButtonStyle {
	style := DefaultTheme().Button
	if ctx != nil && ctx.scene != nil && ctx.scene.theme != nil {
		style = ctx.scene.theme.Button
	}
	if b.Style.Font.Face != "" {
		style.Font = b.Style.Font
	}
	if b.Style.TextColor != 0 {
		style.TextColor = b.Style.TextColor
	}
	if b.Style.DisabledText != 0 {
		style.DisabledText = b.Style.DisabledText
	}
	if b.Style.Background != 0 {
		style.Background = b.Style.Background
	}
	if b.Style.Hover != 0 {
		style.Hover = b.Style.Hover
	}
	if b.Style.Pressed != 0 {
		style.Pressed = b.Style.Pressed
	}
	if b.Style.Disabled != 0 {
		style.Disabled = b.Style.Disabled
	}
	if b.Style.Border != 0 {
		style.Border = b.Style.Border
	}
	if b.Style.CornerRadius != 0 {
		style.CornerRadius = b.Style.CornerRadius
	}
	if b.Style.IconSizeDP != 0 {
		style.IconSizeDP = b.Style.IconSizeDP
	}
	if b.Style.TextInsetDP != 0 {
		style.TextInsetDP = b.Style.TextInsetDP
	}
	return style
}
