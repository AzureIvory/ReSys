package widgets

import "ReSys/src/winui/core"

type Label struct {
	widgetBase
	Text  string
	Style TextStyle
}

func NewLabel(id, text string) *Label {
	return &Label{
		widgetBase: newWidgetBase(id, "label"),
		Text:       text,
	}
}

func (l *Label) SetBounds(rect Rect) {
	l.widgetBase.setBounds(l, rect)
}

func (l *Label) SetVisible(visible bool) {
	l.widgetBase.setVisible(l, visible)
}

func (l *Label) SetEnabled(enabled bool) {
	l.widgetBase.setEnabled(l, enabled)
}

func (l *Label) SetText(text string) {
	l.runOnUI(func() {
		if l.Text == text {
			return
		}
		l.Text = text
		l.invalidate(l)
	})
}

func (l *Label) SetStyle(style TextStyle) {
	l.runOnUI(func() {
		l.Style = style
		l.invalidate(l)
	})
}

func (l *Label) OnEvent(Event) bool {
	return false
}

func (l *Label) Paint(ctx *PaintCtx) {
	if !l.Visible() || l.Text == "" {
		return
	}
	style := l.resolveStyle(ctx)
	_ = ctx.DrawText(l.Text, l.Bounds(), style)
}

func (l *Label) resolveStyle(ctx *PaintCtx) TextStyle {
	style := TextStyle{
		Font: FontSpec{
			Face:   "Microsoft YaHei UI",
			SizeDP: 16,
		},
		Color:  core.RGB(16, 16, 16),
		Format: core.DTCenter | core.DTVCenter | core.DTSingleLine,
	}
	if ctx != nil && ctx.scene != nil && ctx.scene.theme != nil {
		style = ctx.scene.theme.Text
	}
	if l.Style.Font.Face != "" {
		style.Font = l.Style.Font
	}
	if l.Style.Color != 0 {
		style.Color = l.Style.Color
	}
	if l.Style.Format != 0 {
		style.Format = l.Style.Format
	}
	return style
}
