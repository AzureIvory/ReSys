package widgets

type ProgressBar struct {
	widgetBase
	value int32
	Style ProgressStyle
}

func NewProgressBar(id string) *ProgressBar {
	return &ProgressBar{
		widgetBase: newWidgetBase(id, "progress"),
	}
}

func (p *ProgressBar) SetBounds(rect Rect) {
	p.widgetBase.setBounds(p, rect)
}

func (p *ProgressBar) SetVisible(visible bool) {
	p.widgetBase.setVisible(p, visible)
}

func (p *ProgressBar) SetEnabled(enabled bool) {
	p.widgetBase.setEnabled(p, enabled)
}

func (p *ProgressBar) SetValue(value int32) {
	p.runOnUI(func() {
		value = clampValue(value, 0, 100)
		if p.value == value {
			return
		}
		p.value = value
		p.invalidate(p)
	})
}

func (p *ProgressBar) SetStyle(style ProgressStyle) {
	p.runOnUI(func() {
		p.Style = style
		p.invalidate(p)
	})
}

func (p *ProgressBar) Value() int32 {
	return p.value
}

func (p *ProgressBar) OnEvent(Event) bool {
	return false
}

func (p *ProgressBar) Paint(ctx *PaintCtx) {
	if !p.Visible() {
		return
	}
	style := p.resolveStyle(ctx)
	_ = ctx.DrawProgress(p.Bounds(), p.value, style)
}

func (p *ProgressBar) resolveStyle(ctx *PaintCtx) ProgressStyle {
	style := DefaultTheme().Progress
	if ctx != nil && ctx.scene != nil && ctx.scene.theme != nil {
		style = ctx.scene.theme.Progress
	}
	if p.Style.Font.Face != "" {
		style.Font = p.Style.Font
	}
	if p.Style.TextColor != 0 {
		style.TextColor = p.Style.TextColor
	}
	if p.Style.TrackColor != 0 {
		style.TrackColor = p.Style.TrackColor
	}
	if p.Style.FillColor != 0 {
		style.FillColor = p.Style.FillColor
	}
	if p.Style.BubbleColor != 0 {
		style.BubbleColor = p.Style.BubbleColor
	}
	if p.Style.CornerRadius != 0 {
		style.CornerRadius = p.Style.CornerRadius
	}
	if p.Style.ShowPercent != style.ShowPercent {
		style.ShowPercent = p.Style.ShowPercent
	}
	return style
}
