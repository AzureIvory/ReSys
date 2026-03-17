package widgets

type Layout interface {
	Apply(parent Rect, children []Widget)
}

type AbsoluteLayout struct{}

func (AbsoluteLayout) Apply(Rect, []Widget) {}

type Axis int

const (
	AxisHorizontal Axis = iota + 1
	AxisVertical
)

type LinearLayout struct {
	Axis     Axis
	Gap      int32
	Padding  int32
	ItemSize int32
}

func (l LinearLayout) Apply(parent Rect, children []Widget) {
	if len(children) == 0 {
		return
	}
	if l.Axis == 0 {
		l.Axis = AxisVertical
	}

	cursorX := parent.X + l.Padding
	cursorY := parent.Y + l.Padding
	availableW := parent.W - l.Padding*2
	availableH := parent.H - l.Padding*2

	for _, child := range children {
		if child == nil {
			continue
		}
		bounds := child.Bounds()
		switch l.Axis {
		case AxisHorizontal:
			width := bounds.W
			if l.ItemSize > 0 {
				width = l.ItemSize
			}
			if width <= 0 {
				width = availableW / int32(len(children))
			}
			height := bounds.H
			if height <= 0 {
				height = availableH
			}
			child.SetBounds(Rect{X: cursorX, Y: cursorY, W: width, H: height})
			cursorX += width + l.Gap
		default:
			height := bounds.H
			if l.ItemSize > 0 {
				height = l.ItemSize
			}
			if height <= 0 {
				height = availableH / int32(len(children))
			}
			width := bounds.W
			if width <= 0 {
				width = availableW
			}
			child.SetBounds(Rect{X: cursorX, Y: cursorY, W: width, H: height})
			cursorY += height + l.Gap
		}
	}
}
