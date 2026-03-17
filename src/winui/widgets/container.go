package widgets

type Container interface {
	Widget
	Add(child Widget)
	Remove(id string)
	Children() []Widget
}

type Panel struct {
	widgetBase
	children []Widget
	layout   Layout
}

func NewPanel(id string) *Panel {
	return &Panel{
		widgetBase: newWidgetBase(id, "panel"),
		layout:     AbsoluteLayout{},
	}
}

func (p *Panel) SetBounds(rect Rect) {
	p.widgetBase.setBounds(p, rect)
	p.applyLayout()
}

func (p *Panel) SetVisible(visible bool) {
	p.widgetBase.setVisible(p, visible)
}

func (p *Panel) SetEnabled(enabled bool) {
	p.widgetBase.setEnabled(p, enabled)
}

func (p *Panel) Add(child Widget) {
	if child == nil {
		return
	}
	node := asWidgetNode(child)
	if node == nil {
		return
	}

	p.children = append(p.children, child)
	node.setParent(p)
	node.setScene(p.scene())
	if container, ok := child.(Container); ok {
		attachSceneRecursive(container, p.scene())
	}
	p.applyLayout()
	p.invalidate(p)
}

func (p *Panel) Remove(id string) {
	for i, child := range p.children {
		if child.ID() != id {
			continue
		}
		if scene := p.scene(); scene != nil {
			scene.disposeTree(child)
		}
		if node := asWidgetNode(child); node != nil {
			node.setParent(nil)
			node.setScene(nil)
		}
		p.children = append(p.children[:i], p.children[i+1:]...)
		p.invalidate(p)
		return
	}
}

func (p *Panel) Children() []Widget {
	out := make([]Widget, len(p.children))
	copy(out, p.children)
	return out
}

func (p *Panel) SetLayout(layout Layout) {
	if layout == nil {
		layout = AbsoluteLayout{}
	}
	p.layout = layout
	p.applyLayout()
	p.invalidate(p)
}

func (p *Panel) OnEvent(Event) bool {
	return false
}

func (p *Panel) Paint(ctx *PaintCtx) {
	if !p.Visible() {
		return
	}
	for _, child := range p.children {
		if child.Visible() {
			child.Paint(ctx)
		}
	}
}

func (p *Panel) setScene(scene *Scene) {
	p.widgetBase.setScene(scene)
	for _, child := range p.children {
		if node := asWidgetNode(child); node != nil {
			node.setScene(scene)
		}
		if container, ok := child.(Container); ok {
			attachSceneRecursive(container, scene)
		}
	}
}

func (p *Panel) applyLayout() {
	if p.layout == nil {
		return
	}
	p.layout.Apply(p.Bounds(), p.children)
}

func attachSceneRecursive(container Container, scene *Scene) {
	node := asWidgetNode(container)
	if node != nil {
		node.setScene(scene)
	}
	for _, child := range container.Children() {
		if childNode := asWidgetNode(child); childNode != nil {
			childNode.setScene(scene)
		}
		if childContainer, ok := child.(Container); ok {
			attachSceneRecursive(childContainer, scene)
		}
	}
}
