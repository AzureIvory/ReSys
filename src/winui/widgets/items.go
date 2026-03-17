package widgets

// ListItem 表示列表类控件的一项数据。
type ListItem struct {
	Value    string
	Text     string
	Disabled bool
}

// displayText 返回用于展示的文本。
func (i ListItem) displayText() string {
	if i.Text != "" {
		return i.Text
	}
	return i.Value
}

// cloneItems 复制并补齐列表项文本。
func cloneItems(items []ListItem) []ListItem {
	cloned := make([]ListItem, 0, len(items))
	for _, item := range items {
		if item.Text == "" {
			item.Text = item.Value
		}
		cloned = append(cloned, item)
	}
	return cloned
}
