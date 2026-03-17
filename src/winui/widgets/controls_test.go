package widgets

import (
	"ReSys/src/winui/core"
	"testing"
)

func TestCheckBoxToggle(t *testing.T) {
	check := NewCheckBox("check", "demo")

	changed := false
	check.SetOnChange(func(checked bool) {
		changed = checked
	})

	check.OnEvent(Event{Type: EventClick})
	if !check.IsChecked() {
		t.Fatalf("expected checkbox checked after click")
	}
	if !changed {
		t.Fatalf("expected checkbox change callback")
	}
}

func TestRadioButtonGroup(t *testing.T) {
	panel := NewPanel("root")
	left := NewRadioButton("left", "Left")
	right := NewRadioButton("right", "Right")
	left.SetGroup("mode")
	right.SetGroup("mode")

	panel.Add(left)
	panel.Add(right)

	left.SetChecked(true)
	right.OnEvent(Event{Type: EventClick})
	if !right.IsChecked() {
		t.Fatalf("expected clicked radio selected")
	}
	if left.IsChecked() {
		t.Fatalf("expected peer radio cleared")
	}
}

func TestComboBoxSelectByClick(t *testing.T) {
	combo := NewComboBox("combo")
	combo.SetBounds(Rect{X: 0, Y: 0, W: 200, H: 40})
	combo.SetItems([]ListItem{
		{Value: "a", Text: "Alpha"},
		{Value: "b", Text: "Beta"},
	})

	combo.OnEvent(Event{Type: EventClick, Point: core.Point{X: 10, Y: 10}})
	if !combo.open {
		t.Fatalf("expected combo open after base click")
	}

	point := core.Point{X: 10, Y: combo.popupRect().Y + combo.dp(12)}
	combo.OnEvent(Event{Type: EventClick, Point: point})
	if combo.SelectedIndex() != 0 {
		t.Fatalf("expected first item selected, got %d", combo.SelectedIndex())
	}
	if combo.open {
		t.Fatalf("expected combo close after selection")
	}
}

func TestEditBoxTyping(t *testing.T) {
	edit := NewEditBox("edit")
	edit.OnEvent(Event{Type: EventFocus})
	edit.OnEvent(Event{Type: EventChar, Rune: 'A'})
	edit.OnEvent(Event{Type: EventChar, Rune: 'B'})
	edit.OnEvent(Event{Type: EventKeyDown, Key: core.KeyEvent{Key: core.KeyBack}})

	if edit.TextValue() != "A" {
		t.Fatalf("expected text A, got %q", edit.TextValue())
	}
}

func TestListBoxKeyboardSelect(t *testing.T) {
	list := NewListBox("list")
	list.SetItems([]ListItem{
		{Value: "1", Text: "One"},
		{Value: "2", Text: "Two"},
	})
	list.OnEvent(Event{Type: EventFocus})
	list.OnEvent(Event{Type: EventKeyDown, Key: core.KeyEvent{Key: core.KeyDown}})

	if list.SelectedIndex() != 0 {
		t.Fatalf("expected keyboard to select first item, got %d", list.SelectedIndex())
	}
}
