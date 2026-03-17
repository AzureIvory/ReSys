package widgets

import "testing"

func TestButtonStateMachine(t *testing.T) {
	button := NewButton("button", "demo")
	button.SetBounds(Rect{X: 0, Y: 0, W: 100, H: 40})

	clicked := 0
	button.OnClick = func() {
		clicked++
	}

	button.OnEvent(Event{Type: EventMouseEnter})
	if !button.Hover {
		t.Fatalf("expected hover state after mouse enter")
	}

	button.OnEvent(Event{Type: EventMouseDown})
	if !button.Down {
		t.Fatalf("expected down state after mouse down")
	}

	button.OnEvent(Event{Type: EventMouseUp})
	if button.Down {
		t.Fatalf("expected down state cleared after mouse up")
	}

	button.OnEvent(Event{Type: EventClick})
	if clicked != 1 {
		t.Fatalf("expected click callback once, got %d", clicked)
	}

	button.OnEvent(Event{Type: EventMouseLeave})
	if button.Hover {
		t.Fatalf("expected hover state cleared after mouse leave")
	}
}

func TestProgressClamp(t *testing.T) {
	progress := NewProgressBar("progress")
	progress.SetValue(120)
	if progress.Value() != 100 {
		t.Fatalf("expected clamp to 100, got %d", progress.Value())
	}

	progress.SetValue(-5)
	if progress.Value() != 0 {
		t.Fatalf("expected clamp to 0, got %d", progress.Value())
	}
}
