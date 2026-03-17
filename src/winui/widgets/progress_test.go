package widgets

import (
	"ReSys/src/winui/core"
	"testing"
)

func TestProgressStyleDefaults(t *testing.T) {
	progress := NewProgressBar("progress")
	style := progress.resolveStyle(nil)

	if style.FillColor != core.RGB(124, 58, 237) {
		t.Fatalf("expected default fill color updated, got %#08x", uint32(style.FillColor))
	}
	if style.BubbleColor != core.RGB(109, 40, 217) {
		t.Fatalf("expected default bubble color updated, got %#08x", uint32(style.BubbleColor))
	}
	if style.TextColor != core.RGB(255, 255, 255) {
		t.Fatalf("expected default text color updated, got %#08x", uint32(style.TextColor))
	}
}

func TestProgressStyleOverride(t *testing.T) {
	progress := NewProgressBar("progress")
	progress.Style = ProgressStyle{
		FillColor:   core.RGB(12, 34, 56),
		BubbleColor: core.RGB(65, 43, 21),
		TextColor:   core.RGB(240, 240, 240),
	}

	style := progress.resolveStyle(nil)
	if style.FillColor != core.RGB(12, 34, 56) {
		t.Fatalf("expected fill override, got %#08x", uint32(style.FillColor))
	}
	if style.BubbleColor != core.RGB(65, 43, 21) {
		t.Fatalf("expected bubble override, got %#08x", uint32(style.BubbleColor))
	}
	if style.TextColor != core.RGB(240, 240, 240) {
		t.Fatalf("expected text override, got %#08x", uint32(style.TextColor))
	}
}
