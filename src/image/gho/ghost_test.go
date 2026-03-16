package gho

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type stubRunner struct {
	args             []string
	lines            []string
	err              error
	blockUntilCancel bool
}

func (r *stubRunner) Run(ctx context.Context, bin string, input []byte, onLine func(string), dir string, args ...string) (string, error) {
	r.args = append([]string(nil), args...)
	for _, line := range r.lines {
		if onLine != nil {
			onLine(line)
		}
	}
	if r.blockUntilCancel {
		<-ctx.Done()
		return "", ctx.Err()
	}
	return "", r.err
}

func writeTestExe(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "Ghost.exe")
	if err := os.WriteFile(path, []byte("stub"), 0o644); err != nil {
		t.Fatalf("write test exe: %v", err)
	}
	return path
}

func TestGhostArgs(t *testing.T) {
	image := writeTestImage(t, "image.gho", makeTestImage(512))
	exe := writeTestExe(t)

	t.Run("restore args", func(t *testing.T) {
		runner := &stubRunner{lines: []string{"100%"}}
		ghost := newGhostWithRunner(exe, runner)

		if err := ghost.RestoreImage(context.Background(), image, 1, 2, nil); err != nil {
			t.Fatalf("RestoreImage() error = %v", err)
		}

		want := buildRestoreArgs(image, 1, 2)
		if len(runner.args) != len(want) {
			t.Fatalf("args len = %d, want %d", len(runner.args), len(want))
		}
		for i := range want {
			if runner.args[i] != want[i] {
				t.Fatalf("args[%d] = %q, want %q", i, runner.args[i], want[i])
			}
		}
	})

	t.Run("create args", func(t *testing.T) {
		runner := &stubRunner{lines: []string{"100%"}}
		ghost := newGhostWithRunner(exe, runner)
		outFile := filepath.Join(t.TempDir(), "backup.gho")

		if err := ghost.CreateImage(context.Background(), 3, 4, outFile, 11, nil); err != nil {
			t.Fatalf("CreateImage() error = %v", err)
		}

		want := buildCreateArgs(3, 4, outFile, 11)
		if len(runner.args) != len(want) {
			t.Fatalf("args len = %d, want %d", len(runner.args), len(want))
		}
		for i := range want {
			if runner.args[i] != want[i] {
				t.Fatalf("args[%d] = %q, want %q", i, runner.args[i], want[i])
			}
		}
	})
}

func TestEstimatedProgress(t *testing.T) {
	tracker := newProgressTracker(time.Unix(0, 0), 1000, "estimate")
	ch := make(chan Progress, 2)

	tracker.publishEstimate(ch, time.Unix(0, 0).Add(30*time.Second))
	progress := <-ch

	if !progress.Estimated {
		t.Fatalf("Estimated = false, want true")
	}
	if progress.Percentage != 47 {
		t.Fatalf("Percentage = %d, want 47", progress.Percentage)
	}
	if progress.BytesProcessed != 470 {
		t.Fatalf("BytesProcessed = %d, want 470", progress.BytesProcessed)
	}
}

func TestRestoreImageCancel(t *testing.T) {
	image := writeTestImage(t, "cancel.gho", makeTestImage(512))
	exe := writeTestExe(t)
	runner := &stubRunner{blockUntilCancel: true}
	ghost := newGhostWithRunner(exe, runner)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- ghost.RestoreImage(ctx, image, 1, 1, nil)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	err := <-done
	if !errors.Is(err, ErrCancelled) {
		t.Fatalf("RestoreImage() error = %v, want ErrCancelled", err)
	}
}

func TestLargeValuesStaySafeOn386(t *testing.T) {
	huge := uint64(1) << 40
	if got := estimateRestoreBytes(huge); got != huge*2 {
		t.Fatalf("estimateRestoreBytes() = %d, want %d", got, huge*2)
	}

	maxUint := ^uint64(0)
	if got := estimateRestoreBytes(maxUint - 1); got != maxUint {
		t.Fatalf("estimateRestoreBytes(max-1) = %d, want %d", got, maxUint)
	}

	if duration := estimateDurationForBytes(huge); duration <= 0 {
		t.Fatalf("estimateDurationForBytes() = %v, want > 0", duration)
	}
}
