package log

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

type lineHandler struct {
	mu       sync.Mutex
	w        io.Writer
	minLevel slog.Level
}

func (h *lineHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.minLevel
}

func (h *lineHandler) Handle(_ context.Context, r slog.Record) error {
	t := r.Time
	if t.IsZero() {
		t = time.Now()
	}
	line := fmt.Sprintf("[%s] %s %s\n",
		t.Format("2006-01-02 15:04:05"),
		r.Level.String(),
		r.Message,
	)

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := io.WriteString(h.w, line)
	return err
}

func (h *lineHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h } // 忽略所有 attrs
func (h *lineHandler) WithGroup(_ string) slog.Handler      { return h } // 忽略 group

var (
	logOnce sync.Once
	logger  *slog.Logger
	logFile *os.File
)

func initLogger() {
	logOnce.Do(func() {
		var w io.Writer = os.Stderr

		if exe, err := os.Executable(); err == nil {
			base := filepath.Dir(exe)
			logDir := filepath.Join(base, "log")
			_ = os.MkdirAll(logDir, 0o755)

			name := fmt.Sprintf("%s_%d.log", time.Now().Format("20060102_150405"), os.Getpid())
			path := filepath.Join(logDir, name)

			if f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
				logFile = f
				w = transform.NewWriter(f, encoding.ReplaceUnsupported(simplifiedchinese.GBK.NewEncoder()))
			}
		}

		h := &lineHandler{w: w, minLevel: slog.LevelInfo}
		logger = slog.New(h)
	})
}

// 程序退出时调用
func CloseLog() {
	if logFile != nil {
		_ = logFile.Close()
		logFile = nil
	}
}

// level: 0=INFO, -1=WARN, -2=ERROR
func LogWrite(level int, msg any, args ...any) {
	initLogger()

	lv := slog.LevelInfo
	switch level {
	case -1:
		lv = slog.LevelWarn
	case -2:
		lv = slog.LevelError
	}

	text := fmt.Sprint(msg)
	if len(args) > 0 {
		text = fmt.Sprintf(text, args...)
	}

	logger.Log(context.Background(), lv, text)
}
