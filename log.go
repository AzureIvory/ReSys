package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// 日志
var (
	logOnce sync.Once
	logMu   sync.Mutex
	logPath string
)

// 初始化日志文件
func initLog() {
	logOnce.Do(func() {
		exe, err := os.Executable()
		if err != nil {
			return
		}
		base := filepath.Dir(exe)
		logDir := filepath.Join(base, "log")
		_ = os.MkdirAll(logDir, 0o755)
		logPath = filepath.Join(logDir, time.Now().Format("20060102_150405")+".log")
	})
}

// 写入一行日志
func logWrite(format string, args ...any) {
	initLog()
	if logPath == "" {
		return
	}
	logMu.Lock()
	defer logMu.Unlock()
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	msg := fmt.Sprintf(format, args...)
	line := fmt.Sprintf("[%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), msg)
	_, _ = f.WriteString(line)
}
