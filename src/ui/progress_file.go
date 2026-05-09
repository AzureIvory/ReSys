//go:build windows

package ui

import (
	"ReSys/src/log"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type progMon struct {
	mu sync.Mutex

	inited bool
	path   string

	pct int32
	msg string

	lines   []string
	lastDyn bool
}

var pMon progMon

// progReset 重置进度文件状态，开始新一轮安装时调用。
func progReset() {
	pMon.mu.Lock()
	defer pMon.mu.Unlock()

	pMon.initPath()
	pMon.pct = 0
	pMon.msg = ""
	pMon.lines = nil
	pMon.lastDyn = false
	pMon.flush()
}

// progMsg 更新状态文本并同步 progress.txt。
func progMsg(msg string) {
	pMon.mu.Lock()
	defer pMon.mu.Unlock()

	pMon.initPath()
	pMon.msg = strings.TrimSpace(msg)
	pMon.sync(false)
}

// progPct 更新进度值；仅在高频阶段覆盖最后一行，避免刷出大量新行。
func progPct(v int32) {
	pMon.mu.Lock()
	defer pMon.mu.Unlock()

	pMon.initPath()
	pMon.pct = v

	if isDynMsg(pMon.msg) || pMon.lastDyn {
		pMon.sync(true)
	}
}

func (m *progMon) initPath() {
	if m.inited {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		m.path = "progress.txt"
	} else {
		m.path = filepath.Join(filepath.Dir(exe), "progress.txt")
	}
	m.inited = true
}

func (m *progMon) sync(force bool) {
	line := fmt.Sprintf("%d%%, %s", m.pct, safeMsg(m.msg))
	dyn := isDynMsg(m.msg)

	if len(m.lines) == 0 {
		m.lines = append(m.lines, line)
		m.lastDyn = dyn
		m.flush()
		return
	}

	last := len(m.lines) - 1
	if dyn || (force && m.lastDyn) {
		if m.lines[last] != line {
			m.lines[last] = line
			m.lastDyn = dyn
			m.flush()
		}
		return
	}

	if m.lines[last] == line {
		m.lastDyn = dyn
		return
	}

	m.lines = append(m.lines, line)
	m.lastDyn = dyn
	m.flush()
}

func (m *progMon) flush() {
	if strings.TrimSpace(m.path) == "" {
		return
	}

	txt := strings.Join(m.lines, "\r\n")
	tmp := m.path + ".tmp"
	if err := os.WriteFile(tmp, []byte(txt), 0o644); err != nil {
		log.LogWrite(-2, "[progress] write temp failed: %v", err)
		return
	}
	_ = os.Remove(m.path)
	if err := os.Rename(tmp, m.path); err != nil {
		log.LogWrite(-2, "[progress] rename failed: %v", err)
		_ = os.Remove(tmp)
	}
}

func safeMsg(msg string) string {
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return "准备中..."
	}
	return msg
}

func isDynMsg(msg string) bool {
	msg = strings.ToLower(strings.TrimSpace(msg))
	if msg == "" {
		return false
	}
	if strings.Contains(msg, "%") {
		return true
	}
	if strings.Contains(msg, "mb/s") || strings.Contains(msg, "kb/s") || strings.Contains(msg, "gb/s") {
		return true
	}
	if strings.Contains(msg, "速度") {
		return true
	}
	return false
}
