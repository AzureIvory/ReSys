package core

import "time"

var (
	procSetTimer  = user32.NewProc("SetTimer")
	procKillTimer = user32.NewProc("KillTimer")
)

func (a *App) SetTimer(id uintptr, interval time.Duration) error {
	if id == 0 {
		return ErrTimerIDZero
	}
	if a == nil || a.hwnd == 0 {
		return ErrNotInitialized
	}
	if interval <= 0 {
		interval = 10 * time.Millisecond
	}

	r1, _, err := procSetTimer.Call(uintptr(a.hwnd), id, uintptr(interval/time.Millisecond), 0)
	if r1 == 0 {
		return wrapError("SetTimer", err)
	}

	a.timerMu.Lock()
	a.activeTimers[id] = struct{}{}
	a.timerMu.Unlock()
	return nil
}

func (a *App) KillTimer(id uintptr) error {
	if a == nil || a.hwnd == 0 {
		return ErrNotInitialized
	}

	r1, _, err := procKillTimer.Call(uintptr(a.hwnd), id)
	if r1 == 0 {
		return wrapError("KillTimer", err)
	}

	a.timerMu.Lock()
	delete(a.activeTimers, id)
	a.timerMu.Unlock()
	return nil
}

func (a *App) killAllTimers() {
	a.timerMu.Lock()
	ids := make([]uintptr, 0, len(a.activeTimers))
	for id := range a.activeTimers {
		ids = append(ids, id)
	}
	a.timerMu.Unlock()

	for _, id := range ids {
		procKillTimer.Call(uintptr(a.hwnd), id)
	}

	a.timerMu.Lock()
	clear(a.activeTimers)
	a.timerMu.Unlock()
}
