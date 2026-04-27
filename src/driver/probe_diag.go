package driver

import (
	"ReSys/src/log"
	"fmt"
	"sync"
)

var (
	driverProbeSinkMu sync.Mutex
	driverProbeSink   func(string)
)

// SetProbeSink registers a sink for verbose probe output from the driver package.
func SetProbeSink(fn func(string)) func() {
	driverProbeSinkMu.Lock()
	prev := driverProbeSink
	driverProbeSink = fn
	driverProbeSinkMu.Unlock()

	return func() {
		driverProbeSinkMu.Lock()
		driverProbeSink = prev
		driverProbeSinkMu.Unlock()
	}
}

func emitDriverProbeLine(level int, line string) {
	log.LogWrite(level, line)

	driverProbeSinkMu.Lock()
	sink := driverProbeSink
	driverProbeSinkMu.Unlock()
	if sink != nil {
		sink(line)
	}
}

func emitDriverProbeLogf(level int, format string, args ...any) {
	emitDriverProbeLine(level, fmt.Sprintf(format, args...))
}
