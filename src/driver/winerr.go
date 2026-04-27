package driver

import (
	"errors"
	"syscall"
)

func asWindowsErrno(err error) (syscall.Errno, bool) {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return 0, false
	}
	return errno, true
}

func isWindowsErrorCode(err error, code uint32) bool {
	errno, ok := asWindowsErrno(err)
	return ok && uint32(errno) == code
}
