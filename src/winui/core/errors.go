package core

import (
	"errors"
	"fmt"
	"syscall"

	"golang.org/x/sys/windows"
)

var (
	ErrNotInitialized = errors.New("winui/core: app not initialized")
	ErrAppClosed      = errors.New("winui/core: app closed")
	ErrTimerIDZero    = errors.New("winui/core: timer id must not be zero")
)

type opError struct {
	Op  string
	Err error
}

func (e *opError) Error() string {
	return fmt.Sprintf("winui/core: %s: %v", e.Op, e.Err)
}

func (e *opError) Unwrap() error {
	return e.Err
}

func wrapError(op string, err error) error {
	if err == nil {
		err = syscall.EINVAL
	}
	return &opError{
		Op:  op,
		Err: normalizeSyscallError(err),
	}
}

func wrapHRESULT(op string, hr uintptr) error {
	return &opError{
		Op:  op,
		Err: fmt.Errorf("HRESULT 0x%08X", uint32(hr)),
	}
}

func normalizeSyscallError(err error) error {
	if err == nil {
		return syscall.EINVAL
	}
	if errno, ok := err.(windows.Errno); ok && errno == windows.ERROR_SUCCESS {
		return syscall.EINVAL
	}
	if errno, ok := err.(syscall.Errno); ok && errno == 0 {
		return syscall.EINVAL
	}
	return err
}
