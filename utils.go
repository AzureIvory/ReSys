package main

import (
	"syscall"
	"unicode/utf16"
	"unsafe"
)

func ansiToUTF8(b []byte) string {
	if len(b) == 0 {
		return ""
	}

	// MultiByteToWideChar(CP_ACP, 0, ...)
	const cpACP = 0
	k32 := syscall.NewLazyDLL("kernel32.dll")
	mb2wc := k32.NewProc("MultiByteToWideChar")

	// 获取所需 UTF-16 长度
	r1, _, _ := mb2wc.Call(
		uintptr(cpACP),
		uintptr(0),
		uintptr(unsafe.Pointer(&b[0])),
		uintptr(len(b)),
		uintptr(0),
		uintptr(0),
	)
	n := int(r1)
	if n <= 0 {
		return string(b)
	}

	w := make([]uint16, n)
	r2, _, _ := mb2wc.Call(
		uintptr(cpACP),
		uintptr(0),
		uintptr(unsafe.Pointer(&b[0])),
		uintptr(len(b)),
		uintptr(unsafe.Pointer(&w[0])),
		uintptr(n),
	)
	if int(r2) <= 0 {
		return string(b)
	}

	// 转为 Go string
	return string(utf16.Decode(w))
}
