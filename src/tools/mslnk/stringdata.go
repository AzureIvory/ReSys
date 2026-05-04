package mslnk

import (
	"bytes"
	"encoding/binary"
	"unicode/utf16"
)

type StringData map[string][]byte

// Update 根据已写入的 StringData 自动设置 Header 标志。
// 本库统一用 UTF-16LE 写 StringData，因此一旦存在字符串数据就设置 IsUnicode。
func (s *StringData) Update(h *header) {
	hasString := false
	if (*s)[StringDataOptions[0]] != nil { // name/description
		h.LinkFlags["HasName"] = true
		hasString = true
	}
	if (*s)[StringDataOptions[3]] != nil { // arguments
		h.LinkFlags["HasArguments"] = true
		hasString = true
	}
	for _, v := range []byte{1, 2, 4} {
		if (*s)[StringDataOptions[v]] != nil {
			h.LinkFlags["Has"+StringDataOptions[v]] = true
			hasString = true
		}
	}
	if hasString {
		h.LinkFlags["IsUnicode"] = true
	}
	h.Update()
}

func (s *StringData) Bytes() []byte {
	var buffer bytes.Buffer
	for _, k := range StringDataOptions {
		binary.Write(&buffer, binary.LittleEndian, (*s)[k])
	}
	return buffer.Bytes()
}

// StringDataStruct 生成 MS-SHLLINK StringData 字段。
// 格式为 2 字节字符数 + UTF-16LE 字符串本体，不包含结尾 NUL。
func StringDataStruct(s string) []byte {
	encoded := utf16.Encode([]rune(s))
	r := make([]byte, 2+len(encoded)*2)
	binary.LittleEndian.PutUint16(r[:2], uint16(len(encoded)))
	for i, v := range encoded {
		binary.LittleEndian.PutUint16(r[2+i*2:], v)
	}
	return r
}

func utf16leNullTerminated(s string) []byte {
	encoded := utf16.Encode([]rune(s))
	r := make([]byte, len(encoded)*2+2)
	for i, v := range encoded {
		binary.LittleEndian.PutUint16(r[i*2:], v)
	}
	return r
}

func ansiCStringFallback(s string) []byte {
	r := make([]byte, 0, len(s)+1)
	for _, v := range s {
		if v >= 0x20 && v <= 0x7e {
			r = append(r, byte(v))
		} else {
			r = append(r, '?')
		}
	}
	return append(r, 0)
}

var StringDataOptions = []string{
	"NameString",
	"RelativePath",
	"WorkingDir",
	"CommandLineArguments",
	"IconLocation",
}
