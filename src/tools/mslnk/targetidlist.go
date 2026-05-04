package mslnk

import (
	"bytes"
	"encoding/binary"
	"regexp"
	"strings"
)

// TODO: targetidlist_test

type ItemID struct {
	Size [2]byte
	Data []byte
}

func ItemIDFile(s string) ItemID {
	return itemIDFS(s, false)
}

// TODO, FIXME: test ItemIDDirectory
func ItemIDDirectory(s string) ItemID {
	return itemIDFS(s, true)
}

func ItemIDDrive(s string) ItemID {
	r := ItemID{
		Size: [2]byte{0x1c, 0x00},
		Data: make([]byte, 0x1c-2),
	}
	r.Data[0] = ItemIDType["drive"]
	copy(r.Data[1:], ansiCStringFallback(normalizeDriveName(s)))
	return r
}

func newLocalTargetIDList(targetPath string) (LinkTargetIDList, bool) {
	targetPath = strings.ReplaceAll(strings.TrimSpace(targetPath), "/", "\\")
	if len(targetPath) < 3 || targetPath[1] != ':' || targetPath[2] != '\\' {
		return LinkTargetIDList{}, false
	}

	items := []ItemID{
		ItemIDCLSID(ItemIDMagic["MY_COMPUTER"]),
		ItemIDDrive(targetPath[:3]),
	}
	parts := strings.Split(strings.Trim(targetPath[3:], "\\"), "\\")
	for i, part := range parts {
		if part == "" {
			continue
		}
		if i == len(parts)-1 {
			items = append(items, ItemIDFile(part))
		} else {
			items = append(items, ItemIDDirectory(part))
		}
	}

	list := LinkTargetIDList{ItemIDList: items}
	list.Size()
	return list, true
}

func normalizeDriveName(s string) string {
	s = strings.ReplaceAll(strings.TrimSpace(s), "/", "\\")
	if len(s) == 1 {
		return s + ":\\"
	}
	if len(s) == 2 && s[1] == ':' {
		return s + "\\"
	}
	return s
}

func itemIDFS(name string, directory bool) ItemID {
	name = strings.Trim(name, "\\/")
	if needsUnicodeItemID(name) {
		return itemIDFSUnicode(name, directory)
	}
	return itemIDFSANSI(name, directory)
}

func itemIDFSANSI(name string, directory bool) ItemID {
	attr := uint16(0x20)
	typeFlag := ItemIDType["file"]
	if directory {
		attr = 0x10
		typeFlag = ItemIDType["directory"]
	}

	nameBytes := ansiCStringFallback(name)
	data := make([]byte, 12+len(nameBytes))
	data[0] = typeFlag
	binary.LittleEndian.PutUint16(data[10:12], attr)
	copy(data[12:], nameBytes)
	return newItemID(data)
}

func itemIDFSUnicode(name string, directory bool) ItemID {
	attr := uint16(0x20)
	typeFlag := byte(0x36) // GROUP_FS | TYPE_FS_UNICODE | TYPE_FS_FILE
	if directory {
		attr = 0x10
		typeFlag = 0x35 // GROUP_FS | TYPE_FS_UNICODE | TYPE_FS_DIRECTORY
	}

	longName := utf16leNullTerminated(name)
	shortName := ansiCStringFallback(generateShortName(name))
	data := make([]byte, 12+len(longName)+len(shortName))
	data[0] = typeFlag
	// data[1] 是 padding；文件大小、修改日期和时间在离线场景下保持 0。
	binary.LittleEndian.PutUint16(data[10:12], attr)
	copy(data[12:], longName)
	copy(data[12+len(longName):], shortName)
	return newItemID(data)
}

func newItemID(data []byte) ItemID {
	size := len(data) + 2
	var sizeBytes [2]byte
	binary.LittleEndian.PutUint16(sizeBytes[:], uint16(size))
	return ItemID{Size: sizeBytes, Data: data}
}

func needsUnicodeItemID(name string) bool {
	if name == "" {
		return false
	}
	// 兼容旧的低层 API：历史测试允许把 "dir\file" 直接传给 ItemIDFile。
	// 新的高层 API 会先切分路径组件，因此不会走到这里。
	if strings.ContainsAny(name, "\\/") {
		return false
	}
	return isLongFilename(name)
}

func isASCII(s string) bool {
	for _, r := range s {
		if r > 0x7f {
			return false
		}
	}
	return true
}

func isLongFilename(name string) bool {
	if name == "" {
		return false
	}
	if strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") {
		return true
	}
	if !isASCII(name) {
		return true
	}

	dotIdx := strings.LastIndex(name, ".")
	baseName := name
	ext := ""
	if dotIdx >= 0 {
		baseName = name[:dotIdx]
		ext = name[dotIdx+1:]
	}
	wrongSymbols := regexp.MustCompile(`[\."/\\\[\]:;=, ]+`)
	if dotIdx >= 0 && (len(baseName) > 8 || len(ext) > 3) {
		return true
	}
	if dotIdx < 0 && len(name) > 12 {
		return true
	}
	return wrongSymbols.MatchString(baseName) || wrongSymbols.MatchString(ext)
}

func generateShortName(longName string) string {
	name := strings.Trim(longName, ".")
	if name == "" {
		name = "ITEM"
	}
	dotIdx := strings.LastIndex(name, ".")
	baseName := name
	ext := ""
	if dotIdx >= 0 {
		baseName = name[:dotIdx]
		ext = name[dotIdx+1:]
	}

	replacer := strings.NewReplacer(
		" ", "",
		".", "_",
		"\"", "_",
		"/", "_",
		"\\", "_",
		"[", "_",
		"]", "_",
		":", "_",
		";", "_",
		"=", "_",
		",", "_",
		"+", "_",
	)
	baseName = replacer.Replace(baseName)
	ext = replacer.Replace(strings.ReplaceAll(ext, " ", ""))

	baseRunes := []rune(baseName)
	if len(baseRunes) > 6 {
		baseRunes = baseRunes[:6]
	}
	extRunes := []rune(ext)
	if len(extRunes) > 3 {
		extRunes = extRunes[:3]
	}

	base := asciiDOSPart(string(baseRunes))
	if base == "" {
		base = "ITEM"
	}
	shortName := base + "~1"
	if len(extRunes) > 0 {
		shortName += "." + asciiDOSPart(string(extRunes))
	}
	return strings.ToUpper(shortName)
}

func asciiDOSPart(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 0x20 && r <= 0x7e {
			b.WriteByte(byte(r))
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

func ItemIDCLSID(b []byte) ItemID {
	r := make([]byte, len(b)+3)
	r[0] = byte(len(r) & 255)
	if len(r) > 255 {
		r[1] = byte(len(r) >> 8)
	}
	r[2] = ItemIDType["clsid"]
	for i, v := range b {
		r[i+3] = v
	}
	return ItemID{
		Size: [2]byte{r[0], r[1]},
		Data: r[2:],
	}
}

type LinkTargetIDList struct {
	IDListSize [2]byte

	// 'IDlist' from spec
	ItemIDList []ItemID
	TerminalID [2]byte
}

func (x *LinkTargetIDList) Size() uint16 {
	var r uint16 = 2
	for _, v := range x.ItemIDList {
		r += uint16(len(v.Data) + len(v.Size))
	}
	x.IDListSize[0] = byte(r & 255)
	if r > 255 {
		x.IDListSize[1] = byte(r >> 8)
	} else {
		x.IDListSize[1] = 0
	}
	return r
}

func (x *LinkTargetIDList) Bytes() []byte {
	var buffer bytes.Buffer
	buffer.Write(x.IDListSize[:])
	for _, v := range x.ItemIDList {
		buffer.Write(v.Size[:])
		buffer.Write(v.Data)
	}
	buffer.Write(x.TerminalID[:])
	return buffer.Bytes()
}

// based on https://github.com/DmitriiShamrikov/mslinks/blob/master/src/mslinks/data/ItemID.java
var (
	ItemIDType = map[string]byte{
		"file":      0x32,
		"directory": 0x31,
		"drive":     0x2f,
		"clsid":     0x1f,
	}

	ItemIDMagic = map[string][]byte{
		"MY_COMPUTER":    {0x50, 0xe0, 0x4f, 0xd0, 0x20, 0xea, 0x3a, 0x69, 0x10, 0xa2, 0xd8, 0x08, 0x00, 0x2b, 0x30, 0x30, 0x9d},
		"file_attr":      {0x20, 0x00},
		"directory_attr": {0x10, 0x00},
	}
)
