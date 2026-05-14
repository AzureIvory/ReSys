package boot

import (
	"ReSys/src/disk"
	"ReSys/src/log"
	"ReSys/src/utils"
	"encoding/binary"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"

	syswin "golang.org/x/sys/windows"
)

var (
	Advapi32                  = syscall.NewLazyDLL("advapi32.dll")
	procOpenProcessToken      = Advapi32.NewProc("OpenProcessToken")
	procLookupPrivilegeValueW = Advapi32.NewProc("LookupPrivilegeValueW")
	procAdjustTokenPrivileges = Advapi32.NewProc("AdjustTokenPrivileges")
	procGetFWVar              = Kernel32.NewProc("GetFirmwareEnvironmentVariableW")
	procGetFWVarEx            = Kernel32.NewProc("GetFirmwareEnvironmentVariableExW")
	procSetFWVar              = Kernel32.NewProc("SetFirmwareEnvironmentVariableW")
	procSetFWVarEx            = Kernel32.NewProc("SetFirmwareEnvironmentVariableExW")
	getFw                     = GetFwType
	enSysEnv                  = enableSysEnvPriv
	findPart                  = disk.FindPartitionByRoot
	getFWVar                  = readFWVar
	setFWVar                  = writeFWVar
	hasGetFWVarEx             = func() bool { return procGetFWVarEx.Find() == nil }
	hasSetFWVarEx             = func() bool { return procSetFWVarEx.Find() == nil }
	callGetFWVar              = getFWVarCall
	callGetFWVarEx            = getFWVarExCall
	callSetFWVar              = setFWVarCall
	callSetFWVarEx            = setFWVarExCall
)

const (
	fwVarGUID     = "{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}"
	fwVarAttrNV   = 0x00000001
	fwVarAttrBS   = 0x00000002
	fwVarAttrRT   = 0x00000004
	loadOptActive = 0x00000001
	dpTypeMedia   = 0x04
	dpSubHD       = 0x01
	dpSubFile     = 0x04
	dpTypeEnd     = 0x7f
	dpSubEnd      = 0xff
)

const (
	sePrivEnabled = 0x00000002
	tokAdjPriv    = 0x0020
	tokQuery      = 0x0008
)

type bootLUID struct {
	LowPart  uint32
	HighPart int32
}

type bootLUIDAttr struct {
	Luid       bootLUID
	Attributes uint32
}

type bootTokPriv struct {
	PrivilegeCount uint32
	Privileges     [1]bootLUIDAttr
}

type bootOpt struct {
	Num    uint16
	Name   string
	Desc   string
	Part   string
	Path   string
	Active bool
}

// SetBootNext 根据 EFI 文件路径找到对应的 Boot####，
// 并写入 UEFI 的 BootNext 变量，使下次启动只进入该项一次。
func SetBootNext(efiPath string) (string, error) {
	full, root, rel, err := splitEFIPath(efiPath)
	if err != nil {
		return "", err
	}

	fw, err := getFw()
	if err != nil {
		return "", fmt.Errorf("GetFwType failed: %w", err)
	}
	if fw != fwTypeUefi {
		return "", fmt.Errorf("current firmware is not UEFI")
	}
	if err := enSysEnv(); err != nil {
		return "", fmt.Errorf("enable firmware privilege failed: %w", err)
	}

	diskInfo, partInfo, err := findPart(root)
	if err != nil {
		return "", fmt.Errorf("find partition by root failed: %w", err)
	}
	partKey, err := partKeyFromDisk(diskInfo, partInfo)
	if err != nil {
		return "", err
	}

	orderRaw, _, err := getFWVar("BootOrder")
	if err != nil {
		return "", fmt.Errorf("read BootOrder failed: %w", err)
	}
	order, err := parseBootOrder(orderRaw)
	if err != nil {
		return "", err
	}

	opts := make([]bootOpt, 0, len(order))
	for _, num := range order {
		name := fmt.Sprintf("Boot%04X", num)
		raw, _, err := getFWVar(name)
		if err != nil {
			log.LogWrite(0, "[SetBootNext] read %s failed: %v", name, err)
			continue
		}
		opt, err := parseBootOpt(name, raw)
		if err != nil {
			log.LogWrite(0, "[SetBootNext] parse %s failed: %v", name, err)
			continue
		}
		opts = append(opts, opt)
	}
	if len(opts) == 0 {
		return "", fmt.Errorf("no valid Boot#### options")
	}

	opt, err := pickBootOpt(opts, partKey, rel)
	if err != nil {
		return "", err
	}

	data := []byte{byte(opt.Num), byte(opt.Num >> 8)}
	if err := setFWVar("BootNext", data, fwVarAttrNV|fwVarAttrBS|fwVarAttrRT); err != nil {
		return "", fmt.Errorf("write BootNext failed: %w", err)
	}

	log.LogWrite(
		0,
		"[SetBootNext] efi=%s boot=%s desc=%s part=%s path=%s",
		full,
		opt.Name,
		opt.Desc,
		opt.Part,
		opt.Path,
	)
	return opt.Name, nil
}

func parseBootOrder(raw []byte) ([]uint16, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("BootOrder is empty")
	}
	if len(raw)%2 != 0 {
		return nil, fmt.Errorf("BootOrder length is invalid: %d", len(raw))
	}

	out := make([]uint16, 0, len(raw)/2)
	for i := 0; i < len(raw); i += 2 {
		out = append(out, binary.LittleEndian.Uint16(raw[i:i+2]))
	}
	return out, nil
}

func parseBootNum(name string) (uint16, error) {
	name = strings.TrimSpace(strings.ToUpper(name))
	if len(name) != 8 || !strings.HasPrefix(name, "BOOT") {
		return 0, fmt.Errorf("invalid boot var name: %s", name)
	}
	v, err := strconv.ParseUint(name[4:], 16, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid boot var name: %s", name)
	}
	return uint16(v), nil
}

func parseBootOpt(name string, raw []byte) (bootOpt, error) {
	num, err := parseBootNum(name)
	if err != nil {
		return bootOpt{}, err
	}
	if len(raw) < 6 {
		return bootOpt{}, fmt.Errorf("%s is too short", name)
	}

	attr := binary.LittleEndian.Uint32(raw[0:4])
	pathLen := int(binary.LittleEndian.Uint16(raw[4:6]))
	desc, used, err := readUTF16Z(raw[6:])
	if err != nil {
		return bootOpt{}, fmt.Errorf("%s description: %w", name, err)
	}

	off := 6 + used
	end := off + pathLen
	if end > len(raw) {
		return bootOpt{}, fmt.Errorf("%s file path list is truncated", name)
	}

	part, path, err := parseFilePathList(raw[off:end])
	if err != nil {
		return bootOpt{}, fmt.Errorf("%s file path list: %w", name, err)
	}

	return bootOpt{
		Num:    num,
		Name:   name,
		Desc:   desc,
		Part:   part,
		Path:   path,
		Active: attr&loadOptActive != 0,
	}, nil
}

func parseFilePathList(raw []byte) (string, string, error) {
	off := 0
	part := ""
	files := []string{}

	for off+4 <= len(raw) {
		size := int(binary.LittleEndian.Uint16(raw[off+2 : off+4]))
		if size < 4 || off+size > len(raw) {
			return "", "", fmt.Errorf("invalid device path node size")
		}

		node := raw[off : off+size]
		typ := node[0]
		sub := node[1]

		switch {
		case typ == dpTypeMedia && sub == dpSubHD:
			if key := parseHDPart(node); key != "" {
				part = key
			}
		case typ == dpTypeMedia && sub == dpSubFile:
			if path := parseFileNode(node); path != "" {
				files = append(files, path)
			}
		case typ == dpTypeEnd && sub == dpSubEnd:
			off = len(raw)
			continue
		}

		off += size
	}

	return part, joinEFIPath(files), nil
}

func parseHDPart(node []byte) string {
	if len(node) < 42 {
		return ""
	}

	partNum := binary.LittleEndian.Uint32(node[4:8])
	sig := node[24:40]
	sigType := node[41]

	switch sigType {
	case 0x02:
		guid := guidText(sig)
		if guid == "" {
			return ""
		}
		return "GPT:" + guid
	case 0x01:
		diskSig := binary.LittleEndian.Uint32(sig[:4])
		if diskSig == 0 || partNum == 0 {
			return ""
		}
		return fmt.Sprintf("MBR:%08X:%d", diskSig, partNum)
	default:
		return ""
	}
}

func parseFileNode(node []byte) string {
	if len(node) <= 4 {
		return ""
	}

	us := make([]uint16, 0, (len(node)-4)/2)
	for i := 4; i+1 < len(node); i += 2 {
		v := binary.LittleEndian.Uint16(node[i : i+2])
		if v == 0 {
			break
		}
		us = append(us, v)
	}
	return normEFIPath(string(utf16.Decode(us)))
}

func joinEFIPath(items []string) string {
	out := ""
	for _, item := range items {
		item = normEFIPath(item)
		if item == "" {
			continue
		}
		if out == "" {
			out = item
			continue
		}
		out = strings.TrimRight(out, `\`) + `\` + strings.TrimLeft(item, `\`)
	}
	return out
}

func pickBootOpt(list []bootOpt, wantPart, wantPath string) (bootOpt, error) {
	best := bootOpt{}
	bestScore := 0
	hitCnt := 0

	for _, item := range list {
		score := 0
		if wantPart != "" && strings.EqualFold(item.Part, wantPart) {
			score += 200
		}
		if wantPath != "" && strings.EqualFold(item.Path, wantPath) {
			score += 100
		}
		if item.Active {
			score++
		}
		if score == 0 {
			continue
		}
		if score > bestScore {
			best = item
			bestScore = score
			hitCnt = 1
			continue
		}
		if score == bestScore {
			hitCnt++
		}
	}

	if bestScore == 0 {
		return bootOpt{}, fmt.Errorf("no Boot#### matched target EFI")
	}
	if hitCnt > 1 {
		return bootOpt{}, fmt.Errorf("multiple Boot#### matched target EFI")
	}
	return best, nil
}

func splitEFIPath(path string) (string, string, string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", "", "", fmt.Errorf("efi path is empty")
	}

	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	path = filepath.Clean(path)

	root, err := utils.NormalizeDrive(path, 2)
	if err != nil {
		return "", "", "", fmt.Errorf("invalid efi path: %w", err)
	}
	rel := path
	if strings.HasPrefix(strings.ToUpper(rel), strings.ToUpper(root)) {
		rel = rel[len(root):]
	}
	rel = normEFIPath(rel)
	if rel == `\` || rel == "" {
		return "", "", "", fmt.Errorf("efi path must point to a file")
	}
	return path, root, rel, nil
}

func normEFIPath(path string) string {
	path = strings.TrimSpace(strings.ReplaceAll(path, "/", `\`))
	if path == "" {
		return ""
	}
	for strings.Contains(path, `\\`) {
		path = strings.ReplaceAll(path, `\\`, `\`)
	}
	if idx := strings.Index(path, `:\`); idx == 1 {
		path = path[3:]
	}
	path = `\` + strings.TrimLeft(path, `\`)
	return strings.ToUpper(path)
}

func partKeyFromDisk(diskInfo disk.DiskInfo, part disk.PartitionInfo) (string, error) {
	switch strings.ToUpper(strings.TrimSpace(diskInfo.PartitionStyle)) {
	case "GPT":
		if part.PartitionGuid == "" {
			return "", fmt.Errorf("partition guid is empty")
		}
		return "GPT:" + strings.ToUpper(part.PartitionGuid), nil
	case "MBR":
		if diskInfo.UniqueId == "" || part.PartitionNumber <= 0 {
			return "", fmt.Errorf("mbr partition identity is incomplete")
		}
		return fmt.Sprintf(
			"MBR:%s:%d",
			strings.ToUpper(strings.TrimSpace(diskInfo.UniqueId)),
			part.PartitionNumber,
		), nil
	default:
		return "", fmt.Errorf("unsupported partition style: %s", diskInfo.PartitionStyle)
	}
}

func readUTF16Z(raw []byte) (string, int, error) {
	if len(raw)%2 != 0 {
		return "", 0, fmt.Errorf("utf16 data length is invalid")
	}

	us := make([]uint16, 0, len(raw)/2)
	for i := 0; i+1 < len(raw); i += 2 {
		v := binary.LittleEndian.Uint16(raw[i : i+2])
		if v == 0 {
			return string(utf16.Decode(us)), i + 2, nil
		}
		us = append(us, v)
	}
	return "", 0, fmt.Errorf("utf16 terminator not found")
}

func guidText(raw []byte) string {
	if len(raw) < 16 {
		return ""
	}

	d1 := binary.LittleEndian.Uint32(raw[0:4])
	d2 := binary.LittleEndian.Uint16(raw[4:6])
	d3 := binary.LittleEndian.Uint16(raw[6:8])
	return strings.ToUpper(fmt.Sprintf(
		"%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		d1,
		d2,
		d3,
		raw[8],
		raw[9],
		raw[10],
		raw[11],
		raw[12],
		raw[13],
		raw[14],
		raw[15],
	))
}

func readFWVar(name string) ([]byte, uint32, error) {
	nm, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return nil, 0, err
	}
	gd, err := syscall.UTF16PtrFromString(fwVarGUID)
	if err != nil {
		return nil, 0, err
	}

	size := 256
	for {
		buf := make([]byte, size)
		r1 := uintptr(0)
		attr := uint32(0)
		var e1 error
		if hasGetFWVarEx() {
			r1, attr, e1 = callGetFWVarEx(nm, gd, buf)
		} else {
			r1, e1 = callGetFWVar(nm, gd, buf)
		}
		if r1 != 0 {
			return buf[:r1], attr, nil
		}

		if errno := callErrno(e1); errno == syswin.ERROR_INSUFFICIENT_BUFFER {
			size *= 2
			if size > 1<<20 {
				return nil, 0, fmt.Errorf("firmware variable %s is too large", name)
			}
			continue
		}
		if errno := callErrno(e1); errno != 0 {
			return nil, 0, errno
		}
		return nil, 0, fmt.Errorf("GetFirmwareEnvironmentVariable failed: %s", name)
	}
}

func writeFWVar(name string, data []byte, attr uint32) error {
	nm, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	gd, err := syscall.UTF16PtrFromString(fwVarGUID)
	if err != nil {
		return err
	}

	var ptr uintptr
	if len(data) > 0 {
		ptr = uintptr(unsafe.Pointer(&data[0]))
	}
	r1 := uintptr(0)
	var e1 error
	if hasSetFWVarEx() {
		r1, e1 = callSetFWVarEx(nm, gd, ptr, len(data), attr)
	} else {
		r1, e1 = callSetFWVar(nm, gd, ptr, len(data))
	}
	if r1 != 0 {
		return nil
	}
	if errno := callErrno(e1); errno != 0 {
		return errno
	}
	return fmt.Errorf("SetFirmwareEnvironmentVariable failed: %s", name)
}

func getFWVarCall(nm, gd *uint16, buf []byte) (uintptr, error) {
	r1, _, e1 := procGetFWVar.Call(
		uintptr(unsafe.Pointer(nm)),
		uintptr(unsafe.Pointer(gd)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	return r1, e1
}

func getFWVarExCall(nm, gd *uint16, buf []byte) (uintptr, uint32, error) {
	var attr uint32
	r1, _, e1 := procGetFWVarEx.Call(
		uintptr(unsafe.Pointer(nm)),
		uintptr(unsafe.Pointer(gd)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&attr)),
	)
	return r1, attr, e1
}

func setFWVarCall(nm, gd *uint16, ptr uintptr, size int) (uintptr, error) {
	r1, _, e1 := procSetFWVar.Call(
		uintptr(unsafe.Pointer(nm)),
		uintptr(unsafe.Pointer(gd)),
		ptr,
		uintptr(size),
	)
	return r1, e1
}

func setFWVarExCall(nm, gd *uint16, ptr uintptr, size int, attr uint32) (uintptr, error) {
	r1, _, e1 := procSetFWVarEx.Call(
		uintptr(unsafe.Pointer(nm)),
		uintptr(unsafe.Pointer(gd)),
		ptr,
		uintptr(size),
		uintptr(attr),
	)
	return r1, e1
}

func enableSysEnvPriv() error {
	var tok syscall.Token

	hProc, err := syscall.GetCurrentProcess()
	if err != nil {
		return err
	}

	r1, _, e1 := procOpenProcessToken.Call(
		uintptr(hProc),
		uintptr(tokAdjPriv|tokQuery),
		uintptr(unsafe.Pointer(&tok)),
	)
	if r1 == 0 {
		if errno := callErrno(e1); errno != 0 {
			return errno
		}
		return fmt.Errorf("OpenProcessToken failed")
	}
	defer syscall.CloseHandle(syscall.Handle(tok))

	var luid bootLUID
	name, _ := syscall.UTF16PtrFromString("SeSystemEnvironmentPrivilege")
	r2, _, e2 := procLookupPrivilegeValueW.Call(
		0,
		uintptr(unsafe.Pointer(name)),
		uintptr(unsafe.Pointer(&luid)),
	)
	if r2 == 0 {
		if errno := callErrno(e2); errno != 0 {
			return errno
		}
		return fmt.Errorf("LookupPrivilegeValueW failed")
	}

	var tp bootTokPriv
	tp.PrivilegeCount = 1
	tp.Privileges[0].Luid = luid
	tp.Privileges[0].Attributes = sePrivEnabled

	r3, _, e3 := procAdjustTokenPrivileges.Call(
		uintptr(tok),
		0,
		uintptr(unsafe.Pointer(&tp)),
		0,
		0,
		0,
	)
	if r3 == 0 {
		if errno := callErrno(e3); errno != 0 {
			return errno
		}
		return fmt.Errorf("AdjustTokenPrivileges failed")
	}
	return nil
}

func callErrno(err error) syscall.Errno {
	if err == nil {
		return 0
	}
	if errno, ok := err.(syscall.Errno); ok {
		return errno
	}
	return 0
}
