package main

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"syscall"
	"unicode"
	"unsafe"
)

// ===================== Enums / Error codes =====================

// FveAccessMode matches Rust: ReadOnly=0, ReadWrite=1.
type FveAccessMode uint32

const (
	ReadOnly  FveAccessMode = 0
	ReadWrite FveAccessMode = 1
)

type FveVolumeStatus uint32

const (
	FullyDecrypted       FveVolumeStatus = 0
	FullyEncrypted       FveVolumeStatus = 1
	EncryptionInProgress FveVolumeStatus = 2
	DecryptionInProgress FveVolumeStatus = 3
	EncryptionPaused     FveVolumeStatus = 4
	DecryptionPaused     FveVolumeStatus = 5
)

type FveProtectionStatus uint32

const (
	ProtectionOff     FveProtectionStatus = 0
	ProtectionOn      FveProtectionStatus = 1
	ProtectionUnknown FveProtectionStatus = 2
)

type FveLockStatus uint32

const (
	Unlocked FveLockStatus = 0
	Locked   FveLockStatus = 1
)

type FveError uint32

const (
	Success              FveError = 0
	InvalidParameter     FveError = 0x80070057
	AccessDenied         FveError = 0x80070005
	VolumeLocked         FveError = 0x80310000
	NotSupported         FveError = 0x80310001
	NotEncrypted         FveError = 0x80310008
	KeyRequired          FveError = 0x80310044
	AuthenticationFailed FveError = 0x8031000D
	BadPassword          FveError = 0x80310027
	BadRecoveryPassword  FveError = 0x80310028
	VolumeUnlocked       FveError = 0x80310023
	NotBitLockerVolume   FveError = 0x80310049
	VolumeRemoved        FveError = 0x8031004A
	Unknown              FveError = 0xFFFFFFFF
)

func FromHRESULT(code uint32) FveError {
	switch code {
	case 0:
		return Success
	case uint32(InvalidParameter):
		return InvalidParameter
	case uint32(AccessDenied):
		return AccessDenied
	case uint32(VolumeLocked):
		return VolumeLocked
	case uint32(NotSupported):
		return NotSupported
	case uint32(NotEncrypted):
		return NotEncrypted
	case uint32(KeyRequired):
		return KeyRequired
	case uint32(AuthenticationFailed):
		return AuthenticationFailed
	case uint32(BadPassword):
		return BadPassword
	case uint32(BadRecoveryPassword):
		return BadRecoveryPassword
	case uint32(VolumeUnlocked):
		return VolumeUnlocked
	case uint32(NotBitLockerVolume):
		return NotBitLockerVolume
	case uint32(VolumeRemoved):
		return VolumeRemoved
	default:
		return Unknown
	}
}

func (e FveError) Code() uint32 { return uint32(e) }

func (e FveError) IndicatesNotEncrypted() bool {
	return e == NotEncrypted || e == NotBitLockerVolume || e == NotSupported
}

func (e FveError) IndicatesLocked() bool {
	return e == VolumeLocked || e == KeyRequired || e == AuthenticationFailed
}

// ===================== Status output (0x80) =====================

// Mirrors Rust layout:
// size=0x80, version=2 (fallback to 1), conversion_status, percent_complete, protection_status,
// volume_size, encrypted_size, encryption_flags.
type fveGetStatusOutput struct {
	Size             uint32     // 0x00
	Version          uint32     // 0x04
	Reserved1        uint32     // 0x08
	ConversionStatus uint32     // 0x0C
	PercentComplete  float64    // 0x10
	Reserved2        [0x20]byte // 0x18..0x37
	ProtectionStatus uint32     // 0x38
	Reserved3        [0x14]byte // 0x3C..0x4F
	VolumeSize       uint64     // 0x50
	EncryptedSize    uint64     // 0x58
	Reserved4        [0x10]byte // 0x60..0x6F
	EncryptionFlags  uint32     // 0x70
	Reserved5        [0x0C]byte // 0x74..0x7F
}

func newStatusOutput(version uint32) fveGetStatusOutput {
	var out fveGetStatusOutput
	out.Size = 0x80
	out.Version = version

	// 强校验：结构体必须是 0x80
	if unsafe.Sizeof(out) != 0x80 {
		// 如果这里炸了，说明 Go 的结构体布局不符合预期，需要重新调整 padding。
		panic(fmt.Sprintf("fveGetStatusOutput size mismatch: got=0x%X want=0x80", unsafe.Sizeof(out)))
	}
	return out
}

func (o *fveGetStatusOutput) getVolumeStatus() FveVolumeStatus {
	switch o.ConversionStatus {
	case 0:
		return FullyDecrypted
	case 1:
		return FullyEncrypted
	case 2:
		return EncryptionInProgress
	case 3:
		return DecryptionInProgress
	case 4:
		return EncryptionPaused
	case 5:
		return DecryptionPaused
	default:
		// 不认识就当 FullyDecrypted
		return FullyDecrypted
	}
}

func (o *fveGetStatusOutput) getProtectionStatus() FveProtectionStatus {
	switch o.ProtectionStatus {
	case 0:
		return ProtectionOff
	case 1:
		return ProtectionOn
	default:
		return ProtectionUnknown
	}
}

func (o *fveGetStatusOutput) getLockStatus() FveLockStatus {
	// protection_status=1 视为 Locked
	if o.ProtectionStatus == 1 {
		return Locked
	}
	return Unlocked
}

// ===================== Public structs =====================

type FveVolumeInfo struct {
	VolumeStatus         FveVolumeStatus
	ProtectionStatus     FveProtectionStatus
	LockStatus           FveLockStatus
	EncryptionPercentage uint8
	EncryptionFlags      uint32
	VolumeSize           uint64
	EncryptedSize        uint64
}

func volumeInfoFrom(out *fveGetStatusOutput) FveVolumeInfo {
	percent := out.PercentComplete
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}
	// Rust: round().clamp(0,100) as u8
	p := uint8(percent + 0.5)

	return FveVolumeInfo{
		VolumeStatus:         out.getVolumeStatus(),
		ProtectionStatus:     out.getProtectionStatus(),
		LockStatus:           out.getLockStatus(),
		EncryptionPercentage: p,
		EncryptionFlags:      out.EncryptionFlags,
		VolumeSize:           out.VolumeSize,
		EncryptedSize:        out.EncryptedSize,
	}
}

// ===================== API loader =====================

type FveApi struct {
	dll *syscall.LazyDLL

	pOpenVolumeW syscall.LazyProc
	pCloseVolume syscall.LazyProc

	pGetStatusW syscall.LazyProc
	pGetStatus  syscall.LazyProc

	pUnlockVolume syscall.LazyProc
	pLockVolume   syscall.LazyProc

	pDecrypt   syscall.LazyProc
	pDecryptEx syscall.LazyProc

	pAuthFromPassphrase syscall.LazyProc
	pAuthFromRecovery   syscall.LazyProc
}

var (
	once     sync.Once
	instance *FveApi
	instErr  error
)

func Instance() (*FveApi, error) {
	once.Do(func() {
		api, err := newFveApi()
		if err != nil {
			instErr = err
			return
		}
		instance = api
	})
	return instance, instErr
}

func newFveApi() (*FveApi, error) {
	dll := syscall.NewLazyDLL("fveapi.dll")

	// 先 Load 一次，尽早发现 DLL 不存在（例如 Win7 非旗舰/企业版、或者组件缺失）
	if err := dll.Load(); err != nil {
		return nil, fmt.Errorf("load fveapi.dll failed: %w", err)
	}

	api := &FveApi{dll: dll}

	api.pOpenVolumeW = *dll.NewProc("FveOpenVolumeW")
	api.pCloseVolume = *dll.NewProc("FveCloseVolume")

	api.pGetStatusW = *dll.NewProc("FveGetStatusW")
	api.pGetStatus = *dll.NewProc("FveGetStatus")

	api.pUnlockVolume = *dll.NewProc("FveUnlockVolume")
	api.pLockVolume = *dll.NewProc("FveLockVolume")

	api.pDecrypt = *dll.NewProc("FveConversionDecrypt")
	api.pDecryptEx = *dll.NewProc("FveConversionDecryptEx")

	api.pAuthFromPassphrase = *dll.NewProc("FveAuthElementFromPassPhraseW")
	api.pAuthFromRecovery = *dll.NewProc("FveAuthElementFromRecoveryPasswordW")

	// Find: 确保导出存在
	procs := []struct {
		name string
		p    *syscall.LazyProc
	}{
		{"FveOpenVolumeW", &api.pOpenVolumeW},
		{"FveCloseVolume", &api.pCloseVolume},
		{"FveGetStatusW", &api.pGetStatusW},
		{"FveGetStatus", &api.pGetStatus},
		{"FveUnlockVolume", &api.pUnlockVolume},
		{"FveLockVolume", &api.pLockVolume},
		{"FveConversionDecrypt", &api.pDecrypt},
		{"FveConversionDecryptEx", &api.pDecryptEx},
		{"FveAuthElementFromPassPhraseW", &api.pAuthFromPassphrase},
		{"FveAuthElementFromRecoveryPasswordW", &api.pAuthFromRecovery},
	}

	for _, it := range procs {
		if err := it.p.Find(); err != nil {
			return nil, fmt.Errorf("proc not found: %s: %w", it.name, err)
		}
	}

	return api, nil
}

// ===================== Helper: normalize volume path =====================

func normalizeVolumePath(path string) string {
	trimmed := strings.TrimSpace(path)

	// Volume GUID 直接保留
	if strings.Contains(trimmed, "Volume{") {
		return trimmed
	}

	// 设备路径格式: \\.\X: 或 \\?\X:
	if len(trimmed) >= 6 {
		prefix := trimmed[:4]
		if prefix == `\\.\` || prefix == `\\?\` {
			rest := trimmed[4:]
			if len(rest) >= 2 && rest[1] == ':' {
				letter := rune(rest[0])
				if unicode.IsLetter(letter) {
					return strings.ToUpper(string(letter)) + ":"
				}
			}
		}
	}

	// 简单盘符格式: X: 或 X:\
	if len(trimmed) >= 2 && trimmed[1] == ':' {
		letter := rune(trimmed[0])
		if unicode.IsLetter(letter) {
			return strings.ToUpper(string(letter)) + ":"
		}
	}

	return trimmed
}

func toUTF16Ptr(s string) (*uint16, error) {
	// syscall.UTF16PtrFromString 会自动加 \0
	return syscall.UTF16PtrFromString(s)
}

// ===================== FveApi methods (match Rust semantics) =====================

func (api *FveApi) GetStatusByPath(volumePath string) (FveVolumeInfo, FveError) {
	normalized := normalizeVolumePath(volumePath)
	p, err := toUTF16Ptr(normalized)
	if err != nil {
		return FveVolumeInfo{}, InvalidParameter
	}

	// 先尝试 version=2
	out := newStatusOutput(2)
	hr := api.callGetStatusW(p, &out)
	if hr == 0 {
		return volumeInfoFrom(&out), Success
	}

	// Win7/老版本兼容：如果返回 invalid arg，尝试 version=1
	if hr == uint32(InvalidParameter) {
		out1 := newStatusOutput(1)
		hr2 := api.callGetStatusW(p, &out1)
		if hr2 == 0 {
			return volumeInfoFrom(&out1), Success
		}
		return FveVolumeInfo{}, FromHRESULT(hr2)
	}

	return FveVolumeInfo{}, FromHRESULT(hr)
}

func (api *FveApi) OpenVolume(volumePath string) (*FveVolumeHandle, FveError) {
	return api.OpenVolumeEx(volumePath, ReadOnly)
}

func (api *FveApi) OpenVolumeEx(volumePath string, mode FveAccessMode) (*FveVolumeHandle, FveError) {
	normalized := normalizeVolumePath(volumePath)
	p, err := toUTF16Ptr(normalized)
	if err != nil {
		return nil, InvalidParameter
	}

	var h syscall.Handle
	r1, _, _ := api.pOpenVolumeW.Call(
		uintptr(unsafe.Pointer(p)),
		uintptr(uint32(mode)),
		uintptr(unsafe.Pointer(&h)),
	)
	hr := uint32(r1)
	if hr != 0 {
		return nil, FromHRESULT(hr)
	}

	vh := &FveVolumeHandle{handle: h, api: api}
	// runtime.SetFinalizer 在 syscall import 下不写 runtime 也可，不过这里不强制依赖 finalizer
	return vh, Success
}

func (api *FveApi) IsEncrypted(volumePath string) (bool, FveError) {
	info, e := api.GetStatusByPath(volumePath)
	if e != Success {
		return false, e
	}
	return info.VolumeStatus != FullyDecrypted, Success
}

func (api *FveApi) IsLocked(volumePath string) (bool, FveError) {
	info, e := api.GetStatusByPath(volumePath)
	if e != Success {
		return false, e
	}
	return info.LockStatus == Locked, Success
}

func (api *FveApi) GetVolumeStatus(volumePath string) (FveVolumeStatus, FveError) {
	info, e := api.GetStatusByPath(volumePath)
	if e != Success {
		return FullyDecrypted, e
	}
	return info.VolumeStatus, Success
}

func (api *FveApi) GetProtectionStatus(volumePath string) (FveProtectionStatus, FveError) {
	info, e := api.GetStatusByPath(volumePath)
	if e != Success {
		return ProtectionUnknown, e
	}
	return info.ProtectionStatus, Success
}

func (api *FveApi) GetLockStatus(volumePath string) (FveLockStatus, FveError) {
	info, e := api.GetStatusByPath(volumePath)
	if e != Success {
		return Unlocked, e
	}
	return info.LockStatus, Success
}

func (api *FveApi) callGetStatusW(path *uint16, out *fveGetStatusOutput) uint32 {
	r1, _, _ := api.pGetStatusW.Call(
		uintptr(unsafe.Pointer(path)),
		uintptr(unsafe.Pointer(out)),
	)
	return uint32(r1)
}

// ===================== Volume handle (RAII-like) =====================

type FveVolumeHandle struct {
	handle syscall.Handle
	api    *FveApi
}

func (h *FveVolumeHandle) Close() FveError {
	if h == nil || h.handle == 0 {
		return Success
	}
	r1, _, _ := h.api.pCloseVolume.Call(uintptr(h.handle))
	hr := uint32(r1)
	// 不管 Close 是否成功，都避免重复 close
	h.handle = 0
	if hr != 0 {
		return FromHRESULT(hr)
	}
	return Success
}

func (h *FveVolumeHandle) GetStatus() (FveVolumeInfo, FveError) {
	if h == nil || h.handle == 0 {
		return FveVolumeInfo{}, InvalidParameter
	}
	out := newStatusOutput(2)
	r1, _, _ := h.api.pGetStatus.Call(
		uintptr(h.handle),
		uintptr(unsafe.Pointer(&out)),
	)
	hr := uint32(r1)
	if hr == 0 {
		return volumeInfoFrom(&out), Success
	}
	// 同样做 version=1 fallback
	if hr == uint32(InvalidParameter) {
		out1 := newStatusOutput(1)
		r2, _, _ := h.api.pGetStatus.Call(
			uintptr(h.handle),
			uintptr(unsafe.Pointer(&out1)),
		)
		hr2 := uint32(r2)
		if hr2 == 0 {
			return volumeInfoFrom(&out1), Success
		}
		return FveVolumeInfo{}, FromHRESULT(hr2)
	}
	return FveVolumeInfo{}, FromHRESULT(hr)
}

func (h *FveVolumeHandle) UnlockWithPassword(password string) FveError {
	if h == nil || h.handle == 0 {
		return InvalidParameter
	}
	auth, e := h.api.createPassphraseAuth(password)
	if e != Success {
		return e
	}
	r1, _, _ := h.api.pUnlockVolume.Call(
		uintptr(h.handle),
		uintptr(auth),
	)
	hr := uint32(r1)
	if hr != 0 {
		return FromHRESULT(hr)
	}
	return Success
}

func (h *FveVolumeHandle) UnlockWithRecoveryKey(recoveryKey string) FveError {
	if h == nil || h.handle == 0 {
		return InvalidParameter
	}
	auth, e := h.api.createRecoveryAuth(recoveryKey)
	if e != Success {
		return e
	}
	r1, _, _ := h.api.pUnlockVolume.Call(
		uintptr(h.handle),
		uintptr(auth),
	)
	hr := uint32(r1)
	if hr != 0 {
		return FromHRESULT(hr)
	}
	return Success
}

func (h *FveVolumeHandle) Lock(dismountFirst bool) FveError {
	if h == nil || h.handle == 0 {
		return InvalidParameter
	}
	var df uintptr
	if dismountFirst {
		df = 1
	}
	r1, _, _ := h.api.pLockVolume.Call(
		uintptr(h.handle),
		df,
	)
	hr := uint32(r1)
	if hr != 0 {
		return FromHRESULT(hr)
	}
	return Success
}

func (h *FveVolumeHandle) StartDecryption() FveError {
	if h == nil || h.handle == 0 {
		return InvalidParameter
	}
	r1, _, _ := h.api.pDecrypt.Call(uintptr(h.handle))
	hr := uint32(r1)
	if hr != 0 {
		return FromHRESULT(hr)
	}
	return Success
}

func (h *FveVolumeHandle) StartDecryptionEx(flags uint32) FveError {
	if h == nil || h.handle == 0 {
		return InvalidParameter
	}
	r1, _, _ := h.api.pDecryptEx.Call(
		uintptr(h.handle),
		uintptr(flags),
	)
	hr := uint32(r1)
	if hr != 0 {
		return FromHRESULT(hr)
	}
	return Success
}

func (h *FveVolumeHandle) AsRaw() uintptr {
	if h == nil {
		return 0
	}
	return uintptr(h.handle)
}

// ===================== Auth element creation =====================
// 注意：这里完全按你 Rust 的“返回 *void”签名写。
// 如果你后续验证 Win7/某些版本函数实际是“写入 caller buffer”形式，
// 需要改签名和内存策略（否则会崩）。现在以“与 Rust 一致”为优先。

func (api *FveApi) createPassphraseAuth(passphrase string) (uintptr, FveError) {
	p, err := toUTF16Ptr(passphrase)
	if err != nil {
		return 0, InvalidParameter
	}
	var auth uintptr
	r1, _, _ := api.pAuthFromPassphrase.Call(
		uintptr(unsafe.Pointer(p)),
		uintptr(unsafe.Pointer(&auth)),
	)
	hr := uint32(r1)
	if hr != 0 || auth == 0 {
		return 0, FromHRESULT(hr)
	}
	return auth, Success
}

func (api *FveApi) createRecoveryAuth(recoveryKey string) (uintptr, FveError) {
	p, err := toUTF16Ptr(recoveryKey)
	if err != nil {
		return 0, InvalidParameter
	}
	var auth uintptr
	r1, _, _ := api.pAuthFromRecovery.Call(
		uintptr(unsafe.Pointer(p)),
		uintptr(unsafe.Pointer(&auth)),
	)
	hr := uint32(r1)
	if hr != 0 || auth == 0 {
		return 0, FromHRESULT(hr)
	}
	return auth, Success
}

// ===================== Utilities =====================

// FormatRecoveryKey matches Rust: keep digits only, must be 48 digits, group by 6 with '-'.
func FormatRecoveryKey(input string) (string, error) {
	var b strings.Builder
	b.Grow(len(input))
	for _, r := range input {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	digits := b.String()
	if len(digits) != 48 {
		return "", fmt.Errorf("recovery key must be 48 digits, got %d", len(digits))
	}
	parts := make([]string, 0, 8)
	for i := 0; i < 48; i += 6 {
		parts = append(parts, digits[i:i+6])
	}
	return strings.Join(parts, "-"), nil
}

// A small helper to make sure caller doesn't pass empty API.
func MustInstance() *FveApi {
	api, err := Instance()
	if err != nil {
		panic(err)
	}
	return api
}

// Optional sanity check
var ErrNotWindows = errors.New("windows only")
