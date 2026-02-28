package main

import (
	"fmt"
	"math"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// 来自逆向分析：test dword [rsi+0x70], 0x17f
const FVEFlagCheckMask uint32 = 0x0000017F

type AccessMode uint32

const (
	ReadOnly  AccessMode = 0
	ReadWrite AccessMode = 1
)

type VolumeStatus uint32

const (
	FullyDecrypted       VolumeStatus = 0
	FullyEncrypted       VolumeStatus = 1
	EncryptionInProgress VolumeStatus = 2
	DecryptionInProgress VolumeStatus = 3
	EncryptionPaused     VolumeStatus = 4
	DecryptionPaused     VolumeStatus = 5
)

func volumeStatusFrom(v uint32) VolumeStatus {
	switch v {
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
		return FullyDecrypted
	}
}

type ProtectionStatus uint32

const (
	ProtectionOff     ProtectionStatus = 0
	ProtectionOn      ProtectionStatus = 1
	ProtectionUnknown ProtectionStatus = 2
)

func protectionStatusFrom(v uint32) ProtectionStatus {
	switch v {
	case 0:
		return ProtectionOff
	case 1:
		return ProtectionOn
	default:
		return ProtectionUnknown
	}
}

type LockStatus uint32

const (
	Unlocked LockStatus = 0
	Locked   LockStatus = 1
)

func lockStatusFrom(v uint32) LockStatus {
	if v == 0 {
		return Unlocked
	}
	return Locked
}

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
)

func (e FveError) Error() string {
	switch e {
	case Success:
		return "操作成功"
	case InvalidParameter:
		return "无效参数"
	case AccessDenied:
		return "访问被拒绝，请以管理员权限运行"
	case VolumeLocked:
		return "卷已锁定，需要密码解锁"
	case NotSupported:
		return "卷不支持BitLocker"
	case NotEncrypted:
		return "卷未启用BitLocker加密"
	case KeyRequired:
		return "需要认证密钥"
	case AuthenticationFailed:
		return "认证失败"
	case BadPassword:
		return "密码错误"
	case BadRecoveryPassword:
		return "恢复密钥错误"
	case VolumeUnlocked:
		return "卷已解锁"
	case NotBitLockerVolume:
		return "不是BitLocker卷"
	case VolumeRemoved:
		return "卷已移除"
	default:
		return fmt.Sprintf("未知错误: 0x%08X", uint32(e))
	}
}

func fromHRESULT(hr uint32) error {
	if hr == 0 {
		return nil
	}
	switch hr {
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
		return FveError(hr)
	}
}

type GetStatusOutput struct {
	Size             uint32     // +0x00
	Version          uint32     // +0x04
	Reserved1        uint32     // +0x08
	ConversionStatus uint32     // +0x0C
	PercentComplete  float64    // +0x10
	Reserved2        [0x20]byte // +0x18..0x37
	ProtectionStatus uint32     // +0x38
	Reserved3        [0x14]byte // +0x3C..0x4F
	VolumeSize       uint64     // +0x50
	EncryptedSize    uint64     // +0x58
	Reserved4        [0x10]byte // +0x60..0x6F
	EncryptionFlags  uint32     // +0x70
	Reserved5        [0x0C]byte // +0x74..0x7F
}

func NewGetStatusOutput() GetStatusOutput {
	return GetStatusOutput{
		Size:    0x80,
		Version: 2,
	}
}

func (o *GetStatusOutput) IsEncrypted() bool {
	if (o.EncryptionFlags & FVEFlagCheckMask) != 0 {
		return true
	}
	switch o.ConversionStatus {
	case uint32(FullyEncrypted), uint32(EncryptionInProgress), uint32(EncryptionPaused),
		uint32(DecryptionInProgress), uint32(DecryptionPaused):
		return true
	default:
		return false
	}
}

func (o *GetStatusOutput) IsLocked() bool {
	return o.ProtectionStatus == uint32(ProtectionOn)
}

func (o *GetStatusOutput) GetVolumeStatus() VolumeStatus {
	return volumeStatusFrom(o.ConversionStatus)
}

func (o *GetStatusOutput) GetProtectionStatus() ProtectionStatus {
	return protectionStatusFrom(o.ProtectionStatus)
}

func (o *GetStatusOutput) GetLockStatus() LockStatus {
	return lockStatusFrom(o.ProtectionStatus)
}

type VolumeInfoB struct {
	VolumeStatus      VolumeStatus
	ProtectionStatus  ProtectionStatus
	LockStatus        LockStatus
	EncryptionPercent uint8
	EncryptionFlags   uint32
	VolumeSize        uint64
	EncryptedSize     uint64
}

func volumeInfoFrom(o *GetStatusOutput) VolumeInfoB {
	pct := math.Round(o.PercentComplete)
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	return VolumeInfoB{
		VolumeStatus:      o.GetVolumeStatus(),
		ProtectionStatus:  o.GetProtectionStatus(),
		LockStatus:        o.GetLockStatus(),
		EncryptionPercent: uint8(pct),
		EncryptionFlags:   o.EncryptionFlags,
		VolumeSize:        o.VolumeSize,
		EncryptedSize:     o.EncryptedSize,
	}
}

func init() {
	// 强制确保结构体布局是 0x80（128）字节，避免 32/64 位或字段对齐导致错位
	if unsafe.Sizeof(GetStatusOutput{}) != 0x80 {
		panic(fmt.Sprintf("GetStatusOutput size mismatch: got=%d, want=128", unsafe.Sizeof(GetStatusOutput{})))
	}
}

type API struct {
	dll *windows.LazyDLL

	pOpenVolumeW                      *windows.LazyProc // FveOpenVolumeW
	pCloseVolume                      *windows.LazyProc // FveCloseVolume
	pGetStatusW                       *windows.LazyProc // FveGetStatusW
	pGetStatus                        *windows.LazyProc // FveGetStatus
	pUnlockVolume                     *windows.LazyProc // FveUnlockVolume
	pLockVolume                       *windows.LazyProc // FveLockVolume
	pConversionDecrypt                *windows.LazyProc // FveConversionDecrypt
	pConversionDecryptEx              *windows.LazyProc // FveConversionDecryptEx
	pAuthElementFromPassPhraseW       *windows.LazyProc // FveAuthElementFromPassPhraseW
	pAuthElementFromRecoveryPasswordW *windows.LazyProc // FveAuthElementFromRecoveryPasswordW
}

var (
	apiOnce sync.Once
	apiInst *API
	apiErr  error
)

func Instance() (*API, error) {
	apiOnce.Do(func() {
		apiInst, apiErr = loadAPI()
	})
	return apiInst, apiErr
}

func loadAPI() (*API, error) {
	dll := windows.NewLazySystemDLL("fveapi.dll")

	api := &API{
		dll:                               dll,
		pOpenVolumeW:                      dll.NewProc("FveOpenVolumeW"),
		pCloseVolume:                      dll.NewProc("FveCloseVolume"),
		pGetStatusW:                       dll.NewProc("FveGetStatusW"),
		pGetStatus:                        dll.NewProc("FveGetStatus"),
		pUnlockVolume:                     dll.NewProc("FveUnlockVolume"),
		pLockVolume:                       dll.NewProc("FveLockVolume"),
		pConversionDecrypt:                dll.NewProc("FveConversionDecrypt"),
		pConversionDecryptEx:              dll.NewProc("FveConversionDecryptEx"),
		pAuthElementFromPassPhraseW:       dll.NewProc("FveAuthElementFromPassPhraseW"),
		pAuthElementFromRecoveryPasswordW: dll.NewProc("FveAuthElementFromRecoveryPasswordW"),
	}

	if err := dll.Load(); err != nil {
		return nil, fmt.Errorf("无法加载 fveapi.dll: %w", err)
	}
	for name, p := range map[string]*windows.LazyProc{
		"FveOpenVolumeW":                      api.pOpenVolumeW,
		"FveCloseVolume":                      api.pCloseVolume,
		"FveGetStatusW":                       api.pGetStatusW,
		"FveGetStatus":                        api.pGetStatus,
		"FveUnlockVolume":                     api.pUnlockVolume,
		"FveLockVolume":                       api.pLockVolume,
		"FveConversionDecrypt":                api.pConversionDecrypt,
		"FveConversionDecryptEx":              api.pConversionDecryptEx,
		"FveAuthElementFromPassPhraseW":       api.pAuthElementFromPassPhraseW,
		"FveAuthElementFromRecoveryPasswordW": api.pAuthElementFromRecoveryPasswordW,
	} {
		if err := p.Find(); err != nil {
			return nil, fmt.Errorf("找不到 %s: %w", name, err)
		}
	}

	return api, nil
}

func (a *API) GetStatusByPath(volumePath string) (VolumeInfoB, error) {
	normalized, _ := NormalizeDrive(volumePath, 3)
	p, err := windows.UTF16PtrFromString(normalized)
	if err != nil {
		return VolumeInfoB{}, InvalidParameter
	}

	out := NewGetStatusOutput()
	r1, _, _ := a.pGetStatusW.Call(
		uintptr(unsafe.Pointer(p)),
		uintptr(unsafe.Pointer(&out)),
	)
	hr := uint32(r1)
	if hr != 0 {
		return VolumeInfoB{}, fromHRESULT(hr)
	}
	return volumeInfoFrom(&out), nil
}

func (a *API) OpenVolume(volumePath string) (*VolumeHandle, error) {
	return a.OpenVolumeEx(volumePath, ReadOnly)
}

func (a *API) OpenVolumeEx(volumePath string, mode AccessMode) (*VolumeHandle, error) {
	normalized, _ := NormalizeDrive(volumePath, 3)
	p, err := windows.UTF16PtrFromString(normalized)
	if err != nil {
		return nil, InvalidParameter
	}

	var h uintptr
	r1, _, _ := a.pOpenVolumeW.Call(
		uintptr(unsafe.Pointer(p)),
		uintptr(uint32(mode)),
		uintptr(unsafe.Pointer(&h)),
	)
	hr := uint32(r1)
	if hr != 0 || h == 0 {
		if hr == 0 {
			return nil, fromHRESULT(uint32(InvalidParameter))
		}
		return nil, fromHRESULT(hr)
	}

	vh := &VolumeHandle{h: h, api: a}
	return vh, nil
}

type VolumeHandle struct {
	h   uintptr
	api *API
}

func (v *VolumeHandle) AsRaw() uintptr { return v.h }

func (v *VolumeHandle) Close() error {
	if v == nil || v.h == 0 {
		return nil
	}
	h := v.h
	v.h = 0

	r1, _, _ := v.api.pCloseVolume.Call(h)
	hr := uint32(r1)
	return fromHRESULT(hr)
}

func (v *VolumeHandle) GetStatus() (VolumeInfoB, error) {
	out := NewGetStatusOutput()
	r1, _, _ := v.api.pGetStatus.Call(
		v.h,
		uintptr(unsafe.Pointer(&out)),
	)
	hr := uint32(r1)
	if hr != 0 {
		return VolumeInfoB{}, fromHRESULT(hr)
	}
	return volumeInfoFrom(&out), nil
}

func (v *VolumeHandle) UnlockWithPassword(password string) error {
	auth, err := v.api.createPassphraseAuth(password)
	if err != nil {
		return err
	}
	r1, _, _ := v.api.pUnlockVolume.Call(v.h, auth)
	return fromHRESULT(uint32(r1))
}

func (v *VolumeHandle) UnlockWithRecoveryKey(recoveryKey string) error {
	auth, err := v.api.createRecoveryAuth(recoveryKey)
	if err != nil {
		return err
	}
	r1, _, _ := v.api.pUnlockVolume.Call(v.h, auth)
	return fromHRESULT(uint32(r1))
}

func (v *VolumeHandle) Lock(dismountFirst bool) error {
	var b uintptr
	if dismountFirst {
		b = 1
	}
	r1, _, _ := v.api.pLockVolume.Call(v.h, b)
	return fromHRESULT(uint32(r1))
}

func (v *VolumeHandle) StartDecryption() error {
	r1, _, _ := v.api.pConversionDecrypt.Call(v.h)
	return fromHRESULT(uint32(r1))
}

func (v *VolumeHandle) StartDecryptionEx(flags uint32) error {
	r1, _, _ := v.api.pConversionDecryptEx.Call(v.h, uintptr(flags))
	return fromHRESULT(uint32(r1))
}

func (a *API) createPassphraseAuth(passphrase string) (uintptr, error) {
	p, err := windows.UTF16PtrFromString(passphrase)
	if err != nil {
		return 0, InvalidParameter
	}
	var auth uintptr
	r1, _, _ := a.pAuthElementFromPassPhraseW.Call(
		uintptr(unsafe.Pointer(p)),
		uintptr(unsafe.Pointer(&auth)),
	)
	hr := uint32(r1)
	if hr != 0 || auth == 0 {
		if hr == 0 {
			return 0, InvalidParameter
		}
		return 0, fromHRESULT(hr)
	}
	return auth, nil
}

func (a *API) createRecoveryAuth(recovery string) (uintptr, error) {
	p, err := windows.UTF16PtrFromString(recovery)
	if err != nil {
		return 0, InvalidParameter
	}
	var auth uintptr
	r1, _, _ := a.pAuthElementFromRecoveryPasswordW.Call(
		uintptr(unsafe.Pointer(p)),
		uintptr(unsafe.Pointer(&auth)),
	)
	hr := uint32(r1)
	if hr != 0 || auth == 0 {
		if hr == 0 {
			return 0, InvalidParameter
		}
		return 0, fromHRESULT(hr)
	}
	return auth, nil
}

// 把输入提取 48 位数字并格式化成 8 组 6 位
func FormatRecoveryKey(input string) (string, error) {
	var digits strings.Builder
	digits.Grow(48)
	for _, r := range input {
		if r >= '0' && r <= '9' {
			digits.WriteRune(r)
		}
	}
	s := digits.String()
	if len(s) != 48 {
		return "", fmt.Errorf("恢复密钥格式错误：应为48位数字，实际为%d位", len(s))
	}
	parts := []string{
		s[0:6], s[6:12], s[12:18], s[18:24],
		s[24:30], s[30:36], s[36:42], s[42:48],
	}
	return strings.Join(parts, "-"), nil
}
