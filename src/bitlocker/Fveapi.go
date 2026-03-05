package bitlocker

import (
	"ReSys/src/utils"
	"errors"
	"fmt"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

// ReadOnly=0, ReadWrite=1.
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

// FromHRESULT 将 Windows 的 HRESULT/错误码（uint32）映射到本文件定义的 FveError。
// 目的：把底层 API 返回的数值统一归一化为枚举，便于上层逻辑判断/分支处理。
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

// Code 返回该错误对应的原始数值（uint32）。
// 方便在需要打印/上报或与系统错误码对照时使用。
func (e FveError) Code() uint32 { return uint32(e) }

// IndicatesNotEncrypted 判断该错误是否“强烈暗示：该卷并非 BitLocker 加密卷/未加密/不支持”。
// 用途：上层可用来把“不是加密卷”的情况当作一种正常分支（而非致命错误）。
func (e FveError) IndicatesNotEncrypted() bool {
	return e == NotEncrypted || e == NotBitLockerVolume || e == NotSupported
}

// IndicatesLocked 判断该错误是否“强烈暗示：卷处于锁定或需要密钥/鉴权失败”。
// 用途：上层可用来决定是否提示用户输入密码/恢复密钥等。
func (e FveError) IndicatesLocked() bool {
	return e == VolumeLocked || e == KeyRequired || e == AuthenticationFailed
}

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

// newStatusOutput 构造一个用于接收 FveGetStatus / FveGetStatusW 输出的结构体。
// 参数 version：期望的输出结构版本（通常先用 2，老系统可能只支持 1）。
// 关键点：会做强校验，确保 Go 结构体布局大小必须恰好为 0x80，否则直接 panic。
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

// getVolumeStatus 根据底层 ConversionStatus 字段，解析出卷的加解密状态（FveVolumeStatus）。
// 如果遇到未知值，按 FullyDecrypted 兜底（更保守：避免误判为加密中）。
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

// getProtectionStatus 根据底层 ProtectionStatus 字段，解析出保护状态（FveProtectionStatus）。
// 0=Off, 1=On, 其他=Unknown。
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

// getLockStatus 推导卷锁定状态（FveLockStatus）。
// 注意：这里用 protection_status=1 视为 Locked（与该项目 Rust 侧语义保持一致）。
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

// volumeInfoFrom 将底层 fveGetStatusOutput 转成更易用的上层结构 FveVolumeInfo。
// 行为：会把 PercentComplete 夹到 [0,100]，然后按 Rust 逻辑 round() 后转 uint8。
func volumeInfoFrom(out *fveGetStatusOutput) FveVolumeInfo {
	percent := out.PercentComplete
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}
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

// Instance 返回单例的 FveApi（线程安全，只初始化一次）。
// 目的：避免重复加载 DLL/重复查找导出函数，且统一管理初始化错误。
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

// newFveApi 创建并初始化 FveApi：加载 fveapi.dll 并绑定所需导出函数。
// 行为：
// 1) 先 dll.Load() 以便尽早暴露“组件缺失/系统不支持”等问题；
// 2) NewProc 获取函数入口；
// 3) Find() 校验导出确实存在（否则尽早返回错误）。
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

// toUTF16Ptr 将 Go string 转换为 Windows API 常用的 UTF-16 以 \0 结尾的指针。
// 内部使用 syscall.UTF16PtrFromString（会自动追加终止符）。
func toUTF16Ptr(s string) (*uint16, error) {
	// syscall.UTF16PtrFromString 会自动加 \0
	return syscall.UTF16PtrFromString(s)
}

// ===================== FveApi methods (match Rust semantics) =====================

// GetStatusByPath 通过卷路径（例如 "C:" / "C:\\" / "\\?\Volume{...}\\" 等）查询 BitLocker 状态。
// 行为：
// 1) NormalizeDrive 规范化路径；
// 2) 先用 version=2 调用 FveGetStatusW；
// 3) 若返回 InvalidParameter，则降级尝试 version=1（兼容 Win7/老系统）；
// 返回：解析后的 FveVolumeInfo + FveError（Success 表示成功）。
func (api *FveApi) GetStatusByPath(volumePath string) (FveVolumeInfo, FveError) {
	normalized, _ := utils.NormalizeDrive(volumePath, 3)
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

// OpenVolume 以只读方式打开卷，返回可用于后续操作的句柄（FveVolumeHandle）。
// 等价于 OpenVolumeEx(volumePath, ReadOnly)。
func (api *FveApi) OpenVolume(volumePath string) (*FveVolumeHandle, FveError) {
	return api.OpenVolumeEx(volumePath, ReadOnly)
}

// OpenVolumeEx 以指定访问模式打开卷（只读/读写）。
// 成功返回：FveVolumeHandle（包含底层句柄）；失败返回对应 FveError。
// 注意：返回的句柄需要调用 Close() 释放（类似 RAII）。
func (api *FveApi) OpenVolumeEx(volumePath string, mode FveAccessMode) (*FveVolumeHandle, FveError) {
	normalized, _ := utils.NormalizeDrive(volumePath, 3)
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

// IsEncrypted 判断卷是否处于“已加密/正在加密/暂停加密/正在解密/暂停解密”等非 FullyDecrypted 状态。
// 返回：bool 表示是否加密；FveError 表示查询是否成功。
func (api *FveApi) IsEncrypted(volumePath string) (bool, FveError) {
	info, e := api.GetStatusByPath(volumePath)
	if e != Success {
		return false, e
	}
	return info.VolumeStatus != FullyDecrypted, Success
}

// IsLocked 判断卷是否处于锁定状态。
// 返回：bool 表示是否 Locked；FveError 表示查询是否成功。
func (api *FveApi) IsLocked(volumePath string) (bool, FveError) {
	info, e := api.GetStatusByPath(volumePath)
	if e != Success {
		return false, e
	}
	return info.LockStatus == Locked, Success
}

// GetVolumeStatus 返回卷的加/解密状态（FveVolumeStatus）。
// 若查询失败，返回值会给一个默认 FullyDecrypted（同时返回错误码 e）。
func (api *FveApi) GetVolumeStatus(volumePath string) (FveVolumeStatus, FveError) {
	info, e := api.GetStatusByPath(volumePath)
	if e != Success {
		return FullyDecrypted, e
	}
	return info.VolumeStatus, Success
}

// GetProtectionStatus 返回 BitLocker 保护状态（ProtectionOn/Off/Unknown）。
// 若查询失败，返回 ProtectionUnknown 并携带错误码。
func (api *FveApi) GetProtectionStatus(volumePath string) (FveProtectionStatus, FveError) {
	info, e := api.GetStatusByPath(volumePath)
	if e != Success {
		return ProtectionUnknown, e
	}
	return info.ProtectionStatus, Success
}

// GetLockStatus 返回卷锁定状态（Locked/Unlocked）。
// 若查询失败，返回 Unlocked 并携带错误码（默认值不代表真实状态）。
func (api *FveApi) GetLockStatus(volumePath string) (FveLockStatus, FveError) {
	info, e := api.GetStatusByPath(volumePath)
	if e != Success {
		return Unlocked, e
	}
	return info.LockStatus, Success
}

// callGetStatusW 调用底层导出函数 FveGetStatusW（按路径查询）。
// 参数：path 为 UTF-16 指针；out 为接收输出结构体指针。
// 返回：HRESULT（0 表示成功）。
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

// Close 关闭/释放底层卷句柄。
// 设计：无论 Close 调用是否成功，都会把 handle 置 0，避免重复 close。
// 返回：Success 表示关闭成功（或本来就已关闭）；否则返回对应错误码。
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

// GetStatus 通过已打开的句柄查询状态（与 GetStatusByPath 类似，但走 FveGetStatus(handle)）。
// 行为：先用 version=2；若 InvalidParameter 则降级到 version=1（兼容老系统）。
// 返回：FveVolumeInfo + FveError（Success 表示成功）。
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

// UnlockWithPassword 使用用户密码解锁卷。
// 逻辑：先构造“口令鉴权元素”（createPassphraseAuth），再调用 FveUnlockVolume(handle, auth)。
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

// UnlockWithRecoveryKey 使用恢复密钥（Recovery Password）解锁卷。
// 逻辑：先构造“恢复密钥鉴权元素”（createRecoveryAuth），再调用 FveUnlockVolume(handle, auth)。
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

// Lock 锁定卷（可选：先卸载/断开挂载）。
// 参数 dismountFirst：true 表示在锁定前先尝试 dismount；false 直接锁定。
// 返回：Success 表示成功；否则返回错误码。
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

// StartDecryption 发起解密（BitLocker 转换：Decrypt）。
// 实际调用 FveConversionDecrypt(handle)。
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

// StartDecryptionEx 发起解密（扩展版本，可传 flags）。
// 实际调用 FveConversionDecryptEx(handle, flags)。
// flags 的具体含义取决于 fveapi.dll 定义（这里保持与 Rust 侧一致的透传）。
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

// AsRaw 返回底层原始句柄值（uintptr），用于与其他底层调用互操作。
// 注意：仅暴露数值，不负责生命周期；仍需通过 Close() 管理句柄释放。
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

// createPassphraseAuth 通过口令（passphrase）创建 FVE 鉴权元素（auth element）。
// 返回：auth 指针（uintptr）+ 错误码。
// 注意：这里假设底层函数会分配/返回一个指针给调用方；如果某些系统实现不同，需要调整内存策略。
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

// createRecoveryAuth 通过恢复密钥（recoveryKey）创建 FVE 鉴权元素（auth element）。
// 返回：auth 指针（uintptr）+ 错误码。
// 注意：同 createPassphraseAuth，这里以“函数返回指针”语义为前提。
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

// FormatRecoveryKey 把用户输入的恢复密钥格式化为标准形式：
// 规则：
// 1) 仅保留数字；
// 2) 必须恰好 48 位；
// 3) 每 6 位分组，用 '-' 连接（共 8 组）。
// 返回：格式化后的字符串；若位数不对则返回 error。
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

// MustInstance 获取 FveApi 单例；如果初始化失败则直接 panic。
// 用途：适合在“程序启动就必须能用 BitLocker API”的场景下简化错误处理。
func MustInstance() *FveApi {
	api, err := Instance()
	if err != nil {
		panic(err)
	}
	return api
}

// Optional sanity check
var ErrNotWindows = errors.New("windows only")
