package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

// --------------------- public types ---------------------

// VolumeStatus 表示卷（分区）的 BitLocker 状态（上层业务统一使用这个枚举）。
type VolumeStatus int

const (
	VolNotEncrypted      VolumeStatus = iota // 未启用 BitLocker / 未加密
	VolEncryptedUnlocked                     // 已加密且已解锁
	VolEncryptedLocked                       // 已加密但处于锁定状态（需要解锁）
	VolEncrypting                            // 正在加密（或加密暂停也可归入这类）
	VolDecrypting                            // 正在解密（或解密暂停/残留进度也可归入这类）
	VolUnknown                               // 无法识别/命令失败/输出解析失败
)

// AsString 将 VolumeStatus 转成稳定的英文字符串，便于日志/上报/对齐 Rust 输出。
func (s VolumeStatus) AsString() string {
	switch s {
	case VolNotEncrypted:
		return "NotEncrypted"
	case VolEncryptedUnlocked:
		return "EncryptedUnlocked"
	case VolEncryptedLocked:
		return "EncryptedLocked"
	case VolEncrypting:
		return "Encrypting"
	case VolDecrypting:
		return "Decrypting"
	default:
		return "Unknown"
	}
}

// IsEncrypted 判断该状态是否属于“加密域”（包括已加密/锁定/加密中/解密中）。
func (s VolumeStatus) IsEncrypted() bool {
	return s == VolEncryptedUnlocked || s == VolEncryptedLocked || s == VolEncrypting || s == VolDecrypting
}

// NeedsUnlock 判断是否需要解锁（只有 VolEncryptedLocked 才需要解锁）。
func (s VolumeStatus) NeedsUnlock() bool { return s == VolEncryptedLocked }

// UnlockResult 表示“解锁”操作的结果（用于 API 返回给上层/UI）。
type UnlockResult struct {
	Letter    string  // 盘符，如 "C:"
	Success   bool    // 是否成功
	Message   string  // 面向用户的消息
	ErrorCode *uint32 // 可选：底层错误码（HRESULT 等），nil 表示未知/未提供
}

// unlockSuccess 构造一个“解锁成功”的返回值。
func unlockSuccess(letter, msg string) UnlockResult {
	return UnlockResult{Letter: letter, Success: true, Message: msg}
}

// unlockFailure 构造一个“解锁失败”的返回值（可附带错误码）。
func unlockFailure(letter, msg string, code *uint32) UnlockResult {
	return UnlockResult{Letter: letter, Success: false, Message: msg, ErrorCode: code}
}

// DecryptResult 表示“关闭 BitLocker / 开始解密”操作的结果（用于 API 返回给上层/UI）。
type DecryptResult struct {
	Letter    string  // 盘符，如 "C:"
	Success   bool    // 是否成功
	Message   string  // 面向用户的消息
	ErrorCode *uint32 // 可选：底层错误码
}

// decryptSuccess 构造一个“解密启动/结果成功”的返回值。
func decryptSuccess(letter, msg string) DecryptResult {
	return DecryptResult{Letter: letter, Success: true, Message: msg}
}

// decryptFailure 构造一个“解密失败”的返回值（可附带错误码）。
func decryptFailure(letter, msg string, code *uint32) DecryptResult {
	return DecryptResult{Letter: letter, Success: false, Message: msg, ErrorCode: code}
}

// BitLockerVolumeInfo 表示枚举到的 BitLocker 卷信息（用于列表展示/筛选）。
type BitLockerVolumeInfo struct {
	Letter               string // 盘符，如 "C:"
	Label                string // 卷标（Volume Label）
	TotalSizeMB          uint64 // 总容量（MB）
	Status               VolumeStatus
	ProtectionMethod     string // 保护方式描述（这里主要从 manage-bde 输出推断）
	EncryptionPercentage *uint8 // 加密百分比；nil 表示未知（无法解析/无法获取）
}

// --------------------- manager ---------------------

// BitLockerManager 封装 BitLocker 操作入口。
// useFveapi=true 表示优先使用 fveapi.dll（更直接、更快）；否则回退到 manage-bde.exe 命令行。
type BitLockerManager struct {
	useFveapi bool
}

// New 创建 BitLockerManager 实例。
// 初始化时尝试加载/初始化 fveapi（如果可用则优先走 fveapi 路径）。
func New() *BitLockerManager {
	use := false
	// fveapi.dll 可能不存在/不可用，或者 FindProc 失败
	if api, err := Instance(); err == nil && api != nil {
		use = true
	}
	return &BitLockerManager{useFveapi: use}
}

// IsAvailable 判断 BitLocker 管理能力是否可用：
// - fveapi 可用，或
// - manage-bde.exe 可执行。
func (m *BitLockerManager) IsAvailable() bool {
	return m.useFveapi || isManageBdeAvailable()
}

// GetStatus 获取指定盘符的状态（对齐 Rust：输入盘符 char）。
// 优先走 fveapi，失败或不可用则走 manage-bde。
func (m *BitLockerManager) GetStatus(driveLetter byte) VolumeStatus {
	if m.useFveapi {
		return m.getStatusFveapi(driveLetter)
	}
	return m.getStatusManageBde(driveLetter)
}

// GetStatusWithPercentage 获取指定盘符状态 + 进度（百分比）。
// 若进度不可得则返回 0（同时状态仍尽量准确）。
func (m *BitLockerManager) GetStatusWithPercentage(driveLetter byte) (VolumeStatus, float32) {
	if m.useFveapi {
		return m.getStatusWithPercentageFveapi(driveLetter)
	}
	return m.getStatusWithPercentageManageBde(driveLetter)
}

// NeedsUnlock 判断指定盘符是否需要解锁（内部复用 GetStatus）。
func (m *BitLockerManager) NeedsUnlock(driveLetter byte) bool {
	return m.GetStatus(driveLetter).NeedsUnlock()
}

// GetRecoveryKey 获取指定 drive 的恢复密钥（Recovery Password）。
// drive 支持 "C:" / "C:\" 等；默认盘符为 C。
// 对齐 Rust：无论是否 use_fveapi，都用 manage-bde -protectors -get 来取恢复密钥。
func (m *BitLockerManager) GetRecoveryKey(drive string) (string, error) {
	letter := firstDriveLetter(drive)
	if letter == 0 {
		letter = 'C'
	}
	vol := fmt.Sprintf("%c:", letter)

	// Rust 版：无论是否 use_fveapi，都用 manage-bde -protectors -get
	return getRecoveryKeyManageBde(vol)
}

// UnlockWithPassword 使用密码解锁指定 drive。
// 流程：
// 1) 参数检查；
// 2) 根据状态决定是否需要解锁；
// 3) 执行解锁（fveapi 或 manage-bde）；
// 4) 若解锁命令成功，则轮询等待“完全可访问”。
func (m *BitLockerManager) UnlockWithPassword(drive, password string) UnlockResult {
	letter := firstDriveLetter(drive)
	if letter == 0 {
		letter = 'C'
	}
	vol := fmt.Sprintf("%c:", letter)

	if strings.TrimSpace(password) == "" {
		return unlockFailure(vol, "密码不能为空", nil)
	}

	st := m.GetStatus(letter)
	if st == VolNotEncrypted {
		return unlockFailure(vol, "该驱动器未启用 BitLocker 加密", nil)
	}
	if st == VolEncryptedUnlocked {
		return unlockSuccess(vol, "驱动器已经是解锁状态")
	}

	var res UnlockResult
	if m.useFveapi {
		res = m.unlockWithPasswordFveapi(letter, password)
	} else {
		res = unlockWithPasswordManageBde(vol, password)
	}

	if res.Success {
		return m.waitForUnlockComplete(letter, vol)
	}
	return res
}

// UnlockWithRecoveryKey 使用恢复密钥解锁指定 drive。
// 逻辑与 UnlockWithPassword 类似，但会先格式化 recovery key（提取数字并按 6 位分组）。
func (m *BitLockerManager) UnlockWithRecoveryKey(drive, recoveryKey string) UnlockResult {
	letter := firstDriveLetter(drive)
	if letter == 0 {
		letter = 'C'
	}
	vol := fmt.Sprintf("%c:", letter)

	key := strings.TrimSpace(recoveryKey)
	if key == "" {
		return unlockFailure(vol, "恢复密钥不能为空", nil)
	}
	// 对齐 Rust：把输入里的数字抽出来，格式化为 8 组 * 6 位
	if formatted, err := FormatRecoveryKey(key); err == nil {
		key = formatted
	}

	st := m.GetStatus(letter)
	if st == VolNotEncrypted {
		return unlockFailure(vol, "该驱动器未启用 BitLocker 加密", nil)
	}
	if st == VolEncryptedUnlocked {
		return unlockSuccess(vol, "驱动器已经是解锁状态")
	}

	var res UnlockResult
	if m.useFveapi {
		res = m.unlockWithRecoveryKeyFveapi(letter, key)
	} else {
		res = unlockWithRecoveryKeyManageBde(vol, key)
	}

	if res.Success {
		return m.waitForUnlockComplete(letter, vol)
	}
	return res
}

// Decrypt 关闭 BitLocker（开始彻底解密）。
// drive 支持 "C:" / "C:\"；默认 C。
// 行为：先根据状态做短路；优先 fveapi 发起解密，失败再回退 manage-bde -off。
func (m *BitLockerManager) Decrypt(drive string) DecryptResult {
	letter := firstDriveLetter(drive)
	if letter == 0 {
		letter = 'C'
	}
	vol := fmt.Sprintf("%c:", letter)

	st := m.GetStatus(letter)
	switch st {
	case VolNotEncrypted:
		return decryptSuccess(vol, "分区已经是未加密状态")
	case VolEncryptedLocked:
		// 这里用一个固定的错误码占位，提示“请先解锁”
		code := uint32(0x80310001)
		return decryptFailure(vol, "分区处于锁定状态，请先解锁后再进行彻底解密", &code)
	case VolDecrypting:
		return decryptSuccess(vol, "分区正在解密中，请等待完成")
	}

	if m.useFveapi {
		res := m.decryptFveapi(letter)
		if res.Success {
			return res
		}
		// fveapi 失败回退 manage-bde
	}
	return decryptManageBde(vol)
}

// CanDecrypt 判断该盘符是否允许发起解密：只有“已加密且已解锁”才允许。
func (m *BitLockerManager) CanDecrypt(driveLetter byte) bool {
	return m.GetStatus(driveLetter) == VolEncryptedUnlocked
}

// --------------------- volume enumeration (fixed drives only) ---------------------

// GetEncryptedVolumes 枚举所有盘符 A-Z（跳过 X），只返回：固定磁盘 + 处于加密域 的卷信息。
func (m *BitLockerManager) GetEncryptedVolumes() []BitLockerVolumeInfo {
	var vols []BitLockerVolumeInfo
	for c := byte('A'); c <= byte('Z'); c++ {
		if c == 'X' { // 跳过 PE 盘
			continue
		}
		if info, ok := m.probeDrive(c); ok {
			vols = append(vols, info)
		}
	}
	return vols
}

// GetLockedVolumes 在已加密卷列表里再过滤出“需要解锁”的卷。
func (m *BitLockerManager) GetLockedVolumes() []BitLockerVolumeInfo {
	all := m.GetEncryptedVolumes()
	out := make([]BitLockerVolumeInfo, 0, len(all))
	for _, v := range all {
		if v.Status.NeedsUnlock() {
			out = append(out, v)
		}
	}
	return out
}

// HasLockedVolumes 判断系统是否存在任何锁定的加密卷。
func (m *BitLockerManager) HasLockedVolumes() bool {
	return len(m.GetLockedVolumes()) > 0
}

// CheckPartitionsLocked 检查给定分区列表（如 []{"C:", "D:"}）中哪些处于锁定状态。
// 返回锁定盘符列表（如 []{"C:", "D:"}）。
func (m *BitLockerManager) CheckPartitionsLocked(partitions []string) []string {
	var locked []string
	for _, p := range partitions {
		letter := firstDriveLetter(p)
		if letter == 0 {
			continue
		}
		if m.NeedsUnlock(letter) {
			locked = append(locked, fmt.Sprintf("%c:", letter))
		}
	}
	return locked
}

// HasLockedPartitions 判断给定分区列表中是否存在锁定分区。
func (m *BitLockerManager) HasLockedPartitions(partitions []string) bool {
	return len(m.CheckPartitionsLocked(partitions)) > 0
}

// GetLockedPartitions 返回给定分区列表中锁定的分区盘符（同 CheckPartitionsLocked，提供语义化 API）。
func (m *BitLockerManager) GetLockedPartitions(partitions []string) []string {
	return m.CheckPartitionsLocked(partitions)
}

// GetEncryptedPartitions 返回给定分区列表中属于“加密域”的分区盘符列表。
func (m *BitLockerManager) GetEncryptedPartitions(partitions []string) []string {
	var enc []string
	for _, p := range partitions {
		letter := firstDriveLetter(p)
		if letter == 0 {
			continue
		}
		if m.GetStatus(letter).IsEncrypted() {
			enc = append(enc, fmt.Sprintf("%c:", letter))
		}
	}
	return enc
}

// --------------------- internal: fveapi path ---------------------

// getStatusFveapi 通过 fveapi.dll 获取盘符状态，并转换成 VolumeStatus。
// 失败时会根据错误类型做一定映射，并在必要时回退到 manage-bde 解析。
func (m *BitLockerManager) getStatusFveapi(letter byte) VolumeStatus {
	api, err := Instance()
	if err != nil || api == nil {
		return m.getStatusManageBde(letter)
	}
	vol := fmt.Sprintf("%c:", letter)

	info, fe := api.GetStatusByPath(vol)
	if fe == Success {
		return volumeStatusFromFveInfo(info)
	}

	// Rust 对齐：locked errors => EncryptedLocked
	if fe == VolumeLocked || fe == KeyRequired {
		return VolEncryptedLocked
	}

	// not encrypted
	if fe == NotEncrypted || fe == NotBitLockerVolume || fe == NotSupported {
		return VolNotEncrypted
	}

	// AccessDenied：回退 manage-bde（有时权限/策略导致 fveapi 查询失败）
	if fe == AccessDenied {
		return m.getStatusManageBde(letter)
	}

	// 其他错误：回退
	return m.getStatusManageBde(letter)
}

// getStatusWithPercentageFveapi 通过 fveapi 获取状态 + 加密进度百分比。
// 如果失败/不支持，则回退到 manage-bde 解析。
func (m *BitLockerManager) getStatusWithPercentageFveapi(letter byte) (VolumeStatus, float32) {
	api, err := Instance()
	if err != nil || api == nil {
		return m.getStatusWithPercentageManageBde(letter)
	}
	vol := fmt.Sprintf("%c:", letter)

	info, fe := api.GetStatusByPath(vol)
	if fe == Success {
		st := volumeStatusFromFveInfo(info)
		return st, float32(info.EncryptionPercentage)
	}
	// locked -> EncryptedLocked + percent unknown
	if fe == VolumeLocked || fe == KeyRequired {
		return VolEncryptedLocked, 0
	}
	if fe == NotEncrypted || fe == NotBitLockerVolume || fe == NotSupported {
		return VolNotEncrypted, 0
	}
	return m.getStatusWithPercentageManageBde(letter)
}

// volumeStatusFromFveInfo 将 fveapi 的 FveVolumeInfo 映射到本文件的 VolumeStatus。
// 注意：这里有“Rust 对齐”的特殊逻辑：FullyDecrypted 但 percent>0 时仍判为解密中。
func volumeStatusFromFveInfo(info FveVolumeInfo) VolumeStatus {
	switch info.VolumeStatus {
	case FullyEncrypted:
		if info.LockStatus == Locked {
			return VolEncryptedLocked
		}
		return VolEncryptedUnlocked
	case EncryptionInProgress, EncryptionPaused:
		return VolEncrypting
	case DecryptionInProgress, DecryptionPaused:
		return VolDecrypting
	case FullyDecrypted:
		// Rust 对齐：FullyDecrypted 但 percent>0 => 仍视为解密中
		if info.EncryptionPercentage > 0 {
			return VolDecrypting
		}
		return VolNotEncrypted
	default:
		return VolUnknown
	}
}

// unlockWithPasswordFveapi 走 fveapi 方式用密码解锁卷。
// 流程：OpenVolume -> UnlockWithPassword -> 根据错误码转友好提示。
func (m *BitLockerManager) unlockWithPasswordFveapi(letter byte, password string) UnlockResult {
	api, err := Instance()
	if err != nil || api == nil {
		return unlockFailure(fmt.Sprintf("%c:", letter), fmt.Sprintf("FveApi 初始化失败: %v", err), nil)
	}
	vol := fmt.Sprintf("%c:", letter)

	h, fe := api.OpenVolume(vol)
	if fe != Success {
		code := fe.Code()
		return unlockFailure(vol, fmt.Sprintf("打开卷失败: 0x%08X", code), &code)
	}
	defer h.Close()

	fe = h.UnlockWithPassword(password)
	if fe == Success {
		return unlockSuccess(vol, "解锁成功")
	}
	code := fe.Code()
	switch fe {
	case BadPassword:
		return unlockFailure(vol, "密码错误", &code)
	case VolumeUnlocked:
		return unlockSuccess(vol, "驱动器已经是解锁状态")
	default:
		return unlockFailure(vol, fmt.Sprintf("解锁失败: 0x%08X", code), &code)
	}
}

// unlockWithRecoveryKeyFveapi 走 fveapi 方式用恢复密钥解锁卷。
func (m *BitLockerManager) unlockWithRecoveryKeyFveapi(letter byte, recoveryKey string) UnlockResult {
	api, err := Instance()
	if err != nil || api == nil {
		return unlockFailure(fmt.Sprintf("%c:", letter), fmt.Sprintf("FveApi 初始化失败: %v", err), nil)
	}
	vol := fmt.Sprintf("%c:", letter)

	h, fe := api.OpenVolume(vol)
	if fe != Success {
		code := fe.Code()
		return unlockFailure(vol, fmt.Sprintf("打开卷失败: 0x%08X", code), &code)
	}
	defer h.Close()

	fe = h.UnlockWithRecoveryKey(recoveryKey)
	if fe == Success {
		return unlockSuccess(vol, "解锁成功")
	}
	code := fe.Code()
	switch fe {
	case BadRecoveryPassword:
		return unlockFailure(vol, "恢复密钥错误", &code)
	case VolumeUnlocked:
		return unlockSuccess(vol, "驱动器已经是解锁状态")
	default:
		return unlockFailure(vol, fmt.Sprintf("解锁失败: 0x%08X", code), &code)
	}
}

// decryptFveapi 走 fveapi 发起解密（关闭 BitLocker）。
// 注意：解密必须以 ReadWrite 打开卷句柄。
func (m *BitLockerManager) decryptFveapi(letter byte) DecryptResult {
	api, err := Instance()
	if err != nil || api == nil {
		return decryptFailure(fmt.Sprintf("%c:", letter), fmt.Sprintf("FveApi 初始化失败: %v", err), nil)
	}
	vol := fmt.Sprintf("%c:", letter)

	// 解密必须 ReadWrite
	h, fe := api.OpenVolumeEx(vol, ReadWrite)
	if fe != Success {
		code := fe.Code()
		return decryptFailure(vol, fmt.Sprintf("打开卷失败: 0x%08X", code), &code)
	}
	defer h.Close()

	fe = h.StartDecryption()
	if fe == Success {
		return decryptSuccess(vol, "已开始解密，此过程可能需要较长时间，请勿中断")
	}
	if fe == NotEncrypted {
		return decryptSuccess(vol, "分区已经是未加密状态")
	}
	code := fe.Code()
	return decryptFailure(vol, fmt.Sprintf("启动解密失败: 0x%08X", code), &code)
}

// waitForUnlockComplete 解锁后等待卷完全可访问（对齐 Rust：最多 5 分钟，500ms 轮询）。
// 说明：有些情况下解锁命令成功后，系统还需要一点时间来挂载/刷新权限，所以这里做轮询确认。
func (m *BitLockerManager) waitForUnlockComplete(letter byte, vol string) UnlockResult {
	timeout := 5 * time.Minute
	interval := 500 * time.Millisecond
	start := time.Now()

	for {
		if time.Since(start) > timeout {
			return unlockFailure(vol, "解锁超时，分区可能仍在后台处理中", nil)
		}

		st := m.GetStatus(letter)
		switch st {
		case VolEncryptedUnlocked:
			if verifyPartitionAccessible(letter) {
				return unlockSuccess(vol, "完全解锁成功")
			}
		case VolEncryptedLocked:
			// 还在锁定，继续等
		case VolNotEncrypted:
			return unlockSuccess(vol, "分区未加密")
		default:
			// Encrypting/Decrypting/Unknown：继续轮询
		}

		time.Sleep(interval)
	}
}

// verifyPartitionAccessible 通过读取根目录来验证分区是否已可访问。
// 返回 true 表示可正常 ReadDir，false 表示可能仍未完全可用或权限受限。
func verifyPartitionAccessible(letter byte) bool {
	path := fmt.Sprintf("%c:\\", letter)
	_, err := os.ReadDir(path)
	return err == nil
}

// --------------------- internal: manage-bde path ---------------------

// getStatusManageBde 使用 manage-bde -status 获取输出并解析成 VolumeStatus。
func (m *BitLockerManager) getStatusManageBde(letter byte) VolumeStatus {
	vol := fmt.Sprintf("%c:", letter)
	out, err := runManageBde(nil, "-status", vol)
	if err != nil {
		return VolUnknown
	}
	return determineVolumeStatus(out)
}

// getStatusWithPercentageManageBde 使用 manage-bde -status 获取输出，解析状态与进度。
// 若未能解析进度，则尝试通过关键字做兜底（fully encrypted=>100，fully decrypted=>0）。
func (m *BitLockerManager) getStatusWithPercentageManageBde(letter byte) (VolumeStatus, float32) {
	vol := fmt.Sprintf("%c:", letter)
	out, err := runManageBde(nil, "-status", vol)
	if err != nil {
		return VolUnknown, 0
	}
	st := determineVolumeStatus(out)
	if p := getEncryptionPercentage(out); p != nil {
		return st, float32(*p)
	}
	// 兜底
	if strings.Contains(strings.ToLower(out), "fully encrypted") || strings.Contains(out, "已完全加密") {
		return st, 100
	}
	if strings.Contains(strings.ToLower(out), "fully decrypted") || strings.Contains(out, "已完全解密") {
		return st, 0
	}
	return st, 0
}

// unlockWithRecoveryKeyManageBde 使用 manage-bde 通过恢复密钥解锁卷。
// 规则：调用 -unlock <vol> -recoverypassword <key>，然后根据输出关键词判断成功/失败原因。
func unlockWithRecoveryKeyManageBde(vol, recoveryKey string) UnlockResult {
	out, err := runManageBde(nil, "-unlock", vol, "-recoverypassword", recoveryKey)
	if err != nil {
		return unlockFailure(vol, fmt.Sprintf("执行命令失败: %v", err), nil)
	}

	l := strings.ToLower(out)
	if strings.Contains(l, "successfully unlocked") ||
		strings.Contains(l, "unlock was successful") ||
		strings.Contains(l, "已成功解锁") ||
		strings.Contains(l, "解锁成功") {
		return unlockSuccess(vol, "解锁成功")
	}

	// 常见恢复密钥错误提示
	if strings.Contains(l, "recovery password") && (strings.Contains(l, "failed") || strings.Contains(l, "incorrect")) ||
		strings.Contains(l, "恢复密码") && strings.Contains(l, "失败") {
		return unlockFailure(vol, "恢复密钥错误", nil)
	}

	msg := extractErrorMessage(out)
	if msg == "" {
		msg = "解锁失败"
	}
	return unlockFailure(vol, msg, nil)
}

// unlockWithPasswordManageBde 使用 manage-bde 通过密码解锁卷。
// 实现：
// 1) 先尝试 -unlock <vol> -password <pwd>（部分系统可用）；
// 2) 若不行，则用 -password（让工具提示输入），并把密码写入 stdin（更兼容）。
func unlockWithPasswordManageBde(vol, password string) UnlockResult {
	// 1) -password <pwd>（部分系统可用，但非典型）
	out, err := runManageBde(nil, "-unlock", vol, "-password", password)
	if err == nil && looksUnlocked(out) {
		return unlockSuccess(vol, "解锁成功")
	}

	// 2) 回退：-password（提示输入），我们把密码写进 stdin
	out2, err2 := runManageBde([]byte(password+"\r\n"), "-unlock", vol, "-password")
	if err2 != nil {
		return unlockFailure(vol, fmt.Sprintf("执行命令失败: %v", err2), nil)
	}

	if looksUnlocked(out2) {
		return unlockSuccess(vol, "解锁成功")
	}

	// 常见密码错误提示
	l := strings.ToLower(out2)
	if strings.Contains(l, "password failed") ||
		strings.Contains(l, "incorrect password") ||
		strings.Contains(l, "密码失败") ||
		strings.Contains(l, "密码不正确") ||
		strings.Contains(l, "密码错误") {
		return unlockFailure(vol, "密码错误", nil)
	}

	msg := extractErrorMessage(out2)
	if msg == "" {
		msg = "解锁失败"
	}
	return unlockFailure(vol, msg, nil)
}

// decryptManageBde 使用 manage-bde -off 关闭 BitLocker 并启动解密。
// 额外处理：如果因为 autounlock keys 导致 -off 失败，则先清理 autounlock keys 再重试。
func decryptManageBde(vol string) DecryptResult {
	out, err := runManageBde(nil, "-off", vol)
	if err != nil {
		return decryptFailure(vol, fmt.Sprintf("执行命令失败: %v", err), nil)
	}
	l := strings.ToLower(out)

	// 成功启动解密
	if strings.Contains(l, "decryption is now in progress") ||
		strings.Contains(l, "started decryption") ||
		strings.Contains(l, "正在进行解密") ||
		strings.Contains(l, "已开始解密") ||
		strings.Contains(l, "解密正在进行") {
		return decryptSuccess(vol, "已开始解密，此过程可能需要较长时间，请勿中断")
	}

	// 已经是未加密
	if strings.Contains(l, "already decrypted") ||
		strings.Contains(l, "not enabled") ||
		strings.Contains(l, "已解密") ||
		strings.Contains(l, "未启用") ||
		strings.Contains(l, "未对此驱动器启用") {
		return decryptSuccess(vol, "分区已经是未加密状态")
	}

	// 常见：autounlock keys 导致 off 失败 → ClearAllKeys 再 off
	if strings.Contains(l, "autounlock") ||
		strings.Contains(out, "自动解锁") ||
		strings.Contains(out, "ClearAllKeys") ||
		strings.Contains(out, "ClearAllAutoUnlockKeys") {
		_, _ = runManageBde(nil, "-autounlock", "-ClearAllKeys", vol)
		out2, err2 := runManageBde(nil, "-off", vol)
		if err2 == nil {
			l2 := strings.ToLower(out2)
			if strings.Contains(l2, "decryption is now in progress") ||
				strings.Contains(l2, "started decryption") ||
				strings.Contains(l2, "正在进行解密") ||
				strings.Contains(l2, "已开始解密") {
				return decryptSuccess(vol, "已开始解密，此过程可能需要较长时间，请勿中断")
			}
		}
	}

	msg := extractErrorMessage(out)
	if msg == "" {
		msg = "启动解密失败"
	}
	return decryptFailure(vol, msg, nil)
}

// getRecoveryKeyManageBde 通过 manage-bde -protectors -get 获取恢复密钥。
// 解析输出中典型的 48 位（8 组 * 6 位）格式。
func getRecoveryKeyManageBde(vol string) (string, error) {
	// manage-bde -protectors -get C: -Type RecoveryPassword
	out, err := runManageBde(nil, "-protectors", "-get", vol, "-Type", "RecoveryPassword")
	if err != nil {
		return "", fmt.Errorf("执行命令失败: %w", err)
	}
	if key := extractRecoveryKey(out); key != "" {
		return key, nil
	}
	return "", errors.New("未找到恢复密钥")
}

// --------------------- parsing manage-bde output ---------------------

// determineVolumeStatus 解析 manage-bde -status 输出，推断 VolumeStatus。
// 策略：
// 1) 优先识别“加密/解密进行中”；
// 2) 再识别 fully decrypted / protection off / not enabled；
// 3) 再识别 locked 与 encrypted；
// 4) 最后兜底 Unknown。
func determineVolumeStatus(output string) VolumeStatus {
	l := strings.ToLower(output)

	// 1) 优先检查“解密/加密进行中”
	if strings.Contains(l, "decryption in progress") ||
		strings.Contains(l, "解密进行中") ||
		strings.Contains(l, "解密正在进行") {
		return VolDecrypting
	}
	if strings.Contains(l, "encryption in progress") ||
		strings.Contains(l, "加密进行中") ||
		strings.Contains(l, "加密正在进行") {
		return VolEncrypting
	}

	// 2) fully decrypted + percent>0 => decrypting（对齐 Rust 的“残留进度仍视作解密中”）
	if strings.Contains(l, "fully decrypted") || strings.Contains(output, "完全解密") || strings.Contains(output, "已完全解密") {
		if p := extractEncryptionPercentageFloat(output); p != nil && *p > 0 {
			return VolDecrypting
		}
		return VolNotEncrypted
	}

	// 3) 未启用 BitLocker / protection off
	if strings.Contains(l, "bitlocker drive encryption is not enabled") ||
		strings.Contains(output, "未启用") ||
		strings.Contains(output, "未对此驱动器启用") ||
		strings.Contains(l, "protection off") ||
		strings.Contains(output, "保护关闭") {
		if p := extractEncryptionPercentageFloat(output); p != nil && *p > 0 {
			return VolDecrypting
		}
		return VolNotEncrypted
	}

	// 4) 锁定？
	isLocked := (strings.Contains(l, "lock status") && strings.Contains(l, "locked")) ||
		(strings.Contains(output, "锁定状态") && strings.Contains(output, "已锁定"))

	// 5) 已加密？
	isEncrypted := strings.Contains(l, "fully encrypted") ||
		strings.Contains(output, "已完全加密") ||
		strings.Contains(l, "protection on") ||
		strings.Contains(output, "保护开启") ||
		(strings.Contains(l, "encryption method") && !strings.Contains(l, "none")) ||
		(strings.Contains(output, "加密方法") && !strings.Contains(output, "无"))

	if isEncrypted {
		if isLocked {
			return VolEncryptedLocked
		}
		return VolEncryptedUnlocked
	}

	// 6) 部分信息：有 conversion status 但不是 fully 的，也认为在加密域内
	if strings.Contains(l, "conversion status") || strings.Contains(output, "转换状态") {
		if strings.Contains(l, "percentage encrypted") || strings.Contains(output, "加密百分比") {
			if isLocked {
				return VolEncryptedLocked
			}
			return VolEncryptedUnlocked
		}
	}

	return VolUnknown
}

// getProtectionMethod 从 manage-bde 输出里粗略提取“保护方式/加密方式”的描述。
// 找到包含关键字的行后，取冒号后的值作为方法描述。
func getProtectionMethod(output string) string {
	for _, line := range strings.Split(output, "\n") {
		t := strings.TrimSpace(line)
		low := strings.ToLower(t)
		if strings.Contains(low, "key protector") ||
			strings.Contains(t, "密钥保护程序") ||
			strings.Contains(t, "加密方法") ||
			strings.Contains(low, "encryption method") {
			if v := afterColon(t); v != "" && v != "None" && v != "无" {
				return v
			}
		}
	}
	// 若无法精确解析，给一个默认值（实际环境里通常就是“密码/恢复密钥”组合）
	return "密码/恢复密钥"
}

// getEncryptionPercentage 从 manage-bde 输出解析“加密百分比/解密百分比”，返回四舍五入后的 uint8 指针。
// 若无法解析则返回 nil，并提供 fully encrypted/decrypted 的兜底。
func getEncryptionPercentage(output string) *uint8 {
	for _, line := range strings.Split(output, "\n") {
		t := strings.TrimSpace(line)
		low := strings.ToLower(t)
		if strings.Contains(low, "percentage encrypted") ||
			strings.Contains(t, "加密百分比") ||
			strings.Contains(low, "percentage decrypted") ||
			strings.Contains(t, "解密百分比") {
			v := afterColon(t)
			if v == "" {
				continue
			}
			num := takeNumberPrefix(v)
			if num == "" {
				continue
			}
			f, err := strconv.ParseFloat(num, 64)
			if err != nil {
				continue
			}
			if f < 0 {
				f = 0
			}
			if f > 100 {
				f = 100
			}
			p := uint8(f + 0.5)
			return &p
		}
	}

	// 关键词兜底：完全加密/完全解密
	l := strings.ToLower(output)
	if strings.Contains(l, "fully encrypted") || strings.Contains(output, "已完全加密") {
		p := uint8(100)
		return &p
	}
	if strings.Contains(l, "fully decrypted") || strings.Contains(output, "已完全解密") {
		p := uint8(0)
		return &p
	}

	return nil
}

// extractEncryptionPercentageFloat 解析“已加密百分比”，返回 float64 指针。
// 用途：determineVolumeStatus 里判断“fully decrypted 但 percent>0”的特殊情况。
func extractEncryptionPercentageFloat(output string) *float64 {
	for _, line := range strings.Split(output, "\n") {
		t := strings.TrimSpace(line)
		low := strings.ToLower(t)
		if strings.Contains(low, "percentage encrypted") || strings.Contains(t, "已加密百分比") || strings.Contains(t, "加密百分比") {
			v := afterColon(t)
			num := takeNumberPrefix(v)
			if num == "" {
				continue
			}
			f, err := strconv.ParseFloat(num, 64)
			if err != nil {
				continue
			}
			return &f
		}
	}
	return nil
}

// extractRecoveryKey 从输出中提取 48 位恢复密钥（典型格式：8 组，每组 6 位数字，以 '-' 分隔）。
func extractRecoveryKey(output string) string {
	re := regexp.MustCompile(`\b\d{6}(?:-\d{6}){7}\b`)
	if m := re.FindString(output); m != "" {
		return m
	}
	return ""
}

// looksUnlocked 粗略判断输出是否表达“解锁成功”。
func looksUnlocked(output string) bool {
	l := strings.ToLower(output)
	return strings.Contains(l, "successfully unlocked") ||
		strings.Contains(l, "unlock was successful") ||
		strings.Contains(l, "已成功解锁") ||
		strings.Contains(l, "解锁成功")
}

// extractErrorMessage 从输出中抽取更有用的错误行（包含 "error"/"错误" 的行）。
func extractErrorMessage(output string) string {
	for _, line := range strings.Split(output, "\n") {
		t := strings.TrimSpace(line)
		low := strings.ToLower(t)
		if strings.Contains(low, "error") || strings.Contains(t, "错误") {
			if len([]rune(t)) > 10 {
				return t
			}
		}
	}
	return ""
}

// afterColon 获取冒号（英文 ':' 或中文 '：'）后的内容并去掉空白。
func afterColon(s string) string {
	if i := strings.Index(s, ":"); i >= 0 {
		return strings.TrimSpace(s[i+1:])
	}
	if i := strings.Index(s, "："); i >= 0 {
		return strings.TrimSpace(s[i+1:])
	}
	return ""
}

// takeNumberPrefix 从字符串起始处截取数字/小数点前缀（用于解析百分比等字段）。
func takeNumberPrefix(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= '0' && r <= '9') || r == '.' {
			b.WriteRune(r)
		} else {
			break
		}
	}
	return b.String()
}

// --------------------- probe fixed drive ---------------------

// probeDrive 探测某盘符是否为固定磁盘 + 是否处于加密域，并收集卷信息。
// 返回 (info, true) 表示该盘符满足条件并已填充信息；(zero, false) 表示跳过。
func (m *BitLockerManager) probeDrive(letter byte) (BitLockerVolumeInfo, bool) {
	drive := fmt.Sprintf("%c:", letter)
	root := fmt.Sprintf("%c:\\", letter)

	// 只检查固定磁盘（对齐 Rust）
	if getDriveType(root) != driveFixed {
		return BitLockerVolumeInfo{}, false
	}

	st := m.GetStatus(letter)
	if !st.IsEncrypted() {
		return BitLockerVolumeInfo{}, false
	}

	label, sizeMB := getBitLockerVolumeInfo(drive)

	method := ""
	var pct *uint8

	// 优先 fveapi 取 protection/进度（如果可用且查询成功）
	if m.useFveapi {
		api, err := Instance()
		if err == nil && api != nil {
			if info, fe := api.GetStatusByPath(drive); fe == Success {
				switch info.ProtectionStatus {
				case ProtectionOn:
					method = "密码/恢复密钥"
				case ProtectionOff:
					method = "保护已暂停"
				default:
					method = "未知"
				}

				pp := uint8(0)
				switch info.VolumeStatus {
				case FullyEncrypted:
					pp = 100
					pct = &pp
				case FullyDecrypted:
					pp = 0
					pct = &pp
				default:
					if info.EncryptionPercentage > 0 && info.EncryptionPercentage <= 100 {
						pp = info.EncryptionPercentage
						pct = &pp
					}
				}
			} else {
				// 回退 manage-bde
				method = ""
			}
		}
	}

	// 若 fveapi 未给出 method，则用 manage-bde -status 解析
	if method == "" {
		out, err := runManageBde(nil, "-status", drive)
		if err != nil {
			method = "密码/恢复密钥"
		} else {
			method = getProtectionMethod(out)
			pct = getEncryptionPercentage(out)
		}
	}

	return BitLockerVolumeInfo{
		Letter:               drive,
		Label:                label,
		TotalSizeMB:          sizeMB,
		Status:               st,
		ProtectionMethod:     method,
		EncryptionPercentage: pct,
	}, true
}

// --------------------- manage-bde execution with WOW64 Sysnative ---------------------

// isManageBdeAvailable 判断 manage-bde.exe 是否可用：尝试执行 "-?" 并看是否成功。
func isManageBdeAvailable() bool {
	_, err := runManageBde(nil, "-?")
	return err == nil
}

// runManageBde 执行 manage-bde.exe，并返回解码后的输出。
// 支持：
// - stdin 传入（用于需要交互输入密码的场景）
// - CombinedOutput 同时捕获 stdout/stderr
// - 自动根据输出编码（UTF-16LE/UTF-8/GBK）进行解码
func runManageBde(stdin []byte, args ...string) (string, error) {
	exe := GetSystemExe("manage-bde.exe")
	cmd := exec.Command(exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000, // CREATE_NO_WINDOW：不弹窗
	}
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	decoded := decodeWindowsOutput(out)
	if err != nil {
		// 把输出带上更好排错
		return decoded, fmt.Errorf("%w: %s", err, strings.TrimSpace(decoded))
	}
	return decoded, nil
}

// decodeWindowsOutput 尝试把 Windows 命令输出 bytes 解码为可读字符串。
// 识别顺序：
// 1) UTF-16LE BOM；
// 2) 统计 0x00 判断是否像 UTF-16LE；
// 3) 若看起来是 UTF-8，则直接 string；
// 4) 否则尝试 GBK（中文系统常见）；
// 5) 最后兜底直接 string(b)。
func decodeWindowsOutput(b []byte) string {
	if len(b) == 0 {
		return ""
	}

	// UTF-16LE BOM
	if len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE {
		return decodeUTF16LE(b[2:])
	}

	// 含大量 0x00，猜 UTF-16LE
	zeroCount := 0
	for i := 1; i < len(b); i += 2 {
		if b[i] == 0x00 {
			zeroCount++
		}
	}
	if zeroCount > len(b)/6 {
		return decodeUTF16LE(b)
	}

	// UTF-8
	if s := string(b); utf8LooksOK(s) {
		return s
	}

	// GBK (中文系统常见)
	reader := transform.NewReader(bytes.NewReader(b), simplifiedchinese.GBK.NewDecoder())
	decoded, err := io.ReadAll(reader)
	if err == nil {
		return string(decoded)
	}

	// 最后兜底
	return string(b)
}

// decodeUTF16LE 将 UTF-16LE 的字节序列解码为 Go string。
// 处理：如果长度是奇数，截掉最后一个字节避免越界。
func decodeUTF16LE(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u16 := make([]uint16, 0, len(b)/2)
	for i := 0; i < len(b); i += 2 {
		u16 = append(u16, uint16(b[i])|uint16(b[i+1])<<8)
	}
	return string(utf16.Decode(u16))
}

// utf8LooksOK 非严格判断字符串是否像 UTF-8：
// 如果包含替换符 \uFFFD，通常意味着原 bytes 并非合法 UTF-8。
func utf8LooksOK(s string) bool {
	return !strings.ContainsRune(s, '\uFFFD')
}

// --------------------- drive info (kernel32) ---------------------

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll") // kernel32.dll：Windows 基础 API
)

// getDriveType 调用 GetDriveTypeW 获取驱动器类型（固定磁盘/可移动/网络等）。
// root 形如 "C:\\"。
func getDriveType(root string) uint32 {
	p, _ := syscall.UTF16PtrFromString(root)
	r, _, _ := procGetDriveTypeW.Call(uintptr(unsafe.Pointer(p)))
	return uint32(r)
}

// getBitLockerVolumeInfo 读取卷标与总容量（MB）。
// drive 形如 "C:"，内部会拼成 root "C:\" 调用 GetVolumeInformationW / GetDiskFreeSpaceExW。
func getBitLockerVolumeInfo(drive string) (label string, totalMB uint64) {
	// drive: "C:"
	root := drive + `\`
	rootPtr, _ := syscall.UTF16PtrFromString(root)

	// volume label
	volName := make([]uint16, 256)
	var (
		serial     uint32
		maxCompLen uint32
		fsFlags    uint32
		fsName     = make([]uint16, 256)
	)

	_, _, _ = procGetVolumeInformationW.Call(
		uintptr(unsafe.Pointer(rootPtr)),
		uintptr(unsafe.Pointer(&volName[0])),
		uintptr(len(volName)),
		uintptr(unsafe.Pointer(&serial)),
		uintptr(unsafe.Pointer(&maxCompLen)),
		uintptr(unsafe.Pointer(&fsFlags)),
		uintptr(unsafe.Pointer(&fsName[0])),
		uintptr(len(fsName)),
	)

	label = syscall.UTF16ToString(volName)

	// total size
	var (
		freeBytesAvail uint64
		totalBytes     uint64
		totalFreeBytes uint64
	)
	ok, _, _ := procGetDiskFreeSpaceExW.Call(
		uintptr(unsafe.Pointer(rootPtr)),
		uintptr(unsafe.Pointer(&freeBytesAvail)),
		uintptr(unsafe.Pointer(&totalBytes)),
		uintptr(unsafe.Pointer(&totalFreeBytes)),
	)
	if ok == 0 {
		return label, 0
	}
	totalMB = totalBytes / (1024 * 1024)
	return label, totalMB
}

// --------------------- helpers ---------------------

// firstDriveLetter 从输入字符串提取盘符字母（大写）。
// 支持：
// - "C:" / "c:\"
// - "\\.\C:" / "\\?\C:" 等前缀形式
// 返回 0 表示无法识别。
func firstDriveLetter(s string) byte {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	// 支持 "C:" / "c:\" / "\\.\C:" / "\\?\C:"
	if strings.HasPrefix(s, `\\.\`) || strings.HasPrefix(s, `\\?\`) {
		if len(s) >= 6 && s[5] == ':' {
			return byte(strings.ToUpper(string(s[4]))[0])
		}
	}
	if len(s) >= 2 && s[1] == ':' {
		return byte(strings.ToUpper(string(s[0]))[0])
	}
	return 0
}

// --------------------- convenience funcs  ---------------------

// PartitionNeedsUnlock 便捷函数：判断指定分区（如 "C:"）是否需要解锁。
func PartitionNeedsUnlock(drive string) bool {
	letter := firstDriveLetter(drive)
	if letter == 0 {
		letter = 'C'
	}
	return New().NeedsUnlock(letter)
}

// UnlockPartitionWithPassword 便捷函数：用密码解锁指定分区。
func UnlockPartitionWithPassword(drive, password string) UnlockResult {
	return New().UnlockWithPassword(drive, password)
}

// UnlockPartitionWithRecoveryKey 便捷函数：用恢复密钥解锁指定分区。
func UnlockPartitionWithRecoveryKey(drive, recoveryKey string) UnlockResult {
	return New().UnlockWithRecoveryKey(drive, recoveryKey)
}

// DecryptPartition 便捷函数：关闭 BitLocker 并启动解密。
func DecryptPartition(drive string) DecryptResult {
	return New().Decrypt(drive)
}

// PartitionCanDecrypt 便捷函数：判断指定分区是否允许启动解密（需已解锁）。
func PartitionCanDecrypt(drive string) bool {
	letter := firstDriveLetter(drive)
	if letter == 0 {
		letter = 'C'
	}
	return New().CanDecrypt(letter)
}

// GetRecoveryKeyPartition 便捷函数：获取指定分区的恢复密钥。
func GetRecoveryKeyPartition(drive string) (string, error) {
	return New().GetRecoveryKey(drive)
}
