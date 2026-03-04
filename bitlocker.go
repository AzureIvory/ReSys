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

type VolumeStatus int

const (
	NotEncrypted VolumeStatus = iota
	EncryptedUnlocked
	EncryptedLocked
	Encrypting
	Decrypting
	Unknown
)

func (s VolumeStatus) AsString() string {
	switch s {
	case NotEncrypted:
		return "NotEncrypted"
	case EncryptedUnlocked:
		return "EncryptedUnlocked"
	case EncryptedLocked:
		return "EncryptedLocked"
	case Encrypting:
		return "Encrypting"
	case Decrypting:
		return "Decrypting"
	default:
		return "Unknown"
	}
}

func (s VolumeStatus) IsEncrypted() bool {
	return s == EncryptedUnlocked || s == EncryptedLocked || s == Encrypting || s == Decrypting
}

func (s VolumeStatus) NeedsUnlock() bool { return s == EncryptedLocked }

type UnlockResult struct {
	Letter    string
	Success   bool
	Message   string
	ErrorCode *uint32
}

func unlockSuccess(letter, msg string) UnlockResult {
	return UnlockResult{Letter: letter, Success: true, Message: msg}
}
func unlockFailure(letter, msg string, code *uint32) UnlockResult {
	return UnlockResult{Letter: letter, Success: false, Message: msg, ErrorCode: code}
}

type DecryptResult struct {
	Letter    string
	Success   bool
	Message   string
	ErrorCode *uint32
}

func decryptSuccess(letter, msg string) DecryptResult {
	return DecryptResult{Letter: letter, Success: true, Message: msg}
}
func decryptFailure(letter, msg string, code *uint32) DecryptResult {
	return DecryptResult{Letter: letter, Success: false, Message: msg, ErrorCode: code}
}

type VolumeInfo struct {
	Letter               string
	Label                string
	TotalSizeMB          uint64
	Status               VolumeStatus
	ProtectionMethod     string
	EncryptionPercentage *uint8 // nil 表示未知
}

// --------------------- manager ---------------------

type BitLockerManager struct {
	useFveapi bool
}

func New() *BitLockerManager {
	use := false
	// fveapi.dll 可能不存在/不可用，或者 FindProc 失败
	if api, err := Instance(); err == nil && api != nil {
		use = true
	}
	return &BitLockerManager{useFveapi: use}
}

func (m *BitLockerManager) IsAvailable() bool {
	return m.useFveapi || isManageBdeAvailable()
}

// GetStatus：对齐 Rust：输入盘符 char
func (m *BitLockerManager) GetStatus(driveLetter byte) VolumeStatus {
	if m.useFveapi {
		return m.getStatusFveapi(driveLetter)
	}
	return m.getStatusManageBde(driveLetter)
}

func (m *BitLockerManager) GetStatusWithPercentage(driveLetter byte) (VolumeStatus, float32) {
	if m.useFveapi {
		return m.getStatusWithPercentageFveapi(driveLetter)
	}
	return m.getStatusWithPercentageManageBde(driveLetter)
}

func (m *BitLockerManager) NeedsUnlock(driveLetter byte) bool {
	return m.GetStatus(driveLetter).NeedsUnlock()
}

// drive: "C:" / "C:\"
func (m *BitLockerManager) GetRecoveryKey(drive string) (string, error) {
	letter := firstDriveLetter(drive)
	if letter == 0 {
		letter = 'C'
	}
	vol := fmt.Sprintf("%c:", letter)

	// Rust 版：无论是否 use_fveapi，都用 manage-bde -protectors -get
	return getRecoveryKeyManageBde(vol)
}

// drive: "C:" / "C:\"
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
	if st == NotEncrypted {
		return unlockFailure(vol, "该驱动器未启用 BitLocker 加密", nil)
	}
	if st == EncryptedUnlocked {
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
	if st == NotEncrypted {
		return unlockFailure(vol, "该驱动器未启用 BitLocker 加密", nil)
	}
	if st == EncryptedUnlocked {
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

// drive: "C:" / "C:\"
func (m *BitLockerManager) Decrypt(drive string) DecryptResult {
	letter := firstDriveLetter(drive)
	if letter == 0 {
		letter = 'C'
	}
	vol := fmt.Sprintf("%c:", letter)

	st := m.GetStatus(letter)
	switch st {
	case NotEncrypted:
		return decryptSuccess(vol, "分区已经是未加密状态")
	case EncryptedLocked:
		code := uint32(0x80310001)
		return decryptFailure(vol, "分区处于锁定状态，请先解锁后再进行彻底解密", &code)
	case Decrypting:
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

func (m *BitLockerManager) CanDecrypt(driveLetter byte) bool {
	return m.GetStatus(driveLetter) == EncryptedUnlocked
}

// --------------------- volume enumeration (fixed drives only) ---------------------

func (m *BitLockerManager) GetEncryptedVolumes() []VolumeInfo {
	var vols []VolumeInfo
	for c := byte('A'); c <= byte('Z'); c++ {
		if c == 'X' { // 对齐 Rust：跳过 PE 盘
			continue
		}
		if info, ok := m.probeDrive(c); ok {
			vols = append(vols, info)
		}
	}
	return vols
}

func (m *BitLockerManager) GetLockedVolumes() []VolumeInfo {
	all := m.GetEncryptedVolumes()
	out := make([]VolumeInfo, 0, len(all))
	for _, v := range all {
		if v.Status.NeedsUnlock() {
			out = append(out, v)
		}
	}
	return out
}

func (m *BitLockerManager) HasLockedVolumes() bool {
	return len(m.GetLockedVolumes()) > 0
}

// partitions: []{"C:", "D:"}
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

func (m *BitLockerManager) HasLockedPartitions(partitions []string) bool {
	return len(m.CheckPartitionsLocked(partitions)) > 0
}

func (m *BitLockerManager) GetLockedPartitions(partitions []string) []string {
	return m.CheckPartitionsLocked(partitions)
}

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
		return EncryptedLocked
	}

	// not encrypted
	if fe == NotEncrypted || fe == NotBitLockerVolume || fe == NotSupported {
		return NotEncrypted
	}

	// AccessDenied：回退 manage-bde
	if fe == AccessDenied {
		return m.getStatusManageBde(letter)
	}

	// 其他错误：回退
	return m.getStatusManageBde(letter)
}

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
		return EncryptedLocked, 0
	}
	if fe == NotEncrypted || fe == NotBitLockerVolume || fe == NotSupported {
		return NotEncrypted, 0
	}
	return m.getStatusWithPercentageManageBde(letter)
}

func volumeStatusFromFveInfo(info FveVolumeInfo) VolumeStatus {
	switch info.VolumeStatus {
	case FullyEncrypted:
		if info.LockStatus == Locked {
			return EncryptedLocked
		}
		return EncryptedUnlocked
	case EncryptionInProgress, EncryptionPaused:
		return Encrypting
	case DecryptionInProgress, DecryptionPaused:
		return Decrypting
	case FullyDecrypted:
		// Rust 对齐：FullyDecrypted 但 percent>0 => 仍视为解密中
		if info.EncryptionPercentage > 0 {
			return Decrypting
		}
		return NotEncrypted
	default:
		return Unknown
	}
}

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

func (m *BitLockerManager) decryptFveapi(letter byte) DecryptResult {
	api, err := Instance()
	if err != nil || api == nil {
		return decryptFailure(fmt.Sprintf("%c:", letter), fmt.Sprintf("FveApi 初始化失败: %v", err), nil)
	}
	vol := fmt.Sprintf("%c:", letter)

	// Rust 对齐：解密必须 ReadWrite
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

// 解锁后等待完全可访问（对齐 Rust：最多 5 分钟，500ms 轮询）
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
		case EncryptedUnlocked:
			if verifyPartitionAccessible(letter) {
				return unlockSuccess(vol, "完全解锁成功")
			}
		case EncryptedLocked:
			// 还在锁定，继续等
		case NotEncrypted:
			return unlockSuccess(vol, "分区未加密")
		default:
			// Encrypting/Decrypting/Unknown：继续轮询
		}

		time.Sleep(interval)
	}
}

func verifyPartitionAccessible(letter byte) bool {
	path := fmt.Sprintf("%c:\\", letter)
	_, err := os.ReadDir(path)
	return err == nil
}

// --------------------- internal: manage-bde path ---------------------

func (m *BitLockerManager) getStatusManageBde(letter byte) VolumeStatus {
	vol := fmt.Sprintf("%c:", letter)
	out, err := runManageBde(nil, "-status", vol)
	if err != nil {
		return Unknown
	}
	return determineVolumeStatus(out)
}

func (m *BitLockerManager) getStatusWithPercentageManageBde(letter byte) (VolumeStatus, float32) {
	vol := fmt.Sprintf("%c:", letter)
	out, err := runManageBde(nil, "-status", vol)
	if err != nil {
		return Unknown, 0
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

func unlockWithRecoveryKeyManageBde(vol, recoveryKey string) UnlockResult {
	// 文档明确支持：-recoverypassword xxxxxx-... :contentReference[oaicite:4]{index=4}
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

func unlockWithPasswordManageBde(vol, password string) UnlockResult {
	// 1) 先按你 Rust 的方式尝试：-password <pwd>（部分系统可用，但非典型）
	out, err := runManageBde(nil, "-unlock", vol, "-password", password)
	if err == nil && looksUnlocked(out) {
		return unlockSuccess(vol, "解锁成功")
	}

	// 2) 回退到文档语义：-password（提示输入），我们把密码写进 stdin :contentReference[oaicite:5]{index=5}
	out2, err2 := runManageBde([]byte(password+"\r\n"), "-unlock", vol, "-password")
	if err2 != nil {
		return unlockFailure(vol, fmt.Sprintf("执行命令失败: %v", err2), nil)
	}

	if looksUnlocked(out2) {
		return unlockSuccess(vol, "解锁成功")
	}

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

	// 常见：autounlock keys 导致 off 失败 → ClearAllKeys 再 off（这个行为在不少环境会出现）
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

func getRecoveryKeyManageBde(vol string) (string, error) {
	// Rust 对齐：manage-bde -protectors -get C: -Type RecoveryPassword
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

func determineVolumeStatus(output string) VolumeStatus {
	l := strings.ToLower(output)

	// 1) 优先检查“解密/加密进行中”
	if strings.Contains(l, "decryption in progress") ||
		strings.Contains(l, "解密进行中") ||
		strings.Contains(l, "解密正在进行") {
		return Decrypting
	}
	if strings.Contains(l, "encryption in progress") ||
		strings.Contains(l, "加密进行中") ||
		strings.Contains(l, "加密正在进行") {
		return Encrypting
	}

	// 2) fully decrypted + percent>0 => decrypting
	if strings.Contains(l, "fully decrypted") || strings.Contains(output, "完全解密") || strings.Contains(output, "已完全解密") {
		if p := extractEncryptionPercentageFloat(output); p != nil && *p > 0 {
			return Decrypting
		}
		return NotEncrypted
	}

	// 3) 未启用 BitLocker / protection off
	if strings.Contains(l, "bitlocker drive encryption is not enabled") ||
		strings.Contains(output, "未启用") ||
		strings.Contains(output, "未对此驱动器启用") ||
		strings.Contains(l, "protection off") ||
		strings.Contains(output, "保护关闭") {
		if p := extractEncryptionPercentageFloat(output); p != nil && *p > 0 {
			return Decrypting
		}
		return NotEncrypted
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
			return EncryptedLocked
		}
		return EncryptedUnlocked
	}

	// 6) 部分信息：有 conversion status 但不是 fully 的，也认为在加密域内
	if strings.Contains(l, "conversion status") || strings.Contains(output, "转换状态") {
		if strings.Contains(l, "percentage encrypted") || strings.Contains(output, "加密百分比") {
			if isLocked {
				return EncryptedLocked
			}
			return EncryptedUnlocked
		}
	}

	return Unknown
}

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
	return "密码/恢复密钥"
}

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

func extractEncryptionPercentageFloat(output string) *float64 {
	// 用于 determine_volume_status 的“fully decrypted but percent>0”检查
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

func extractRecoveryKey(output string) string {
	// 48 位恢复密码典型格式：111111-222222-...（8 组）
	re := regexp.MustCompile(`\b\d{6}(?:-\d{6}){7}\b`)
	if m := re.FindString(output); m != "" {
		return m
	}
	return ""
}

func looksUnlocked(output string) bool {
	l := strings.ToLower(output)
	return strings.Contains(l, "successfully unlocked") ||
		strings.Contains(l, "unlock was successful") ||
		strings.Contains(l, "已成功解锁") ||
		strings.Contains(l, "解锁成功")
}

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

func afterColon(s string) string {
	if i := strings.Index(s, ":"); i >= 0 {
		return strings.TrimSpace(s[i+1:])
	}
	if i := strings.Index(s, "："); i >= 0 {
		return strings.TrimSpace(s[i+1:])
	}
	return ""
}

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

func (m *BitLockerManager) probeDrive(letter byte) (VolumeInfo, bool) {
	drive := fmt.Sprintf("%c:", letter)
	root := fmt.Sprintf("%c:\\", letter)

	// 只检查固定磁盘（对齐 Rust）
	if getDriveType(root) != driveFixed {
		return VolumeInfo{}, false
	}

	st := m.GetStatus(letter)
	if !st.IsEncrypted() {
		return VolumeInfo{}, false
	}

	label, sizeMB := getVolumeInfo(drive)

	method := ""
	var pct *uint8

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

	if method == "" {
		out, err := runManageBde(nil, "-status", drive)
		if err != nil {
			method = "密码/恢复密钥"
		} else {
			method = getProtectionMethod(out)
			pct = getEncryptionPercentage(out)
		}
	}

	return VolumeInfo{
		Letter:               drive,
		Label:                label,
		TotalSizeMB:          sizeMB,
		Status:               st,
		ProtectionMethod:     method,
		EncryptionPercentage: pct,
	}, true
}

// --------------------- manage-bde execution with WOW64 Sysnative ---------------------

func isManageBdeAvailable() bool {
	_, err := runManageBde(nil, "-?")
	return err == nil
}

func runManageBde(stdin []byte, args ...string) (string, error) {
	exe := GetSystemExe("manage-bde.exe")
	cmd := exec.Command(exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000, // CREATE_NO_WINDOW
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

func utf8LooksOK(s string) bool {
	// 非严格校验：有替换符说明可能不是 UTF-8
	return !strings.ContainsRune(s, '\uFFFD')
}

// --------------------- drive info (kernel32) ---------------------

const (
	driveUnknown   = 0
	driveNoRootDir = 1
	driveRemovable = 2
	driveFixed     = 3
	driveRemote    = 4
	driveCDROM     = 5
	driveRAMDisk   = 6
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
)

func getDriveType(root string) uint32 {
	p, _ := syscall.UTF16PtrFromString(root)
	r, _, _ := procGetDriveTypeW.Call(uintptr(unsafe.Pointer(p)))
	return uint32(r)
}

func getVolumeInfo(drive string) (label string, totalMB uint64) {
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

// --------------------- convenience funcs (对齐 Rust partition_* 形式) ---------------------

func PartitionNeedsUnlock(drive string) bool {
	letter := firstDriveLetter(drive)
	if letter == 0 {
		letter = 'C'
	}
	return New().NeedsUnlock(letter)
}

func UnlockPartitionWithPassword(drive, password string) UnlockResult {
	return New().UnlockWithPassword(drive, password)
}

func UnlockPartitionWithRecoveryKey(drive, recoveryKey string) UnlockResult {
	return New().UnlockWithRecoveryKey(drive, recoveryKey)
}

func DecryptPartition(drive string) DecryptResult {
	return New().Decrypt(drive)
}

func PartitionCanDecrypt(drive string) bool {
	letter := firstDriveLetter(drive)
	if letter == 0 {
		letter = 'C'
	}
	return New().CanDecrypt(letter)
}

func GetRecoveryKeyPartition(drive string) (string, error) {
	return New().GetRecoveryKey(drive)
}
