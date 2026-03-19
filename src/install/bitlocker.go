package install

import (
	bl "ReSys/src/bitlocker"
	"ReSys/src/log"
	"ReSys/src/ui"
	"fmt"
	"strings"
	"time"
)

const bitLockerPollInterval = 2 * time.Second

func handleBitLockerBeforeEnterPE(ctx *InstallContext) error {
	if ctx == nil || ctx.Plan == nil {
		return fmt.Errorf("install context is nil")
	}
	if !ctx.Plan.Flags.NeedBitLockerHandling {
		return nil
	}

	manager := bl.New()
	if !manager.IsAvailable() {
		log.LogWrite(0, "[handleBitLockerBeforeEnterPE] BitLocker manager unavailable, skip")
		return nil
	}

	vols := manager.GetEncryptedVolumes()
	if len(vols) == 0 {
		log.LogWrite(0, "[handleBitLockerBeforeEnterPE] no encrypted fixed volumes found")
		return nil
	}

	log.LogWrite(0, "[handleBitLockerBeforeEnterPE] encrypted volumes=%s", formatBitLockerVolumes(vols))
	ui.UiSetStatus("正在检查 BitLocker 分区...")

	if err := unlockBitLockerVolumes(manager, vols); err != nil {
		return err
	}
	if err := decryptBitLockerVolumes(manager); err != nil {
		return err
	}

	log.LogWrite(0, "[handleBitLockerBeforeEnterPE] BitLocker handling completed")
	return nil
}

func unlockBitLockerVolumes(manager *bl.BitLockerManager, vols []bl.BitLockerVolumeInfo) error {
	for _, vol := range vols {
		if !vol.Status.NeedsUnlock() {
			continue
		}
		if err := unlockBitLockerVolume(manager, vol); err != nil {
			return err
		}
	}
	return nil
}

func unlockBitLockerVolume(manager *bl.BitLockerManager, vol bl.BitLockerVolumeInfo) error {
	drive := strings.TrimSpace(vol.Letter)
	if drive == "" {
		return fmt.Errorf("bitlocker volume letter is empty")
	}

	ui.UiSetStatus(fmt.Sprintf("正在解锁 BitLocker 分区 %s...", drive))
	log.LogWrite(0, "[unlockBitLockerVolume] start unlock: drive=%s label=%s method=%s", drive, vol.Label, vol.ProtectionMethod)

	lastErr := ""
	if key, err := manager.GetRecoveryKey(drive); err == nil && strings.TrimSpace(key) != "" {
		log.LogWrite(0, "[unlockBitLockerVolume] trying automatic recovery key unlock: drive=%s", drive)
		res := manager.UnlockWithRecoveryKey(drive, key)
		if res.Success {
			log.LogWrite(0, "[unlockBitLockerVolume] automatic recovery key unlock succeeded: drive=%s", drive)
			return nil
		}
		lastErr = fallbackBitLockerMessage(res.Message, "自动解锁失败")
		log.LogWrite(0, "[unlockBitLockerVolume] automatic recovery key unlock failed: drive=%s msg=%s", drive, lastErr)
	} else if err != nil {
		log.LogWrite(0, "[unlockBitLockerVolume] recovery key unavailable: drive=%s err=%v", drive, err)
	}

	for {
		credential, useRecoveryKey, canceled, err := ui.UiPromptBitLockerUnlock("BitLocker 解锁", buildBitLockerPromptText(vol, lastErr))
		if err != nil {
			return err
		}
		if canceled {
			return fmt.Errorf("用户取消了 %s 的 BitLocker 解锁", drive)
		}

		var res bl.UnlockResult
		if useRecoveryKey {
			res = manager.UnlockWithRecoveryKey(drive, credential)
		} else {
			res = manager.UnlockWithPassword(drive, credential)
		}
		if res.Success {
			log.LogWrite(0, "[unlockBitLockerVolume] manual unlock succeeded: drive=%s recovery=%t", drive, useRecoveryKey)
			return nil
		}

		lastErr = fallbackBitLockerMessage(res.Message, "解锁失败")
		log.LogWrite(0, "[unlockBitLockerVolume] manual unlock failed: drive=%s recovery=%t msg=%s", drive, useRecoveryKey, lastErr)
	}
}

func decryptBitLockerVolumes(manager *bl.BitLockerManager) error {
	vols := manager.GetEncryptedVolumes()
	waiting := make([]string, 0, len(vols))
	seen := make(map[string]struct{}, len(vols))

	for _, vol := range vols {
		drive := strings.TrimSpace(vol.Letter)
		if drive == "" {
			continue
		}

		switch vol.Status {
		case bl.VolEncryptedUnlocked:
			ui.UiSetStatus(fmt.Sprintf("正在启动 BitLocker 解密 %s...", drive))
			res := manager.Decrypt(drive)
			if !res.Success {
				status := manager.GetStatus(firstDriveLetter(drive))
				if status != bl.VolDecrypting && status != bl.VolNotEncrypted {
					return fmt.Errorf("%s 启动解密失败: %s", drive, fallbackBitLockerMessage(res.Message, "未知错误"))
				}
			}
			if _, ok := seen[drive]; !ok {
				waiting = append(waiting, drive)
				seen[drive] = struct{}{}
			}
		case bl.VolDecrypting:
			if _, ok := seen[drive]; !ok {
				waiting = append(waiting, drive)
				seen[drive] = struct{}{}
			}
		case bl.VolEncryptedLocked:
			return fmt.Errorf("%s 仍处于锁定状态，无法继续进入 PE", drive)
		case bl.VolEncrypting:
			return fmt.Errorf("%s 当前正在加密，无法继续进入 PE", drive)
		case bl.VolUnknown:
			return fmt.Errorf("%s 的 BitLocker 状态未知，无法继续进入 PE", drive)
		}
	}

	if len(waiting) == 0 {
		log.LogWrite(0, "[decryptBitLockerVolumes] no decryption wait needed")
		return nil
	}

	log.LogWrite(0, "[decryptBitLockerVolumes] waiting volumes=%s", strings.Join(waiting, ","))
	return waitForBitLockerDecryption(manager, waiting)
}

func waitForBitLockerDecryption(manager *bl.BitLockerManager, drives []string) error {
	for {
		allDone := true
		waiting := make([]string, 0, len(drives))
		maxEncryptedPct := float32(0)

		for _, drive := range drives {
			letter := firstDriveLetter(drive)
			if letter == 0 {
				continue
			}

			status, encryptedPct := manager.GetStatusWithPercentage(letter)
			switch status {
			case bl.VolNotEncrypted:
				continue
			case bl.VolEncryptedUnlocked, bl.VolDecrypting:
				allDone = false
				decryptedPct := clampFloat32(100-encryptedPct, 0, 100)
				waiting = append(waiting, fmt.Sprintf("%s %.1f%%", drive, decryptedPct))
				if encryptedPct > maxEncryptedPct {
					maxEncryptedPct = encryptedPct
				}
			case bl.VolEncryptedLocked:
				return fmt.Errorf("%s 在等待解密期间重新锁定，无法继续进入 PE", drive)
			case bl.VolEncrypting:
				return fmt.Errorf("%s 当前正在加密，无法继续进入 PE", drive)
			default:
				return fmt.Errorf("%s 的 BitLocker 状态未知，无法继续进入 PE", drive)
			}
		}

		if allDone {
			ui.UiSetStatus("BitLocker 解密完成，继续准备 PE...")
			return nil
		}

		progress := clampFloat32(100-maxEncryptedPct, 0, 100)
		ui.UiSetStatus(fmt.Sprintf("正在解密 BitLocker 分区... %s", strings.Join(waiting, " / ")))
		ui.UiSetProgress(MapPct(50, 10, float64(progress)))
		time.Sleep(bitLockerPollInterval)
	}
}

func buildBitLockerPromptText(vol bl.BitLockerVolumeInfo, lastErr string) string {
	label := strings.TrimSpace(vol.Label)
	if label == "" {
		label = "-"
	}

	msg := fmt.Sprintf(
		"检测到 BitLocker 锁定分区 %s\n卷标: %s\n进入 PE 前必须先完成解锁。\n如果输入的是密码，请点击“用密码解锁”；如果输入的是 48 位恢复密钥，请点击“用恢复密钥”。\n请先点击输入框再输入。",
		vol.Letter,
		label,
	)
	if strings.TrimSpace(lastErr) != "" {
		msg += "\n上次失败: " + strings.TrimSpace(lastErr)
	}
	return msg
}

func formatBitLockerVolumes(vols []bl.BitLockerVolumeInfo) string {
	if len(vols) == 0 {
		return ""
	}

	items := make([]string, 0, len(vols))
	for _, vol := range vols {
		label := strings.TrimSpace(vol.Label)
		if label == "" {
			label = "-"
		}
		items = append(items, fmt.Sprintf("%s[%s]=%s", vol.Letter, label, vol.Status.AsString()))
	}
	return strings.Join(items, ", ")
}

func fallbackBitLockerMessage(msg, fallback string) string {
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return fallback
	}
	return msg
}

func clampFloat32(v, min, max float32) float32 {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

func firstDriveLetter(s string) byte {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
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
