package install

import (
	bl "ReSys/src/bitlocker"
	"ReSys/src/log"
	"ReSys/src/ui"
	"fmt"
	"strings"
)

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
	ui.UiSetStatus(ui.Tr("install.bitlocker.checkPartitions"))

	if err := prepareBitLockerVolumesForPE(manager, vols); err != nil {
		return err
	}

	log.LogWrite(0, "[handleBitLockerBeforeEnterPE] BitLocker handling completed")
	return nil
}

func prepareBitLockerVolumesForPE(manager *bl.BitLockerManager, vols []bl.BitLockerVolumeInfo) error {
	for _, vol := range vols {
		if err := prepareBitLockerVolumeForPE(manager, vol); err != nil {
			return err
		}
	}
	return nil
}

func prepareBitLockerVolumeForPE(manager *bl.BitLockerManager, vol bl.BitLockerVolumeInfo) error {
	drive := strings.TrimSpace(vol.Letter)
	if drive == "" {
		return fmt.Errorf("bitlocker volume letter is empty")
	}

	status := manager.GetStatus(firstDriveLetter(drive))
	switch status {
	case bl.VolNotEncrypted:
		return nil
	case bl.VolEncryptedLocked:
		if err := unlockBitLockerVolume(manager, vol); err != nil {
			return err
		}
	case bl.VolEncrypting:
		return fmt.Errorf("%s is still encrypting, cannot continue to PE", drive)
	case bl.VolUnknown:
		return fmt.Errorf("%s has unknown BitLocker status, cannot continue to PE", drive)
	}

	ui.UiSetStatus(ui.Trf("install.bitlocker.deleteProtectors", drive))
	log.LogWrite(0, "[prepareBitLockerVolumeForPE] deleting BitLocker protectors: drive=%s", drive)

	res := manager.DeleteAllProtectors(drive)
	if !res.Success {
		return fmt.Errorf("%s delete BitLocker protectors failed: %s", drive, fallbackBitLockerMessage(res.Message, "unknown error"))
	}

	log.LogWrite(0, "[prepareBitLockerVolumeForPE] BitLocker protectors deleted: drive=%s msg=%s", drive, fallbackBitLockerMessage(res.Message, ""))
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

	ui.UiSetStatus(ui.Trf("install.bitlocker.unlockVolume", drive))
	log.LogWrite(0, "[unlockBitLockerVolume] start unlock: drive=%s label=%s method=%s", drive, vol.Label, vol.ProtectionMethod)

	lastErr := ""
	if key, err := manager.GetRecoveryKey(drive); err == nil && strings.TrimSpace(key) != "" {
		log.LogWrite(0, "[unlockBitLockerVolume] trying automatic recovery key unlock: drive=%s", drive)
		res := manager.UnlockWithRecoveryKey(drive, key)
		if res.Success {
			log.LogWrite(0, "[unlockBitLockerVolume] automatic recovery key unlock succeeded: drive=%s", drive)
			return nil
		}
		lastErr = fallbackBitLockerMessage(res.Message, ui.Tr("install.bitlocker.autoUnlockFailed"))
		log.LogWrite(0, "[unlockBitLockerVolume] automatic recovery key unlock failed: drive=%s msg=%s", drive, lastErr)
	} else if err != nil {
		log.LogWrite(0, "[unlockBitLockerVolume] recovery key unavailable: drive=%s err=%v", drive, err)
	}

	for {
		credential, useRecoveryKey, canceled, err := ui.UiPromptBitLockerUnlock(ui.Tr("prompt.title"), buildBitLockerPromptText(vol, lastErr))
		if err != nil {
			return err
		}
		if canceled {
			return fmt.Errorf("user canceled BitLocker unlock for %s", drive)
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

		lastErr = fallbackBitLockerMessage(res.Message, ui.Tr("install.bitlocker.unlockFailed"))
		log.LogWrite(0, "[unlockBitLockerVolume] manual unlock failed: drive=%s recovery=%t msg=%s", drive, useRecoveryKey, lastErr)
	}
}

func buildBitLockerPromptText(vol bl.BitLockerVolumeInfo, lastErr string) string {
	label := strings.TrimSpace(vol.Label)
	if label == "" {
		label = "-"
	}

	msg := ui.Trf("install.bitlocker.promptText", vol.Letter, label)
	if strings.TrimSpace(lastErr) != "" {
		msg += "\n" + ui.Trf("install.bitlocker.promptLastError", strings.TrimSpace(lastErr))
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
