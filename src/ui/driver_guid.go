//go:build windows

package ui

import (
	driversvc "ReSys/src/driver"
	"fmt"
	"strings"
)

type driverGUID struct {
	Key          string
	GUID         string
	FallbackName string
}

const monitorDriverGUIDValue = "4D36E96E-E325-11CE-BFC1-08002BE10318"

var driverGUIDCata = []driverGUID{
	{Key: "audio_processing_object", GUID: "5989FCE8-9CD0-467D-8A6A-5419E31529D4", FallbackName: "Audio Processing Object (APO)"},
	{Key: "battery", GUID: "72631E54-78A4-11D0-BCF7-00AA00B7B32A", FallbackName: "Battery Device"},
	{Key: "biometric", GUID: "53D29EF7-377C-4D14-864B-EB3A85769359", FallbackName: "Biometric Device"},
	{Key: "bluetooth", GUID: "E0CBF06C-CD8B-4647-BB8A-263B43F0F974", FallbackName: "Bluetooth Device"},
	{Key: "camera", GUID: "CA3E7AB9-B4C3-4AE6-8251-579EF933890F", FallbackName: "Camera Device"},
	{Key: "cdrom_drive", GUID: "4D36E965-E325-11CE-BFC1-08002BE10318", FallbackName: "CD-ROM Drive"},
	{Key: "disk_drive", GUID: "4D36E967-E325-11CE-BFC1-08002BE10318", FallbackName: "Disk Drive"},
	{Key: "display_adapter", GUID: "4D36E968-E325-11CE-BFC1-08002BE10318", FallbackName: "Display Adapter"},
	{Key: "extension_inf", GUID: "E2F84CE7-8EFA-411C-AA69-97454CA4CB57", FallbackName: "Extension INF"},
	{Key: "floppy_controller", GUID: "4D36E969-E325-11CE-BFC1-08002BE10318", FallbackName: "Floppy Disk Controller"},
	{Key: "floppy_drive", GUID: "4D36E980-E325-11CE-BFC1-08002BE10318", FallbackName: "Floppy Disk Drive"},
	{Key: "hard_disk_controller", GUID: "4D36E96A-E325-11CE-BFC1-08002BE10318", FallbackName: "Hard Disk Controller"},
	{Key: "hid", GUID: "745A17A0-74D3-11D0-B6FE-00A0C90F57DA", FallbackName: "Human Interface Device (HID)"},
	{Key: "ieee_1284_4", GUID: "48721B56-6795-11D2-B1A8-0080C72E74A2", FallbackName: "IEEE 1284.4 Device"},
	{Key: "ieee_1284_4_print", GUID: "49CE6AC8-6F86-11D2-B1E5-0080C72E74A2", FallbackName: "IEEE 1284.4 Print Function"},
	{Key: "ieee_1394_61883", GUID: "7EBEFBC0-3200-11D2-B4C2-00A0C9697D07", FallbackName: "IEEE 1394 61883 Device"},
	{Key: "ieee_1394_avc", GUID: "C06FF265-AE09-48F0-812C-16753D7CBA83", FallbackName: "IEEE 1394 AVC Device"},
	{Key: "ieee_1394_sbp2", GUID: "D48179BE-EC20-11D1-B6B8-00C04FA372A7", FallbackName: "IEEE 1394 SBP2 Device"},
	{Key: "ieee_1394_controller", GUID: "6BDD1FC1-810F-11D0-BEC7-08002BE2092F", FallbackName: "IEEE 1394 Host Controller"},
	{Key: "image", GUID: "6BDD1FC6-810F-11D0-BEC7-08002BE2092F", FallbackName: "Image Device"},
	{Key: "irda", GUID: "6BDD1FC5-810F-11D0-BEC7-08002BE2092F", FallbackName: "IrDA Device"},
	{Key: "keyboard", GUID: "4D36E96B-E325-11CE-BFC1-08002BE10318", FallbackName: "Keyboard"},
	{Key: "medium_changer", GUID: "CE5939AE-EBDE-11D0-B181-0000F8753EC4", FallbackName: "Medium Changer"},
	{Key: "memory_technology_driver", GUID: "4D36E970-E325-11CE-BFC1-08002BE10318", FallbackName: "Memory Technology Driver"},
	{Key: "modem", GUID: "4D36E96D-E325-11CE-BFC1-08002BE10318", FallbackName: "Modem"},
	{Key: "monitor", GUID: "4D36E96E-E325-11CE-BFC1-08002BE10318", FallbackName: "Monitor"},
	{Key: "mouse", GUID: "4D36E96F-E325-11CE-BFC1-08002BE10318", FallbackName: "Mouse"},
	{Key: "multifunction", GUID: "4D36E971-E325-11CE-BFC1-08002BE10318", FallbackName: "Multifunction Device"},
	{Key: "multimedia", GUID: "4D36E96C-E325-11CE-BFC1-08002BE10318", FallbackName: "Multimedia"},
	{Key: "multiport_serial", GUID: "50906CB8-BA12-11D1-BF5D-0000F805F530", FallbackName: "Multiport Serial Adapter"},
	{Key: "network_adapter", GUID: "4D36E972-E325-11CE-BFC1-08002BE10318", FallbackName: "Network Adapter"},
	{Key: "network_client", GUID: "4D36E973-E325-11CE-BFC1-08002BE10318", FallbackName: "Network Client"},
	{Key: "network_service", GUID: "4D36E974-E325-11CE-BFC1-08002BE10318", FallbackName: "Network Service"},
	{Key: "network_transport", GUID: "4D36E975-E325-11CE-BFC1-08002BE10318", FallbackName: "Network Transport"},
	{Key: "pci_ssl_accelerator", GUID: "268C95A1-EDFE-11D3-95C3-0010DC4050A5", FallbackName: "PCI SSL Accelerator"},
	{Key: "pcmcia_adapter", GUID: "4D36E977-E325-11CE-BFC1-08002BE10318", FallbackName: "PCMCIA Adapter"},
	{Key: "ports", GUID: "4D36E978-E325-11CE-BFC1-08002BE10318", FallbackName: "Ports (COM and LPT)"},
	{Key: "printer", GUID: "4D36E979-E325-11CE-BFC1-08002BE10318", FallbackName: "Printer"},
	{Key: "pnp_printers", GUID: "4658EE7E-F050-11D1-B6BD-00C04FA372A7", FallbackName: "Printer Bus-Specific Driver"},
	{Key: "processor", GUID: "50127DC3-0F36-415E-A6CC-4CB3BE910B65", FallbackName: "Processor"},
	{Key: "scsi_adapter", GUID: "4D36E97B-E325-11CE-BFC1-08002BE10318", FallbackName: "SCSI/RAID/NVMe Controller"},
	{Key: "security", GUID: "D94EE5D8-D189-4994-83D2-F68D7D41B0E6", FallbackName: "Security Device"},
	{Key: "sensor", GUID: "5175D334-C371-4806-B3BA-71FD53C9258D", FallbackName: "Sensor"},
	{Key: "smart_card_reader", GUID: "50DD5230-BA8A-11D1-BF5D-0000F805F530", FallbackName: "Smart Card Reader"},
	{Key: "software_component", GUID: "5C4C3332-344D-483C-8739-259E934C9CC8", FallbackName: "Software Component"},
	{Key: "nvme_disk", GUID: "75416E63-5912-4DFA-AE8F-3EFACCAFFB14", FallbackName: "Storage Disk"},
	{Key: "storage_volume", GUID: "71A27CDD-812A-11D0-BEC7-08002BE2092F", FallbackName: "Storage Volume"},
	{Key: "system", GUID: "4D36E97D-E325-11CE-BFC1-08002BE10318", FallbackName: "System Device"},
	{Key: "tape_drive", GUID: "6D807884-7D21-11CF-801C-08002BE10318", FallbackName: "Tape Drive"},
	{Key: "ucm", GUID: "E6F1AA1C-7F3B-4473-B2E8-C97D8AC71D53", FallbackName: "USB Connector Manager"},
	{Key: "usb_device", GUID: "88BAE032-5A81-49F0-BC3D-A4FF138216D6", FallbackName: "USB Device"},
	{Key: "wceusbs", GUID: "25DBCE51-6C8F-4A72-8A6D-B54C2B4FC835", FallbackName: "Windows CE USB ActiveSync Device"},
	{Key: "wpd", GUID: "EEC5AD98-8080-425F-922A-DABF3DE3F69A", FallbackName: "Windows Portable Device (WPD)"},
}

func loadDriverGUIDOptions() ([]manualDriverGUIDOption, error) {
	if len(driverGUIDCata) == 0 {
		return nil, fmt.Errorf("driver GUID catalog is empty")
	}

	items := make([]manualDriverGUIDOption, 0, len(driverGUIDCata))
	seen := make(map[string]struct{}, len(driverGUIDCata))
	for _, entry := range driverGUIDCata {
		guid, err := driversvc.NormalizeClassGUID(entry.GUID)
		if err != nil {
			return nil, fmt.Errorf("invalid driver GUID catalog entry %q: %s", entry.Key, entry.GUID)
		}
		if _, exists := seen[guid]; exists {
			return nil, fmt.Errorf("duplicate driver GUID catalog entry: %s", guid)
		}

		seen[guid] = struct{}{}
		items = append(items, manualDriverGUIDOption{
			Name:    localizedDriverGUIDLabel(entry),
			GUID:    guid,
			CheckID: driverGUIDCheckID(guid),
			Enabled: !strings.EqualFold(strings.TrimSpace(entry.GUID), monitorDriverGUIDValue),
		})
	}

	return items, nil
}

func localizedDriverGUIDLabel(entry driverGUID) string {
	labelKey := "manual.driver.guidOptions." + entry.Key
	label := strings.TrimSpace(T(labelKey))
	if label == "" || label == labelKey {
		return entry.FallbackName
	}
	return label
}
