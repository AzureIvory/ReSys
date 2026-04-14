//go:build windows

package installcfg

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseSourceWithText(t *testing.T) {
	t.Parallel()

	raw := `{
		"image_path":"D:\\images\\install.wim",
		"index":-1,
		"partition":"C:",
		"PEwim":"D:\\pe\\boot.wim",
		"boot":{
			"method":"NONE",
			"boot_partition":"AUTO"
		},
		"restart":true,
		"unattended":{
			"state":true,
			"unattended_file":"AUTO"
		},
		"backup_driver":{
			"state":true,
			"file":["oem*.inf"],
			"guid":["{88BAE032-5A81-49F0-BC3D-A4FF138216D6}"]
		},
		"format":{
			"state":true,
			"fs":"NTFS",
			"quick":true,
			"letter":"AUTO",
			"label":"Windows"
		}
	}`

	cfg, err := ParseSource(raw)
	if err != nil {
		t.Fatalf("ParseSource(text) error = %v", err)
	}
	if cfg.Boot.Method != BootSkip {
		t.Fatalf("boot method = %q, want %q", cfg.Boot.Method, BootSkip)
	}
	if cfg.Partition != "C:" {
		t.Fatalf("partition = %q, want %q", cfg.Partition, "C:")
	}
	if cfg.Format.Letter != "AUTO" {
		t.Fatalf("format.letter = %q, want %q", cfg.Format.Letter, "AUTO")
	}
}

func TestParseSourceWithAbsPath(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "manual.json")
	raw := `{
		"image_path":"D:\\images\\install.wim",
		"partition":"D:",
		"boot":{"method":"uefi","boot_partition":"AUTO"},
		"restart":false,
		"unattended":{"state":false,"unattended_file":"AUTO"},
		"backup_driver":{"state":false,"file":[],"guid":[]},
		"format":{"state":true,"fs":"FAT32","quick":false,"letter":"AUTO","label":"DATA"}
	}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	cfg, err := ParseSource(path)
	if err != nil {
		t.Fatalf("ParseSource(path) error = %v", err)
	}
	if cfg.Boot.Method != BootUEFI {
		t.Fatalf("boot method = %q, want %q", cfg.Boot.Method, BootUEFI)
	}
	if cfg.Format.FS != "FAT32" {
		t.Fatalf("format.fs = %q, want %q", cfg.Format.FS, "FAT32")
	}
}

func TestParseSourceRejectsBadFormatLetter(t *testing.T) {
	t.Parallel()

	raw := `{
		"image_path":"D:\\images\\install.wim",
		"partition":"C:",
		"boot":{"method":"auto","boot_partition":"AUTO"},
		"restart":true,
		"unattended":{"state":true,"unattended_file":"AUTO"},
		"backup_driver":{"state":false,"file":[],"guid":[]},
		"format":{"state":true,"fs":"NTFS","quick":true,"letter":"D","label":""}
	}`

	_, err := ParseSource(raw)
	if err == nil {
		t.Fatal("ParseSource() error = nil, want non-nil")
	}
}

func TestMarshalRoundTrip(t *testing.T) {
	t.Parallel()

	src := Config{
		ImagePath: "D:\\images\\install.wim",
		Index:     3,
		Partition: "C:",
		PEWIM:     "D:\\pe\\boot.wim",
		Boot: Boot{
			Method:        BootBIOS,
			BootPartition: "AUTO",
		},
		Restart: true,
		Unattended: Unattended{
			State: true,
			File:  "AUTO",
		},
		BackupDriver: BackupDriver{
			State: true,
			File:  []string{"oem12.inf"},
			GUID:  []string{"{88BAE032-5A81-49F0-BC3D-A4FF138216D6}"},
		},
		Format: Format{
			State:  true,
			FS:     "NTFS",
			Quick:  true,
			Letter: "AUTO",
			Label:  "Windows",
		},
	}

	text, err := Marshal(src)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	got, err := ParseSource(text)
	if err != nil {
		t.Fatalf("ParseSource(round trip) error = %v", err)
	}
	if got.Boot.Method != BootBIOS {
		t.Fatalf("boot method = %q, want %q", got.Boot.Method, BootBIOS)
	}
	if len(got.BackupDriver.File) != 1 || got.BackupDriver.File[0] != "oem12.inf" {
		t.Fatalf("backup_driver.file = %#v, want [oem12.inf]", got.BackupDriver.File)
	}
}
