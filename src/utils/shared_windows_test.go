//go:build windows

package utils

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFirstNonEmpty(t *testing.T) {
	got := FirstNonEmpty("   ", "", "  abc  ", "def")
	if got != "abc" {
		t.Fatalf("FirstNonEmpty() = %q, want %q", got, "abc")
	}
}

func TestParsePartRef(t *testing.T) {
	tests := []struct {
		name    string
		ref     string
		wantDsk int
		wantPar int
		wantErr bool
	}{
		{name: "normal", ref: "3:7", wantDsk: 3, wantPar: 7},
		{name: "trimmed", ref: " 10 : 2 ", wantDsk: 10, wantPar: 2},
		{name: "empty", ref: "", wantErr: true},
		{name: "bad format", ref: "1-2", wantErr: true},
		{name: "bad disk", ref: "x:2", wantErr: true},
		{name: "bad part", ref: "1:y", wantErr: true},
	}

	for _, tt := range tests {
		diskNumber, partNumber, err := ParsePartRef(tt.ref)
		if tt.wantErr {
			if err == nil {
				t.Fatalf("%s: ParsePartRef(%q) error = nil", tt.name, tt.ref)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: ParsePartRef(%q) error = %v", tt.name, tt.ref, err)
		}
		if diskNumber != tt.wantDsk || partNumber != tt.wantPar {
			t.Fatalf(
				"%s: ParsePartRef(%q) = (%d, %d), want (%d, %d)",
				tt.name,
				tt.ref,
				diskNumber,
				partNumber,
				tt.wantDsk,
				tt.wantPar,
			)
		}
	}
}

func TestBootType(t *testing.T) {
	tests := []struct {
		name      string
		mode      string
		diskStyle string
		want      string
	}{
		{name: "manual uefi", mode: "manual_uefi", diskStyle: "MBR", want: "UEFI"},
		{name: "manual bios", mode: "manual_bios", diskStyle: "GPT", want: "BIOS"},
		{name: "auto gpt", mode: "auto", diskStyle: "GPT", want: "UEFI"},
		{name: "auto mbr", mode: "auto", diskStyle: "MBR", want: "BIOS"},
		{name: "legacy gpt", mode: "manual", diskStyle: "GPT", want: "UEFI"},
	}

	for _, tt := range tests {
		if got := BootType(tt.mode, tt.diskStyle); got != tt.want {
			t.Fatalf("%s: BootType(%q, %q) = %q, want %q", tt.name, tt.mode, tt.diskStyle, got, tt.want)
		}
	}
}

func TestNeedBootPart(t *testing.T) {
	if !NeedBootPart("manual") {
		t.Fatal("NeedBootPart(manual) = false, want true")
	}
	if !NeedBootPart("manual_uefi") {
		t.Fatal("NeedBootPart(manual_uefi) = false, want true")
	}
	if NeedBootPart("auto") {
		t.Fatal("NeedBootPart(auto) = true, want false")
	}
}

func TestMissingPE(t *testing.T) {
	if !MissingPE(true, false, "") {
		t.Fatal("MissingPE(true, false, \"\") = false, want true")
	}
	if MissingPE(true, true, "") {
		t.Fatal("MissingPE(true, true, \"\") = true, want false")
	}
	if MissingPE(false, false, "") {
		t.Fatal("MissingPE(false, false, \"\") = true, want false")
	}
	if MissingPE(true, false, `D:\boot.wim`) {
		t.Fatal("MissingPE(true, false, path) = true, want false")
	}
}

func TestDetectTarget(t *testing.T) {
	tests := []struct {
		name string
		text string
		want string
	}{
		{name: "win7", text: "Windows 7 Professional", want: "win7"},
		{name: "win10", text: "Windows 10 IoT", want: "win10"},
		{name: "win11", text: "Windows 11 Pro", want: "win11"},
		{name: "unknown", text: "Windows Server", want: ""},
	}

	for _, tt := range tests {
		if got := DetectTarget(tt.text); got != tt.want {
			t.Fatalf("%s: DetectTarget(%q) = %q, want %q", tt.name, tt.text, got, tt.want)
		}
	}
}

func TestNeedsPE(t *testing.T) {
	systemDrive := os.Getenv("SystemDrive")
	if systemDrive == "" {
		systemDrive = "C:"
	}

	if !NeedsPE(systemDrive+`\`, systemDrive) {
		t.Fatalf("NeedsPE(%q, %q) = false, want true", systemDrive+`\`, systemDrive)
	}

	otherDrive := "Z:"
	if len(systemDrive) > 0 && (systemDrive[0] == 'Z' || systemDrive[0] == 'z') {
		otherDrive = "Y:"
	}
	if NeedsPE(otherDrive+`\`, systemDrive) {
		t.Fatalf("NeedsPE(%q, %q) = true, want false", otherDrive+`\`, systemDrive)
	}
}

func TestProjectFileAndDir(t *testing.T) {
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() error = %v", err)
	}
	defer func() {
		_ = os.Chdir(oldWD)
	}()

	root := filepath.Join(t.TempDir(), "workspace")
	nested := filepath.Join(root, "a", "b", "c")
	filePath := filepath.Join(root, "rules", "ui", "default", "default.json")
	dirPath := filepath.Join(root, "rules", "core")

	if err := os.MkdirAll(filepath.Dir(filePath), 0o755); err != nil {
		t.Fatalf("MkdirAll(file) error = %v", err)
	}
	if err := os.MkdirAll(dirPath, 0o755); err != nil {
		t.Fatalf("MkdirAll(dir) error = %v", err)
	}
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("MkdirAll(nested) error = %v", err)
	}
	if err := os.WriteFile(filePath, []byte(`{}`), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.Chdir(nested); err != nil {
		t.Fatalf("Chdir() error = %v", err)
	}

	gotFile, err := ProjectFile(filepath.Join("rules", "ui", "default", "default.json"))
	if err != nil {
		t.Fatalf("ProjectFile() error = %v", err)
	}
	if gotFile != filePath {
		t.Fatalf("ProjectFile() = %q, want %q", gotFile, filePath)
	}

	gotDir, err := ProjectDir("rules", "core")
	if err != nil {
		t.Fatalf("ProjectDir() error = %v", err)
	}
	if gotDir != dirPath {
		t.Fatalf("ProjectDir() = %q, want %q", gotDir, dirPath)
	}
}
