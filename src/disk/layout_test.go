//go:build windows

package disk

import (
	"reflect"
	"testing"
)

func TestNormLayoutRejectsSystemDisk(t *testing.T) {
	_, err := normLayout(
		1,
		"gpt",
		260,
		[]LayoutPart{
			{SizeMB: 102400, FS: "ntfs", Label: "Windows", Letter: "W"},
		},
		1,
	)
	if err == nil {
		t.Fatal("normLayout() error = nil, want non-nil")
	}
}

func TestLayoutScriptGPT(t *testing.T) {
	req, err := normLayout(
		3,
		"guid",
		260,
		[]LayoutPart{
			{SizeMB: 102400, FS: "ntfs", Label: "Windows", Letter: "W"},
			{FS: "fat32", Label: "Data Part"},
		},
		1,
	)
	if err != nil {
		t.Fatalf("normLayout() error = %v", err)
	}

	got, err := layoutScript(req)
	if err != nil {
		t.Fatalf("layoutScript() error = %v", err)
	}

	want := []string{
		"select disk 3",
		"online disk noerr",
		"attributes disk clear readonly noerr",
		"clean",
		"convert gpt",
		"create partition efi size=260",
		`format quick fs=fat32 label=SYSTEM`,
		"create partition msr size=16",
		"create partition primary size=102400",
		`format quick fs=ntfs label=Windows`,
		"assign letter=W",
		"create partition primary",
		`format quick fs=fat32 label="Data Part"`,
		"assign",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("layoutScript() = %#v, want %#v", got, want)
	}
}

func TestLayoutScriptMBR(t *testing.T) {
	req, err := normLayout(
		2,
		"mbr",
		260,
		[]LayoutPart{
			{SizeMB: 51200, FS: "ntfs", Label: "SYS", Letter: "S"},
			{FS: "ntfs", Label: "DATA", Letter: "T"},
		},
		0,
	)
	if err != nil {
		t.Fatalf("normLayout() error = %v", err)
	}

	got, err := layoutScript(req)
	if err != nil {
		t.Fatalf("layoutScript() error = %v", err)
	}

	want := []string{
		"select disk 2",
		"online disk noerr",
		"attributes disk clear readonly noerr",
		"clean",
		"convert mbr",
		"create partition primary size=51200",
		`format quick fs=ntfs label=SYS`,
		"assign letter=S",
		"create partition primary",
		`format quick fs=ntfs label=DATA`,
		"assign letter=T",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("layoutScript() = %#v, want %#v", got, want)
	}
}

func TestNormLayoutRejectsGrowPartNotLast(t *testing.T) {
	_, err := normLayout(
		2,
		"gpt",
		260,
		[]LayoutPart{
			{FS: "ntfs", Label: "Data"},
			{SizeMB: 1024, FS: "ntfs", Label: "Tail"},
		},
		0,
	)
	if err == nil {
		t.Fatal("normLayout() error = nil, want non-nil")
	}
}
