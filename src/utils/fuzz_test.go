package utils

import (
	"fmt"
	"testing"
)

func FuzzParsePartRef(f *testing.F) {
	seeds := []string{
		"1:1",
		"12:34",
		" 5 : 9 ",
		"bad",
		"",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, ref string) {
		diskNumber, partNumber, err := ParsePartRef(ref)
		if err != nil {
			return
		}
		if diskNumber < 0 || partNumber < 0 {
			t.Fatalf("ParsePartRef returned negative values: %d:%d", diskNumber, partNumber)
		}

		roundTrip := fmt.Sprintf("%d:%d", diskNumber, partNumber)
		diskNumber2, partNumber2, err := ParsePartRef(roundTrip)
		if err != nil {
			t.Fatalf("round-trip parse failed for %q: %v", roundTrip, err)
		}
		if diskNumber != diskNumber2 || partNumber != partNumber2 {
			t.Fatalf("round-trip mismatch: %d:%d != %d:%d", diskNumber, partNumber, diskNumber2, partNumber2)
		}
	})
}

func FuzzDetectTarget(f *testing.F) {
	seeds := []string{
		"Windows 7 Professional",
		"Windows 10 Pro",
		"Windows 11 Home",
		"Windows Server",
		"",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, text string) {
		target := DetectTarget(text)
		switch target {
		case "", "win7", "win10", "win11":
			return
		default:
			t.Fatalf("DetectTarget returned unexpected value: %q", target)
		}
	})
}
