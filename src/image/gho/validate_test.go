package gho

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func makeTestImage(size int) []byte {
	if size < minHeaderSize {
		size = minHeaderSize
	}

	buf := make([]byte, size)
	buf[0] = 0xFE
	buf[1] = 0xEF
	binary.LittleEndian.PutUint32(buf[4:8], 0x01020304)
	return buf
}

func writeTestImage(t *testing.T, name string, data []byte) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write test image: %v", err)
	}
	return path
}

func setPasswordLayout(t *testing.T, buf []byte, layoutName string, flag byte, raw []byte, key byte) {
	t.Helper()

	var layout *passwordLayout
	for i := range passwordLayouts {
		if passwordLayouts[i].Name == layoutName {
			layout = &passwordLayouts[i]
			break
		}
	}
	if layout == nil {
		t.Fatalf("layout %s not found", layoutName)
	}
	if layout.DataOffset+len(raw) > len(buf) {
		t.Fatalf("layout %s exceeds test buffer", layoutName)
	}

	buf[layout.FlagOffset] = flag
	buf[layout.LengthOffset] = byte(len(raw))
	for i, b := range raw {
		buf[layout.DataOffset+i] = b ^ key
	}
}

func TestValidateImage(t *testing.T) {
	t.Run("valid header", func(t *testing.T) {
		path := writeTestImage(t, "valid.gho", makeTestImage(512))
		if err := ValidateImage(path); err != nil {
			t.Fatalf("ValidateImage() error = %v", err)
		}
	})

	t.Run("alternate header", func(t *testing.T) {
		buf := make([]byte, 0x400+minHeaderSize)
		copy(buf[0x200:], makeTestImage(minHeaderSize))

		path := writeTestImage(t, "alternate.ghs", buf)
		header, err := InspectImage(path)
		if err != nil {
			t.Fatalf("InspectImage() error = %v", err)
		}
		if header.HeaderOffset != 0x200 {
			t.Fatalf("HeaderOffset = 0x%X, want 0x200", header.HeaderOffset)
		}
	})

	t.Run("invalid signature", func(t *testing.T) {
		buf := make([]byte, 512)
		path := writeTestImage(t, "invalid.gho", buf)

		err := ValidateImage(path)
		if err == nil {
			t.Fatal("ValidateImage() error = nil, want invalid image error")
		}
		if !errors.Is(err, ErrInvalidImage) {
			t.Fatalf("ValidateImage() error = %v, want ErrInvalidImage", err)
		}
	})
}
