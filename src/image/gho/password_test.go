package gho

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestReadPasswordInfo(t *testing.T) {
	t.Run("no password", func(t *testing.T) {
		path := writeTestImage(t, "nopass.gho", makeTestImage(512))

		info := ReadPasswordInfo(path)
		if !info.IsValidGHO {
			t.Fatalf("IsValidGHO = false, want true, error=%s", info.Error)
		}
		if info.HasPassword {
			t.Fatalf("HasPassword = true, want false")
		}
		if info.PasswordLength != 0 {
			t.Fatalf("PasswordLength = %d, want 0", info.PasswordLength)
		}
	})

	t.Run("v1 xor", func(t *testing.T) {
		buf := makeTestImage(512)
		setPasswordLayout(t, buf, "V1", 0x01, []byte("P@ssw0rd"), 0xAA)
		path := writeTestImage(t, "v1.gho", buf)

		info := ReadPasswordInfo(path)
		if !info.HasPassword || !info.PasswordPresent {
			t.Fatalf("password not decoded: %+v", info)
		}
		if info.Password != "P@ssw0rd" {
			t.Fatalf("Password = %q, want %q", info.Password, "P@ssw0rd")
		}
		if !bytes.Equal(info.RawPassword, []byte("P@ssw0rd")) {
			t.Fatalf("RawPassword = %v, want %v", info.RawPassword, []byte("P@ssw0rd"))
		}
		if info.DecodeMethod != "xor-0xAA" {
			t.Fatalf("DecodeMethod = %q, want xor-0xAA", info.DecodeMethod)
		}
	})

	t.Run("v2 continues after v1 flag zero", func(t *testing.T) {
		buf := makeTestImage(512)
		setPasswordLayout(t, buf, "V2", 0x01, []byte("layout-v2"), 0xAA)
		path := writeTestImage(t, "v2.gho", buf)

		info := ReadPasswordInfo(path)
		if info.FormatVariant != "V2" {
			t.Fatalf("FormatVariant = %q, want V2", info.FormatVariant)
		}
		if info.Password != "layout-v2" {
			t.Fatalf("Password = %q, want layout-v2", info.Password)
		}
	})

	t.Run("v3 alternate key", func(t *testing.T) {
		buf := makeTestImage(512)
		setPasswordLayout(t, buf, "V3", 0x01, []byte("restore!"), 0x5A)
		path := writeTestImage(t, "v3.gho", buf)

		info := ReadPasswordInfo(path)
		if info.FormatVariant != "V3" {
			t.Fatalf("FormatVariant = %q, want V3", info.FormatVariant)
		}
		if info.Password != "restore!" {
			t.Fatalf("Password = %q, want restore!", info.Password)
		}
		if info.DecodeMethod != "xor-0x5A" {
			t.Fatalf("DecodeMethod = %q, want xor-0x5A", info.DecodeMethod)
		}
	})

	t.Run("alternate offset hit", func(t *testing.T) {
		buf := makeTestImage(0x500)
		alt := buf[0x400 : 0x400+minHeaderSize]
		setPasswordLayout(t, alt, "V2", 0x01, []byte("alt-block"), 0xAA)
		path := writeTestImage(t, "alternate-offset.gho", buf)

		info := ReadPasswordInfo(path)
		if info.HeaderOffset != 0x400 {
			t.Fatalf("HeaderOffset = 0x%X, want 0x400", info.HeaderOffset)
		}
		if info.Password != "alt-block" {
			t.Fatalf("Password = %q, want alt-block", info.Password)
		}
	})

	t.Run("tail ghpw hit", func(t *testing.T) {
		buf := makeTestImage(512)
		tailStart := len(buf) - 128 + 32
		copy(buf[tailStart:], []byte("GHPW"))
		raw := []byte("tail-secret")
		buf[tailStart+4] = byte(len(raw))
		for i, b := range raw {
			buf[tailStart+5+i] = b ^ 0xAA
		}
		path := writeTestImage(t, "tail.gho", buf)

		info := ReadPasswordInfo(path)
		if info.FormatVariant != "TAIL-GHPW" {
			t.Fatalf("FormatVariant = %q, want TAIL-GHPW", info.FormatVariant)
		}
		if info.Password != "tail-secret" {
			t.Fatalf("Password = %q, want tail-secret", info.Password)
		}
	})

	t.Run("invalid signature", func(t *testing.T) {
		path := writeTestImage(t, "broken.gho", make([]byte, 512))
		info := ReadPasswordInfo(path)
		if info.IsValidGHO {
			t.Fatalf("IsValidGHO = true, want false")
		}
		if info.Error == "" {
			t.Fatal("Error = empty, want message")
		}
	})

	t.Run("non ascii displayable utf8", func(t *testing.T) {
		buf := makeTestImage(512)
		setPasswordLayout(t, buf, "V1", 0x01, []byte("密码"), 0xAA)
		path := writeTestImage(t, "utf8.gho", buf)

		info := ReadPasswordInfo(path)
		if !info.PasswordPresent || !info.PasswordDisplayable {
			t.Fatalf("PasswordPresent=%v PasswordDisplayable=%v, want both true", info.PasswordPresent, info.PasswordDisplayable)
		}
		if info.Password != "密码" {
			t.Fatalf("Password = %q, want 密码", info.Password)
		}
	})

	t.Run("non displayable bytes preserved", func(t *testing.T) {
		raw := []byte{0xFF, 0x01, 0x7F}
		buf := makeTestImage(512)
		setPasswordLayout(t, buf, "V1", 0x01, raw, 0xAA)
		path := writeTestImage(t, "raw.gho", buf)

		info := ReadPasswordInfo(path)
		if !info.HasPassword {
			t.Fatalf("HasPassword = false, want true")
		}
		if info.PasswordPresent || info.PasswordDisplayable {
			t.Fatalf("PasswordPresent=%v PasswordDisplayable=%v, want both false", info.PasswordPresent, info.PasswordDisplayable)
		}
		if !bytes.Equal(info.RawPassword, raw) {
			t.Fatalf("RawPassword = %v, want %v", info.RawPassword, raw)
		}
	})
}

func ExampleReadPasswordInfo() {
	buf := makeTestImage(512)
	path := filepath.Join(os.TempDir(), "example.gho")
	_ = os.WriteFile(path, buf, 0o644)
	defer os.Remove(path)

	info := ReadPasswordInfo(path)
	fmt.Println(info.IsValidGHO, info.HasPassword, info.PasswordLength)
	// Output:
	// true false 0
}
