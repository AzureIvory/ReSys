package gho

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	rslog "ReSys/src/log"
)

const (
	minHeaderSize = 64
)

var (
	ErrExecutableNotFound = errors.New("gho: executable not found")
	ErrImageNotFound      = errors.New("gho: image not found")
	ErrInvalidImage       = errors.New("gho: invalid image")
	ErrInvalidPartition   = errors.New("gho: invalid partition")
	ErrCancelled          = errors.New("gho: cancelled")
	ErrExecutionFailed    = errors.New("gho: execution failed")
)

var alternateHeaderOffsets = []int64{0x200, 0x400, 0x800, 0x1000}

type ImageHeader struct {
	FilePath      string
	FileSize      int64
	Extension     string
	Signature     [2]byte
	Version       uint32
	HeaderOffset  int64
	SignatureMode string
	Warnings      []string
}

// ValidateImage only performs basic image checks: existence, size, extension, and known Ghost signatures.
func ValidateImage(path string) error {
	_, err := InspectImage(path)
	return err
}

// InspectImage manually parses the fixed-offset GHO/GHS header without using packed struct mapping.
func InspectImage(path string) (ImageHeader, error) {
	filePath, size, ext, err := validateImagePath(path)
	if err != nil {
		return ImageHeader{
			FilePath:  filePath,
			FileSize:  size,
			Extension: ext,
		}, err
	}

	file, err := os.Open(filePath)
	if err != nil {
		rslog.LogWrite(-2, "[InspectImage]打开镜像失败: %v", err)
		return ImageHeader{
			FilePath:  filePath,
			FileSize:  size,
			Extension: ext,
		}, fmt.Errorf("%w: %s", ErrInvalidImage, err)
	}
	defer file.Close()

	head, err := readFixedBlock(file, 0, minHeaderSize)
	if err != nil {
		return ImageHeader{
			FilePath:  filePath,
			FileSize:  size,
			Extension: ext,
		}, fmt.Errorf("%w: read header: %v", ErrInvalidImage, err)
	}

	if header, ok := inspectBuffer(filePath, size, ext, 0, head, false); ok {
		return header, nil
	}

	for _, off := range alternateHeaderOffsets {
		if off+minHeaderSize > size {
			continue
		}

		block, err := readFixedBlock(file, off, minHeaderSize)
		if err != nil {
			continue
		}
		if header, ok := inspectBuffer(filePath, size, ext, off, block, true); ok {
			return header, nil
		}
	}

	return ImageHeader{
		FilePath:  filePath,
		FileSize:  size,
		Extension: ext,
	}, fmt.Errorf("%w: unsupported signature", ErrInvalidImage)
}

func validateImagePath(path string) (string, int64, string, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return "", 0, "", fmt.Errorf("%w: empty path", ErrImageNotFound)
	}

	absPath, err := filepath.Abs(trimmed)
	if err != nil {
		absPath = trimmed
	}

	info, err := os.Stat(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			return absPath, 0, strings.ToLower(filepath.Ext(absPath)), fmt.Errorf("%w: %s", ErrImageNotFound, absPath)
		}
		return absPath, 0, strings.ToLower(filepath.Ext(absPath)), fmt.Errorf("%w: %s", ErrInvalidImage, err)
	}
	if info.IsDir() {
		return absPath, 0, strings.ToLower(filepath.Ext(absPath)), fmt.Errorf("%w: %s is a directory", ErrInvalidImage, absPath)
	}

	ext := strings.ToLower(filepath.Ext(absPath))
	if ext != ".gho" && ext != ".ghs" {
		return absPath, info.Size(), ext, fmt.Errorf("%w: unsupported extension %s", ErrInvalidImage, ext)
	}
	if info.Size() < minHeaderSize {
		return absPath, info.Size(), ext, fmt.Errorf("%w: file smaller than %d bytes", ErrInvalidImage, minHeaderSize)
	}

	return absPath, info.Size(), ext, nil
}

func inspectBuffer(path string, size int64, ext string, offset int64, block []byte, alternate bool) (ImageHeader, bool) {
	signature, mode, ok, warning := detectSignature(block)
	if !ok {
		return ImageHeader{}, false
	}

	header := ImageHeader{
		FilePath:      path,
		FileSize:      size,
		Extension:     ext,
		Signature:     signature,
		Version:       binary.LittleEndian.Uint32(block[4:8]),
		HeaderOffset:  offset,
		SignatureMode: mode,
	}

	if warning != "" {
		header.Warnings = appendWarning(header.Warnings, warning)
	}
	if alternate {
		header.Warnings = appendWarning(header.Warnings, fmt.Sprintf("主头未命中，使用备用头偏移 0x%X", offset))
	}

	return header, true
}

func readFixedBlock(r io.ReaderAt, offset int64, size int) ([]byte, error) {
	if size <= 0 {
		return nil, nil
	}

	buf := make([]byte, size)
	n, err := r.ReadAt(buf, offset)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if n < size {
		return nil, io.ErrUnexpectedEOF
	}
	return buf, nil
}

func detectSignature(block []byte) ([2]byte, string, bool, string) {
	var signature [2]byte
	if len(block) < 2 {
		return signature, "", false, ""
	}

	signature[0], signature[1] = block[0], block[1]
	switch signature {
	case [2]byte{0xFE, 0xEF}:
		return signature, "feef", true, ""
	case [2]byte{0x47, 0x46}:
		return signature, "gf", true, ""
	case [2]byte{0xEB, 0x00}:
		return signature, "eb00", true, ""
	}

	if signature[0] == 0xEB || signature[0] == 0xE9 {
		return signature, "jump-heuristic", true, "签名仅由首字节跳转指令启发式识别，不能视为强格式保证"
	}

	return signature, "", false, ""
}

func appendWarning(warnings []string, warning string) []string {
	warning = strings.TrimSpace(warning)
	if warning == "" {
		return warnings
	}
	for _, existing := range warnings {
		if existing == warning {
			return warnings
		}
	}
	return append(warnings, warning)
}
