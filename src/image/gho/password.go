package gho

import (
	"fmt"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"

	rslog "ReSys/src/log"
)

const maxPasswordBytes = 32

type PasswordInfo struct {
	HasPassword         bool
	Password            string
	PasswordPresent     bool
	PasswordLength      int
	IsValidGHO          bool
	Error               string
	FormatVariant       string
	DecodeMethod        string
	Warning             string
	Warnings            []string
	RawPassword         []byte
	PasswordDisplayable bool
	HeaderOffset        int64
	Signature           [2]byte
	Version             uint32
}

type passwordLayout struct {
	Name         string
	FlagOffset   int
	LengthOffset int
	DataOffset   int
	Keys         []byte
	KnownFlags   []byte
}

type candidateKind int

const (
	candidateKindNone candidateKind = iota
	candidateKindNoPassword
	candidateKindPassword
)

type passwordCandidate struct {
	info  PasswordInfo
	score int
	kind  candidateKind
}

var passwordLayouts = []passwordLayout{
	{Name: "V1", FlagOffset: 0x18, LengthOffset: 0x19, DataOffset: 0x1C, Keys: []byte{0xAA, 0x55}, KnownFlags: []byte{0x01, 0xFF}},
	{Name: "V2", FlagOffset: 0x08, LengthOffset: 0x09, DataOffset: 0x0C, Keys: []byte{0xAA, 0x55}},
	{Name: "V3", FlagOffset: 0x28, LengthOffset: 0x29, DataOffset: 0x2C, Keys: []byte{0xAA, 0x55, 0xFF, 0x5A, 0xA5, 0x00}},
}

// ReadPasswordInfo heuristically parses password fields in GHO/GHS using known offsets and fallback regions.
func ReadPasswordInfo(path string) PasswordInfo {
	header, err := InspectImage(path)
	if err != nil {
		rslog.LogWrite(-2, "[ReadPasswordInfo]镜像校验失败: %v", err)
		return PasswordInfo{
			IsValidGHO: false,
			Error:      err.Error(),
		}
	}

	file, err := os.Open(header.FilePath)
	if err != nil {
		rslog.LogWrite(-2, "[ReadPasswordInfo]打开镜像失败: %v", err)
		return PasswordInfo{
			IsValidGHO: false,
			Error:      fmt.Sprintf("%v", err),
		}
	}
	defer file.Close()

	offsets := make([]int64, 0, 1+len(alternateHeaderOffsets))
	offsets = append(offsets, 0)
	for _, off := range alternateHeaderOffsets {
		if off+minHeaderSize <= header.FileSize {
			offsets = append(offsets, off)
		}
	}

	var (
		bestPassword *passwordCandidate
		bestNoPass   *passwordCandidate
	)

	for _, off := range offsets {
		block, err := readFixedBlock(file, off, minHeaderSize)
		if err != nil {
			continue
		}

		candidates := scanPasswordLayouts(block, off, header)
		for i := range candidates {
			candidate := candidates[i]
			switch candidate.kind {
			case candidateKindPassword:
				if bestPassword == nil || candidate.score > bestPassword.score {
					copyCandidate := candidate
					bestPassword = &copyCandidate
				}
			case candidateKindNoPassword:
				if bestNoPass == nil || candidate.score > bestNoPass.score {
					copyCandidate := candidate
					bestNoPass = &copyCandidate
				}
			}
		}
	}

	for _, candidate := range scanTailPasswordCandidates(file, header) {
		if candidate.kind != candidateKindPassword {
			continue
		}
		if bestPassword == nil || candidate.score > bestPassword.score {
			copyCandidate := candidate
			bestPassword = &copyCandidate
		}
	}

	if bestPassword != nil {
		return finalizePasswordInfo(bestPassword.info)
	}
	if bestNoPass != nil {
		return finalizePasswordInfo(bestNoPass.info)
	}

	return finalizePasswordInfo(basePasswordInfo(header, false))
}

func scanPasswordLayouts(block []byte, blockOffset int64, header ImageHeader) []passwordCandidate {
	var candidates []passwordCandidate

	for _, layout := range passwordLayouts {
		if layout.DataOffset > len(block) || layout.LengthOffset >= len(block) || layout.FlagOffset >= len(block) {
			continue
		}

		flag := block[layout.FlagOffset]
		length := int(block[layout.LengthOffset])
		if flag == 0 {
			candidates = append(candidates, buildNoPasswordCandidate(layout, blockOffset, header, length))
			continue
		}
		if length <= 0 || length > maxPasswordBytes {
			continue
		}
		if layout.DataOffset+length > len(block) {
			continue
		}

		encrypted := append([]byte(nil), block[layout.DataOffset:layout.DataOffset+length]...)
		if allBytesZero(encrypted) {
			continue
		}

		if candidate, ok := buildPasswordCandidate(layout.Name, encrypted, length, blockOffset, header, layout.Keys, containsByte(layout.KnownFlags, flag)); ok {
			candidates = append(candidates, candidate)
		}
	}

	return candidates
}

func scanTailPasswordCandidates(file *os.File, header ImageHeader) []passwordCandidate {
	if header.FileSize < 5 {
		return nil
	}

	tailSize := header.FileSize
	if tailSize > 128 {
		tailSize = 128
	}
	offset := header.FileSize - tailSize
	block, err := readFixedBlock(file, offset, int(tailSize))
	if err != nil {
		return nil
	}

	var candidates []passwordCandidate
	for i := 0; i+5 <= len(block); i++ {
		if string(block[i:i+4]) != "GHPW" {
			continue
		}

		length := int(block[i+4])
		if length <= 0 || length > maxPasswordBytes || i+5+length > len(block) {
			continue
		}

		encrypted := append([]byte(nil), block[i+5:i+5+length]...)
		candidate, ok := buildPasswordCandidate("TAIL-GHPW", encrypted, length, offset+int64(i), header, []byte{0xAA, 0x55, 0xFF, 0x5A, 0xA5, 0x00}, true)
		if !ok {
			continue
		}
		candidate.info.Warnings = appendWarning(candidate.info.Warnings, "尾部 GHPW 标记属于启发式命中，不能视为强格式保证")
		candidate.info.Warning = strings.Join(candidate.info.Warnings, "; ")
		candidates = append(candidates, candidate)
	}

	return candidates
}

func buildPasswordCandidate(variant string, encrypted []byte, length int, blockOffset int64, header ImageHeader, keys []byte, knownFlag bool) (passwordCandidate, bool) {
	bestScore := -1
	var bestInfo PasswordInfo

	seen := make(map[byte]struct{}, len(keys))
	for _, key := range keys {
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}

		raw := xorDecodePassword(encrypted, key)
		if len(raw) == 0 {
			continue
		}

		text, displayable := renderPassword(raw)
		if !displayable && key == 0x00 {
			continue
		}
		if !displayable && !knownFlag && blockOffset != 0 && variant != "TAIL-GHPW" {
			continue
		}
		if displayable && !knownFlag && blockOffset != 0 && variant != "TAIL-GHPW" && !isStrongAlternatePassword(text) {
			continue
		}

		info := basePasswordInfo(header, true)
		info.PasswordLength = length
		info.FormatVariant = variant
		info.DecodeMethod = fmt.Sprintf("xor-0x%02X", key)
		info.HeaderOffset = blockOffset
		info.RawPassword = append([]byte(nil), raw...)
		info.PasswordDisplayable = displayable
		info.Warnings = appendWarning(info.Warnings, fmt.Sprintf("%s 密码位置通过启发式匹配，不能视为强格式保证", variant))
		if blockOffset != 0 {
			info.Warnings = appendWarning(info.Warnings, fmt.Sprintf("密码数据来自偏移 0x%X", blockOffset))
		}
		if !displayable {
			info.Warnings = appendWarning(info.Warnings, "解码结果不可直接显示，已保留原始字节")
		}
		if displayable {
			info.Password = text
			info.PasswordPresent = true
		}

		score := candidateScore(len(raw), displayable, passwordTextQuality(text), key, blockOffset, knownFlag)
		if score > bestScore {
			bestScore = score
			bestInfo = info
		}
	}

	if bestScore < 0 {
		return passwordCandidate{}, false
	}

	return passwordCandidate{
		info:  finalizePasswordInfo(bestInfo),
		score: bestScore,
		kind:  candidateKindPassword,
	}, true
}

func buildNoPasswordCandidate(layout passwordLayout, blockOffset int64, header ImageHeader, length int) passwordCandidate {
	info := basePasswordInfo(header, false)
	info.FormatVariant = layout.Name
	info.DecodeMethod = "flag=0"
	info.HeaderOffset = blockOffset
	if length > 0 {
		info.Warnings = appendWarning(info.Warnings, fmt.Sprintf("%s 的 flag=0 但长度=%d，已继续尝试其他布局", layout.Name, length))
	}

	score := 40
	if blockOffset == 0 {
		score += 10
	}
	if layout.Name == "V1" {
		score += 5
	}

	return passwordCandidate{
		info:  finalizePasswordInfo(info),
		score: score,
		kind:  candidateKindNoPassword,
	}
}

func basePasswordInfo(header ImageHeader, hasPassword bool) PasswordInfo {
	info := PasswordInfo{
		HasPassword:  hasPassword,
		IsValidGHO:   true,
		Signature:    header.Signature,
		Version:      header.Version,
		HeaderOffset: header.HeaderOffset,
		Warnings:     append([]string(nil), header.Warnings...),
	}
	if hasPassword {
		info.Warnings = appendWarning(info.Warnings, "密码结果基于偏移和异或规则启发式推断，不是格式强保证")
	}
	return info
}

func finalizePasswordInfo(info PasswordInfo) PasswordInfo {
	info.Warnings = append([]string(nil), info.Warnings...)
	info.Warning = strings.Join(info.Warnings, "; ")
	return info
}

func xorDecodePassword(encrypted []byte, key byte) []byte {
	out := make([]byte, 0, len(encrypted))
	for _, b := range encrypted {
		decoded := b ^ key
		if decoded == 0 {
			break
		}
		out = append(out, decoded)
	}
	return out
}

func renderPassword(raw []byte) (string, bool) {
	if len(raw) == 0 {
		return "", false
	}
	if utf8.Valid(raw) {
		text := string(raw)
		if isDisplayableString(text) {
			return text, true
		}
	}
	if isASCIIPrintable(raw) {
		return string(raw), true
	}
	return "", false
}

func isDisplayableString(text string) bool {
	if strings.TrimSpace(text) == "" {
		return false
	}
	for _, r := range text {
		if r == '\uFFFD' {
			return false
		}
		if !unicode.IsPrint(r) && !unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

func isASCIIPrintable(raw []byte) bool {
	for _, b := range raw {
		if b == ' ' {
			continue
		}
		if b < 0x21 || b > 0x7E {
			return false
		}
	}
	return true
}

func candidateScore(rawLen int, displayable bool, quality int, key byte, blockOffset int64, knownFlag bool) int {
	score := 60 + rawLen
	if displayable {
		score += 100 + quality
	}
	if knownFlag {
		score += 20
	}
	if key == 0xAA {
		score += 8
	}
	if blockOffset == 0 {
		score += 5
	}
	return score
}

func passwordTextQuality(text string) int {
	if text == "" {
		return 0
	}

	score := 0
	for _, r := range text {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			score += 5
		case unicode.IsSpace(r):
			score += 1
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			score -= 1
		default:
			score -= 3
		}
	}
	return score
}

func isStrongAlternatePassword(text string) bool {
	if text == "" {
		return false
	}

	runeCount := 0
	for range text {
		runeCount++
	}
	if runeCount < 3 {
		return false
	}

	return passwordTextQuality(text) >= runeCount*2
}

func containsByte(list []byte, want byte) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

func allBytesZero(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}
