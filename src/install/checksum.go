package install

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"strings"

	"ReSys/src/data"
	"ReSys/src/download"
)

func imageChecksumConfig(it data.RuleItem) *download.ChecksumConfig {
	switch {
	case strings.TrimSpace(it.Hash.Sha256) != "":
		return &download.ChecksumConfig{
			Name:        "sha256",
			New:         sha256.New,
			ExpectedHex: strings.TrimSpace(it.Hash.Sha256),
		}
	case strings.TrimSpace(it.Hash.Sha1) != "":
		return &download.ChecksumConfig{
			Name:        "sha1",
			New:         sha1.New,
			ExpectedHex: strings.TrimSpace(it.Hash.Sha1),
		}
	case strings.TrimSpace(it.Hash.MD5) != "":
		return &download.ChecksumConfig{
			Name:        "md5",
			New:         md5.New,
			ExpectedHex: strings.TrimSpace(it.Hash.MD5),
		}
	default:
		return nil
	}
}

func validateImageChecksum(path string, it data.RuleItem) error {
	cfg := imageChecksumConfig(it)
	if cfg == nil {
		return nil
	}

	got, err := computeChecksumHex(path, cfg.New)
	if err != nil {
		return fmt.Errorf("%s 校验失败: %w", strings.ToUpper(cfg.Name), err)
	}
	if !strings.EqualFold(strings.TrimSpace(got), strings.TrimSpace(cfg.ExpectedHex)) {
		return fmt.Errorf("%s 不匹配: %s", strings.ToUpper(cfg.Name), got)
	}
	return nil
}

func validateDownloadedImageFile(it data.RuleItem, imagePath string) error {
	if err := validateImageChecksum(imagePath, it); err != nil {
		return err
	}
	if imageChecksumConfig(it) != nil {
		return nil
	}
	return validateImageFile(it, imagePath)
}

func computeChecksumHex(path string, newHash func() hash.Hash) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := newHash()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
