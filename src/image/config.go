package image

import (
	"strings"

	"ReSys/src/config"
)

var loadImageAppConfig = config.LoadAppConfig

type imageScanPolicy struct {
	scanDepth          int
	minLocalImageGiB   float64
	minLocalImageBytes int64
	skipNames          []string
	skipNameSet        map[string]struct{}
}

// ImageScanConfigSnapshot 描述当前 image 配置的生效结果，供探针与回归验证使用。
type ImageScanConfigSnapshot struct {
	ScanDepth          int      `json:"scan_depth"`
	MinLocalImageGiB   float64  `json:"min_local_image_gib"`
	MinLocalImageBytes int64    `json:"min_local_image_bytes"`
	SkipNames          []string `json:"skip_names"`
}

func currentImageScanPolicy() imageScanPolicy {
	def := config.DefaultAppConfig().Image
	policy := imageScanPolicy{
		scanDepth:        def.ScanDepth,
		minLocalImageGiB: def.MinLocalImage,
		skipNames:        normalizeSkipNames(def.SkipNames),
	}

	cfg, err := loadImageAppConfig()
	if err == nil {
		if cfg.Image.ScanDepth > 0 {
			policy.scanDepth = cfg.Image.ScanDepth
		}
		if cfg.Image.MinLocalImage > 0 {
			policy.minLocalImageGiB = cfg.Image.MinLocalImage
		}
		if len(cfg.Image.SkipNames) > 0 {
			policy.skipNames = normalizeSkipNames(cfg.Image.SkipNames)
		}
	}

	policy.minLocalImageBytes = imageGiBToBytes(policy.minLocalImageGiB)
	policy.skipNameSet = make(map[string]struct{}, len(policy.skipNames))
	for _, name := range policy.skipNames {
		policy.skipNameSet[name] = struct{}{}
	}
	return policy
}

// CollectImageScanConfigSnapshot 返回当前 image 配置的生效快照。
func CollectImageScanConfigSnapshot() ImageScanConfigSnapshot {
	policy := currentImageScanPolicy()
	return ImageScanConfigSnapshot{
		ScanDepth:          policy.scanDepth,
		MinLocalImageGiB:   policy.minLocalImageGiB,
		MinLocalImageBytes: policy.minLocalImageBytes,
		SkipNames:          append([]string(nil), policy.skipNames...),
	}
}

func normalizeSkipNames(items []string) []string {
	out := make([]string, 0, len(items))
	seen := map[string]struct{}{}
	for _, item := range items {
		item = strings.ToLower(strings.TrimSpace(item))
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

func imageGiBToBytes(gib float64) int64 {
	if gib <= 0 {
		return 0
	}
	return int64(gib*1024*1024*1024 + 0.5)
}
