package utils

import "strings"

// FirstNonEmpty 返回首个非空字符串，并自动去掉两端空白。
func FirstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

// DetectTarget 从若干文本片段里识别目标系统类型。
// 当前只识别 Win7 / Win10 / Win11，识别不到时返回空字符串。
func DetectTarget(values ...string) string {
	if len(values) == 0 {
		return ""
	}

	var b strings.Builder
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(value)
	}

	text := strings.ToLower(b.String())
	switch {
	case strings.Contains(text, "windows 7"), strings.Contains(text, "win7"):
		return "win7"
	case strings.Contains(text, "windows 11"), strings.Contains(text, "win11"):
		return "win11"
	case strings.Contains(text, "windows 10"), strings.Contains(text, "win10"):
		return "win10"
	default:
		return ""
	}
}

// MissingPE 判断当前配置是否“必须进入 PE，但又没有可用的 PE 镜像”。
func MissingPE(needsPE, autoPE bool, pePath string) bool {
	return needsPE && !autoPE && strings.TrimSpace(pePath) == ""
}
