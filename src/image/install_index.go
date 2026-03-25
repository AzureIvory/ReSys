package image

import (
	"ReSys/src/dism"
	"strings"
)

// SelectInstallIndex picks the preferred install index from parsed image infos.
func SelectInstallIndex(infos []dism.ImageMeta) int {
	if len(infos) == 0 {
		return 1
	}

	preferred := []string{
		"旗舰版", "ultimate",
		"专业工作站", "professional workstation", "pro workstation",
		"专业教育", "professional education", "pro education",
		"专业版", "professional", "pro",
		"家庭版", "home",
		"企业版", "enterprise",
		"教育版", "education",
		"家庭高级版", "home premium",
		"家庭普通版", "home basic",
		"纯净版", "clean",
	}
	for _, key := range preferred {
		want := strings.ToLower(key)
		for _, info := range infos {
			if !info.IsOS {
				continue
			}
			text := strings.ToLower(info.Name + " " + info.Description + " " + info.Edition + " " + info.Flags)
			if strings.Contains(text, want) {
				return info.Index
			}
		}
	}
	return infos[len(infos)-1].Index
}
