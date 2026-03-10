package main

import (
	"ReSys/src/disk"
	D "ReSys/src/dism"
	"ReSys/src/file"
	"ReSys/src/image"
	"ReSys/src/log"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var Dism = D.NewDism()

// 安装 WIM 镜像到指定卷。
// wimPath:wim路径
// index:要安装的索引
// targetVol:目标卷，如"C:"、"C:\"
func ApplyWimImage(wimPath string, index int, targetVol string) error {
	p := strings.TrimSpace(wimPath)
	if len(p) < 4 || !strings.EqualFold(strings.ToLower(filepath.Ext(p)), ".wim") {
		return fmt.Errorf("不是WIM镜像: %s", wimPath)
	}

	return Dism.ApplyImageCmd(wimPath, targetVol, uint32(index), nil)
}

// 安装ESD镜像到指定卷
func ApplyEsdImage(esdPath string, index int, targetVol string) error {
	return Dism.ApplyImageCmd(esdPath, targetVol, uint32(index), nil)
}

// 安装ISO镜像到指定卷
func ApplyISOImage(isoPath string, index int, targetVol string) error {
	isoRoot, err := MountISO(isoPath, 30*time.Second)
	if err != nil {
		parts := disk.Findpart()
		if len(parts) == 0 {
			log.LogWrite(0, "[ApplyISOImage]ApplyISOImage 未找到可用分区用于解包ISO")
			return fmt.Errorf("未找到可用分区用于解包ISO！")
		}
		var lastErr error
		for _, part := range parts {
			tempDir := filepath.Join(part, "TEMPISO")
			if err := os.MkdirAll(tempDir, 0755); err != nil {
				lastErr = err
				continue
			}
			if err := UnpackISO(isoPath, tempDir); err != nil {
				lastErr = err
				continue
			}
			isoRoot = tempDir
			lastErr = nil
			break
		}
		if lastErr != nil || isoRoot == "" {
			log.LogWrite(0, "[ApplyISOImage]ApplyISOImage 解包ISO失败:"+err.Error())
			return fmt.Errorf("解包ISO失败！")
		}
	}

	installPath := filepath.Join(isoRoot, "sources", "install.wim")
	if _, err := os.Stat(installPath); err != nil {
		installPath = filepath.Join(isoRoot, "sources", "install.esd")
	}
	if _, err := os.Stat(installPath); err != nil {
		found, findErr := FindFile(isoRoot, "install.wim|install.esd", 3)
		if findErr != nil || len(found) == 0 {
			log.LogWrite(0, "[ApplyISOImage]ApplyISOImage ISO中未找到安装镜像！")
			return fmt.Errorf("ISO中未找到安装镜像！")
		}
		installPath = found[0]
	}

	if strings.EqualFold(filepath.Ext(installPath), ".esd") {
		if ApplyEsdImage(installPath, index, targetVol) != nil {
			log.LogWrite(0, "[ApplyISOImage]ApplyISOImage 应用镜像失败！")
			return fmt.Errorf("应用镜像失败！")
		}
		return nil
	}
	if strings.EqualFold(filepath.Ext(installPath), ".wim") {
		if ApplyWimImage(installPath, index, targetVol) != nil {
			log.LogWrite(0, "[ApplyISOImage]ApplyISOImage 应用镜像失败！")
			return fmt.Errorf("应用镜像失败！")
		}
		return nil
	}
	log.LogWrite(0, "[ApplyISOImage]ApplyISOImage 不支持的镜像")

	return fmt.Errorf("ISO安装镜像类型不支持！")
}

// 把字节转成MB/GB
func bytesToMBGBStr(size uint64) string {
	const (
		mb = 1024 * 1024
		gb = 1024 * 1024 * 1024
	)
	if size == 0 {
		return ""
	}
	if size < gb {
		v := float64(size) / float64(mb)
		return fmt.Sprintf("%.1f MB", v)
	}
	v := float64(size) / float64(gb)
	return fmt.Sprintf("%.2f GB", v)
}

// 结合 Installation / Edition / 名称 做系统索引判断 + Size
func finalizeImageMeta(m *D.ImageMeta) {
	m.Size = bytesToMBGBStr(m.SizeBytes)

	name := strings.ToLower(m.Name + " " + m.Description)
	inst := strings.ToLower(m.Installation)
	edition := strings.ToLower(m.Edition)

	isPEInstall := strings.Contains(inst, "windowspe") || strings.Contains(inst, "winpe")
	isPEEdition := strings.Contains(edition, "windowspe")

	isSetupName :=
		strings.Contains(name, "setup media") ||
			strings.Contains(name, "windows setup") ||
			strings.Contains(name, "windows pe") ||
			strings.Contains(name, "winpe") ||
			strings.Contains(name, "winre") ||
			strings.Contains(name, "recovery")
	isClientOrServer := strings.Contains(inst, "client") || strings.Contains(inst, "server")
	if inst == "" && !isPEInstall && !isPEEdition && !isSetupName {
		m.IsOS = true
		return
	}
	m.IsOS = isClientOrServer && !isPEInstall && !isPEEdition && !isSetupName
}



// 按优先级选择镜像索引
func selectInstallIndex(infos []D.ImageMeta) int {
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
	best := 0
	for _, key := range preferred {
		for _, info := range infos {
			if !info.IsOS {
				continue
			}
			text := strings.ToLower(info.Name + " " + info.Description + " " + info.Edition + " " + info.Flags)
			if strings.Contains(text, strings.ToLower(key)) {
				best = info.Index
				return best
			}
		}
	}
	return infos[len(infos)-1].Index
}






