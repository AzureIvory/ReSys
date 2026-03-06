package dism

import (
	"ReSys/src/log"
	tools "ReSys/src/tools"
	"ReSys/src/utils"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// 返回 tools 目录下对应系统/架构的 dism.exe 绝对路径。
// tools/xp/dism.exe 或 tools/32/dism.exe 或 tools/64/dism.exe
func GetDism() (string, error) {
	baseDir := ""
	if exe, err := os.Executable(); err == nil {
		baseDir = filepath.Dir(exe)
	}
	if baseDir == "" {
		baseDir = "."
	}

	subDir := "32"
	if isWinXP() {
		subDir = "xp"
	} else if systemArch() == "64" {
		subDir = "64"
	}

	localPath := filepath.Join(baseDir, "tools", subDir, "dism.exe")
	if utils.FileExists(localPath) {
		log.LogWrite(0, "[GetDism] 找到本地 DISM: %s\n", localPath)
		return localPath, nil
	}

	// 检测 PE 环境
	peDrives := []string{"X", "Y", "Z", "W"}
	for _, drive := range peDrives {
		pePaths := []string{
			filepath.Join(drive+":\\", "Windows", "System32", "dism.exe"),
			filepath.Join(drive+":\\", "Windows", "System32", "Dism", "dism.exe"),
		}
		for _, p := range pePaths {
			if utils.FileExists(p) {
				log.LogWrite(0, "[GetDism] 找到 PE 环境 DISM: %s\n", p)
				return p, nil
			}
		}
	}

	if sysDism, err := exec.LookPath("dism.exe"); err == nil {
		log.LogWrite(0, "[GetDism] 使用系统 PATH 中的 DISM: %s\n", sysDism)
		return sysDism, nil
	}

	winDirs := []string{
		os.Getenv("WINDIR"),
		os.Getenv("SystemRoot"),
		"C:\\Windows",
	}

	for _, winDir := range winDirs {
		if winDir == "" {
			continue
		}

		sysPaths := []string{
			filepath.Join(winDir, "sysnative", "dism.exe"),
			filepath.Join(winDir, "System32", "dism.exe"),
			filepath.Join(winDir, "System32", "Dism", "dism.exe"),
		}

		for _, p := range sysPaths {
			if utils.FileExists(p) {
				log.LogWrite(0, "[GetDism] 找到系统 DISM: %s\n", p)
				return p, nil
			}
		}
	}
	return "", fmt.Errorf("未找到可用的 dism.exe。\n"+
		"已尝试搜索:\n"+
		"- %s\n"+
		"- X, Y, Z, W 盘的 PE 环境路径\n"+
		"- 系统环境变量 PATH\n"+
		"- Windows\\System32 目录", localPath)
}

// 验证dism.exe是否可用
func verifyDism(dismpath string) bool {
	_, err := tools.RunCmd(dism, nil, nil, "", "/?")
	return err == nil
}
