package dism

import (
	"ReSys/src/log"
	"ReSys/src/tools"
	"ReSys/src/utils"
	"ReSys/src/windows"
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"
)

// reDISMPercent 用于匹配 DISM 输出中的百分比，例如 "42.3%"、"100%"。
var reDISMPercent = regexp.MustCompile(`(?i)(\d{1,3})(?:\.\d+)?\s*%`)

// DismProgress 表示 DISM/WIM 操作进度。
type DismProgress struct {
	Percentage uint8  // 当前进度百分比
	Status     string // 当前状态描述
}

// ImageMeta 表示镜像元信息（兼容 DISM / wimlib info 文本解析）。
// 镜像信息
type ImageMeta struct {
	Index       int
	Name        string
	Description string
	Flags       string

	SizeBytes uint64 // 原始字节数
	Size      string // 转换为MB/GB格式

	Edition      string // Professional/WindowsPE/...
	Installation string // Client/Server/WindowsPE/...
	SystemRoot   string // WINDOWS/...
	Arch         string // x86 / x64 / arm64 ...

	IsOS bool // 是否认为是系统
}

// Dism 同时封装 Wimgapi 能力与 dism.exe 命令行能力。
type Dism struct {
	dismPath string
}

// NewDism 创建一个 Dism 实例。
// 该构造函数会尝试预解析 dism.exe 路径，但不会因为找不到 dism.exe 而失败，
// 这样 API 类方法仍可正常使用。
func NewDism() *Dism {
	d := &Dism{}
	if p, err := d.GetDismCmd(); err == nil {
		d.dismPath = p
	}
	return d
}

// GetDismCmd 返回可用的 dism.exe 路径，并缓存到实例中。
// 搜索顺序：tools 目录 -> PE 环境 -> PATH -> 系统目录。
func (d *Dism) GetDismCmd() (string, error) {
	if d != nil && d.dismPath != "" && utils.FileExists(d.dismPath) {
		return d.dismPath, nil
	}

	baseDir := ""
	if exe, err := os.Executable(); err == nil {
		baseDir = filepath.Dir(exe)
	}
	if baseDir == "" {
		baseDir = "."
	}

	subDir := "32"
	if windows.IsWinXP() {
		subDir = "xp"
	} else if windows.SystemArch() == "64" {
		subDir = "64"
	}

	localPath := filepath.Join(baseDir, "tools", subDir, "dism.exe")
	if utils.FileExists(localPath) {
		if d != nil {
			d.dismPath = localPath
		}
		log.LogWrite(0, "[Dism.GetDismCmd] 找到本地 DISM: %s\n", localPath)
		return localPath, nil
	}

	peDrives := []string{"X", "Y", "Z", "W"}
	for _, drive := range peDrives {
		pePaths := []string{
			filepath.Join(drive+":\\", "Windows", "System32", "dism.exe"),
			filepath.Join(drive+":\\", "Windows", "System32", "Dism", "dism.exe"),
			filepath.Join(drive+":\\", "Windows", "SysWOW64", "dism.exe"),
		}
		for _, p := range pePaths {
			if utils.FileExists(p) {
				if d != nil {
					d.dismPath = p
				}
				log.LogWrite(0, "[Dism.GetDismCmd] 找到 PE 环境 DISM: %s\n", p)
				return p, nil
			}
		}
	}

	if sysDism, err := exec.LookPath("dism.exe"); err == nil && sysDism != "" {
		if d != nil {
			d.dismPath = sysDism
		}
		log.LogWrite(0, "[Dism.GetDismCmd] 使用 PATH 中的 DISM: %s\n", sysDism)
		return sysDism, nil
	}

	winDirs := []string{
		os.Getenv("WINDIR"),
		os.Getenv("SystemRoot"),
		`C:\Windows`,
	}

	for _, winDir := range winDirs {
		if strings.TrimSpace(winDir) == "" {
			continue
		}

		sysPaths := []string{
			filepath.Join(winDir, "sysnative", "dism.exe"),
			filepath.Join(winDir, "System32", "dism.exe"),
			filepath.Join(winDir, "System32", "Dism", "dism.exe"),
			filepath.Join(winDir, "SysWOW64", "dism.exe"),
		}

		for _, p := range sysPaths {
			if utils.FileExists(p) {
				if d != nil {
					d.dismPath = p
				}
				log.LogWrite(0, "[Dism.GetDismCmd] 找到系统 DISM: %s\n", p)
				return p, nil
			}
		}
	}

	return "", fmt.Errorf("未找到可用的 dism.exe")
}

// VerifyDismCmd 验证当前解析到的 dism.exe 是否可正常执行。
func (d *Dism) VerifyDismCmd() bool {
	dismPath, err := d.GetDismCmd()
	if err != nil {
		log.LogWrite(0, "[Dism.VerifyDismCmd] 获取 dism.exe 失败: %v\n", err)
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, dismPath, "/?")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	err = cmd.Run()
	log.LogWrite(0, "[Dism.VerifyDismCmd] Verify result: %v\n", err)
	return err == nil
}

// ApplyImageApi 将指定索引的镜像应用到目标目录。
func (d *Dism) ApplyImageApi(imageFile, applyDir string, index uint32, progressCh chan<- DismProgress) error {
	api, err := NewWimg("")
	if err != nil {
		log.LogWrite(-2, "[Dism.ApplyImageApi] Wimgapi init failed: %v\n", err)
		return fmt.Errorf("wimgapi init failed: %w", err)
	}

	hWim, _, err := api.CreateFile(imageFile, WIM_GENERIC_READ, WIM_OPEN_EXISTING, 0, WIM_COMPRESS_NONE)
	if err != nil {
		log.LogWrite(-2, "[Dism.ApplyImageApi] WIMCreateFile(read) failed: %v\n", err)
		return fmt.Errorf("WIMCreateFile(read) failed: %w", err)
	}
	defer api.CloseHandle(hWim)

	_ = api.SetTemporaryPath(hWim, os.TempDir())
	_, _ = api.RegisterCallback(hWim)
	defer api.UnregisterCallback(hWim)

	stop, wg := startWimProgressPoll(api, progressCh, "Applying...", 0, 100)
	defer func() {
		close(stop)
		wg.Wait()
	}()

	hImg, err := api.LoadImage(hWim, index)
	if err != nil {
		log.LogWrite(-2, "[Dism.ApplyImageApi] WIMLoadImage(%d) failed: %v\n", index, err)
		return fmt.Errorf("WIMLoadImage(%d) failed: %w", index, err)
	}
	defer api.CloseHandle(hImg)

	if err := api.ApplyImage(hImg, applyDir, 0); err != nil {
		log.LogWrite(-2, "[Dism.ApplyImageApi] WIMApplyImage failed: %v\n", err)
		return fmt.Errorf("WIMApplyImage failed: %w", err)
	}

	sendProgress(progressCh, 100, "Done")
	return nil
}

// ApplyImageCmd 使用 dism.exe 命令行将指定索引的镜像应用到目标目录。
func (d *Dism) ApplyImageCmd(imageFile, applyDir string, index uint32, progressCh chan<- DismProgress) error {
	imageFile = strings.TrimSpace(imageFile)
	applyDir = strings.TrimSpace(applyDir)

	if index == 0 {
		return fmt.Errorf("invalid image index: %d", index)
	}
	if imageFile == "" {
		return errors.New("image file is empty")
	}
	if applyDir == "" {
		return errors.New("apply dir is empty")
	}
	if !utils.FileExists(imageFile) {
		return fmt.Errorf("镜像文件不存在: %s", imageFile)
	}
	if !utils.FileExists(strings.TrimRight(applyDir, `\\`)) {
		return fmt.Errorf("目标目录不存在: %s", applyDir)
	}

	args := []string{
		"/Apply-Image",
		"/ImageFile:" + imageFile,
		"/Index:" + strconv.FormatUint(uint64(index), 10),
		"/ApplyDir:" + applyDir,
		"/ScratchDir:" + ensureScratchDirectory(),
	}

	dismPath, err := d.GetDismCmd()
	if err != nil {
		return err
	}

	cmd := exec.Command(dismPath, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = cmd.Stdout

	var out bytes.Buffer
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)

	if err := cmd.Start(); err != nil {
		return err
	}

	var lastPct uint8 = 255
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}

		out.WriteString(line)
		out.WriteByte('\n')

		if m := reDISMPercent.FindStringSubmatch(line); len(m) == 2 {
			n, _ := strconv.Atoi(m[1])
			if n < 0 {
				n = 0
			}
			if n > 100 {
				n = 100
			}

			p := uint8(n)
			if p != lastPct {
				lastPct = p
				sendProgress(progressCh, p, line)
			}
		}
	}
	if scanErr := sc.Err(); scanErr != nil {
		return scanErr
	}

	if err := cmd.Wait(); err != nil {
		fullOut := strings.TrimSpace(out.String())
		msg := extractErrorText(fullOut)
		if msg == "" {
			msg = err.Error()
		}
		if fullOut != "" {
			return fmt.Errorf("dism apply failed: %s\n%s", msg, fullOut)
		}
		return fmt.Errorf("dism apply failed: %s", msg)
	}

	sendProgress(progressCh, 100, "Done")
	return nil
}

// CaptureImageApi 以 LZX 压缩格式捕获目录为 WIM 镜像。
func (d *Dism) CaptureImageApi(imageFile, captureDir, name, description string, progressCh chan<- DismProgress) error {
	return d.captureImageCommonApi(imageFile, captureDir, name, description, WIM_COMPRESS_LZX, progressCh)
}

// AppendImageApi 向现有 WIM 追加一个镜像。
func (d *Dism) AppendImageApi(imageFile, captureDir, name, description string, progressCh chan<- DismProgress) error {
	return d.captureImageCommonApi(imageFile, captureDir, name, description, WIM_COMPRESS_LZX, progressCh)
}

// CaptureImageESDApi 以 LZMS 压缩格式捕获目录，适合生成 ESD。
func (d *Dism) CaptureImageESDApi(imageFile, captureDir, name, description string, progressCh chan<- DismProgress) error {
	return d.captureImageCommonApi(imageFile, captureDir, name, description, WIM_COMPRESS_LZMS, progressCh)
}

// AppendImageESDApi 向现有 ESD/WIM 追加镜像，使用 LZMS 压缩。
func (d *Dism) AppendImageESDApi(imageFile, captureDir, name, description string, progressCh chan<- DismProgress) error {
	return d.captureImageCommonApi(imageFile, captureDir, name, description, WIM_COMPRESS_LZMS, progressCh)
}

// CaptureImageSWMApiCmd 捕获目录并分割为 SWM 分卷文件。
// 该方法前半段使用 API 捕获，后半段使用 dism.exe 分卷，因此使用 ApiCmd 后缀。
func (d *Dism) CaptureImageSWMApiCmd(imageFile, captureDir, name, description string, splitSizeMB uint32, progressCh chan<- DismProgress) error {
	base := imageFile
	ext := filepath.Ext(imageFile)
	if strings.EqualFold(ext, ".swm") {
		base = strings.TrimSuffix(imageFile, ext)
	}
	tempWim := base + ".tmp.wim"

	sendProgress(progressCh, 0, "正在捕获镜像...")

	api, err := NewWimg("")
	if err != nil {
		return fmt.Errorf("wimgapi init failed: %w", err)
	}

	hWim, _, err := api.CreateFile(tempWim, WIM_GENERIC_WRITE, WIM_OPEN_ALWAYS, 0, WIM_COMPRESS_LZX)
	if err != nil {
		return fmt.Errorf("WIMCreateFile(tmp.wim) failed: %w", err)
	}
	defer api.CloseHandle(hWim)

	_ = api.SetTemporaryPath(hWim, os.TempDir())
	_, _ = api.RegisterCallback(hWim)
	defer api.UnregisterCallback(hWim)

	stop, wg := startWimProgressPoll(api, progressCh, "Capturing...", 0, 80)
	hImg, capErr := api.CaptureImage(hWim, captureDir, 0)
	close(stop)
	wg.Wait()

	if capErr != nil {
		_ = os.Remove(tempWim)
		return fmt.Errorf("capture tmp.wim failed: %w", capErr)
	}
	if hImg != 0 {
		_ = api.SetImageInformation(hImg, buildImageInfoXML(name, description))
		_ = api.CloseHandle(hImg)
	}

	sendProgress(progressCh, 80, "正在分割镜像...")

	args := []string{
		"/Split-Image",
		"/ImageFile:" + tempWim,
		"/SWMFile:" + imageFile,
		"/FileSize:" + strconv.FormatUint(uint64(splitSizeMB), 10),
	}
	splitErr := d.runDismWithProgressScaledCmd(args, progressCh, 80, 20)
	_ = os.Remove(tempWim)
	if splitErr != nil {
		return fmt.Errorf("split to swm failed: %w", splitErr)
	}

	sendProgress(progressCh, 100, "分卷完成")
	return nil
}

// GetImageInfoApi 读取镜像文件中的镜像列表信息。
// 优先通过 Wimgapi 获取 XML，失败时回退到文件头解析。
func (d *Dism) GetImageInfoApi(imageFile string) ([]ImageMeta, error) {
	api, err := NewWimg("")
	if err == nil {
		hWim, _, e := api.CreateFile(imageFile, WIM_GENERIC_READ, WIM_OPEN_EXISTING, 0, WIM_COMPRESS_NONE)
		if e == nil {
			defer api.CloseHandle(hWim)

			xml, e2 := api.GetImageInformation(hWim)
			if e2 == nil && strings.TrimSpace(xml) != "" {
				if imgs, e3 := parseWimXML(xml); e3 == nil && len(imgs) > 0 {
					return imgs, nil
				}
			}
		}
	}

	return parseWimXMLMetadataFromFile(imageFile)
}

// ListImageInfos 读取 WIM/ESD 的镜像元信息（优先 DISM，失败回退 wimlib-imagex）。
func (d *Dism) ListImageInfos(imagePath string) ([]ImageMeta, error) {
	if _, err := os.Stat(imagePath); err != nil {
		log.LogWrite(0, "[Dism.ListImageInfos] 镜像不存在: path=%s err=%v", imagePath, err)
		return nil, fmt.Errorf("image not found: %w", err)
	}

	if out, err := d.executeAndGetOutputCmd([]string{"/English", "/Get-WimInfo", "/WimFile:" + imagePath}); err == nil {
		if imgs, perr := parseImageInfoText(out); perr == nil && len(imgs) > 0 {
			log.LogWrite(0, "[Dism.ListImageInfos] 使用 DISM 结果")
			return imgs, nil
		} else {
			log.LogWrite(0, "[Dism.ListImageInfos] DISM 解析失败，回退 wimlib: err=%v", perr)
		}
	} else {
		log.LogWrite(0, "[Dism.ListImageInfos] DISM 失败，回退 wimlib: err=%v", err)
	}

	wimlib := ""
	if exe, err := os.Executable(); err == nil {
		local := filepath.Join(filepath.Dir(exe), "tools", "wimlib-imagex.exe")
		if utils.FileExists(local) {
			wimlib = local
		}
	}
	if wimlib == "" {
		if p, err := exec.LookPath("wimlib-imagex.exe"); err == nil {
			wimlib = p
		}
	}
	if wimlib == "" {
		return nil, errors.New("wimlib-imagex.exe not found")
	}

	if out, err := tools.RunCmd(wimlib, nil, nil, "", "info", imagePath); err == nil {
		if imgs, perr := parseImageInfoText(out); perr == nil && len(imgs) > 0 {
			log.LogWrite(0, "[Dism.ListImageInfos] 使用 wimlib 结果")
			return imgs, nil
		} else {
			log.LogWrite(0, "[Dism.ListImageInfos] wimlib 解析失败: err=%v", perr)
			return nil, perr
		}
	} else {
		log.LogWrite(0, "[Dism.ListImageInfos] DISM/WIMLIB 均失败: err=%v", err)
		return nil, fmt.Errorf("both DISM and wimlib-imagex failed: %w", err)
	}
}

// AddDriverOfflineCmd 向离线映像添加驱动。
func (d *Dism) AddDriverOfflineCmd(
	imagePath string,
	driverPath string,
	recurse bool,
	forceUnsigned bool,
	progressCh chan<- DismProgress,
) error {
	imagePath = normalizeImagePath(imagePath)
	driverPath = strings.TrimSpace(driverPath)

	if !utils.FileExists(strings.TrimRight(imagePath, `\`)) {
		return fmt.Errorf("离线映像路径不存在: %s", imagePath)
	}
	if !utils.FileExists(driverPath) {
		return fmt.Errorf("驱动路径不存在: %s", driverPath)
	}

	scratchDir := ensureScratchDirectory()
	sendProgress(progressCh, 0, "正在准备添加驱动...")

	args := []string{
		"/Image:" + imagePath,
		"/Add-Driver",
		"/Driver:" + driverPath,
		"/ScratchDir:" + scratchDir,
	}
	if recurse {
		args = append(args, "/Recurse")
	}
	if forceUnsigned {
		args = append(args, "/ForceUnsigned")
	}

	return d.runDismWithProgressCmd(args, progressCh)
}

// AddDriversFromDirectoryCmd 递归扫描目录并导入全部驱动。
func (d *Dism) AddDriversFromDirectoryCmd(
	imagePath string,
	driverDir string,
	progressCh chan<- DismProgress,
) error {
	return d.AddDriverOfflineCmd(imagePath, driverDir, true, true, progressCh)
}

// AddPackageOfflineCmd 向离线映像安装单个更新包。
func (d *Dism) AddPackageOfflineCmd(
	imagePath string,
	packagePath string,
	ignoreCheck bool,
	progressCh chan<- DismProgress,
) error {
	imagePath = normalizeImagePath(imagePath)
	packagePath = strings.TrimSpace(packagePath)

	if !utils.FileExists(strings.TrimRight(imagePath, `\`)) {
		return fmt.Errorf("离线映像路径不存在: %s", imagePath)
	}
	if !utils.FileExists(packagePath) {
		return fmt.Errorf("包路径不存在: %s", packagePath)
	}

	scratchDir := ensureScratchDirectory()
	sendProgress(progressCh, 0, "正在准备添加更新包...")

	args := []string{
		"/Image:" + imagePath,
		"/Add-Package",
		"/PackagePath:" + packagePath,
		"/ScratchDir:" + scratchDir,
	}
	if ignoreCheck {
		args = append(args, "/IgnoreCheck")
	}

	return d.runDismWithProgressCmd(args, progressCh)
}

// AddPackageOfflineSimpleCmd 向离线映像安装单个更新包的简化版接口。
func (d *Dism) AddPackageOfflineSimpleCmd(
	imagePath string,
	packagePath string,
	progressCh chan<- DismProgress,
) error {
	return d.AddPackageOfflineCmd(imagePath, packagePath, false, progressCh)
}

// AddPackagesFromDirectoryCmd 批量安装目录下所有 CAB 文件。
// 返回值分别为：成功数量、失败数量、整体错误。
func (d *Dism) AddPackagesFromDirectoryCmd(
	imagePath string,
	packageDir string,
	progressCh chan<- DismProgress,
) (int, int, error) {
	if !utils.FileExists(packageDir) {
		return 0, 0, fmt.Errorf("包目录不存在: %s", packageDir)
	}

	cabs, err := findCabFiles(packageDir)
	if err != nil {
		return 0, 0, err
	}
	if len(cabs) == 0 {
		return 0, 0, errors.New("no .cab files found in directory")
	}

	success, fail := 0, 0
	total := len(cabs)

	for i, cab := range cabs {
		start := uint8(i * 100 / total)
		end := uint8((i + 1) * 100 / total)
		span := end - start

		sendProgress(progressCh, start, fmt.Sprintf("Installing CAB (%d/%d): %s", i+1, total, filepath.Base(cab)))

		args := []string{
			"/Image:" + normalizeImagePath(imagePath),
			"/Add-Package",
			"/PackagePath:" + cab,
			"/ScratchDir:" + ensureScratchDirectory(),
		}
		if e := d.runDismWithProgressScaledCmd(args, progressCh, start, span); e != nil {
			fail++
			log.LogWrite(-1, "[Dism.AddPackagesFromDirectoryCmd] 安装失败: %s, err=%v\n", cab, e)
			continue
		}
		success++
	}

	sendProgress(progressCh, 100, fmt.Sprintf("批量安装完成：成功 %d，失败 %d", success, fail))

	if success == 0 {
		return success, fail, fmt.Errorf("所有 CAB 包安装失败")
	}
	return success, fail, nil
}

// ExportDriversOfflineCmd 从离线映像导出驱动。
func (d *Dism) ExportDriversOfflineCmd(
	imagePath string,
	destination string,
	progressCh chan<- DismProgress,
) error {
	imagePath = normalizeImagePath(imagePath)
	destination = strings.TrimSpace(destination)

	if !utils.FileExists(strings.TrimRight(imagePath, `\`)) {
		return fmt.Errorf("离线映像路径不存在: %s", imagePath)
	}
	if err := os.MkdirAll(destination, 0o755); err != nil {
		return fmt.Errorf("创建导出目录失败: %w", err)
	}

	scratchDir := ensureScratchDirectory()
	sendProgress(progressCh, 0, "正在准备导出驱动...")

	args := []string{
		"/Image:" + imagePath,
		"/Export-Driver",
		"/Destination:" + destination,
		"/ScratchDir:" + scratchDir,
	}

	return d.runDismWithProgressCmd(args, progressCh)
}

// ImportDriversSmartCmd 智能导入目录中的驱动和 CAB 包。
func (d *Dism) ImportDriversSmartCmd(
	imagePath string,
	sourceDir string,
	progressCh chan<- DismProgress,
) error {
	if !utils.FileExists(sourceDir) {
		return fmt.Errorf("源目录不存在: %s", sourceDir)
	}

	hasINF, hasCAB, err := analyzeDirectory(sourceDir)
	if err != nil {
		return err
	}
	if !hasINF && !hasCAB {
		return fmt.Errorf("目录中没有找到驱动文件（.inf）或 CAB 包（.cab）")
	}

	var errs []string
	infOK := false
	cabOK := false

	if hasCAB {
		sendProgress(progressCh, 0, "正在添加 CAB 更新包...")
		if _, _, err := d.AddPackagesFromDirectoryCmd(imagePath, sourceDir, nil); err != nil {
			errs = append(errs, "CAB 导入失败: "+err.Error())
		} else {
			cabOK = true
		}
	}

	if hasINF {
		basePct := uint8(0)
		if hasCAB {
			basePct = 50
		}
		sendProgress(progressCh, basePct, "正在添加驱动...")
		if err := d.AddDriversFromDirectoryCmd(imagePath, sourceDir, nil); err != nil {
			errs = append(errs, "驱动导入失败: "+err.Error())
		} else {
			infOK = true
		}
	}

	sendProgress(progressCh, 100, "导入完成")

	switch {
	case hasINF && hasCAB && !infOK && !cabOK:
		return fmt.Errorf("驱动和 CAB 导入均失败: %s", strings.Join(errs, "；"))
	case len(errs) > 0 && (infOK || cabOK):
		return nil
	default:
		return nil
	}
}

// GetDriversCmd 获取离线系统中已安装驱动列表。
func (d *Dism) GetDriversCmd(imagePath string) (string, error) {
	imagePath = normalizeImagePath(imagePath)
	if !utils.FileExists(strings.TrimRight(imagePath, `\`)) {
		return "", fmt.Errorf("离线映像路径不存在: %s", imagePath)
	}

	args := []string{
		"/Image:" + imagePath,
		"/Get-Drivers",
		"/ScratchDir:" + ensureScratchDirectory(),
	}
	return d.executeAndGetOutputCmd(args)
}

// GetPackagesCmd 获取离线系统中已安装更新包列表。
func (d *Dism) GetPackagesCmd(imagePath string) (string, error) {
	imagePath = normalizeImagePath(imagePath)
	if !utils.FileExists(strings.TrimRight(imagePath, `\`)) {
		return "", fmt.Errorf("离线映像路径不存在: %s", imagePath)
	}

	args := []string{
		"/Image:" + imagePath,
		"/Get-Packages",
		"/ScratchDir:" + ensureScratchDirectory(),
	}
	return d.executeAndGetOutputCmd(args)
}

// captureImageCommonApi 执行通用的镜像捕获流程。
func (d *Dism) captureImageCommonApi(
	imageFile string,
	captureDir string,
	name string,
	description string,
	compression uint32,
	progressCh chan<- DismProgress,
) error {
	api, err := NewWimg("")
	if err != nil {
		return fmt.Errorf("wimgapi init failed: %w", err)
	}

	hWim, _, err := api.CreateFile(imageFile, WIM_GENERIC_WRITE, WIM_OPEN_ALWAYS, 0, compression)
	if err != nil {
		return fmt.Errorf("WIMCreateFile(write) failed: %w", err)
	}
	defer api.CloseHandle(hWim)

	_ = api.SetTemporaryPath(hWim, os.TempDir())
	_, _ = api.RegisterCallback(hWim)
	defer api.UnregisterCallback(hWim)

	stop, wg := startWimProgressPoll(api, progressCh, "Capturing...", 0, 100)
	defer func() {
		close(stop)
		wg.Wait()
	}()

	hImg, err := api.CaptureImage(hWim, captureDir, 0)
	if err != nil {
		return fmt.Errorf("WIMCaptureImage failed: %w", err)
	}
	defer api.CloseHandle(hImg)

	xml := buildImageInfoXML(name, description)
	_ = api.SetImageInformation(hImg, xml)

	sendProgress(progressCh, 100, "Done")
	return nil
}

// executeAndGetOutputCmd 执行 dism.exe 并返回完整输出。
func (d *Dism) executeAndGetOutputCmd(args []string) (string, error) {
	dismPath, err := d.GetDismCmd()
	if err != nil {
		return "", err
	}

	cmd := exec.Command(dismPath, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))

	if err != nil {
		msg := extractErrorText(text)
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("dism failed: %s", msg)
	}
	return text, nil
}

// runDismWithProgressCmd 使用 dism.exe 执行命令，并将进度映射到 0..100。
func (d *Dism) runDismWithProgressCmd(args []string, progressCh chan<- DismProgress) error {
	return d.runDismWithProgressScaledCmd(args, progressCh, 0, 100)
}

// runDismWithProgressScaledCmd 使用 dism.exe 执行命令，并将原始进度缩放到指定区间。
func (d *Dism) runDismWithProgressScaledCmd(args []string, progressCh chan<- DismProgress, startPct, spanPct uint8) error {
	dismPath, err := d.GetDismCmd()
	if err != nil {
		return err
	}

	cmd := exec.Command(dismPath, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = cmd.Stdout

	var out bytes.Buffer
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)

	if err := cmd.Start(); err != nil {
		return err
	}

	var lastPct uint8 = 255

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}

		out.WriteString(line)
		out.WriteByte('\n')

		if m := reDISMPercent.FindStringSubmatch(line); len(m) == 2 {
			n, _ := strconv.Atoi(m[1])
			if n < 0 {
				n = 0
			}
			if n > 100 {
				n = 100
			}

			p := startPct + uint8(uint32(n)*uint32(spanPct)/100)
			if p > 100 {
				p = 100
			}
			if p != lastPct {
				lastPct = p
				sendProgress(progressCh, p, line)
			}
		}
	}
	_ = sc.Err()

	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("dism failed: %w\n%s", err, out.String())
	}
	return nil
}

// sendProgress 以非阻塞方式发送进度，避免调用方未消费导致阻塞。
func sendProgress(ch chan<- DismProgress, pct uint8, status string) {
	if ch == nil {
		return
	}
	select {
	case ch <- DismProgress{Percentage: pct, Status: status}:
	default:
	}
}

// startWimProgressPoll 启动后台轮询协程，将底层 Wimgapi 进度映射到指定区间。
func startWimProgressPoll(api *API, progressCh chan<- DismProgress, prefix string, startPct, spanPct uint8) (chan struct{}, *sync.WaitGroup) {
	stop := make(chan struct{})
	wg := &sync.WaitGroup{}
	wg.Add(1)

	go func() {
		defer wg.Done()

		tk := time.NewTicker(120 * time.Millisecond)
		defer tk.Stop()

		var last uint8 = 255
		for {
			select {
			case <-stop:
				return
			case <-tk.C:
				p := api.Progress()
				if p == last {
					continue
				}
				last = p

				scaled := startPct + uint8(uint32(p)*uint32(spanPct)/100)
				if scaled > 100 {
					scaled = 100
				}
				sendProgress(progressCh, scaled, fmt.Sprintf("%s %d%%", prefix, scaled))
			}
		}
	}()

	return stop, wg
}

// buildImageInfoXML 构造最小可用的镜像信息 XML。
func buildImageInfoXML(name, desc string) string {
	name = escapeXML(name)
	desc = escapeXML(desc)
	return fmt.Sprintf(`<IMAGE><NAME>%s</NAME><DESCRIPTION>%s</DESCRIPTION></IMAGE>`, name, desc)
}

// escapeXML 对 XML 特殊字符进行转义。
func escapeXML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, `"`, "&quot;")
	s = strings.ReplaceAll(s, "'", "&apos;")
	return s
}

// parseWimXMLMetadataFromFile 直接从 WIM 文件中读取 XML 元数据块。
func parseWimXMLMetadataFromFile(imageFile string) ([]ImageMeta, error) {
	f, err := os.Open(imageFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	header := make([]byte, 208)
	if _, err := f.Read(header); err != nil {
		return nil, err
	}

	if len(header) < 8 || !bytes.Equal(header[:8], []byte("MSWIM\x00\x00\x00")) {
		return nil, errors.New("not a valid WIM file signature")
	}

	xmlOffset := leU64(header[48:56])
	xmlSize := leU64(header[56:64])
	if xmlOffset == 0 || xmlSize == 0 || xmlSize > 100_000_000 {
		return nil, errors.New("invalid xml metadata offset/size")
	}

	if _, err := f.Seek(int64(xmlOffset), 0); err != nil {
		return nil, err
	}

	xmlData := make([]byte, int(xmlSize))
	if _, err := f.Read(xmlData); err != nil {
		return nil, err
	}

	xmlStr, err := decodeUTF16LE(xmlData)
	if err != nil {
		return nil, err
	}
	return parseWimXML(xmlStr)
}

// parseWimXML 从 WIM XML 中提取镜像条目列表。
func parseWimXML(xml string) ([]ImageMeta, error) {
	var images []ImageMeta
	pos := 0

	for {
		i := strings.Index(xml[pos:], `<IMAGE INDEX="`)
		if i < 0 {
			break
		}
		absStart := pos + i

		indexStart := absStart + len(`<IMAGE INDEX="`)
		indexEnd := strings.IndexByte(xml[indexStart:], '"')
		if indexEnd < 0 {
			pos = indexStart
			continue
		}

		indexStr := xml[indexStart : indexStart+indexEnd]
		idx64, _ := strconv.ParseUint(indexStr, 10, 32)
		idx := int(idx64)

		imgEnd := strings.Index(xml[absStart:], `</IMAGE>`)
		if imgEnd < 0 {
			pos = indexStart
			continue
		}
		block := xml[absStart : absStart+imgEnd+len(`</IMAGE>`)]

		name := firstNonEmpty(
			extractXMLTag(block, "DISPLAYNAME"),
			extractXMLTag(block, "NAME"),
		)
		if name == "" {
			name = fmt.Sprintf("镜像 %d", idx)
		}

		sizeBytes := uint64(0)
		if s := extractXMLTag(block, "TOTALBYTES"); s != "" {
			if v, err := strconv.ParseUint(strings.TrimSpace(s), 10, 64); err == nil {
				sizeBytes = v
			}
		}

		installType := strings.TrimSpace(extractXMLTag(block, "INSTALLATIONTYPE"))

		if idx > 0 {
			meta := ImageMeta{
				Index:        idx,
				Name:         strings.TrimSpace(name),
				SizeBytes:    sizeBytes,
				Installation: installType,
			}
			finalizeImageMeta(&meta)
			images = append(images, meta)
		}

		pos = absStart + imgEnd + len(`</IMAGE>`)
	}

	if len(images) == 0 {
		return nil, errors.New("no image entries found in XML")
	}
	return images, nil
}

// extractXMLTag 提取指定 XML 标签中的文本内容。
func extractXMLTag(xml, tag string) string {
	open := "<" + tag + ">"
	close := "</" + tag + ">"

	s := strings.Index(xml, open)
	if s < 0 {
		return ""
	}
	s += len(open)

	e := strings.Index(xml[s:], close)
	if e < 0 {
		return ""
	}
	return strings.TrimSpace(xml[s : s+e])
}

// firstNonEmpty 返回第一个非空字符串。
func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

// leU64 按小端序将 8 字节切片解码为 uint64。
func leU64(b []byte) uint64 {
	if len(b) < 8 {
		return 0
	}
	return uint64(b[0]) |
		uint64(b[1])<<8 |
		uint64(b[2])<<16 |
		uint64(b[3])<<24 |
		uint64(b[4])<<32 |
		uint64(b[5])<<40 |
		uint64(b[6])<<48 |
		uint64(b[7])<<56
}

// decodeUTF16LE 将 UTF-16LE 字节流解码为 Go 字符串。
func decodeUTF16LE(data []byte) (string, error) {
	if len(data) < 2 {
		return "", errors.New("data too short")
	}

	start := 0
	if len(data) >= 2 && data[0] == 0xFF && data[1] == 0xFE {
		start = 2
	}

	n := (len(data) - start) / 2
	u16 := make([]uint16, 0, n)
	for i := 0; i < n; i++ {
		off := start + i*2
		if off+1 >= len(data) {
			break
		}
		u := uint16(data[off]) | uint16(data[off+1])<<8
		u16 = append(u16, u)
	}

	for len(u16) > 0 && u16[len(u16)-1] == 0 {
		u16 = u16[:len(u16)-1]
	}

	return string(utf16.Decode(u16)), nil
}

// normalizeImagePath 规范化镜像路径，确保以反斜杠结尾。
func normalizeImagePath(path string) string {
	p := strings.TrimSpace(path)
	p = strings.ReplaceAll(p, "/", `\`)
	if p == "" {
		return p
	}
	if strings.HasSuffix(p, `\`) {
		return p
	}
	return p + `\`
}

// ensureScratchDirectory 返回一个可用的 scratch 目录。
// 优先级：PE 临时目录 -> 程序目录 temp -> 系统临时目录。
func ensureScratchDirectory() string {
	peCandidates := []string{
		`X:\Windows\TEMP`,
		`X:\TEMP`,
		`Y:\Windows\TEMP`,
		`Y:\TEMP`,
		`Z:\Windows\TEMP`,
		`Z:\TEMP`,
		`W:\Windows\TEMP`,
		`W:\TEMP`,
	}

	for _, dir := range peCandidates {
		if utils.FileExists(dir) {
			return dir
		}
		parent := filepath.Dir(dir)
		if utils.FileExists(parent) && os.MkdirAll(dir, 0o755) == nil {
			return dir
		}
	}

	if exe, err := os.Executable(); err == nil {
		exeTemp := filepath.Join(filepath.Dir(exe), "temp")
		if os.MkdirAll(exeTemp, 0o755) == nil {
			return exeTemp
		}
	}

	systemTemp := os.TempDir()
	_ = os.MkdirAll(systemTemp, 0o755)
	return systemTemp
}

// findCabFiles 递归查找目录下所有 .cab 文件。
func findCabFiles(dir string) ([]string, error) {
	var result []string

	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if strings.EqualFold(filepath.Ext(path), ".cab") {
			result = append(result, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return result, nil
}

// analyzeDirectory 递归分析目录内容，检查是否包含 .inf 和 .cab 文件。
func analyzeDirectory(dir string) (hasINF bool, hasCAB bool, err error) {
	err = filepath.WalkDir(dir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}

		switch strings.ToLower(filepath.Ext(path)) {
		case ".inf":
			hasINF = true
		case ".cab":
			hasCAB = true
		}

		if hasINF && hasCAB {
			return errors.New("__stop_walk__")
		}
		return nil
	})

	if err != nil && err.Error() != "__stop_walk__" {
		return false, false, err
	}
	return hasINF, hasCAB, nil
}

// extractErrorText 从命令输出中提取更有价值的错误文本。
func extractErrorText(output string) string {
	output = strings.TrimSpace(output)
	if output == "" {
		return ""
	}

	lines := strings.Split(output, "\n")
	for i, line := range lines {
		lower := strings.ToLower(strings.TrimSpace(line))
		if strings.Contains(lower, "error") || strings.Contains(line, "错误") || strings.Contains(line, "失败") {
			end := i + 3
			if end > len(lines) {
				end = len(lines)
			}
			return strings.TrimSpace(strings.Join(lines[i:end], "\n"))
		}
	}

	start := len(lines) - 5
	if start < 0 {
		start = 0
	}
	return strings.TrimSpace(strings.Join(lines[start:], "\n"))
}

// parseImageInfoText 解析 DISM / wimlib-imagex info 输出信息。
func parseImageInfoText(out string) ([]ImageMeta, error) {
	var (
		res []ImageMeta
		cur *ImageMeta
	)

	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}

		colon := strings.Index(line, ":")
		if colon <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:colon])
		val := strings.TrimSpace(line[colon+1:])

		switch {
		case key == "Index" || key == "Image Index":
			if cur != nil && cur.Index != 0 {
				finalizeImageMeta(cur)
				res = append(res, *cur)
			}
			cur = &ImageMeta{}
			if idx, err := strconv.Atoi(val); err == nil {
				cur.Index = idx
			}

		case key == "Name":
			if cur != nil {
				cur.Name = val
			}

		case key == "Description":
			if cur != nil {
				cur.Description = val
			}

		case key == "Flags":
			if cur != nil {
				cur.Flags = val
			}

		case strings.HasPrefix(key, "Size"):
			if cur != nil {
				cur.SizeBytes = parseSizeBytes(val)
			}

		case strings.HasPrefix(key, "Edition"):
			if cur != nil {
				cur.Edition = val
			}

		case strings.HasPrefix(key, "Installation"):
			if cur != nil {
				cur.Installation = val
			}

		case key == "Architecture" || key == "Arch":
			if cur != nil {
				cur.Arch = val
			}

		case strings.HasPrefix(key, "System Root"):
			if cur != nil {
				cur.SystemRoot = val
			}
		}
	}

	if cur != nil && cur.Index != 0 {
		finalizeImageMeta(cur)
		res = append(res, *cur)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(res) == 0 {
		return nil, errors.New("no image info parsed")
	}
	return res, nil
}

// parseSizeBytes 提取形如 "xx bytes" / "xx 字节" 字段中的字节数。
func parseSizeBytes(s string) uint64 {
	s = strings.ToLower(s)
	if idx := strings.Index(s, "bytes"); idx != -1 {
		s = s[:idx]
	} else if idx := strings.Index(s, "字节"); idx != -1 {
		s = s[:idx]
	}

	var b []rune
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b = append(b, r)
		}
	}
	if len(b) == 0 {
		return 0
	}
	n, _ := strconv.ParseUint(string(b), 10, 64)
	return n
}

// bytesToMBGBStr 将字节转换为 MB/GB 文本。
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

// finalizeImageMeta 结合 Installation / Edition / 名称判断是否为可安装系统条目。
func finalizeImageMeta(m *ImageMeta) {
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
