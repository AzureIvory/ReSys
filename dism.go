//go:build windows

package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
)

// DismProgress 表示 DISM 或 WIM 操作的进度状态。
type DismProgress struct {
	Percentage uint8  // 当前进度百分比
	Status     string // 当前状态描述
}

// ImageInfo 描述 WIM/ESD 中单个镜像条目的基本信息。
type ImageInfo struct {
	Index            uint32 // 镜像索引
	Name             string // 镜像名称
	SizeBytes        uint64 // 镜像大小（字节）
	InstallationType string // 安装类型，例如 Client / Server
}

// Dism 提供镜像应用、捕获、驱动注入、CAB 安装等能力。
type Dism struct{}

// NewDism 创建一个 Dism 实例。
func NewDism() Dism { return Dism{} }

// sendProgress 以非阻塞方式发送进度，避免调用方未消费通道时造成死锁。
func sendProgress(ch chan<- DismProgress, pct uint8, status string) {
	if ch == nil {
		return
	}
	select {
	case ch <- DismProgress{Percentage: pct, Status: status}:
	default:
	}
}

// =======================
// wimgapi 高层封装（apply/capture/...）
// =======================

// ApplyImage 将指定索引的镜像应用到目标目录。
func (Dism) ApplyImage(imageFile, applyDir string, index uint32, progressCh chan<- DismProgress) error {
	api, err := NewWimg("")
	if err != nil {
		return fmt.Errorf("wimgapi init failed: %w", err)
	}

	// 以只读方式打开 WIM/ESD 文件。
	hWim, _, err := api.CreateFile(imageFile, WIM_GENERIC_READ, WIM_OPEN_EXISTING, 0, WIM_COMPRESS_NONE)
	if err != nil {
		return fmt.Errorf("WIMCreateFile(read) failed: %w", err)
	}
	defer api.CloseHandle(hWim)

	// 设置临时目录，提升兼容性。
	_ = api.SetTemporaryPath(hWim, os.TempDir())

	// 注册回调以便获取底层进度。
	_, _ = api.RegisterCallback(hWim)
	defer api.UnregisterCallback(hWim)

	// 启动轮询，将底层进度映射到 0..100。
	stop, wg := startWimProgressPoll(api, progressCh, "Applying...", 0, 100)
	defer func() {
		close(stop)
		wg.Wait()
	}()

	// 加载指定索引的镜像。
	hImg, err := api.LoadImage(hWim, index)
	if err != nil {
		return fmt.Errorf("WIMLoadImage(%d) failed: %w", index, err)
	}
	defer api.CloseHandle(hImg)

	// 应用镜像到目标目录。
	if err := api.ApplyImage(hImg, applyDir, 0); err != nil {
		return fmt.Errorf("WIMApplyImage failed: %w", err)
	}

	sendProgress(progressCh, 100, "Done")
	return nil
}

// CaptureImage 以 LZX 压缩格式捕获目录为 WIM 镜像。
func (Dism) CaptureImage(imageFile, captureDir, name, description string, progressCh chan<- DismProgress) error {
	return captureImageCommon(imageFile, captureDir, name, description, WIM_COMPRESS_LZX, progressCh)
}

// AppendImage 向现有 WIM 追加一个镜像。
// 约定：当目标文件存在时，Capture 行为等同追加。
func (Dism) AppendImage(imageFile, captureDir, name, description string, progressCh chan<- DismProgress) error {
	return captureImageCommon(imageFile, captureDir, name, description, WIM_COMPRESS_LZX, progressCh)
}

// CaptureImageESD 以 LZMS 压缩格式捕获目录，适合生成 ESD。
func (Dism) CaptureImageESD(imageFile, captureDir, name, description string, progressCh chan<- DismProgress) error {
	return captureImageCommon(imageFile, captureDir, name, description, WIM_COMPRESS_LZMS, progressCh)
}

// AppendImageESD 向现有 ESD/WIM 中追加镜像，使用 LZMS 压缩。
func (Dism) AppendImageESD(imageFile, captureDir, name, description string, progressCh chan<- DismProgress) error {
	return captureImageCommon(imageFile, captureDir, name, description, WIM_COMPRESS_LZMS, progressCh)
}

// captureImageCommon 执行通用的镜像捕获流程。
func captureImageCommon(imageFile, captureDir, name, description string, compression uint32, progressCh chan<- DismProgress) error {
	api, err := NewWimg("")
	if err != nil {
		return fmt.Errorf("wimgapi init failed: %w", err)
	}

	// 使用 OPEN_ALWAYS：文件存在则打开，不存在则创建。
	hWim, _, err := api.CreateFile(imageFile, WIM_GENERIC_WRITE, WIM_OPEN_ALWAYS, 0, compression)
	if err != nil {
		return fmt.Errorf("WIMCreateFile(write) failed: %w", err)
	}
	defer api.CloseHandle(hWim)

	_ = api.SetTemporaryPath(hWim, os.TempDir())

	_, _ = api.RegisterCallback(hWim)
	defer api.UnregisterCallback(hWim)

	// 捕获阶段进度映射到 0..100。
	stop, wg := startWimProgressPoll(api, progressCh, "Capturing...", 0, 100)
	defer func() {
		close(stop)
		wg.Wait()
	}()

	// 从目录捕获镜像。
	hImg, err := api.CaptureImage(hWim, captureDir, 0)
	if err != nil {
		return fmt.Errorf("WIMCaptureImage failed: %w", err)
	}
	defer api.CloseHandle(hImg)

	// 写入最小可用的镜像元信息。
	xml := buildImageInfoXML(name, description)
	_ = api.SetImageInformation(hImg, xml) // 某些环境下可能受限，因此不强制失败。

	sendProgress(progressCh, 100, "Done")
	return nil
}

// CaptureImageSWM 捕获目录并分割为 SWM 分卷文件。
// 实现方式：先捕获为临时 tmp.wim，再调用 dism /Split-Image 分卷。
func (Dism) CaptureImageSWM(imageFile, captureDir, name, description string, splitSizeMB uint32, progressCh chan<- DismProgress) error {
	// 临时文件命名规则：<basename>.tmp.wim
	base := imageFile
	ext := filepath.Ext(imageFile)
	if strings.EqualFold(ext, ".swm") {
		base = strings.TrimSuffix(imageFile, ext)
	}
	tempWim := base + ".tmp.wim"

	sendProgress(progressCh, 0, "正在捕获镜像...")

	// 捕获阶段映射到 0..80。
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

	// 分割阶段映射到 80..100。
	args := []string{
		"/Split-Image",
		"/ImageFile:" + tempWim,
		"/SWMFile:" + imageFile,
		"/FileSize:" + strconv.FormatUint(uint64(splitSizeMB), 10),
	}
	splitErr := runDismWithProgressScaled(args, progressCh, 80, 20)
	_ = os.Remove(tempWim)
	if splitErr != nil {
		return fmt.Errorf("split to swm failed: %w", splitErr)
	}

	sendProgress(progressCh, 100, "分卷完成")
	return nil
}

// startWimProgressPoll 启动一个后台轮询协程，持续读取 wimgapi 进度并映射到指定百分比区间。
func startWimProgressPoll(api *API, progressCh chan<- DismProgress, prefix string, startPct, spanPct uint8) (stop chan struct{}, wg *sync.WaitGroup) {
	stop = make(chan struct{})
	wg = &sync.WaitGroup{}
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

				// 将底层 0..100 进度缩放到调用方定义的区间。
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

// buildImageInfoXML 构造可供 WIMSetImageInformation 使用的最小 XML 片段。
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

// =======================
// dism.exe 封装（驱动/CAB）
// =======================

// AddDriversOffline 向离线镜像注入驱动，并递归扫描驱动目录。
func (Dism) AddDriversOffline(imagePath, driverPath string) error {
	args := []string{
		"/Image:" + imagePath,
		"/Add-Driver",
		"/Driver:" + driverPath,
		"/Recurse",
	}
	return runDismWithProgress(args, nil)
}

// AddDriversOfflineWithProgress 向离线镜像注入驱动，并上报进度。
func (Dism) AddDriversOfflineWithProgress(imagePath, driverPath string, progressCh chan<- DismProgress) error {
	args := []string{
		"/Image:" + imagePath,
		"/Add-Driver",
		"/Driver:" + driverPath,
		"/Recurse",
	}
	return runDismWithProgress(args, progressCh)
}

// AddPackageOffline 向离线镜像安装单个 CAB 包。
func (Dism) AddPackageOffline(imagePath, cabPath string) error {
	args := []string{
		"/Image:" + imagePath,
		"/Add-Package",
		"/PackagePath:" + cabPath,
	}
	return runDismWithProgress(args, nil)
}

// AddPackagesOfflineFromDir 批量安装目录下所有 .cab 文件。
// 返回值分别为：成功数量、失败数量、整体错误。
func (Dism) AddPackagesOfflineFromDir(imagePath, cabDir string, progressCh chan<- DismProgress) (int, int, error) {
	var cabs []string
	err := filepath.WalkDir(cabDir, func(p string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		if strings.EqualFold(filepath.Ext(p), ".cab") {
			cabs = append(cabs, p)
		}
		return nil
	})
	if err != nil {
		return 0, 0, err
	}
	if len(cabs) == 0 {
		return 0, 0, errors.New("no .cab files found in directory")
	}

	success, fail := 0, 0
	total := len(cabs)

	for i, cab := range cabs {
		// 将每个 CAB 的安装过程映射到总进度的一段区间。
		start := uint8(i * 100 / total)
		end := uint8((i + 1) * 100 / total)
		span := end - start

		sendProgress(progressCh, start, fmt.Sprintf("Installing CAB (%d/%d): %s", i+1, total, filepath.Base(cab)))

		args := []string{
			"/Image:" + imagePath,
			"/Add-Package",
			"/PackagePath:" + cab,
		}
		if e := runDismWithProgressScaled(args, progressCh, start, span); e != nil {
			fail++
			// 单个包失败时继续安装后续包。
			continue
		}
		success++
	}

	sendProgress(progressCh, 100, fmt.Sprintf("批量安装完成：成功 %d，失败 %d", success, fail))
	return success, fail, nil
}

// 匹配 DISM 输出中的百分比，例如 "42.3%"、"100%"。
var reDISMPercent = regexp.MustCompile(`(?i)(\d{1,3})(?:\.\d+)?\s*%`)

// runDismWithProgress 使用 DISM 执行命令，并将进度映射到 0..100。
func runDismWithProgress(args []string, progressCh chan<- DismProgress) error {
	return runDismWithProgressScaled(args, progressCh, 0, 100)
}

// runDismWithProgressScaled 使用 DISM 执行命令，并将原始百分比缩放到指定区间。
func runDismWithProgressScaled(args []string, progressCh chan<- DismProgress, startPct, spanPct uint8) error {
	if dism == "" {
		return errors.New("global variable 'dism' is empty")
	}

	cmd := exec.Command(dism, args...)

	// 将 stderr 合并到 stdout，便于统一做流式解析。
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = cmd.Stdout

	var out bytes.Buffer
	sc := bufio.NewScanner(stdout)

	// DISM 某些输出行较长，手动扩容 Scanner 缓冲区。
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

		// 解析输出中的百分比。
		if m := reDISMPercent.FindStringSubmatch(line); len(m) == 2 {
			n, _ := strconv.Atoi(m[1])
			if n < 0 {
				n = 0
			}
			if n > 100 {
				n = 100
			}

			// 将 DISM 原始进度缩放到调用方约定区间。
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
		// 失败时附带完整输出，便于定位问题。
		return fmt.Errorf("dism failed: %w\n%s", err, out.String())
	}
	return nil
}

// =======================
// 镜像信息（WIM XML 解析）
// =======================

// GetImageInfo 读取镜像文件中的镜像列表信息。
// 优先通过 wimgapi 获取完整 XML，失败时退回到文件头解析。
func (Dism) GetImageInfo(imageFile string) ([]ImageInfo, error) {
	// 1) 优先使用 WIMGetImageInformation 获取全量 XML。
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

	// 2) 兜底：直接从文件头定位 XML 元数据区域并解析。
	return parseWimXMLMetadataFromFile(imageFile)
}

// parseWimXMLMetadataFromFile 直接从 WIM 文件中读取 XML 元数据块。
func parseWimXMLMetadataFromFile(imageFile string) ([]ImageInfo, error) {
	f, err := os.Open(imageFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// WIM 头部固定读取 208 字节。
	header := make([]byte, 208)
	if _, err := f.Read(header); err != nil {
		return nil, err
	}

	// 校验 WIM 文件签名："MSWIM\0\0\0"
	if len(header) < 8 || !bytes.Equal(header[:8], []byte("MSWIM\x00\x00\x00")) {
		return nil, errors.New("not a valid WIM file signature")
	}

	// 与 Rust 版本保持一致：
	// xml_offset = 48..56
	// xml_size   = 56..64
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

	xmlStr, err := decodeUTF16LEex(xmlData)
	if err != nil {
		return nil, err
	}
	return parseWimXML(xmlStr)
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

// decodeUTF16LEex 将 UTF-16LE 字节流解码为 Go 字符串。
// 支持可选 BOM，并自动去除尾部 0。
func decodeUTF16LEex(data []byte) (string, error) {
	if len(data) < 2 {
		return "", errors.New("data too short")
	}

	start := 0
	// 跳过 UTF-16LE BOM：FF FE
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

	// 去除结尾的空字符。
	for len(u16) > 0 && u16[len(u16)-1] == 0 {
		u16 = u16[:len(u16)-1]
	}

	return string(utf16.Decode(u16)), nil
}

// parseWimXML 从 WIM XML 中提取镜像条目列表。
// 这里使用轻量字符串解析，避免引入完整 XML 结构体映射。
func parseWimXML(xml string) ([]ImageInfo, error) {
	var images []ImageInfo

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
		idx := uint32(idx64)

		imgEnd := strings.Index(xml[absStart:], `</IMAGE>`)
		if imgEnd < 0 {
			pos = indexStart
			continue
		}
		block := xml[absStart : absStart+imgEnd+len(`</IMAGE>`)]

		// 优先使用 DISPLAYNAME，缺失时回退到 NAME。
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

		installType := extractXMLTag(block, "INSTALLATIONTYPE")

		if idx > 0 {
			images = append(images, ImageInfo{
				Index:            idx,
				Name:             strings.TrimSpace(name),
				SizeBytes:        sizeBytes,
				InstallationType: strings.TrimSpace(installType),
			})
		}

		pos = absStart + imgEnd + len(`</IMAGE>`)
	}

	if len(images) == 0 {
		return nil, errors.New("no image entries found in XML")
	}
	return images, nil
}

// extractXMLTag 提取指定 XML 标签中的文本内容。
// 若标签不存在或不完整，则返回空字符串。
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
