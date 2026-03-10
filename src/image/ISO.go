package image

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/kdomanski/iso9660"
	"github.com/kdomanski/iso9660/util"

	"ReSys/src/disk"
	"ReSys/src/log"
)

var (
	Shell32           = syscall.NewLazyDLL("shell32.dll")
	procShellExecuteW = Shell32.NewProc("ShellExecuteW")
)

const (
	swHide = 0 //挂载
)

// 调用ShellExecuteW
func shellExecuteVerb(path string, verb string) error {
	pPath, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		log.LogWrite(0, "[shellExecuteVerb]shellExecuteVerb 路径编码失败: path=%s err=%v", path, err)
		return err
	}
	pVerb, err := syscall.UTF16PtrFromString(verb)
	if err != nil {
		log.LogWrite(0, "[shellExecuteVerb]shellExecuteVerb 动作编码失败: verb=%s err=%v", verb, err)
		return err
	}

	r, _, callErr := procShellExecuteW.Call(
		0,
		uintptr(unsafe.Pointer(pVerb)),
		uintptr(unsafe.Pointer(pPath)),
		0,
		0,
		uintptr(swHide),
	)
	// 返回值 <= 32 代表失败
	if r <= 32 {
		if callErr != nil && callErr != syscall.Errno(0) {
			log.LogWrite(0, "[shellExecuteVerb]shellExecuteVerb 调用失败: path=%s verb=%s err=%v", path, verb, callErr)
			return fmt.Errorf("ShellExecuteW failed: ret=%d err=%w", r, callErr)
		}
		log.LogWrite(0, "[shellExecuteVerb]shellExecuteVerb 调用失败: path=%s verb=%s ret=%d", path, verb, r)
		return fmt.Errorf("ShellExecuteW failed: ret=%d", r)
	}
	return nil
}

// 使用ShellExecute挂载ISO，返回新挂载的光驱盘符
func MountISO(isoPath string, wait time.Duration) (string, error) {
	if _, err := os.Stat(isoPath); err != nil {
		log.LogWrite(0, "[MountISO]MountISO ISO不存在: path=%s err=%v", isoPath, err)
		return "", fmt.Errorf("iso not found: %w", err)
	}

	// 记录现有CD盘符
	before, err := disk.ListCD()
	if err != nil {
		log.LogWrite(0, "[MountISO]MountISO 获取CD盘符失败: err=%v", err)
		return "", fmt.Errorf("list cdrom before mount: %w", err)
	}
	beforeSet := make(map[string]struct{}, len(before))
	for _, d := range before {
		beforeSet[d] = struct{}{}
	}

	if err := shellExecuteVerb(isoPath, "mount"); err != nil {
		if err2 := shellExecuteVerb(isoPath, "open"); err2 != nil {
			log.LogWrite(0, "[MountISO]MountISO 执行挂载失败: mountErr=%v openErr=%v", err, err2)
			return "", fmt.Errorf("mount/open iso failed: %v / %v", err, err2)
		}
	}

	// 找新的CD盘符
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		time.Sleep(500 * time.Millisecond)

		now, err := disk.ListCD()
		if err != nil {
			log.LogWrite(0, "[MountISO]MountISO 获取CD盘符失败: err=%v", err)
			continue
		}
		for _, d := range now {
			if _, ok := beforeSet[d]; !ok {
				return d, nil
			}
		}
	}

	return "", errors.New("timeout: iso mounted but no new cdrom drive detected")
}

// 将ISO的内容解包到指定目录
func UnpackISO(isoPath, dstDir string) error {
	if err := os.MkdirAll(dstDir, 0755); err != nil {
		log.LogWrite(0, "[UnpackISO]UnpackISO 创建目录失败: dir=%s err=%v", dstDir, err)
		return fmt.Errorf("create dst dir: %w", err)
	}

	f, err := os.Open(isoPath)
	if err != nil {
		log.LogWrite(0, "[UnpackISO]UnpackISO 打开ISO失败: path=%s err=%v", isoPath, err)
		return fmt.Errorf("open iso: %w", err)
	}
	defer f.Close()

	if err := util.ExtractImageToDirectory(f, dstDir); err != nil {
		log.LogWrite(0, "[UnpackISO]UnpackISO 解包失败: path=%s dir=%s err=%v", isoPath, dstDir, err)
		return fmt.Errorf("extract iso: %w", err)
	}
	return nil
}

// detectISOFormat 读取 ISO 第 16 个逻辑扇区的卷描述符，
// 通过标准标识判断镜像是 ISO9660 还是 UDF。
func detectISOFormat(r io.ReaderAt) (string, error) {
	const sectorSize = 2048
	header := make([]byte, sectorSize)

	// ISO 卷描述符从第 16 个扇区开始；读不到说明镜像不完整或格式异常。
	if _, err := r.ReadAt(header, int64(16*sectorSize)); err != nil {
		return "", err
	}

	// 卷描述符的 1~5 字节是标准标识符。
	identifier := string(header[1:6])

	switch identifier {
	case "CD001":
		// ISO9660 标准卷描述符标识。
		return "iso9660", nil
	case "BEA01":
		// UDF 扩展卷描述符起始标识。
		return "udf", nil
	default:
		// 既不是 ISO9660，也不是已识别的 UDF 头。
		return "", fmt.Errorf("unknown iso format: %s", identifier)
	}
}

// hasISOInstallImage 递归遍历 ISO 目录树，
// 判断是否存在 Windows 安装镜像文件 sources/install.wim 或 sources/install.esd。
func hasISOInstallImage(entry *iso9660.File, base string) bool {
	name := strings.ToLower(entry.Name())
	path := name
	if base != "" {
		path = base + "/" + name
	}

	if !entry.IsDir() {
		// 命中 Windows 安装镜像核心文件即返回 true。
		if path == "sources/install.wim" || path == "sources/install.esd" {
			return true
		}
		return false
	}

	// 目录读取失败时，按未找到处理。
	children, err := entry.GetChildren()
	if err != nil {
		return false
	}

	// 只要任一子节点命中目标文件，即可提前返回。
	for _, child := range children {
		if hasISOInstallImage(child, path) {
			return true
		}
	}
	return false
}
