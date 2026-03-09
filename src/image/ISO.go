package image

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"

	"github.com/kdomanski/iso9660/util"

	"ReSys/src/disk"
	"ReSys/src/log"
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
