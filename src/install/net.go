package install

import (
	"ReSys/src/download"
	"context"
	"fmt"
	"time"
)

var netChk = download.CheckNetwork

// needNet 在访问远端资源前做一次联网检查，错误由上层统一弹窗展示。
func needNet(op string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	ok, err := netChk(ctx)
	if err != nil {
		return fmt.Errorf("未检测到网络连接，无法%s: %w", op, err)
	}
	if !ok {
		return fmt.Errorf("未检测到网络连接，无法%s", op)
	}
	return nil
}
