//go:build windows

package main

import (
	"ReSys/src/boot"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type args struct {
	wim string
	sdi string
}

type resp struct {
	Mode string `json:"mode"`
	OK   bool   `json:"ok"`
	WIM  string `json:"wim,omitempty"`
	SDI  string `json:"sdi,omitempty"`
	Err  string `json:"error,omitempty"`
}

func main() {
	a, err := parseArgs(os.Args[1:])
	if err != nil {
		write(resp{
			Mode: "wim_sdi_to_bcd",
			OK:   false,
			Err:  err.Error(),
		})
		os.Exit(1)
	}

	if err := boot.WimSdiToBCD(a.wim, a.sdi); err != nil {
		write(resp{
			Mode: "wim_sdi_to_bcd",
			OK:   false,
			WIM:  cleanPath(a.wim),
			SDI:  cleanPath(a.sdi),
			Err:  err.Error(),
		})
		os.Exit(1)
	}

	write(resp{
		Mode: "wim_sdi_to_bcd",
		OK:   true,
		WIM:  cleanPath(a.wim),
		SDI:  cleanPath(a.sdi),
	})
}

// parseArgs 解析命令行参数。
func parseArgs(in []string) (args, error) {
	if len(in) != 2 {
		return args{}, fmt.Errorf("用法: fwboot.exe <wimPath> <sdiPath>")
	}
	wim := strings.TrimSpace(in[0])
	if wim == "" {
		return args{}, fmt.Errorf("wimPath 不能为空")
	}
	sdi := strings.TrimSpace(in[1])
	if sdi == "" {
		return args{}, fmt.Errorf("sdiPath 不能为空")
	}
	return args{wim: wim, sdi: sdi}, nil
}

func cleanPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	return filepath.Clean(path)
}

func write(v resp) {
	b, err := json.MarshalIndent(v, "", "\t")
	if err != nil {
		fmt.Println(`{"ok":false,"error":"JSON输出失败"}`)
		return
	}
	fmt.Println(string(b))
}
