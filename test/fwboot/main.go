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
	pe string
}

type resp struct {
	Mode string `json:"mode"`
	OK   bool   `json:"ok"`
	PE   string `json:"pe,omitempty"`
	ID   string `json:"id,omitempty"`
	Err  string `json:"error,omitempty"`
}

func main() {
	a, err := parseArgs(os.Args[1:])
	if err != nil {
		write(resp{
			Mode: "set_fw_once",
			OK:   false,
			Err:  err.Error(),
		})
		os.Exit(1)
	}

	id, err := boot.SetFwOnce(a.pe)
	if err != nil {
		write(resp{
			Mode: "set_fw_once",
			OK:   false,
			PE:   cleanPath(a.pe),
			Err:  err.Error(),
		})
		os.Exit(1)
	}

	write(resp{
		Mode: "set_fw_once",
		OK:   true,
		PE:   cleanPath(a.pe),
		ID:   id,
	})
}

// parseArgs 解析命令行参数。
func parseArgs(in []string) (args, error) {
	if len(in) != 1 {
		return args{}, fmt.Errorf("用法: fwboot.exe <pePath>")
	}

	pe := strings.TrimSpace(in[0])
	if pe == "" {
		return args{}, fmt.Errorf("pePath 不能为空")
	}
	return args{pe: pe}, nil
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
