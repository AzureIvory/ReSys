//go:build windows

package main

import (
	"ReSys/src/boot"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type args struct {
	wim string
	idx int
	esp string
}

type resp struct {
	Mode string `json:"mode"`
	OK   bool   `json:"ok"`
	WIM  string `json:"wim,omitempty"`
	Idx  int    `json:"index,omitempty"`
	ESP  string `json:"esp,omitempty"`
	Err  string `json:"error,omitempty"`
}

func main() {
	a, err := parseArgs(os.Args[1:])
	if err != nil {
		write(resp{
			Mode: "wim_to_efi",
			OK:   false,
			Err:  err.Error(),
		})
		os.Exit(1)
	}

	idx, err := boot.WimToEFI(a.wim, a.idx, a.esp)
	if err != nil {
		write(resp{
			Mode: "wim_to_efi",
			OK:   false,
			WIM:  cleanPath(a.wim),
			Idx:  idxOrIn(idx, a.idx),
			ESP:  showESP(a.wim, a.esp),
			Err:  err.Error(),
		})
		os.Exit(1)
	}

	write(resp{
		Mode: "wim_to_efi",
		OK:   true,
		WIM:  cleanPath(a.wim),
		Idx:  idxOrIn(idx, a.idx),
		ESP:  showESP(a.wim, a.esp),
	})
}

// parseArgs 解析命令行参数。
func parseArgs(in []string) (args, error) {
	if len(in) < 1 || len(in) > 3 {
		return args{}, fmt.Errorf("用法: fwboot.exe <wimPath> [index] [espRoot]")
	}

	wim := strings.TrimSpace(in[0])
	if wim == "" {
		return args{}, fmt.Errorf("wimPath 不能为空")
	}

	out := args{
		wim: wim,
		idx: 0,
	}
	if len(in) >= 2 {
		arg2 := strings.TrimSpace(in[1])
		if idx, err := strconv.Atoi(arg2); err == nil {
			if idx <= 0 {
				return args{}, fmt.Errorf("index 必须是大于 0 的整数")
			}
			out.idx = idx
		} else {
			out.esp = arg2
		}
	}
	if len(in) == 3 {
		if out.idx == 0 {
			return args{}, fmt.Errorf("传入 espRoot 时，第二个参数必须是 index")
		}
		out.esp = strings.TrimSpace(in[2])
	}
	return out, nil
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

func showESP(wimPath, espRoot string) string {
	if strings.TrimSpace(espRoot) != "" {
		return cleanPath(espRoot)
	}
	path := cleanPath(wimPath)
	vol := filepath.VolumeName(path)
	if vol == "" {
		return ""
	}
	return filepath.Clean(vol + `\`)
}

func idxOrIn(idx, in int) int {
	if idx > 0 {
		return idx
	}
	return in
}

func write(v resp) {
	b, err := json.MarshalIndent(v, "", "\t")
	if err != nil {
		fmt.Println(`{"ok":false,"error":"JSON输出失败"}`)
		return
	}
	fmt.Println(string(b))
}
