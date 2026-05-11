//go:build windows

package main

import (
	"ReSys/src/pe"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type args struct {
	scan bool
	ext  []string
}

type resp struct {
	Mode  string `json:"mode"`
	OK    bool   `json:"ok"`
	Found bool   `json:"found"`
	WIM   string `json:"wim,omitempty"`
	SDI   string `json:"sdi,omitempty"`
	Err   string `json:"error,omitempty"`
}

func main() {
	a, err := parseArgs(os.Args[1:])
	if err != nil {
		write(resp{
			Mode: pickMode(os.Args[1:]),
			OK:   false,
			Err:  err.Error(),
		})
		os.Exit(1)
	}

	found, wim, sdi, err := pe.GoToPE(a.scan, a.ext...)
	if err != nil {
		write(resp{
			Mode:  modeName(a.scan),
			OK:    false,
			Found: found,
			WIM:   cleanOut(wim),
			SDI:   cleanOut(sdi),
			Err:   err.Error(),
		})
		os.Exit(1)
	}

	write(resp{
		Mode:  modeName(a.scan),
		OK:    true,
		Found: found,
		WIM:   cleanOut(wim),
		SDI:   cleanOut(sdi),
	})
}

// parseArgs 解析命令行参数。
func parseArgs(in []string) (args, error) {
	if len(in) == 0 {
		return args{}, fmt.Errorf("用法: gotope.exe <true|false> [sdiPath wimPath]")
	}

	scan, err := parseScan(in[0])
	if err != nil {
		return args{}, err
	}

	switch len(in) {
	case 1:
		return args{scan: scan}, nil
	case 3:
		sdi := strings.TrimSpace(in[1])
		wim := strings.TrimSpace(in[2])
		if sdi == "" || wim == "" {
			return args{}, fmt.Errorf("自定义模式必须同时提供 sdiPath 和 wimPath")
		}
		return args{scan: scan, ext: []string{sdi, wim}}, nil
	default:
		return args{}, fmt.Errorf("参数数量错误，用法: gotope.exe <true|false> [sdiPath wimPath]")
	}
}

func parseScan(s string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "1", "scan":
		return true, nil
	case "false", "0", "set":
		return false, nil
	default:
		return false, fmt.Errorf("第一个参数只能是 true 或 false")
	}
}

func modeName(scan bool) string {
	if scan {
		return "scan"
	}
	return "set"
}

func pickMode(in []string) string {
	if len(in) == 0 {
		return "unknown"
	}
	if scan, err := parseScan(in[0]); err == nil {
		return modeName(scan)
	}
	return "unknown"
}

func cleanOut(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
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
