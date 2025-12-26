package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"strings"
)

const (
	winImgURL = "https://api.ttraw.com/Windows.json"
	winPEURL  = "https://api.ttraw.com/WinPE.json"
)

type WinImg struct {
	Arch  string  `json:"arch"`
	Type  string  `json:"type"`
	SHA1  string  `json:"SHA1"`
	Link  string  `json:"link"`
	Link2 string  `json:"link2"`
	Size  float64 `json:"size"`
	Index int     `json:"index"`
	File  string  `json:"file"`
}

func GetWinImgs(osKey string) ([]WinImg, error) {
	resp, err := http.Get(winImgURL)
	if err != nil {
		return nil, fmt.Errorf("获取镜像信息失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("获取镜像信息失败: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取镜像信息失败: %w", err)
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		return nil, fmt.Errorf("解析镜像信息失败: %w", err)
	}

	raw, ok := top[osKey]
	if !ok {
		return nil, fmt.Errorf("未找到系统类型: %s", osKey)
	}

	entries, err := parseImgs(raw)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("未找到可用镜像")
	}
	return entries, nil
}

func parseImgs(raw json.RawMessage) ([]WinImg, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("解析镜像列表失败: %w", err)
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return nil, fmt.Errorf("镜像列表格式异常")
	}

	var entries []WinImg
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("解析镜像列表失败: %w", err)
		}
		_, ok := tok.(string)
		if !ok {
			return nil, fmt.Errorf("镜像列表键格式异常")
		}
		var entry WinImg
		if err := dec.Decode(&entry); err != nil {
			return nil, fmt.Errorf("解析镜像详情失败: %w", err)
		}
		entries = append(entries, entry)
	}

	if _, err := dec.Token(); err != nil {
		return nil, fmt.Errorf("解析镜像列表失败: %w", err)
	}
	return entries, nil
}

func PickImage(entries []WinImg) (*WinImg, error) {
	if len(entries) == 0 {
		return nil, fmt.Errorf("未找到可用镜像")
	}

	for i := range entries {
		if strings.TrimSpace(entries[i].Arch) == "64" {
			return &entries[i], nil
		}
	}

	for i := range entries {
		if strings.TrimSpace(entries[i].Arch) == "32" {
			return &entries[i], nil
		}
	}

	return &entries[0], nil
}

func ImgLink(entry WinImg) (string, error) {
	link := strings.TrimSpace(entry.Link)
	if link == "" {
		link = strings.TrimSpace(entry.Link2)
	}
	if link == "" {
		return "", fmt.Errorf("镜像链接为空")
	}
	return link, nil
}

func ImgFileName(entry WinImg, link string) string {
	if strings.TrimSpace(entry.File) != "" {
		return entry.File
	}
	u, err := url.Parse(link)
	if err == nil {
		base := path.Base(u.Path)
		if base != "" && base != "/" && base != "." {
			return base
		}
	}
	ext := filepath.Ext(link)
	if ext == "" {
		ext = ".iso"
	}
	return "windows_image" + ext
}

type WinPEImg struct {
	Name  string
	Arch  string
	Links []string
}

type WinPEVer struct {
	Links   string `json:"64"`
	Links32 string `json:"32"`
}

func GetWinPE() ([]WinPEImg, error) {
	resp, err := http.Get(winPEURL)
	if err != nil {
		return nil, fmt.Errorf("获取 PE 镜像信息失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("获取 PE 镜像信息失败: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取 PE 镜像信息失败: %w", err)
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		return nil, fmt.Errorf("解析 PE 镜像信息失败: %w", err)
	}

	var entries []WinPEImg
	for group, raw := range top {
		groupEntries, err := parsePEGroup(group, raw)
		if err != nil {
			return nil, err
		}
		entries = append(entries, groupEntries...)
	}

	if len(entries) == 0 {
		return nil, fmt.Errorf("未找到可用 PE 镜像")
	}
	return entries, nil
}

func parsePEGroup(group string, raw json.RawMessage) ([]WinPEImg, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("解析 PE 镜像列表失败: %w", err)
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return nil, fmt.Errorf("PE 镜像列表格式异常")
	}

	var entries []WinPEImg
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("解析 PE 镜像列表失败: %w", err)
		}
		version, ok := tok.(string)
		if !ok {
			return nil, fmt.Errorf("PE 镜像列表键格式异常")
		}
		var entry WinPEVer
		if err := dec.Decode(&entry); err != nil {
			return nil, fmt.Errorf("解析 PE 镜像详情失败: %w", err)
		}
		name := fmt.Sprintf("%s %s", group, version)
		if strings.TrimSpace(entry.Links) != "" {
			entries = append(entries, WinPEImg{
				Name:  name,
				Arch:  "64",
				Links: splitLinks(entry.Links),
			})
		}
		if strings.TrimSpace(entry.Links32) != "" {
			entries = append(entries, WinPEImg{
				Name:  name,
				Arch:  "32",
				Links: splitLinks(entry.Links32),
			})
		}
	}

	if _, err := dec.Token(); err != nil {
		return nil, fmt.Errorf("解析 PE 镜像列表失败: %w", err)
	}
	return entries, nil
}

func splitLinks(raw string) []string {
	parts := strings.Split(raw, "|")
	links := make([]string, 0, len(parts))
	for _, part := range parts {
		link := strings.TrimSpace(part)
		if link == "" {
			continue
		}
		links = append(links, link)
	}
	return links
}
