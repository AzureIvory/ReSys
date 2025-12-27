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
	"strconv"
	"strings"
	"time"
)

const (
	winImgURL = "https://api.ttraw.com/Windows.json"
	winPEURL  = "https://api.ttraw.com/WinPE.json"
	peHtmlURL = "https://www.51cxsoft.com/EasyRC/PEDownload.html"
)

var hc = &http.Client{Timeout: 20 * time.Second}

// ---------------- Windows Img ----------------

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

func getb(u string) ([]byte, error) {
	rp, err := hc.Get(u)
	if err != nil {
		return nil, err
	}
	defer rp.Body.Close()
	if rp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http: %s", rp.Status)
	}
	return io.ReadAll(rp.Body)
}

func GetWinImgs(key string) ([]WinImg, error) {
	b, err := getb(winImgURL)
	if err != nil {
		return nil, fmt.Errorf("获取镜像信息失败: %w", err)
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(b, &top); err != nil {
		return nil, fmt.Errorf("解析镜像信息失败: %w", err)
	}

	raw, ok := top[key]
	if !ok {
		return nil, fmt.Errorf("未找到系统类型: %s", key)
	}

	ent, err := parseImgs(raw)
	if err != nil {
		return nil, err
	}
	if len(ent) == 0 {
		return nil, fmt.Errorf("未找到可用镜像")
	}
	return ent, nil
}

func parseImgs(raw json.RawMessage) ([]WinImg, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tk, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("解析镜像列表失败: %w", err)
	}
	if d, ok := tk.(json.Delim); !ok || d != '{' {
		return nil, fmt.Errorf("镜像列表格式异常")
	}

	var ent []WinImg
	for dec.More() {
		tk, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("解析镜像列表失败: %w", err)
		}
		if _, ok := tk.(string); !ok {
			return nil, fmt.Errorf("镜像列表键格式异常")
		}
		var it WinImg
		if err := dec.Decode(&it); err != nil {
			return nil, fmt.Errorf("解析镜像详情失败: %w", err)
		}
		ent = append(ent, it)
	}
	if _, err := dec.Token(); err != nil {
		return nil, fmt.Errorf("解析镜像列表失败: %w", err)
	}
	return ent, nil
}

func PickImage(ent []WinImg) (*WinImg, error) {
	if len(ent) == 0 {
		return nil, fmt.Errorf("未找到可用镜像")
	}
	for i := range ent {
		if strings.TrimSpace(ent[i].Arch) == "64" {
			return &ent[i], nil
		}
	}
	for i := range ent {
		if strings.TrimSpace(ent[i].Arch) == "32" {
			return &ent[i], nil
		}
	}
	return &ent[0], nil
}

func ImgLink(it WinImg) (string, error) {
	ln := strings.TrimSpace(it.Link)
	if ln == "" {
		ln = strings.TrimSpace(it.Link2)
	}
	if ln == "" {
		return "", fmt.Errorf("镜像链接为空")
	}
	return ln, nil
}

func ImgName(it WinImg, ln string) string {
	if strings.TrimSpace(it.File) != "" {
		return it.File
	}
	if u, err := url.Parse(ln); err == nil {
		bs := path.Base(u.Path)
		if bs != "" && bs != "/" && bs != "." {
			return bs
		}
	}
	ext := filepath.Ext(ln)
	if ext == "" {
		ext = ".iso"
	}
	return "windows_image" + ext
}

// ---------------- WinPE ----------------

type WinPEImg struct {
	// 兼容原有字段
	Name  string
	Arch  string
	Links []string

	// 新增：便于优先级筛选/展示（不影响原功能）
	Grp string
	Ver string
	Sz  float64 // 可选：WinPE.json 里可能有 size
}

type peVer struct {
	X64 string  `json:"64"`
	X32 string  `json:"32"`
	Sz  float64 `json:"size,omitempty"`
}

func GetWinPE() ([]WinPEImg, error) {
	b, err := getb(winPEURL)
	if err != nil {
		return nil, fmt.Errorf("获取 PE 镜像信息失败: %w", err)
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(b, &top); err != nil {
		return nil, fmt.Errorf("解析 PE 镜像信息失败: %w", err)
	}

	var out []WinPEImg
	for grp, raw := range top {
		dec := json.NewDecoder(bytes.NewReader(raw))
		tk, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("解析 PE 镜像列表失败: %w", err)
		}
		if d, ok := tk.(json.Delim); !ok || d != '{' {
			return nil, fmt.Errorf("PE 镜像列表格式异常")
		}

		for dec.More() {
			tk, err := dec.Token()
			if err != nil {
				return nil, fmt.Errorf("解析 PE 镜像列表失败: %w", err)
			}
			ver, ok := tk.(string)
			if !ok {
				return nil, fmt.Errorf("PE 镜像列表键格式异常")
			}

			var pv peVer
			if err := dec.Decode(&pv); err != nil {
				return nil, fmt.Errorf("解析 PE 镜像详情失败: %w", err)
			}

			nm := grp + " " + ver

			if strings.TrimSpace(pv.X64) != "" {
				ps := strings.Split(pv.X64, "|")
				ln := make([]string, 0, len(ps))
				for _, p := range ps {
					s := strings.TrimSpace(p)
					if s != "" {
						ln = append(ln, s)
					}
				}
				out = append(out, WinPEImg{
					Name: nm, Grp: grp, Ver: ver, Sz: pv.Sz,
					Arch: "64", Links: ln,
				})
			}
			if strings.TrimSpace(pv.X32) != "" {
				ps := strings.Split(pv.X32, "|")
				ln := make([]string, 0, len(ps))
				for _, p := range ps {
					s := strings.TrimSpace(p)
					if s != "" {
						ln = append(ln, s)
					}
				}
				out = append(out, WinPEImg{
					Name: nm, Grp: grp, Ver: ver, Sz: pv.Sz,
					Arch: "32", Links: ln,
				})
			}
		}

		if _, err := dec.Token(); err != nil {
			return nil, fmt.Errorf("解析 PE 镜像列表失败: %w", err)
		}
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("未找到可用 PE 镜像")
	}
	return out, nil
}

// PELnk：优先 WinPE.json（FIRPE > Win11PE精简版 > 64位）
// 若失败则回退到 PEDownload.html（Win11 精简版 + 备用线路）
// 返回：name / size(可选) / links(按优先级) / err
func PELnk() (string, float64, []string, error) {
	// 1) WinPE.json 优先
	pes, err := GetWinPE()
	if err == nil && len(pes) > 0 {
		bi, bs := -1, -1
		for i := range pes {
			s := 0
			if strings.EqualFold(strings.TrimSpace(pes[i].Grp), "FIRPE") {
				s += 1000
			}
			v := strings.TrimSpace(pes[i].Ver)
			if strings.Contains(v, "Win11PE精简版") || strings.Contains(v, "Windows 11 PE 精简版") {
				s += 200
			}
			a := strings.TrimSpace(pes[i].Arch)
			if a == "64" {
				s += 50
			} else if a == "32" {
				s += 10
			}
			if s > bs {
				bs, bi = s, i
			}
		}
		if bi >= 0 && len(pes[bi].Links) > 0 {
			return pes[bi].Name, pes[bi].Sz, pes[bi].Links, nil
		}
	}

	// 2) PEDownload.html 回退：Win11 精简版 + 备用线路
	b, e2 := getb(peHtmlURL)
	if e2 != nil {
		if err != nil {
			return "", 0, nil, err
		}
		return "", 0, nil, fmt.Errorf("获取 PEDownload.html 失败: %w", e2)
	}
	txt := string(b)

	up := strings.ToUpper(txt)
	p1 := strings.Index(up, "[PEX64]")
	if p1 < 0 {
		return "", 0, nil, fmt.Errorf("未找到 [PEX64] 段")
	}
	rest := txt[p1+len("[PEX64]"):]
	// 找下一段开始（常见是 [PEX86] / [XPPE]）
	nx := strings.Index(rest, "[")
	if nx > 0 {
		rest = rest[:nx]
	}

	type it struct {
		nm  string
		url string
		u2  string
	}
	m := map[int]*it{}

	ls := strings.Split(strings.ReplaceAll(rest, "\r", ""), "\n")
	for _, l := range ls {
		l = strings.TrimSpace(l)
		if len(l) < 6 || !strings.HasPrefix(l, "PE") {
			continue
		}
		eq := strings.Index(l, "=")
		if eq < 0 {
			continue
		}
		k := strings.TrimSpace(l[:eq])
		v := strings.TrimSpace(l[eq+1:])
		if v == "" {
			continue
		}

		// k: PE3Name / PE3Url / PE3Url2
		j := 2
		for j < len(k) && k[j] >= '0' && k[j] <= '9' {
			j++
		}
		if j == 2 {
			continue
		}
		id, er := strconv.Atoi(k[2:j])
		if er != nil || id <= 0 {
			continue
		}
		key := k[j:]

		itm := m[id]
		if itm == nil {
			itm = &it{}
			m[id] = itm
		}
		switch key {
		case "Name":
			itm.nm = v
		case "Url":
			itm.url = v
		case "Url2":
			itm.u2 = v
		}
	}

	// 按编号顺序找：主=精简版，备=精简版_备用线路
	var a, b2 *it
	for i := 1; i <= 50; i++ {
		x := m[i]
		if x == nil {
			continue
		}
		if a == nil && strings.TrimSpace(x.nm) == "Windows 11 PE 精简版" {
			a = x
		}
		if b2 == nil && strings.TrimSpace(x.nm) == "Windows 11 PE 精简版_备用线路" {
			b2 = x
		}
	}

	dd := map[string]bool{}
	add := func(out *[]string, s string) {
		s = strings.TrimSpace(s)
		if s == "" || dd[s] {
			return
		}
		dd[s] = true
		*out = append(*out, s)
	}

	var out []string
	if a != nil {
		add(&out, a.url)
		add(&out, a.u2)
	}
	if b2 != nil {
		add(&out, b2.url)
		add(&out, b2.u2)
	}

	if len(out) == 0 {
		return "", 0, nil, fmt.Errorf("未解析到 Win11 精简版/备用线路 链接")
	}
	return "EasyRC Windows 11 PE 精简版", 0, out, nil
}
