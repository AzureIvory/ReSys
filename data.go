package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
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
func localDataPath(name string) string {
	exe, err := os.Executable()
	if err != nil {
		return name
	}
	return filepath.Join(filepath.Dir(exe), name)
}

func getbWithFallback(url, localPath string) ([]byte, error) {
	if strings.TrimSpace(url) != "" {
		if b, err := getb(url); err == nil {
			return b, nil
		}
	}
	if strings.TrimSpace(localPath) == "" {
		return nil, fmt.Errorf("获取数据失败，且未提供本地文件")
	}
	b, err := os.ReadFile(localPath)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func GetWinImgs(key string) ([]WinImg, error) {
	b, err := getbWithFallback(winImgURL, localDataPath("Windows.json"))
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

// WinPE

type WinPEImg struct {
	Name        string
	Arch        string
	Links       []string
	Grp         string
	Ver         string
	Sz          float64
	MD5         string
	OffsetStart int64
	OffsetEnd   int64
}

type peEnt struct {
	URL    string  `json:"url"`
	Size   float64 `json:"size,omitempty"`
	MD5    string  `json:"md5,omitempty"`
	Offset string  `json:"offset,omitempty"`
}

type peVer struct {
	X64 peEnt   `json:"64"`
	X32 peEnt   `json:"32"`
	Sz  float64 `json:"size,omitempty"`
}

// 兼容 "a|b" 与 "a | b"
func splitPipeList(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	sep := " | "
	var ps []string
	if strings.Contains(s, sep) {
		ps = strings.Split(s, sep)
	} else {
		ps = strings.Split(s, "|")
	}
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseOffsetRange(s string) (start, end int64, ok bool, err error) {
	ps := splitPipeList(s)
	if len(ps) < 2 {
		return 0, 0, false, nil
	}
	st, er1 := strconv.ParseInt(strings.TrimSpace(ps[0]), 0, 64)
	if er1 != nil {
		return 0, 0, false, er1
	}
	ed, er2 := strconv.ParseInt(strings.TrimSpace(ps[1]), 0, 64)
	if er2 != nil {
		return 0, 0, false, er2
	}
	return st, ed, true, nil
}

func GetWinPE() ([]WinPEImg, error) {
	b, err := getbWithFallback(winPEURL, localDataPath("WinPE.json"))
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

			if u := strings.TrimSpace(pv.X64.URL); u != "" {
				ln := splitPipeList(u)
				// 解析 offset（可选）
				oS, oE, ok, oErr := parseOffsetRange(pv.X64.Offset)
				if oErr != nil {
					return nil, fmt.Errorf("解析 PE offset 失败: %w", oErr)
				}
				sz := pv.X64.Size
				if sz <= 0 {
					sz = pv.Sz
				}
				out = append(out, WinPEImg{
					Name: nm, Grp: grp, Ver: ver, Sz: sz,
					Arch: "64", Links: ln,
					MD5: strings.TrimSpace(pv.X64.MD5),
					OffsetStart: func() int64 {
						if ok {
							return oS
						}
						return 0
					}(),
					OffsetEnd: func() int64 {
						if ok {
							return oE
						}
						return 0
					}(),
				})
			}
			if u := strings.TrimSpace(pv.X32.URL); u != "" {
				ln := splitPipeList(u)
				oS, oE, ok, oErr := parseOffsetRange(pv.X32.Offset)
				if oErr != nil {
					return nil, fmt.Errorf("解析 PE offset 失败: %w", oErr)
				}
				sz := pv.X32.Size
				if sz <= 0 {
					sz = pv.Sz
				}
				out = append(out, WinPEImg{
					Name: nm, Grp: grp, Ver: ver, Sz: sz,
					Arch: "32", Links: ln,
					MD5: strings.TrimSpace(pv.X32.MD5),
					OffsetStart: func() int64 {
						if ok {
							return oS
						}
						return 0
					}(),
					OffsetEnd: func() int64 {
						if ok {
							return oE
						}
						return 0
					}(),
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

// PELnk：优先 PEDownload.html（尽量找 Win11 精简版；找不到则取第一个链接）
// 若失败则回退到 WinPE.json（FIRPE > Win11PE精简版 > 64位）
// 返回：name / size(可选) / links(按优先级) / err
func PELnk() (string, float64, []string, error) {
	// 1) PEDownload.html 优先：尽量找 Win11 精简版；若找不到相关文字则取第一个链接
	b, e1 := getbWithFallback(peHtmlURL, localDataPath("PEDownload.html"))
	if e1 == nil {
		txt := string(b)

		up := strings.ToUpper(txt)
		p1 := strings.Index(up, "[PEX64]")
		if p1 >= 0 {
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

			dd := map[string]bool{}
			add := func(out *[]string, s string) {
				s = strings.TrimSpace(s)
				if s == "" || dd[s] {
					return
				}
				dd[s] = true
				*out = append(*out, s)
			}

			isMain := func(nm string) bool {
				nm = strings.TrimSpace(nm)
				// 兼容不同写法：Windows 11 PE 精简版 / Win11PE精简版 等
				if strings.Contains(nm, "Windows 11") && strings.Contains(nm, "精简") {
					return true
				}
				if strings.Contains(nm, "Win11") && strings.Contains(nm, "精简") {
					return true
				}
				if strings.Contains(nm, "Windows11") && strings.Contains(nm, "精简") {
					return true
				}
				return false
			}
			isBak := func(nm string) bool {
				nm = strings.TrimSpace(nm)
				return strings.Contains(nm, "备用")
			}

			// 先尝试：主=精简版，备=备用线路（按编号顺序）
			var a, b2 *it
			for i := 1; i <= 50; i++ {
				x := m[i]
				if x == nil {
					continue
				}
				if a == nil && isMain(x.nm) && !isBak(x.nm) {
					a = x
				}
				if b2 == nil && isMain(x.nm) && isBak(x.nm) {
					b2 = x
				}
			}

			var out []string
			if a != nil {
				add(&out, a.url)
				add(&out, a.u2)
				if b2 != nil {
					add(&out, b2.url)
					add(&out, b2.u2)
				}
				if len(out) > 0 {
					// 追加 WinPE.json 的优选链接作为进一步备用（去重，保持顺序）
					name := "EasyRC Windows 11 PE 精简版"
					sz := 0.0
					pes, e3 := GetWinPE()
					if e3 == nil && len(pes) > 0 {
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
							if sz == 0 {
								sz = pes[bi].Sz
							}
							for _, s := range pes[bi].Links {
								add(&out, s)
							}
						}
					}
					return name, sz, out, nil
				}
			}

			// 若没找到“Windows 11 PE 精简版”等文字：取 [PEX64] 段全部链接（按先后顺序），去重；
			// 使用时先用第一个，失效就用第二个…类推；再追加 WinPE.json 的优选链接作为进一步备用
			var first *it
			for i := 1; i <= 50; i++ {
				x := m[i]
				if x == nil {
					continue
				}
				if first == nil && (strings.TrimSpace(x.url) != "" || strings.TrimSpace(x.u2) != "") {
					first = x
				}
				add(&out, x.url)
				add(&out, x.u2)
			}
			if len(out) > 0 {
				name := "EasyRC PE"
				if first != nil && strings.TrimSpace(first.nm) != "" {
					name = "EasyRC " + strings.TrimSpace(first.nm)
				}
				sz := 0.0

				pes, e3 := GetWinPE()
				if e3 == nil && len(pes) > 0 {
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
						if name == "EasyRC PE" {
							name = pes[bi].Name
						}
						if sz == 0 {
							sz = pes[bi].Sz
						}
						for _, s := range pes[bi].Links {
							add(&out, s)
						}
					}
				}
				return name, sz, out, nil
			}
		}
	}

	// 2) WinPE.json 回退（FIRPE > Win11PE精简版 > 64位）
	pes, err := GetWinPE()
	if err != nil {
		return "", 0, nil, err
	}
	if len(pes) == 0 {
		return "", 0, nil, fmt.Errorf("未找到可用 PE 镜像")
	}

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
	return "", 0, nil, fmt.Errorf("未找到可用 PE 镜像")
}
