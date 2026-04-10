package data

import (
	"ReSys/src/log"
	"ReSys/src/utils"
	winos "ReSys/src/windows"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// WinPEImg 琛ㄧず宸茬粡瀹屾垚鑱氬悎鍜岃鑼冨寲鐨?WinPE 涓嬭浇椤广€?
//
// PE 涓嬭浇娴佺▼浠嶇劧闇€瑕佷繚鐣欏亸绉婚噺銆佸垎缁勫悕鍜屾牎楠屼俊鎭紝
// 杩欎簺瀛楁涓嶉€傚悎鐩存帴鎸傚湪閫氱敤鐨?RuleItem 涓娿€?
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

// ruleItemsSource 琛ㄧず鍗曚釜瑙勫垯鏂囦欢瑙ｆ瀽鍚庣殑鑱氬悎缁撴灉銆?
//
// Source銆丷ank 鍜?RulePath 灞炰簬瑙勫垯鏂囦欢绾у厓鏁版嵁锛?
// Items 鍒欐槸璇ヨ鍒欐枃浠朵骇鍑虹殑缁熶竴鏉＄洰鍒楄〃銆?
type ruleItemsSource struct {
	RulePath string
	Source   string
	Rank     int
	Items    []RuleItem
}

// imageRuleCandidate 琛ㄧず瑙勮寖鍖栧悗鐨勯暅鍍忚鍒欓」鍙婂叾鏉ユ簮淇℃伅銆?
//
// 杩欓噷棰濆淇濈暀瑙勫垯鏂囦欢璺緞銆佹潵婧愬悕鍜?Rank锛?
// 渚夸簬鑱氬悎鍚庡仛绋冲畾鎺掑簭鍜岃法鏂囦欢鍘婚噸銆?
type imageRuleCandidate struct {
	Item     RuleItem
	RulePath string
	Source   string
	Rank     int
}

// peRuleCandidate 琛ㄧず瑙勮寖鍖栧悗鐨?PE 鍊欓€夐」鍙婂叾鏉ユ簮淇℃伅銆?
type peRuleCandidate struct {
	Item     WinPEImg
	RulePath string
	Source   string
	Rank     int
}

// GetInstallImageItems 鎵弿鎸囧畾绯荤粺鐩綍涓嬬殑鍏ㄩ儴闀滃儚瑙勫垯銆?
//
// 璇ュ嚱鏁颁細瀹屾垚瑙勮寖鍖栥€佸幓閲嶅拰鎺掑簭锛屾渶缁堣繑鍥炲彲鐩存帴鐢ㄤ簬涓嬭浇鐨?RuleItem 鍒楄〃銆?
// 鏂拌鍒欏彧瑕佹斁杩涘搴旂郴缁熺洰褰曞苟閫氳繃瑙ｆ瀽锛屽氨浼氳嚜鍔ㄥ弬涓庣粨鏋滆仛鍚堛€?
func GetInstallImageItems(system string) ([]RuleItem, error) {
	systemCode, err := normalizeSystemCode(system)
	if err != nil {
		return nil, err
	}

	dir, err := imageRulesDir(systemCode)
	if err != nil {
		return nil, err
	}

	sources, err := loadRules(dir)
	if err != nil {
		log.LogWrite(0, "[GetInstallImageItems] 鍔犺浇闀滃儚瑙勫垯澶辫触: system=%s err=%v", systemCode, err)
		return nil, err
	}

	candidates := make([]imageRuleCandidate, 0, 16)
	seen := map[string]struct{}{}
	for _, src := range sources {
		for _, item := range src.Items {
			item = normalizeImageRuleItem(item)
			if !hasImageRuleValue(item) {
				continue
			}

			key := buildImageRuleKey(item)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}

			candidates = append(candidates, imageRuleCandidate{
				Item:     item,
				RulePath: src.RulePath,
				Source:   src.Source,
				Rank:     src.Rank,
			})
		}
	}

	sortImageRuleCandidates(candidates)
	out := make([]RuleItem, 0, len(candidates))
	for _, cand := range candidates {
		out = append(out, cand.Item)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("鏈壘鍒板彲鐢ㄧ殑闀滃儚瑙勫垯缁撴灉")
	}
	return out, nil
}

// RuleItemFileName 杩斿洖瑙勫垯椤瑰缓璁娇鐢ㄧ殑鏂囦欢鍚嶃€?
//
// 浼樺厛绾у涓嬶細
// 1. 瑙勫垯閲屾樉寮忕粰鍑虹殑 FileName
// 2. 浠庝笅杞介摼鎺ラ噷鎺ㄥ鍑虹殑 basename
// 3. 浠呰兘鎷垮埌鎵╁睍鍚嶆椂鍥為€€涓?windows_image.<ext>
// 4. 鏈€缁堝厹搴曚负 windows_image.iso
func RuleItemFileName(it RuleItem, ln string) string {
	if strings.TrimSpace(it.FileName) != "" {
		return it.FileName
	}
	if u, err := url.Parse(ln); err == nil {
		base := path.Base(u.Path)
		if base != "" && base != "/" && base != "." {
			return base
		}
	}
	if ext := filepath.Ext(ln); ext != "" {
		return "windows_image" + ext
	}
	return "windows_image.iso"
}

// GetWinPE 鎵弿鍏ㄩ儴 PE 瑙勫垯骞惰繑鍥炴帓搴忓悗鐨?PE 鍒楄〃銆?
func GetWinPE() ([]WinPEImg, error) {
	candidates, err := loadPERules()
	if err != nil {
		log.LogWrite(0, "[GetWinPE] 鍔犺浇 PE 瑙勫垯澶辫触: err=%v", err)
		return nil, err
	}

	out := make([]WinPEImg, 0, len(candidates))
	for _, cand := range candidates {
		out = append(out, cand.Item)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("鏈壘鍒板彲鐢ㄧ殑 PE 瑙勫垯缁撴灉")
	}
	return out, nil
}

// splitPipeList 鎶婂舰濡?"a | b" 鎴?"a|b" 鐨勬枃鏈媶鎴愬瓧绗︿覆鍒楄〃銆?
func splitPipeList(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}

	parts := strings.Split(s, "|")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// parseOffset 瑙ｆ瀽 "璧峰 | 缁撴潫" 褰㈠紡鐨勫亸绉诲尯闂淬€?
//
// 瀛楁涓虹┖鎴栨牸寮忎笉瀹屾暣鏃惰繑鍥?ok=false锛屼笉鐩存帴瑙嗕负閿欒銆?
func parseOffset(s string) (start, end int64, ok bool, err error) {
	parts := splitPipeList(s)
	if len(parts) < 2 {
		return 0, 0, false, nil
	}

	start, err = strconv.ParseInt(strings.TrimSpace(parts[0]), 0, 64)
	if err != nil {
		return 0, 0, false, err
	}
	end, err = strconv.ParseInt(strings.TrimSpace(parts[1]), 0, 64)
	if err != nil {
		return 0, 0, false, err
	}
	return start, end, true, nil
}

// PELnk 杩斿洖褰撳墠绯荤粺鎺ㄨ崘浣跨敤鐨?PE 涓嬭浇淇℃伅銆?
//
// 瑙勫垯浼氬厛鎸?Rank 鍜岀増鏈彿鎺掑簭锛屽啀缁撳悎褰撳墠绯荤粺鏋舵瀯浼樺厛閫夋嫨鍚屾灦鏋勯」銆?
func PELnk() (string, float64, []string, error) {
	arch := winos.SystemArch()
	candidates, err := loadPERules()
	if err != nil {
		return "", 0, nil, err
	}

	best, ok := selectPE(candidates, arch)
	if !ok {
		return "", 0, nil, fmt.Errorf("未找到可用的 PE 下载项")
	}
	return best.Item.Name, best.Item.Sz, append([]string(nil), best.Item.Links...), nil
}

// loadPERules 閫掑綊鎵弿 pe-sources 鐩綍锛屽苟鎶婅鍒欑粨鏋滆浆鎹㈡垚 WinPEImg銆?
//
// 杩欓噷浼氶澶栧鐞?offset銆佸垎缁勫悕鍜屽幓閲嶆帓搴忥紝渚?GetWinPE 鍜?PELnk 鍏辩敤銆?
func loadPERules() ([]peRuleCandidate, error) {
	root, err := peRulesDir()
	if err != nil {
		return nil, err
	}

	sources, err := loadRules(root)
	if err != nil {
		return nil, err
	}

	out := make([]peRuleCandidate, 0, 16)
	seen := map[string]struct{}{}
	for _, src := range sources {
		group := peGroupFromRule(src.RulePath, root)
		sourceName := utils.FirstNonEmpty(
			strings.TrimSpace(src.Source),
			strings.TrimSuffix(filepath.Base(src.RulePath), filepath.Ext(src.RulePath)),
		)

		for _, item := range src.Items {
			start, end := int64(0), int64(0)
			if s, e, ok, err := parseOffset(item.Offset); err == nil && ok {
				start, end = s, e
			}

			links := make([]string, 0, len(item.Link.Links))
			for _, link := range item.Link.Links {
				link = strings.TrimSpace(link)
				if link != "" {
					links = append(links, link)
				}
			}

			name := utils.FirstNonEmpty(
				strings.TrimSpace(item.Name),
				strings.TrimSpace(item.FileName),
				sourceName,
			)
			ver := utils.FirstNonEmpty(
				strings.TrimSpace(item.Ver),
				strings.TrimSpace(item.Name),
				sourceName,
			)

			peItem := WinPEImg{
				Name:        name,
				Arch:        normalizeArch(item.Arch),
				Links:       links,
				Grp:         group,
				Ver:         ver,
				Sz:          item.Size,
				MD5:         strings.TrimSpace(item.Hash.MD5),
				OffsetStart: start,
				OffsetEnd:   end,
			}
			if !hasWinPEValue(peItem) {
				continue
			}

			key := buildWinPEKey(peItem)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}

			out = append(out, peRuleCandidate{
				Item:     peItem,
				RulePath: src.RulePath,
				Source:   src.Source,
				Rank:     src.Rank,
			})
		}
	}

	sortPE(out)
	if len(out) == 0 {
		return nil, fmt.Errorf("鏈壘鍒板彲鐢ㄧ殑 PE 瑙勫垯缁撴灉")
	}
	return out, nil
}

// selectPE 鍦ㄥ凡鎺掑簭鐨勫€欓€夊垪琛ㄤ腑閫夋嫨鏈€閫傚悎褰撳墠鏋舵瀯鐨勪竴椤广€?
//
// 鍏堟壘鍚屾灦鏋勶紝鎵句笉鍒板氨鍥為€€鍒扮涓€椤广€?
func selectPE(candidates []peRuleCandidate, arch string) (peRuleCandidate, bool) {
	if len(candidates) == 0 {
		return peRuleCandidate{}, false
	}

	arch = normalizeArch(arch)
	for _, cand := range candidates {
		if normalizeArch(cand.Item.Arch) == arch {
			return cand, true
		}
	}
	return candidates[0], true
}

// loadRules 閫掑綊鎵弿鐩綍涓殑鍏ㄩ儴 json 瑙勫垯鏂囦欢锛屽苟杩囨护鎺夌鐢ㄩ」銆?
//
// parser.go 璐熻矗瑙ｆ瀽鍗曚釜瑙勫垯鏂囦欢锛岃繖閲屽彧璐熻矗鐩綍鑱氬悎銆佸閿欏拰鎺掑簭銆?
// 鍙湁褰撴暣涓洰褰曢兘娌℃湁浠讳綍鍙敤缁撴灉鏃讹紝鎵嶈繑鍥為敊璇€?
func loadRules(dir string) ([]ruleItemsSource, error) {
	files, err := collectJSON(dir)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("瑙勫垯鐩綍涓嬫病鏈夋壘鍒?json 鏂囦欢: %s", dir)
	}

	out := make([]ruleItemsSource, 0, len(files))
	var errs []string
	for _, file := range files {
		res, err := ParseRuleFile(file)
		if err != nil {
			log.LogWrite(0, "[loadRules] 瑙ｆ瀽瑙勫垯鏂囦欢澶辫触: file=%s err=%v", file, err)
			errs = append(errs, fmt.Sprintf("%s: %v", file, err))
			continue
		}
		if !res.Enabled {
			log.LogWrite(0, "[loadRules] 璺宠繃宸茬鐢ㄨ鍒? file=%s source=%s", file, res.Source)
			continue
		}
		if len(res.Items) == 0 {
			continue
		}

		out = append(out, ruleItemsSource{
			RulePath: file,
			Source:   res.Source,
			Rank:     res.Rank,
			Items:    res.Items,
		})
	}

	if len(out) > 0 {
		sortRuleSources(out)
		return out, nil
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("瑙勫垯鐩綍娌℃湁鎴愬姛鍔犺浇浠讳綍鍙敤瑙勫垯: %s", strings.Join(errs, " | "))
	}
	return nil, fmt.Errorf("瑙勫垯鐩綍涓嬫病鏈夊彲鐢ㄨ鍒欑粨鏋? %s", dir)
}

// imageRulesDir 杩斿洖鎸囧畾绯荤粺瀵瑰簲鐨勯暅鍍忚鍒欑洰褰曘€?
func imageRulesDir(system string) (string, error) {
	root, err := utils.ProjectDir("rules", "core")
	if err != nil {
		return "", err
	}

	dir := filepath.Join(root, "image-sources", system)
	if st, err := os.Stat(dir); err == nil && st.IsDir() {
		return dir, nil
	}
	return "", fmt.Errorf("闀滃儚瑙勫垯鐩綍涓嶅瓨鍦? %s", dir)
}

// peRulesDir 杩斿洖 PE 瑙勫垯鏍圭洰褰曘€?
func peRulesDir() (string, error) {
	root, err := utils.ProjectDir("rules", "core")
	if err != nil {
		return "", err
	}

	dir := filepath.Join(root, "pe-sources")
	if st, err := os.Stat(dir); err == nil && st.IsDir() {
		return dir, nil
	}
	return "", fmt.Errorf("PE 瑙勫垯鐩綍涓嶅瓨鍦? %s", dir)
}

// collectJSON 递归收集目录下的全部 json 文件，并按路径排序。
func collectJSON(dir string) ([]string, error) {
	out := make([]string, 0, 8)
	if err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.EqualFold(filepath.Ext(d.Name()), ".json") {
			out = append(out, path)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

// normalizeSystemCode 鎶婁笉鍚屽啓娉曠殑绯荤粺鍚嶅綊涓€鎴愯鍒欑洰褰曚娇鐢ㄧ殑鏁板瓧浠ｅ彿銆?
func normalizeSystemCode(system string) (string, error) {
	system = strings.ToLower(strings.TrimSpace(system))
	system = strings.TrimPrefix(system, "windows")
	system = strings.TrimPrefix(system, "win")
	system = strings.TrimLeft(system, "-_ ")
	system = strings.TrimSpace(system)
	if i := strings.Index(system, "-"); i >= 0 {
		system = strings.TrimSpace(system[:i])
	}
	switch system {
	case "7", "8", "10", "11":
		return system, nil
	default:
		return "", fmt.Errorf("涓嶆敮鎸佺殑绯荤粺浠ｅ彿: %s", system)
	}
}

// normalizeImageRuleItem 鍙暣鐞嗕細褰卞搷绛涢€夈€佹帓搴忓拰鏍￠獙鐨勫瓧娈点€?
func normalizeImageRuleItem(item RuleItem) RuleItem {
	item.System = strings.TrimSpace(item.System)
	item.Name = strings.TrimSpace(item.Name)
	item.FileName = strings.TrimSpace(item.FileName)
	item.Language = strings.TrimSpace(item.Language)
	item.Arch = normalizeArch(item.Arch)
	item.Link.Type = defaultLinkType(item.Link.Type)
	item.Link.Links = compactRuleLinks(item.Link.Links)
	item.Hash.Sha1 = strings.TrimSpace(item.Hash.Sha1)
	item.Hash.Sha256 = strings.TrimSpace(item.Hash.Sha256)
	item.Hash.MD5 = strings.TrimSpace(item.Hash.MD5)
	return item
}

// buildImageRuleKey 鐢熸垚闀滃儚瑙勫垯鐨勭ǔ瀹氬幓閲嶉敭銆?
func buildImageRuleKey(it RuleItem) string {
	return strings.Join([]string{
		strings.TrimSpace(it.Arch),
		strings.TrimSpace(it.Link.Type),
		strings.TrimSpace(it.Hash.Sha1),
		strings.TrimSpace(it.FileName),
		strconv.Itoa(it.Index),
		strings.Join(it.Link.Links, "|"),
	}, "|")
}

// buildWinPEKey 鐢熸垚 WinPE 鍊欓€夐」鐨勭ǔ瀹氬幓閲嶉敭銆?
func buildWinPEKey(it WinPEImg) string {
	return strings.Join([]string{
		strings.TrimSpace(it.Name),
		strings.TrimSpace(it.Arch),
		strings.Join(it.Links, "|"),
		strings.TrimSpace(it.MD5),
		fmt.Sprintf("%d", it.OffsetStart),
		fmt.Sprintf("%d", it.OffsetEnd),
	}, "|")
}

// sortRuleSources 鎸?Rank銆佹潵婧愬悕鍜岃鍒欒矾寰勫瑙勫垯缁撴灉鍋氱ǔ瀹氭帓搴忋€?
func sortRuleSources(items []ruleItemsSource) {
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Rank != items[j].Rank {
			return items[i].Rank > items[j].Rank
		}
		if strings.TrimSpace(items[i].Source) != strings.TrimSpace(items[j].Source) {
			return strings.TrimSpace(items[i].Source) < strings.TrimSpace(items[j].Source)
		}
		return items[i].RulePath < items[j].RulePath
	})
}

// sortImageRuleCandidates 瀵归暅鍍忓€欓€夐」鍋氭渶缁堟帓搴忋€?
//
// 鏇撮珮 Rank 鐨勬潵婧愭帓鍦ㄥ墠闈紱鍚?Rank 涓嬩紭鍏?URL锛?
// 鍐嶆寜 index銆佹枃浠跺悕鍜屾潵婧愬悕淇濇寔椤哄簭绋冲畾銆?
func sortImageRuleCandidates(items []imageRuleCandidate) {
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Rank != items[j].Rank {
			return items[i].Rank > items[j].Rank
		}
		if strings.TrimSpace(items[i].Item.Link.Type) != strings.TrimSpace(items[j].Item.Link.Type) {
			return strings.TrimSpace(items[i].Item.Link.Type) < strings.TrimSpace(items[j].Item.Link.Type)
		}
		if items[i].Item.Index != items[j].Item.Index {
			return items[i].Item.Index > items[j].Item.Index
		}
		if strings.TrimSpace(items[i].Item.FileName) != strings.TrimSpace(items[j].Item.FileName) {
			return strings.TrimSpace(items[i].Item.FileName) < strings.TrimSpace(items[j].Item.FileName)
		}
		if strings.TrimSpace(items[i].Source) != strings.TrimSpace(items[j].Source) {
			return strings.TrimSpace(items[i].Source) < strings.TrimSpace(items[j].Source)
		}
		return buildImageRuleKey(items[i].Item) < buildImageRuleKey(items[j].Item)
	})
}

// sortPE 瀵?PE 鍊欓€夐」鍋氱ǔ瀹氭帓搴忋€?
//
// 鍏堢湅 Rank锛屽啀鐪嬪彲姣旇緝鐨勭増鏈彿锛屾渶鍚庡洖閫€鍒板悕绉板拰鏉ユ簮鍚嶃€?
func sortPE(items []peRuleCandidate) {
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Rank != items[j].Rank {
			return items[i].Rank > items[j].Rank
		}
		vi := ruleVerScore(items[i].Item.Ver, items[i].Item.Name)
		vj := ruleVerScore(items[j].Item.Ver, items[j].Item.Name)
		if vi != vj {
			return vi > vj
		}
		if items[i].Item.Name != items[j].Item.Name {
			return items[i].Item.Name < items[j].Item.Name
		}
		if strings.TrimSpace(items[i].Source) != strings.TrimSpace(items[j].Source) {
			return strings.TrimSpace(items[i].Source) < strings.TrimSpace(items[j].Source)
		}
		return buildWinPEKey(items[i].Item) < buildWinPEKey(items[j].Item)
	})
}

// hasImageRuleValue 鍒ゆ柇闀滃儚瑙勫垯鏄惁鑷冲皯鍏峰鏂囦欢鍚嶆垨涓嬭浇閾炬帴銆?
func hasImageRuleValue(it RuleItem) bool {
	return strings.TrimSpace(it.FileName) != "" || len(it.Link.Links) > 0
}

// hasWinPEValue 鍒ゆ柇 PE 瑙勫垯鏄惁鑷冲皯鍏峰鍚嶇О鍜屼笅杞介摼鎺ャ€?
func hasWinPEValue(it WinPEImg) bool {
	return strings.TrimSpace(it.Name) != "" && len(it.Links) > 0
}

// compactRuleLinks 鍘绘帀绌洪摼鎺ュ苟鎸夐娆″嚭鐜伴『搴忓幓閲嶃€?
func compactRuleLinks(links []string) []string {
	if len(links) == 0 {
		return nil
	}

	out := make([]string, 0, len(links))
	seen := make(map[string]struct{}, len(links))
	for _, link := range links {
		link = strings.TrimSpace(link)
		if link == "" {
			continue
		}
		if _, ok := seen[link]; ok {
			continue
		}
		seen[link] = struct{}{}
		out = append(out, link)
	}
	return out
}

// normalizeArch 鎶婂父瑙佹灦鏋勫埆鍚嶆槧灏勬垚缁熶竴鍊笺€?
func normalizeArch(arch string) string {
	arch = strings.ToLower(strings.TrimSpace(arch))
	switch {
	case strings.Contains(arch, "arm64"), strings.Contains(arch, "aarch64"):
		return "arm64"
	case strings.Contains(arch, "x64"), strings.Contains(arch, "amd64"), arch == "64":
		return "64"
	case strings.Contains(arch, "x86"), strings.Contains(arch, "i386"), arch == "32", arch == "86":
		return "32"
	default:
		return arch
	}
}

// peGroupFromRule 鏍规嵁瑙勫垯鏂囦欢鐨勭浉瀵硅矾寰勬帹瀵煎垎缁勫悕銆?
//
// 渚嬪锛?
// - pe-sources/direct/a.json -> direct
// - pe-sources/easyrc.json   -> easyrc
func peGroupFromRule(rulePath, root string) string {
	rel, err := filepath.Rel(root, rulePath)
	if err != nil {
		return strings.TrimSuffix(filepath.Base(rulePath), filepath.Ext(rulePath))
	}

	rel = filepath.ToSlash(rel)
	dir := path.Dir(rel)
	if dir == "." || dir == "" {
		return strings.TrimSuffix(path.Base(rel), path.Ext(rel))
	}
	parts := strings.Split(dir, "/")
	if len(parts) > 0 && parts[0] != "" {
		return parts[0]
	}
	return strings.TrimSuffix(path.Base(rel), path.Ext(rel))
}

var versionPattern = regexp.MustCompile(`(\d+(?:\.\d+)?)`)

// ruleVerScore 浠庣増鏈彿鎴栧悕绉伴噷鎻愬彇绗竴涓彲姣旇緝鐨勬暟瀛楃増鏈€?
//
// 杩欓噷鍙仛绠€鍗曟帓搴忚緟鍔╋紝涓嶈拷姹傚鏉傝涔夊寲鐗堟湰姣旇緝銆?
func ruleVerScore(values ...string) float64 {
	for _, value := range values {
		matches := versionPattern.FindStringSubmatch(strings.TrimSpace(value))
		if len(matches) < 2 {
			continue
		}
		if v, err := strconv.ParseFloat(matches[1], 64); err == nil {
			return v
		}
	}
	return 0
}
