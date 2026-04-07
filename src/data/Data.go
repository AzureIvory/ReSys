package data

import (
	"ReSys/src/log"
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

// WinImg 是安装镜像流程继续沿用的兼容结构。
//
// 规则引擎最终会先解析成 RuleItem，再在这里收敛成旧流程能直接消费的字段，
// 这样可以在不改动 install/image 等调用方的前提下完成 data 包重构。
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

// WinPEImg 是 PE 下载与提取流程使用的统一结构。
//
// Links 保存候选下载地址，Grp 用于区分规则分组，Ver 用于排序，
// OffsetStart/OffsetEnd 仅在下载的是封装 exe、需要从中剥离 boot.wim 时才会使用。
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

// ruleItemsSource 表示一个规则文件解析后的聚合结果。
//
// Source / Rank / RulePath 都是规则文件级元信息，Items 是该规则产出的统一条目列表。
type ruleItemsSource struct {
	RulePath string
	Source   string
	Rank     int
	Items    []RuleItem
}

// winImgCandidate 用于镜像候选项排序和去重。
//
// 这里额外保留规则文件来源，是为了在同一条镜像由多个来源同时命中时，
// 可以先按 Rank 决定优先级，再用来源和文件路径做稳定排序。
type winImgCandidate struct {
	Item     WinImg
	RulePath string
	Source   string
	Rank     int
}

// peRuleCandidate 用于 PE 规则排序与架构选择。
type peRuleCandidate struct {
	Item     WinPEImg
	RulePath string
	Source   string
	Rank     int
}

// GetWinImgs 扫描指定系统目录下的全部镜像规则，并返回去重后的镜像列表。
//
// 目录规则约定如下：
//   - rules/core/image-sources/7  只存放 Win7 规则
//   - rules/core/image-sources/8  只存放 Win8 规则
//   - rules/core/image-sources/10 只存放 Win10 规则
//   - rules/core/image-sources/11 只存放 Win11 规则
//
// 函数不会按文件名挑规则，只会递归扫描目录中的全部 json，
// 因此后续新增来源时只需要把规则文件放到对应目录即可。
func GetWinImgs(system string) ([]WinImg, error) {
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
		log.LogWrite(0, "[GetWinImgs] 加载镜像规则失败: system=%s err=%v", systemCode, err)
		return nil, err
	}

	candidates := make([]winImgCandidate, 0, 16)
	seen := map[string]struct{}{}
	for _, src := range sources {
		for _, item := range src.Items {
			img := ruleItemToWinImg(item)
			if !hasWinImgValue(img) {
				continue
			}

			key := buildWinImgKey(img)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}

			candidates = append(candidates, winImgCandidate{
				Item:     img,
				RulePath: src.RulePath,
				Source:   src.Source,
				Rank:     src.Rank,
			})
		}
	}

	sortWinImgCandidates(candidates)
	out := make([]WinImg, 0, len(candidates))
	for _, cand := range candidates {
		out = append(out, cand.Item)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("未找到可用的镜像规则结果")
	}
	return out, nil
}

// PickImage 从镜像列表中挑选一个默认项。
//
// 旧流程默认优先 64 位，其次 32 位，最后回退到第一项；
// 这里继续保留这个策略，避免影响安装入口的既有行为。
func PickImage(ent []WinImg) (*WinImg, error) {
	if len(ent) == 0 {
		return nil, fmt.Errorf("镜像列表为空")
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

// ImgLink 返回镜像的首选下载地址。
//
// 旧结构只有 Link / Link2 两个字段，因此这里维持“先主链后备用链”的选择方式。
func ImgLink(it WinImg) (string, error) {
	ln := strings.TrimSpace(it.Link)
	if ln == "" {
		ln = strings.TrimSpace(it.Link2)
	}
	if ln == "" {
		log.LogWrite(0, "[ImgLink] 镜像缺少可用下载地址: file=%s arch=%s", it.File, it.Arch)
		return "", fmt.Errorf("镜像缺少可用下载地址")
	}
	return ln, nil
}

// ImgName 根据镜像元数据推导最终文件名。
//
// 优先使用规则里显式给出的 File；如果没有，则尝试从下载链接中截取文件名；
// 再不行就按链接后缀回退，最后兜底生成一个 windows_image.* 名称。
func ImgName(it WinImg, ln string) string {
	if strings.TrimSpace(it.File) != "" {
		return it.File
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

// GetWinPE 扫描全部 PE 规则并返回排序后的候选列表。
//
// 是否优先完全由规则文件里的 Rank 决定，目录名本身不再隐式参与排序。
func GetWinPE() ([]WinPEImg, error) {
	candidates, err := loadPERules()
	if err != nil {
		log.LogWrite(0, "[GetWinPE] 加载 PE 规则失败: err=%v", err)
		return nil, err
	}

	out := make([]WinPEImg, 0, len(candidates))
	for _, cand := range candidates {
		out = append(out, cand.Item)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("未找到可用的 PE 规则结果")
	}
	return out, nil
}

// splitPipeList 把 "a | b" 或 "a|b" 形式的文本拆成列表。
//
// 目前主要用于解析 offset 和某些规则里手写的多值字段。
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

// parseOffset 解析 "起始 | 结束" 形式的偏移区间。
//
// 规则里允许写十进制或带前缀的整数；如果字段为空或格式不完整，
// 会返回 ok=false，而不是直接把它视为错误。
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

// PELnk 返回当前系统推荐使用的 PE 下载信息。
//
// 选择过程分两步：
//  1. 先按规则 Rank、版本号、名称等维度得到全局有序列表
//  2. 再结合当前系统架构优先挑选同架构条目，找不到才回退到第一项
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

// loadPERules 递归扫描 pe-sources 目录，并把所有规则转成 WinPEImg 候选项。
//
// 这里会处理三件事：
//  1. 调用统一解析器读取规则
//  2. 解析 offset，补齐 PE 专属字段
//  3. 按 Rank 去重排序，供 GetWinPE / PELnk 复用
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
		sourceName := firstNonEmptyString(strings.TrimSpace(src.Source), strings.TrimSuffix(filepath.Base(src.RulePath), filepath.Ext(src.RulePath)))

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

			name := firstNonEmptyString(strings.TrimSpace(item.Name), strings.TrimSpace(item.FileName), sourceName)
			ver := firstNonEmptyString(strings.TrimSpace(item.Ver), strings.TrimSpace(item.Name), sourceName)
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
		return nil, fmt.Errorf("未找到可用的 PE 规则结果")
	}
	return out, nil
}

// selectPE 在已排序好的候选列表中选择最适合当前系统架构的一项。
//
// 列表本身已经按 Rank 和版本优先级排好序，因此这里只做最小决策：
// 先找同架构，找不到就回退到第一项。
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

// loadRules 递归扫描目录中的全部 json 规则文件，并过滤掉禁用项。
//
// 这个函数是 data.go 和 parser.go 之间的桥梁：
// parser.go 负责“解析单个规则文件”，这里负责“目录聚合、容错、排序”。
//
// 设计上允许某个规则文件解析失败但其他规则继续工作，
// 只有当整个目录都没有任何有效结果时才返回错误。
func loadRules(dir string) ([]ruleItemsSource, error) {
	files, err := collectJSON(dir)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("规则目录下没有找到 json 文件: %s", dir)
	}

	out := make([]ruleItemsSource, 0, len(files))
	var errs []string
	for _, file := range files {
		res, err := ParseRuleFile(file)
		if err != nil {
			log.LogWrite(0, "[loadRules] 解析规则文件失败: file=%s err=%v", file, err)
			errs = append(errs, fmt.Sprintf("%s: %v", file, err))
			continue
		}
		if !res.Enabled {
			log.LogWrite(0, "[loadRules] 跳过已禁用规则: file=%s source=%s", file, res.Source)
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
		return nil, fmt.Errorf("规则目录没有成功加载任何可用规则: %s", strings.Join(errs, " | "))
	}
	return nil, fmt.Errorf("规则目录下没有可用规则结果: %s", dir)
}

// imageRulesDir 返回指定系统的镜像规则目录。
func imageRulesDir(system string) (string, error) {
	root, err := rulesCoreDir()
	if err != nil {
		return "", err
	}

	dir := filepath.Join(root, "image-sources", system)
	if st, err := os.Stat(dir); err == nil && st.IsDir() {
		return dir, nil
	}
	return "", fmt.Errorf("镜像规则目录不存在: %s", dir)
}

// peRulesDir 返回 PE 规则根目录。
func peRulesDir() (string, error) {
	root, err := rulesCoreDir()
	if err != nil {
		return "", err
	}

	dir := filepath.Join(root, "pe-sources")
	if st, err := os.Stat(dir); err == nil && st.IsDir() {
		return dir, nil
	}
	return "", fmt.Errorf("PE 规则目录不存在: %s", dir)
}

// rulesCoreDir 在可执行文件目录和当前工作目录附近寻找 rules/core。
//
// 这样可以同时兼容：
//   - 直接在源码目录运行
//   - 从构建产物目录运行
func rulesCoreDir() (string, error) {
	candidates := make([]string, 0, 4)
	if exe, err := os.Executable(); err == nil && strings.TrimSpace(exe) != "" {
		exeDir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(exeDir, "rules", "core"),
			filepath.Join(exeDir, "..", "rules", "core"),
		)
	}
	if wd, err := os.Getwd(); err == nil && strings.TrimSpace(wd) != "" {
		candidates = append(candidates, filepath.Join(wd, "rules", "core"))
	}

	seen := map[string]struct{}{}
	for _, cand := range candidates {
		if cand == "" {
			continue
		}
		abs, err := filepath.Abs(cand)
		if err != nil {
			continue
		}
		if _, ok := seen[abs]; ok {
			continue
		}
		seen[abs] = struct{}{}

		if st, err := os.Stat(abs); err == nil && st.IsDir() {
			return abs, nil
		}
	}
	return "", fmt.Errorf("未找到 rules/core 目录")
}

// collectJSON 递归收集目录下全部 json 文件，并按路径排序。
//
// 排序可以保证目录扫描结果稳定，避免同 Rank 来源在不同机器上顺序漂移。
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

// normalizeSystemCode 把各种系统写法归一成规则目录使用的数字代号。
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
		return "", fmt.Errorf("不支持的系统代号: %s", system)
	}
}

// ruleItemToWinImg 把统一规则条目压缩成旧镜像结构。
func ruleItemToWinImg(item RuleItem) WinImg {
	var link1, link2 string
	if len(item.Link.Links) > 0 {
		link1 = strings.TrimSpace(item.Link.Links[0])
	}
	if len(item.Link.Links) > 1 {
		link2 = strings.TrimSpace(item.Link.Links[1])
	}
	return WinImg{
		Arch:  normalizeArch(item.Arch),
		Type:  defaultLinkType(item.Link.Type),
		SHA1:  strings.TrimSpace(item.Hash.Sha1),
		Link:  link1,
		Link2: link2,
		Size:  item.Size,
		Index: item.Index,
		File:  strings.TrimSpace(item.FileName),
	}
}

// buildWinImgKey 生成镜像去重键。
func buildWinImgKey(it WinImg) string {
	return strings.Join([]string{
		strings.TrimSpace(it.Arch),
		strings.TrimSpace(it.Type),
		strings.TrimSpace(it.SHA1),
		strings.TrimSpace(it.Link),
		strings.TrimSpace(it.Link2),
		strings.TrimSpace(it.File),
		strconv.Itoa(it.Index),
	}, "|")
}

// buildWinPEKey 生成 PE 去重键。
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

// sortRuleSources 对规则文件结果做稳定排序。
//
// 先按 Rank 降序，再按来源名和路径做稳定排序。
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

// sortWinImgCandidates 对镜像候选项做最终排序。
func sortWinImgCandidates(items []winImgCandidate) {
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Rank != items[j].Rank {
			return items[i].Rank > items[j].Rank
		}
		if strings.TrimSpace(items[i].Item.Type) != strings.TrimSpace(items[j].Item.Type) {
			return strings.TrimSpace(items[i].Item.Type) < strings.TrimSpace(items[j].Item.Type)
		}
		if items[i].Item.Index != items[j].Item.Index {
			return items[i].Item.Index > items[j].Item.Index
		}
		if strings.TrimSpace(items[i].Item.File) != strings.TrimSpace(items[j].Item.File) {
			return strings.TrimSpace(items[i].Item.File) < strings.TrimSpace(items[j].Item.File)
		}
		if strings.TrimSpace(items[i].Source) != strings.TrimSpace(items[j].Source) {
			return strings.TrimSpace(items[i].Source) < strings.TrimSpace(items[j].Source)
		}
		return buildWinImgKey(items[i].Item) < buildWinImgKey(items[j].Item)
	})
}

// sortPE 对 PE 候选项做稳定排序。
//
// 先看 Rank，再看版本号，最后回落到名称和来源，保证排序可预期。
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

// hasWinImgValue 判断条目是否至少具备镜像下载所需的最小字段。
func hasWinImgValue(it WinImg) bool {
	return strings.TrimSpace(it.File) != "" ||
		strings.TrimSpace(it.Link) != "" ||
		strings.TrimSpace(it.Link2) != ""
}

// hasWinPEValue 判断条目是否至少具备 PE 下载所需的最小字段。
func hasWinPEValue(it WinPEImg) bool {
	return strings.TrimSpace(it.Name) != "" && len(it.Links) > 0
}

// normalizeArch 统一常见架构写法，减少规则写法差异带来的匹配问题。
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

// peGroupFromRule 根据规则文件相对路径推导分组名。
//
// 例如：
//   - pe-sources/direct/a.json -> direct
//   - pe-sources/easyrc.json   -> easyrc
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

// ruleVerScore 从版本号、名称等字符串里提取第一个可比较的数字版本。
//
// 它主要用于 PE 排序，不追求特别智能，只要能把 2.3 排在 2.2 前面即可。
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
