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

// WinPEImg 表示已经完成聚合和规范化的 WinPE 下载项。
//
// PE 下载流程仍然需要保留偏移量、分组名和校验信息，
// 这些字段不适合直接挂在通用的 RuleItem 上。
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

// ruleItemsSource 表示单个规则文件解析后的聚合结果。
//
// Source、Rank 和 RulePath 属于规则文件级元数据，
// Items 则是该规则文件产出的统一条目列表。
type ruleItemsSource struct {
	RulePath string
	Source   string
	Rank     int
	Items    []RuleItem
}

// imageRuleCandidate 表示规范化后的镜像规则项及其来源信息。
//
// 这里额外保留规则文件路径、来源名和 Rank，
// 便于聚合后做稳定排序和跨文件去重。
type imageRuleCandidate struct {
	Item     RuleItem
	RulePath string
	Source   string
	Rank     int
}

// peRuleCandidate 表示规范化后的 PE 候选项及其来源信息。
type peRuleCandidate struct {
	Item     WinPEImg
	RulePath string
	Source   string
	Rank     int
}

// GetInstallImageItems 扫描指定系统目录下的全部镜像规则。
//
// 该函数会完成规范化、去重和排序，最终返回可直接用于下载的 RuleItem 列表。
// 新规则只要放进对应系统目录并通过解析，就会自动参与结果聚合。
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
		log.LogWrite(0, "[GetInstallImageItems] 加载镜像规则失败: system=%s err=%v", systemCode, err)
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
		return nil, fmt.Errorf("未找到可用的镜像规则结果")
	}
	return out, nil
}

// RuleItemFileName 返回规则项建议使用的文件名。
//
// 优先级如下：
// 1. 规则里显式给出的 FileName
// 2. 从下载链接里推导出的 basename
// 3. 仅能拿到扩展名时回退为 windows_image.<ext>
// 4. 最终兜底为 windows_image.iso
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

// GetWinPE 扫描全部 PE 规则并返回排序后的 PE 列表。
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

// splitPipeList 把形如 "a | b" 或 "a|b" 的文本拆成字符串列表。
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
// 字段为空或格式不完整时返回 ok=false，不直接视为错误。
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
// 规则会先按 Rank 和版本号排序，再结合当前系统架构优先选择同架构项。
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

// loadPERules 递归扫描 pe-sources 目录，并把规则结果转换成 WinPEImg。
//
// 这里会额外处理 offset、分组名和去重排序，供 GetWinPE 和 PELnk 共用。
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
		sourceName := firstNonEmptyString(
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

			name := firstNonEmptyString(
				strings.TrimSpace(item.Name),
				strings.TrimSpace(item.FileName),
				sourceName,
			)
			ver := firstNonEmptyString(
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
		return nil, fmt.Errorf("未找到可用的 PE 规则结果")
	}
	return out, nil
}

// selectPE 在已排序的候选列表中选择最适合当前架构的一项。
//
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
// parser.go 负责解析单个规则文件，这里只负责目录聚合、容错和排序。
// 只有当整个目录都没有任何可用结果时，才返回错误。
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

// imageRulesDir 返回指定系统对应的镜像规则目录。
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

// rulesCoreDir 在可执行文件目录和当前工作目录附近查找 rules/core。
//
// 这样可以兼容直接在源码目录运行，以及从构建产物目录运行两种场景。
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

// normalizeSystemCode 把不同写法的系统名归一成规则目录使用的数字代号。
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

// normalizeImageRuleItem 只整理会影响筛选、排序和校验的字段。
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

// buildImageRuleKey 生成镜像规则的稳定去重键。
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

// buildWinPEKey 生成 WinPE 候选项的稳定去重键。
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

// sortRuleSources 按 Rank、来源名和规则路径对规则结果做稳定排序。
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

// sortImageRuleCandidates 对镜像候选项做最终排序。
//
// 更高 Rank 的来源排在前面；同 Rank 下优先 URL；
// 再按 index、文件名和来源名保持顺序稳定。
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

// sortPE 对 PE 候选项做稳定排序。
//
// 先看 Rank，再看可比较的版本号，最后回退到名称和来源名。
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

// hasImageRuleValue 判断镜像规则是否至少具备文件名或下载链接。
func hasImageRuleValue(it RuleItem) bool {
	return strings.TrimSpace(it.FileName) != "" || len(it.Link.Links) > 0
}

// hasWinPEValue 判断 PE 规则是否至少具备名称和下载链接。
func hasWinPEValue(it WinPEImg) bool {
	return strings.TrimSpace(it.Name) != "" && len(it.Links) > 0
}

// compactRuleLinks 去掉空链接并按首次出现顺序去重。
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

// normalizeArch 把常见架构别名映射成统一值。
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

// peGroupFromRule 根据规则文件的相对路径推导分组名。
//
// 例如：
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

// ruleVerScore 从版本号或名称里提取第一个可比较的数字版本。
//
// 这里只做简单排序辅助，不追求复杂语义化版本比较。
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
