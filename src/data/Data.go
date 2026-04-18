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

// WinPEImg represents a normalized WinPE download item.
//
// WinPE downloads still need offsets, group names, and checksums,
// so those fields stay off the generic RuleItem.
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

// ruleItemsSource represents the aggregated result of one parsed rule file.
// Source, Rank, and RulePath are file-level metadata,
// Items is the unified item list produced by that file.
type ruleItemsSource struct {
	RulePath string
	Source   string
	Rank     int
	Items    []RuleItem
}

// imageRuleCandidate represents a normalized image rule item and its origin.
// We keep the rule file path, source name, and Rank so aggregation can sort
// and deduplicate across files consistently.
type imageRuleCandidate struct {
	Item     RuleItem
	RulePath string
	Source   string
	Rank     int
}

// peRuleCandidate represents a normalized PE candidate and its origin.
type peRuleCandidate struct {
	Item     WinPEImg
	RulePath string
	Source   string
	Rank     int
}

// GetInstallImageItems scans all image rules under the target system directory.
//
// It normalizes, deduplicates, and sorts the result before returning the
// final RuleItem list that can be used directly for downloads.
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

// RuleItemFileName returns the recommended filename for a rule item.
//
// Priority:
// 1. Explicit FileName from the rule
// 2. basename derived from the download URL
// 3. windows_image.<ext> when only an extension is available
// 4. fallback to windows_image.iso
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

// GetWinPE scans all PE rules and returns the sorted PE list.
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

// splitPipeList splits text like "a | b" or "a|b" into a string slice.
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

// parseOffset parses a "start | end" offset range.
//
// Empty or incomplete values return ok=false instead of being treated as
// hard errors.
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

// PELnk returns the recommended PE download info for the current system.
//
// Rules are sorted by Rank and version first, then we prefer the matching
// architecture for the current machine.
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

// loadPERules recursively scans pe-sources and converts the result to WinPEImg.
//
// It also handles offset, group names, and deduped ordering for GetWinPE and
// PELnk.
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
		return nil, fmt.Errorf("未找到可用的 PE 规则结果")
	}
	return out, nil
}

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

// loadRules recursively scans all JSON rule files under a directory and skips
// disabled entries.
//
// parser.go parses one rule file; this layer only handles directory
// aggregation, error tolerance, and sorting.
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

// imageRulesDir returns the image rule directory for the selected system.
func imageRulesDir(system string) (string, error) {
	root, err := utils.ProjectDir("rules", "core")
	if err != nil {
		return "", err
	}

	dir := filepath.Join(root, "image-sources", system)
	if st, err := os.Stat(dir); err == nil && st.IsDir() {
		return dir, nil
	}
	return "", fmt.Errorf("镜像规则目录不存在: %s", dir)
}

// peRulesDir returns the PE rule root directory.
func peRulesDir() (string, error) {
	root, err := utils.ProjectDir("rules", "core")
	if err != nil {
		return "", err
	}

	dir := filepath.Join(root, "pe-sources")
	if st, err := os.Stat(dir); err == nil && st.IsDir() {
		return dir, nil
	}
	return "", fmt.Errorf("PE 规则目录不存在: %s", dir)
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

// normalizeSystemCode normalizes system aliases into the numeric code used by
// rule directories.
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

// normalizeImageRuleItem
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

// buildImageRuleKey builds a stable deduplication key for image rules.
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

// buildWinPEKey builds a stable deduplication key for PE candidates.
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

// sortRuleSources sorts rule results by Rank, source name, and rule path.
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

// sortImageRuleCandidates performs the final ordering for image candidates.
//
// Higher Rank sources come first; within the same Rank we prefer URL, then
// index, filename, and source name for stable ordering.
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

// sortPE performs stable ordering for PE candidates.
//
// We compare Rank first, then the best comparable version, then fall back
// to name and source.
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

// hasImageRuleValue reports whether an image rule has at least a filename or
// download link.
func hasImageRuleValue(it RuleItem) bool {
	return strings.TrimSpace(it.FileName) != "" || len(it.Link.Links) > 0
}

// hasWinPEValue reports whether a PE rule has at least a name and links.
func hasWinPEValue(it WinPEImg) bool {
	return strings.TrimSpace(it.Name) != "" && len(it.Links) > 0
}

// compactRuleLinks drops empty links and deduplicates by first occurrence.
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

// normalizeArch maps common architecture aliases into a canonical value.
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

// peGroupFromRule derives the group name from a rule file path.
//
// Example:
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

// ruleVerScore extracts the first comparable numeric version from a version
// string or name.
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
