package data

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

// RuleHash 淇濆瓨瑙勫垯瑙ｆ瀽鍑虹殑鏍￠獙鍊笺€?
type RuleHash struct {
	Sha1   string
	Sha256 string
	MD5    string
}

// RuleLink 淇濆瓨瑙勫垯瑙ｆ瀽鍑虹殑涓嬭浇閾炬帴銆?
type RuleLink struct {
	Type  string
	Links []string
}

// RuleItem 鏄鍒欒В鏋愬悗鐨勭粺涓€缁撴灉銆?
type RuleItem struct {
	ID          string
	Source      string
	Rank        int
	System      string
	Name        string
	FileName    string
	Description string
	PublishDate string
	Language    string
	Arch        string
	Size        float64
	SizeUnit    string
	Edition     string
	Ver         string
	Index       int
	Hash        RuleHash
	Link        RuleLink
	Offset      string
}

// RuleParseResult 鎻忚堪涓€涓鍒欐枃浠剁殑瑙ｆ瀽缁撴灉銆?
type RuleParseResult struct {
	RulePath string
	Source   string
	Rank     int
	Enabled  bool
	Mode     string
	System   string
	SizeUnit string
	Items    []RuleItem
}

type ruleFile struct {
	Source   string                       `json:"Source"`
	Rank     int                          `json:"Rank"`
	Enabled  *bool                        `json:"Enabled"`
	System   string                       `json:"system"`
	Parser   string                       `json:"parser"`
	URL      map[string]string            `json:"url"`
	Method   string                       `json:"method"`
	Headers  map[string]string            `json:"headers"`
	Data     map[string]any               `json:"data"`
	SizeUnit string                       `json:"SizeUnit"`
	Timeout  int                          `json:"timeout"`
	Rules    map[string]any               `json:"rules"`
	Items    map[string]any               `json:"items"`
	Sections map[string]map[string]string `json:"sections"`
	Group    sectionGroupRule             `json:"group"`
	FieldMap map[string]string            `json:"field_map"`
	Extract  map[string]textExtractRule   `json:"extract"`
}

type sectionGroupRule struct {
	KeyRegex       string   `json:"key_regex"`
	AllowedNumbers []string `json:"allowed_numbers"`
	RequiredFields []string `json:"required_fields"`
}

type textExtractRule struct {
	From  string `json:"from"`
	Regex string `json:"regex"`
	Type  string `json:"type"`
}

type iterMode string

const (
	iterSingle iterMode = "single"
	iterArray  iterMode = "array"
	iterObject iterMode = "object"
)

type iterContext struct {
	mode iterMode
	key  string
	item any
}

type pathToken struct {
	kind  string
	field string
	index int
}

// ParseRuleFile 璇诲彇骞惰В鏋愪竴涓鍒欐枃浠躲€?
func ParseRuleFile(rulePath string) (*RuleParseResult, error) {
	rulePath = strings.TrimSpace(rulePath)
	if rulePath == "" {
		return nil, fmt.Errorf("瑙勫垯鏂囦欢璺緞涓嶈兘涓虹┖")
	}

	b, err := os.ReadFile(rulePath)
	if err != nil {
		return nil, fmt.Errorf("璇诲彇瑙勫垯鏂囦欢澶辫触: %w", err)
	}

	var rf ruleFile
	if err := json.Unmarshal(b, &rf); err != nil {
		return nil, fmt.Errorf("瑙ｆ瀽瑙勫垯鏂囦欢澶辫触: %w", err)
	}

	rf.Method = strings.ToLower(strings.TrimSpace(rf.Method))
	if rf.Method == "" {
		rf.Method = http.MethodGet
	}
	if rf.SizeUnit == "" {
		rf.SizeUnit = "B"
	}
	if rf.Timeout <= 0 {
		rf.Timeout = 8000
	}

	res := &RuleParseResult{
		RulePath: rulePath,
		Source:   defaultRuleSource(rulePath, rf.Source),
		Rank:     rf.Rank,
		Enabled:  ruleEnabled(rf.Enabled),
		System:   strings.TrimSpace(rf.System),
		SizeUnit: strings.TrimSpace(rf.SizeUnit),
	}

	switch {
	case strings.TrimSpace(rf.Parser) != "":
		res.Mode = strings.ToLower(strings.TrimSpace(rf.Parser))
		switch res.Mode {
		case "section_kv_group_v1":
			res.Items, err = parseSectionKVGroupRule(rf)
		default:
			err = fmt.Errorf("涓嶆敮鎸佺殑 parser: %s", rf.Parser)
		}
	case len(rf.Items) > 0:
		res.Mode = "items"
		res.Items, err = parseRuleItems(rf)
	case len(rf.Rules) > 0:
		res.Mode = "rules"
		res.Items, err = parseRuleRules(rf)
	default:
		err = fmt.Errorf("瑙勫垯鏂囦欢涓棦娌℃湁 items 涔熸病鏈?rules")
	}
	if err != nil {
		return nil, err
	}

	applyRuleMeta(res)
	sortRuleItems(res.Items)
	return res, nil
}

func defaultRuleSource(rulePath, source string) string {
	source = strings.TrimSpace(source)
	if source != "" {
		return source
	}
	return strings.TrimSuffix(filepath.Base(rulePath), filepath.Ext(rulePath))
}

func ruleEnabled(enabled *bool) bool {
	if enabled == nil {
		return true
	}
	return *enabled
}

func applyRuleMeta(res *RuleParseResult) {
	if res == nil {
		return
	}
	res.Source = defaultRuleSource(res.RulePath, res.Source)
	for i := range res.Items {
		res.Items[i].Source = firstNonEmptyString(strings.TrimSpace(res.Items[i].Source), res.Source)
		res.Items[i].Rank = res.Rank
		if strings.TrimSpace(res.Items[i].System) == "" {
			res.Items[i].System = res.System
		}
		if strings.TrimSpace(res.Items[i].SizeUnit) == "" {
			res.Items[i].SizeUnit = res.SizeUnit
		}
	}
}

// ParseRuleItems parses one rule file and returns its generic RuleItem entries.
func ParseRuleItems(rulePath string) ([]RuleItem, error) {
	res, err := ParseRuleFile(rulePath)
	if err != nil {
		return nil, err
	}
	return res.Items, nil
}

// ParseRuleWinPEs converts generic rule items into WinPE-specific entries.
func ParseRuleWinPEs(rulePath string) ([]WinPEImg, error) {
	items, err := ParseRuleItems(rulePath)
	if err != nil {
		return nil, err
	}

	out := make([]WinPEImg, 0, len(items))
	for _, it := range items {
		var start, end int64
		if s, e, ok, err := parseOffset(it.Offset); err == nil && ok {
			start, end = s, e
		}

		name := strings.TrimSpace(it.Name)
		if name == "" {
			name = strings.TrimSpace(it.FileName)
		}
		if name == "" {
			name = filepath.Base(rulePath)
		}

		out = append(out, WinPEImg{
			Name:        name,
			Arch:        it.Arch,
			Links:       append([]string(nil), it.Link.Links...),
			Sz:          it.Size,
			MD5:         it.Hash.MD5,
			OffsetStart: start,
			OffsetEnd:   end,
		})
	}
	return out, nil
}

// parseRuleItems 瑙ｆ瀽鐩撮摼妯″紡銆?
func parseRuleItems(rf ruleFile) ([]RuleItem, error) {
	keys := sortedMapKeys(rf.Items)
	out := make([]RuleItem, 0, len(keys))

	for _, key := range keys {
		rawMap, ok := rf.Items[key].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("items.%s 涓嶆槸瀵硅薄", key)
		}
		it, err := buildRuleItemFromMap(key, rawMap, rf.System, rf.SizeUnit)
		if err != nil {
			return nil, err
		}
		out = append(out, it)
	}

	return out, nil
}

// parseRuleRules 瑙ｆ瀽杩滅▼鎺ュ彛妯″紡銆?
func parseRuleRules(rf ruleFile) ([]RuleItem, error) {
	urls := sortedStringMapValues(rf.URL)
	if len(urls) == 0 {
		return nil, fmt.Errorf("rules 妯″紡缂哄皯 url")
	}

	var out []RuleItem
	seen := map[string]struct{}{}
	var errs []string

	for _, rawURL := range urls {
		root, err := fetchRuleJSON(rf, rawURL)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", rawURL, err))
			continue
		}

		items, err := parseRuleItemsFromRoot(rf, root)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", rawURL, err))
			continue
		}

		for _, it := range items {
			k := buildRuleItemKey(it)
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			out = append(out, it)
		}
	}

	if len(out) > 0 {
		return out, nil
	}
	if len(errs) == 0 {
		return nil, fmt.Errorf("瑙勫垯鏈В鏋愬嚭浠讳綍缁撴灉")
	}
	return nil, fmt.Errorf("瑙勫垯瑙ｆ瀽澶辫触: %s", strings.Join(errs, " | "))
}

// parseSectionKVGroupRule 瑙ｆ瀽鍒嗘閿€兼枃鏈€?
func parseSectionKVGroupRule(rf ruleFile) ([]RuleItem, error) {
	urls := sortedStringMapValues(rf.URL)
	if len(urls) == 0 {
		return nil, fmt.Errorf("section_kv_group_v1 妯″紡缂哄皯 url")
	}

	var out []RuleItem
	seen := map[string]struct{}{}
	var errs []string

	for _, rawURL := range urls {
		text, err := fetchRuleText(rf, rawURL)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", rawURL, err))
			continue
		}

		items, err := parseSectionKVGroupText(rf, text, rawURL)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", rawURL, err))
			continue
		}

		for _, it := range items {
			k := buildRuleItemKey(it)
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			out = append(out, it)
		}
	}

	if len(out) > 0 {
		return out, nil
	}
	if len(errs) == 0 {
		return nil, fmt.Errorf("瑙勫垯鏈В鏋愬嚭浠讳綍缁撴灉")
	}
	return nil, fmt.Errorf("瑙勫垯瑙ｆ瀽澶辫触: %s", strings.Join(errs, " | "))
}

// parseSectionKVGroupText 鎸夎鍒欐媶瑙ｄ竴娈靛垎娈甸敭鍊兼枃鏈€?
func parseSectionKVGroupText(rf ruleFile, text string, sourceURL string) ([]RuleItem, error) {
	blocks := parseSectionBlocks(text)
	if len(blocks) == 0 {
		return nil, fmt.Errorf("未找到任何 [Section] 段")
	}

	keyRx, err := compileGroupRegex(rf.Group.KeyRegex)
	if err != nil {
		return nil, err
	}

	fieldMap := defaultSectionFieldMap(rf.FieldMap)
	sectionNames := resolveSectionNames(rf.Sections, blocks)
	out := make([]RuleItem, 0)

	for _, sectionName := range sectionNames {
		block, ok := blocks[sectionName]
		if !ok {
			continue
		}

		kvMap := parseLooseKVBlock(block)
		grouped := groupSectionKV(kvMap, keyRx, rf.Group)
		groupKeys := sortedMapKeys(grouped)
		sort.SliceStable(groupKeys, func(i, j int) bool {
			return intValue(groupKeys[i]) < intValue(groupKeys[j])
		})

		for _, groupID := range groupKeys {
			item, ok, err := buildSectionRuleItem(
				rf,
				sourceURL,
				sectionName,
				groupID,
				rf.Sections[sectionName],
				grouped[groupID],
				fieldMap,
			)
			if err != nil {
				return nil, err
			}
			if !ok {
				continue
			}
			out = append(out, item)
		}
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("鏈В鏋愬嚭浠讳綍鍒嗙粍缁撴灉")
	}
	return out, nil
}

// fetchRuleBytes 鎸夎鍒欒姹傝繙绋嬪唴瀹广€?
func fetchRuleBytes(rf ruleFile, rawURL string) ([]byte, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil, fmt.Errorf("url 涓虹┖")
	}

	b, err := doRuleRequest(rf, rawURL, "")
	if err != nil {
		fallback, fallbackErr := fetchRuleBytesViaPowerShell(rf, rawURL, "")
		if fallbackErr != nil {
			return nil, err
		}
		b = fallback
	}

	if cookie := extractValidationCookie(b); cookie != "" {
		b, err = doRuleRequest(rf, rawURL, cookie)
		if err != nil {
			fallback, fallbackErr := fetchRuleBytesViaPowerShell(rf, rawURL, cookie)
			if fallbackErr != nil {
				return nil, err
			}
			b = fallback
		}
	}
	return b, nil
}

// fetchRuleText 鎷夊彇杩滅▼鏂囨湰鍐呭銆?
func fetchRuleText(rf ruleFile, rawURL string) (string, error) {
	b, err := fetchRuleBytes(rf, rawURL)
	if err != nil {
		return "", err
	}
	return decodeRuleText(b), nil
}

// doRuleRequest 鍙戣捣涓€娆¤鍒欒姹傦紝鍙檮鍔犻澶?Cookie銆?
func doRuleRequest(rf ruleFile, rawURL string, extraCookie string) ([]byte, error) {
	method := strings.ToUpper(strings.TrimSpace(rf.Method))
	if method == "" {
		method = http.MethodGet
	}
	client := &http.Client{Timeout: time.Duration(rf.Timeout) * time.Millisecond}

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		var body io.Reader
		if method == http.MethodPost && len(rf.Data) > 0 {
			b, err := json.Marshal(rf.Data)
			if err != nil {
				return nil, fmt.Errorf("搴忓垪鍖?post 鏁版嵁澶辫触: %w", err)
			}
			body = bytes.NewReader(b)
		}

		req, err := http.NewRequest(method, rawURL, body)
		if err != nil {
			return nil, fmt.Errorf("鍒涘缓璇锋眰澶辫触: %w", err)
		}

		for k, v := range rf.Headers {
			req.Header.Set(k, v)
		}
		if method == http.MethodPost && body != nil && req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/json")
		}
		if req.Header.Get("User-Agent") == "" {
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36")
		}
		if req.Header.Get("Accept") == "" {
			req.Header.Set("Accept", "*/*")
		}

		cookieHeader := strings.TrimSpace(req.Header.Get("Cookie"))
		if extraCookie != "" {
			req.Header.Set("Cookie", mergeCookieHeader(cookieHeader, extraCookie))
		}

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(300 * time.Millisecond)
			continue
		}
		b, err := func() ([]byte, error) {
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return nil, fmt.Errorf("http: %s", resp.Status)
			}
			return io.ReadAll(resp.Body)
		}()
		if err == nil {
			return b, nil
		}
		lastErr = err
		time.Sleep(300 * time.Millisecond)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("璇锋眰澶辫触")
	}
	return nil, lastErr
}

// extractValidationCookie 鎻愬彇椤甸潰涓殑 JS 鏍￠獙 Cookie銆?
func extractValidationCookie(body []byte) string {
	rx := regexp.MustCompile(`document\.cookie\s*=\s*"([^"]+)"`)
	matches := rx.FindSubmatch(body)
	if len(matches) < 2 {
		return ""
	}
	raw := strings.TrimSpace(string(matches[1]))
	if raw == "" {
		return ""
	}
	parts := strings.SplitN(raw, ";", 2)
	return strings.TrimSpace(parts[0])
}

// mergeCookieHeader 鍚堝苟宸叉湁 Cookie 鍜岄澶?Cookie銆?
func mergeCookieHeader(existing string, extra string) string {
	existing = strings.TrimSpace(existing)
	extra = strings.TrimSpace(extra)
	switch {
	case existing == "":
		return extra
	case extra == "":
		return existing
	case strings.Contains(existing, extra):
		return existing
	default:
		return existing + "; " + extra
	}
}

// fetchRuleBytesViaPowerShell 鍦?Windows 涓婂洖閫€鍒?PowerShell 璇锋眰銆?
func fetchRuleBytesViaPowerShell(rf ruleFile, rawURL string, extraCookie string) ([]byte, error) {
	if runtime.GOOS != "windows" {
		return nil, fmt.Errorf("powershell 鍥為€€浠呮敮鎸?windows")
	}

	method := strings.ToUpper(strings.TrimSpace(rf.Method))
	if method == "" {
		method = http.MethodGet
	}

	headers := make(map[string]string, len(rf.Headers)+2)
	for k, v := range rf.Headers {
		headers[k] = v
	}
	if strings.TrimSpace(headers["User-Agent"]) == "" {
		headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36"
	}
	if strings.TrimSpace(headers["Accept"]) == "" {
		headers["Accept"] = "*/*"
	}
	if extraCookie != "" {
		headers["Cookie"] = mergeCookieHeader(headers["Cookie"], extraCookie)
	}

	body := ""
	if method == http.MethodPost && len(rf.Data) > 0 {
		b, err := json.Marshal(rf.Data)
		if err != nil {
			return nil, fmt.Errorf("搴忓垪鍖?post 鏁版嵁澶辫触: %w", err)
		}
		body = string(b)
	}

	cmd := exec.Command(
		"powershell",
		"-NoProfile",
		"-ExecutionPolicy", "Bypass",
		"-Command",
		buildPowerShellRequestScript(rawURL, method, headers, body),
	)
	output, err := cmd.Output()
	if err == nil {
		return output, nil
	}

	if exitErr, ok := err.(*exec.ExitError); ok && len(exitErr.Stderr) > 0 {
		return nil, fmt.Errorf("powershell 璇锋眰澶辫触: %s", strings.TrimSpace(string(exitErr.Stderr)))
	}
	return nil, err
}

// buildPowerShellRequestScript 鐢熸垚鍥為€€璇锋眰鑴氭湰銆?
func buildPowerShellRequestScript(rawURL string, method string, headers map[string]string, body string) string {
	encode := func(v string) string {
		return base64.StdEncoding.EncodeToString([]byte(v))
	}

	var sb strings.Builder
	sb.WriteString("$ProgressPreference='SilentlyContinue';")
	sb.WriteString("[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false);")
	sb.WriteString("$url=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('")
	sb.WriteString(encode(rawURL))
	sb.WriteString("'));")
	sb.WriteString("$method='")
	sb.WriteString(strings.ReplaceAll(method, "'", "''"))
	sb.WriteString("';")
	sb.WriteString("$headers=@{};")

	for _, key := range sortedMapKeys(headers) {
		sb.WriteString("$headers['")
		sb.WriteString(strings.ReplaceAll(key, "'", "''"))
		sb.WriteString("']=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('")
		sb.WriteString(encode(headers[key]))
		sb.WriteString("'));")
	}

	if strings.TrimSpace(body) == "" {
		sb.WriteString("$resp=Invoke-WebRequest -UseBasicParsing -Uri $url -Method $method -Headers $headers;")
	} else {
		sb.WriteString("$body=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('")
		sb.WriteString(encode(body))
		sb.WriteString("'));")
		sb.WriteString("$resp=Invoke-WebRequest -UseBasicParsing -Uri $url -Method $method -Headers $headers -Body $body -ContentType 'application/json';")
	}
	sb.WriteString("[Console]::Write($resp.Content);")
	return sb.String()
}

// decodeRuleText 灏濊瘯鎶婅繙绋嬫枃鏈В鐮佹垚 UTF-8銆?
func decodeRuleText(body []byte) string {
	if utf8.Valid(body) {
		return string(body)
	}
	reader := transform.NewReader(bytes.NewReader(body), simplifiedchinese.GBK.NewDecoder())
	decoded, err := io.ReadAll(reader)
	if err != nil || len(decoded) == 0 {
		return string(body)
	}
	return string(decoded)
}

// fetchRuleJSON 鎸夎鍒欒姹傝繙绋?JSON銆?
func fetchRuleJSON(rf ruleFile, rawURL string) (any, error) {
	b, err := fetchRuleBytes(rf, rawURL)
	if err != nil {
		return nil, err
	}

	var root any
	if err := json.Unmarshal(b, &root); err != nil {
		return nil, fmt.Errorf("瑙ｆ瀽鍝嶅簲 JSON 澶辫触: %w", err)
	}
	return root, nil
}

// parseRuleItemsFromRoot 浠庤繙绋?JSON 涓彁鍙栫粨鏋滈」銆?
func parseRuleItemsFromRoot(rf ruleFile, root any) ([]RuleItem, error) {
	containerPath := findRuleIterPath(rf.Rules)
	ctxs, err := buildIterContexts(root, containerPath)
	if err != nil {
		return nil, err
	}

	out := make([]RuleItem, 0, len(ctxs))
	for idx, ctx := range ctxs {
		item, err := buildRuleItemFromRules(rf, root, ctx, idx)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, nil
}

// buildRuleItemFromRules 鎸変竴缁?rules 鎻愬彇涓€涓粨鏋滈」銆?
func buildRuleItemFromRules(rf ruleFile, root any, ctx iterContext, idx int) (RuleItem, error) {
	system := strings.TrimSpace(ruleValueString(rf.Rules["System"], root, ctx))
	if system == "" {
		system = strings.TrimSpace(rf.System)
	}

	item := RuleItem{
		ID:          strconv.Itoa(idx),
		System:      system,
		Name:        strings.TrimSpace(ruleValueString(rf.Rules["Name"], root, ctx)),
		FileName:    strings.TrimSpace(ruleValueString(rf.Rules["FileName"], root, ctx)),
		Description: strings.TrimSpace(ruleValueString(rf.Rules["Description"], root, ctx)),
		PublishDate: strings.TrimSpace(ruleValueString(rf.Rules["PublishDate"], root, ctx)),
		Language:    strings.TrimSpace(ruleValueString(rf.Rules["Language"], root, ctx)),
		Arch:        strings.TrimSpace(ruleValueString(rf.Rules["Arch"], root, ctx)),
		Size:        ruleValueFloat(rf.Rules["Size"], root, ctx),
		SizeUnit:    strings.TrimSpace(rf.SizeUnit),
		Edition:     strings.TrimSpace(ruleValueString(rf.Rules["Edition"], root, ctx)),
		Ver:         strings.TrimSpace(ruleValueString(rf.Rules["ver"], root, ctx)),
		Index:       ruleValueInt(rf.Rules["index"], root, ctx),
	}

	if item.Name == "" {
		item.Name = item.FileName
	}

	hashMap := mapValue(rf.Rules["hash"])
	item.Hash = RuleHash{
		Sha1:   firstNonEmptyString(ruleValueString(hashMap["Sha1"], root, ctx), ruleValueString(hashMap["SHA1"], root, ctx)),
		Sha256: firstNonEmptyString(ruleValueString(hashMap["Sha256"], root, ctx), ruleValueString(hashMap["SHA256"], root, ctx)),
		MD5:    ruleValueString(hashMap["MD5"], root, ctx),
	}

	linkMap := mapValue(rf.Rules["link"])
	item.Link = RuleLink{
		Type:  defaultLinkType(ruleValueString(linkMap["type"], root, ctx)),
		Links: collectLinkValues(linkMap, root, ctx),
	}

	return item, nil
}

// buildRuleItemFromMap 灏嗙洿閾?items 涓殑涓€涓璞¤浆鎹负缁熶竴缁撴灉銆?
func buildRuleItemFromMap(id string, rawMap map[string]any, defaultSystem, sizeUnit string) (RuleItem, error) {
	hashMap := mapValue(rawMap["hash"])
	linkMap := mapValue(rawMap["link"])

	item := RuleItem{
		ID:          strings.TrimSpace(id),
		System:      firstNonEmptyString(stringValue(rawMap["System"]), strings.TrimSpace(defaultSystem)),
		Name:        strings.TrimSpace(stringValue(rawMap["Name"])),
		FileName:    strings.TrimSpace(stringValue(rawMap["FileName"])),
		Description: strings.TrimSpace(firstNonEmptyString(stringValue(rawMap["Description"]), stringValue(rawMap["Desc"]))),
		PublishDate: strings.TrimSpace(firstNonEmptyString(stringValue(rawMap["PublishDate"]), stringValue(rawMap["Date"]))),
		Language:    strings.TrimSpace(stringValue(rawMap["Language"])),
		Arch:        strings.TrimSpace(stringValue(rawMap["Arch"])),
		Size:        floatValue(rawMap["Size"]),
		SizeUnit:    strings.TrimSpace(sizeUnit),
		Edition:     strings.TrimSpace(stringValue(rawMap["Edition"])),
		Ver:         strings.TrimSpace(firstNonEmptyString(stringValue(rawMap["ver"]), stringValue(rawMap["Ver"]))),
		Index:       intValue(rawMap["index"]),
		Offset:      strings.TrimSpace(stringValue(rawMap["offset"])),
		Hash: RuleHash{
			Sha1:   firstNonEmptyString(stringValue(hashMap["Sha1"]), stringValue(hashMap["SHA1"])),
			Sha256: firstNonEmptyString(stringValue(hashMap["Sha256"]), stringValue(hashMap["SHA256"])),
			MD5:    stringValue(hashMap["MD5"]),
		},
		Link: RuleLink{
			Type:  defaultLinkType(stringValue(linkMap["type"])),
			Links: collectLinkValues(linkMap, nil, iterContext{}),
		},
	}

	if item.Name == "" {
		item.Name = item.FileName
	}

	return item, nil
}

// buildIterContexts 鏍规嵁杩唬璺緞鏋勯€犱笂涓嬫枃銆?
func buildIterContexts(root any, containerPath string) ([]iterContext, error) {
	containerPath = strings.TrimSpace(containerPath)
	if containerPath == "" {
		return []iterContext{{mode: iterSingle, item: root}}, nil
	}

	container, err := resolveStaticPath(root, containerPath)
	if err != nil {
		return nil, err
	}

	switch vv := container.(type) {
	case []any:
		out := make([]iterContext, 0, len(vv))
		for _, item := range vv {
			out = append(out, iterContext{mode: iterArray, item: item})
		}
		return out, nil
	case map[string]any:
		keys := sortedMapKeys(vv)
		out := make([]iterContext, 0, len(keys))
		for _, key := range keys {
			out = append(out, iterContext{mode: iterObject, key: key, item: vv[key]})
		}
		return out, nil
	default:
		return []iterContext{{mode: iterSingle, item: container}}, nil
	}
}

// findRuleIterPath 鎺ㄦ柇 rules 鐨勮凯浠ｅ鍣ㄨ矾寰勩€?
func findRuleIterPath(rules map[string]any) string {
	candidates := []any{
		rules["System"],
		rules["Name"],
		rules["FileName"],
		rules["Description"],
		rules["PublishDate"],
		rules["Language"],
		rules["Edition"],
		rules["Arch"],
		rules["Size"],
		rules["ver"],
		rules["index"],
	}

	hashMap := mapValue(rules["hash"])
	candidates = append(candidates, hashMap["Sha1"], hashMap["SHA1"], hashMap["Sha256"], hashMap["SHA256"], hashMap["MD5"])

	linkMap := mapValue(rules["link"])
	candidates = append(candidates, linkMap["type"])
	for _, key := range sortedLinkKeys(linkMap) {
		candidates = append(candidates, linkMap[key])
	}

	for _, candidate := range candidates {
		path, ok := iterContainerPath(stringValue(candidate))
		if ok {
			return path
		}
	}
	return ""
}

// iterContainerPath 杩斿洖琛ㄨ揪寮忎腑杩唬瀹瑰櫒鐨勮矾寰勩€?
func iterContainerPath(expr string) (string, bool) {
	expr = strings.TrimSpace(expr)
	if expr == "" || !strings.HasPrefix(expr, "$") {
		return "", false
	}
	tokens, err := parsePath(expr)
	if err != nil {
		return "", false
	}
	var prefix []pathToken
	for _, tk := range tokens {
		if tk.kind == "special_number" || tk.kind == "special_key" {
			return tokensToPath(prefix), true
		}
		prefix = append(prefix, tk)
	}
	return "", false
}

// resolveStaticPath 鍙В鏋愪笉甯﹁凯浠ｅ崰浣嶇鐨勮矾寰勩€?
func resolveStaticPath(root any, expr string) (any, error) {
	if strings.TrimSpace(expr) == "" || strings.TrimSpace(expr) == "$" {
		return root, nil
	}

	tokens, err := parsePath(expr)
	if err != nil {
		return nil, err
	}

	cur := root
	for _, tk := range tokens {
		switch tk.kind {
		case "field":
			m, ok := cur.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("璺緞 %s 涓嶆槸瀵硅薄", expr)
			}
			cur = m[tk.field]
		case "index":
			arr, ok := cur.([]any)
			if !ok {
				return nil, fmt.Errorf("璺緞 %s 涓嶆槸鏁扮粍", expr)
			}
			if tk.index < 0 || tk.index >= len(arr) {
				return nil, fmt.Errorf("璺緞 %s 涓嬫爣瓒婄晫", expr)
			}
			cur = arr[tk.index]
		default:
			return nil, fmt.Errorf("璺緞 %s 鍖呭惈鍔ㄦ€佸崰浣嶇", expr)
		}
	}
	return cur, nil
}

// ruleValueString 瑙ｆ瀽瑙勫垯瀛楁锛屼紭鍏堟寜 DSL 鍙栧€硷紝鍚﹀垯褰撲綔甯搁噺銆?
func ruleValueString(def any, root any, ctx iterContext) string {
	val := ruleValueAny(def, root, ctx)
	return stringValue(val)
}

// ruleValueFloat 瑙ｆ瀽瑙勫垯涓殑鏁板瓧銆?
func ruleValueFloat(def any, root any, ctx iterContext) float64 {
	val := ruleValueAny(def, root, ctx)
	return floatValue(val)
}

// ruleValueInt 瑙ｆ瀽瑙勫垯涓殑鏁存暟銆?
func ruleValueInt(def any, root any, ctx iterContext) int {
	val := ruleValueAny(def, root, ctx)
	return intValue(val)
}

// ruleValueAny 瑙ｆ瀽瑙勫垯瀹氫箟涓殑鍗曚釜鍊笺€?
func ruleValueAny(def any, root any, ctx iterContext) any {
	switch vv := def.(type) {
	case nil:
		return ""
	case string:
		vv = strings.TrimSpace(vv)
		if vv == "" {
			return ""
		}
		if strings.HasPrefix(vv, "$") {
			if val, err := resolveDynamicPath(root, vv, ctx); err == nil {
				return val
			}
			return ""
		}
		return vv
	default:
		return vv
	}
}

// resolveDynamicPath 瑙ｆ瀽甯﹀崰浣嶇鐨勮矾寰勮〃杈惧紡銆?
func resolveDynamicPath(root any, expr string, ctx iterContext) (any, error) {
	tokens, err := parsePath(expr)
	if err != nil {
		return nil, err
	}

	cur := root
	for _, tk := range tokens {
		if cur == nil {
			return "", nil
		}

		switch tk.kind {
		case "field":
			m, ok := cur.(map[string]any)
			if !ok {
				return "", nil
			}
			cur = m[tk.field]
		case "index":
			arr, ok := cur.([]any)
			if !ok || tk.index < 0 || tk.index >= len(arr) {
				return "", nil
			}
			cur = arr[tk.index]
		case "special_number":
			cur = ctx.item
		case "special_key":
			cur = ctx.key
		default:
			return "", nil
		}
	}
	return cur, nil
}

// parsePath 灏嗚嚜瀹氫箟 DSL 鎷嗘垚 token銆?
func parsePath(expr string) ([]pathToken, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil, nil
	}
	if expr == "$" {
		return nil, nil
	}
	if !strings.HasPrefix(expr, "$") {
		return nil, fmt.Errorf("闈炴硶璺緞: %s", expr)
	}

	var tokens []pathToken
	for i := 1; i < len(expr); {
		switch expr[i] {
		case '.':
			i++
			start := i
			for i < len(expr) && expr[i] != '.' && expr[i] != '[' {
				i++
			}
			if start == i {
				return nil, fmt.Errorf("闈炴硶璺緞: %s", expr)
			}
			tokens = append(tokens, pathToken{kind: "field", field: expr[start:i]})
		case '[':
			end := strings.IndexByte(expr[i:], ']')
			if end < 0 {
				return nil, fmt.Errorf("闈炴硶璺緞: %s", expr)
			}
			end += i
			part := strings.TrimSpace(expr[i+1 : end])
			switch {
			case part == "number":
				tokens = append(tokens, pathToken{kind: "special_number"})
			case part == "key":
				tokens = append(tokens, pathToken{kind: "special_key"})
			default:
				n, err := strconv.Atoi(part)
				if err != nil {
					return nil, fmt.Errorf("闈炴硶涓嬫爣: %s", part)
				}
				tokens = append(tokens, pathToken{kind: "index", index: n})
			}
			i = end + 1
		default:
			return nil, fmt.Errorf("闈炴硶璺緞: %s", expr)
		}
	}
	return tokens, nil
}

// tokensToPath 鎶?token 閲嶆柊鎷煎洖闈欐€佽矾寰勩€?
func tokensToPath(tokens []pathToken) string {
	if len(tokens) == 0 {
		return "$"
	}
	var sb strings.Builder
	sb.WriteByte('$')
	for _, tk := range tokens {
		switch tk.kind {
		case "field":
			sb.WriteByte('.')
			sb.WriteString(tk.field)
		case "index":
			sb.WriteByte('[')
			sb.WriteString(strconv.Itoa(tk.index))
			sb.WriteByte(']')
		}
	}
	return sb.String()
}

// collectLinkValues 鎻愬彇 link1/link2...銆?
func collectLinkValues(linkMap map[string]any, root any, ctx iterContext) []string {
	keys := sortedLinkKeys(linkMap)
	seen := map[string]struct{}{}
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		link := strings.TrimSpace(ruleValueString(linkMap[key], root, ctx))
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

// sortedLinkKeys 鎸?link 搴忓彿鎺掑簭銆?
func sortedLinkKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		if strings.HasPrefix(strings.ToLower(k), "link") {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		return numericSuffix(keys[i]) < numericSuffix(keys[j])
	})
	return keys
}

// sortedMapKeys 杩斿洖绋冲畾鎺掑簭鍚庣殑閿悕銆?
func sortedMapKeys[T any](m map[string]T) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// sortedStringMapValues 鎸夐敭鍚嶉『搴忚繑鍥為潪绌哄€笺€?
func sortedStringMapValues(m map[string]string) []string {
	keys := sortedMapKeys(m)
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		v := strings.TrimSpace(m[key])
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// sortRuleItems 缁熶竴鎺掑簭锛屼究浜庢祴璇曞拰鎵撳嵃銆?
func sortRuleItems(items []RuleItem) {
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Index != items[j].Index {
			return items[i].Index > items[j].Index
		}
		if items[i].Name != items[j].Name {
			return items[i].Name < items[j].Name
		}
		if items[i].FileName != items[j].FileName {
			return items[i].FileName < items[j].FileName
		}
		return strings.Join(items[i].Link.Links, "|") < strings.Join(items[j].Link.Links, "|")
	})
}

// buildRuleItemKey 鐢熸垚鍘婚噸閿€?
func buildRuleItemKey(it RuleItem) string {
	return strings.Join([]string{
		it.System,
		it.Name,
		it.FileName,
		it.Language,
		it.Arch,
		it.Link.Type,
		strings.Join(it.Link.Links, "|"),
	}, "|")
}

// parseSectionBlocks 鎸?[Section] 鍒嗘銆?
func parseSectionBlocks(text string) map[string]string {
	rx := regexp.MustCompile(`\[(.*?)\]`)
	matches := rx.FindAllStringSubmatchIndex(text, -1)
	out := make(map[string]string, len(matches))

	for i, match := range matches {
		if len(match) < 4 {
			continue
		}
		name := strings.TrimSpace(text[match[2]:match[3]])
		if name == "" {
			continue
		}

		start := match[1]
		end := len(text)
		if i+1 < len(matches) {
			end = matches[i+1][0]
		}
		out[name] = strings.TrimSpace(text[start:end])
	}
	return out
}

// parseLooseKVBlock 瑙ｆ瀽涓€娈垫澗鏁ｆ帓鍒楃殑 key=value 鏂囨湰銆?
func parseLooseKVBlock(block string) map[string]string {
	rx := regexp.MustCompile(`(?:^|[\r\n\t ]+)([A-Za-z][A-Za-z0-9_]*)=`)
	matches := rx.FindAllStringSubmatchIndex(block, -1)
	out := make(map[string]string, len(matches))

	for i, match := range matches {
		if len(match) < 4 {
			continue
		}
		key := strings.TrimSpace(block[match[2]:match[3]])
		if key == "" {
			continue
		}

		start := match[1]
		end := len(block)
		if i+1 < len(matches) {
			end = matches[i+1][0]
		}
		out[key] = strings.TrimSpace(block[start:end])
	}
	return out
}

// compileGroupRegex 杩斿洖鍒嗙粍閿殑姝ｅ垯銆?
func compileGroupRegex(pattern string) (*regexp.Regexp, error) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		pattern = `^PE([0-9]+)(Name|Url|Url2|MS)$`
	}
	rx, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("group.key_regex 鏃犳晥: %w", err)
	}
	return rx, nil
}

// resolveSectionNames 杩斿洖闇€瑕佸鐞嗙殑娈靛悕鍒楄〃銆?
func resolveSectionNames(configured map[string]map[string]string, blocks map[string]string) []string {
	if len(configured) > 0 {
		return sortedMapKeys(configured)
	}
	return sortedMapKeys(blocks)
}

// defaultSectionFieldMap 瑙勮寖鍖栨枃鏈鍒欑殑瀛楁鏄犲皠銆?
func defaultSectionFieldMap(fieldMap map[string]string) map[string]string {
	out := map[string]string{
		"Name":  "Name",
		"Link1": "Url",
		"Link2": "Url2",
		"Meta":  "MS",
	}
	for k, v := range fieldMap {
		key := canonicalRuleField(k)
		if key == "" {
			continue
		}
		out[key] = strings.TrimSpace(v)
	}
	return out
}

// groupSectionKV 鎸?PE 缂栧彿鑱氬悎瀛楁銆?
func groupSectionKV(kvMap map[string]string, keyRx *regexp.Regexp, groupRule sectionGroupRule) map[string]map[string]string {
	allowed := make(map[string]struct{}, len(groupRule.AllowedNumbers))
	for _, num := range groupRule.AllowedNumbers {
		num = strings.TrimSpace(num)
		if num != "" {
			allowed[num] = struct{}{}
		}
	}

	out := map[string]map[string]string{}
	for _, key := range sortedMapKeys(kvMap) {
		num, field, ok := matchGroupedField(keyRx, key)
		if !ok {
			continue
		}
		if len(allowed) > 0 {
			if _, ok := allowed[num]; !ok {
				continue
			}
		}
		if _, ok := out[num]; !ok {
			out[num] = map[string]string{}
		}
		out[num][field] = strings.TrimSpace(kvMap[key])
	}

	if len(groupRule.RequiredFields) == 0 {
		return out
	}

	for num, fields := range out {
		missing := false
		for _, req := range groupRule.RequiredFields {
			req = strings.TrimSpace(req)
			if req == "" {
				continue
			}
			if strings.TrimSpace(fields[req]) == "" {
				missing = true
				break
			}
		}
		if missing {
			delete(out, num)
		}
	}
	return out
}

// matchGroupedField 浠庨敭鍚嶄腑鎻愬彇缂栧彿鍜屽瓧娈靛悕銆?
func matchGroupedField(keyRx *regexp.Regexp, key string) (string, string, bool) {
	matches := keyRx.FindStringSubmatch(strings.TrimSpace(key))
	if len(matches) == 0 {
		return "", "", false
	}

	numIdx := subexpIndex(keyRx, "num")
	fieldIdx := subexpIndex(keyRx, "field")
	num := ""
	field := ""
	if numIdx > 0 && numIdx < len(matches) {
		num = strings.TrimSpace(matches[numIdx])
	}
	if fieldIdx > 0 && fieldIdx < len(matches) {
		field = strings.TrimSpace(matches[fieldIdx])
	}
	if num == "" && len(matches) > 1 {
		num = strings.TrimSpace(matches[1])
	}
	if field == "" && len(matches) > 2 {
		field = strings.TrimSpace(matches[2])
	}
	if num == "" || field == "" {
		return "", "", false
	}
	return num, field, true
}

// subexpIndex 杩斿洖鍛藉悕鎹曡幏缁勭殑浣嶇疆銆?
func subexpIndex(rx *regexp.Regexp, name string) int {
	for i, subName := range rx.SubexpNames() {
		if subName == name {
			return i
		}
	}
	return -1
}

// buildSectionRuleItem 灏嗕竴涓垎缁勭粨鏋滆浆鎹负缁熶竴缁撴瀯銆?
func buildSectionRuleItem(
	rf ruleFile,
	sourceURL string,
	sectionName string,
	groupID string,
	sectionDefaults map[string]string,
	groupFields map[string]string,
	fieldMap map[string]string,
) (RuleItem, bool, error) {
	named := map[string]string{}

	for key, value := range sectionDefaults {
		key = canonicalRuleField(key)
		value = strings.TrimSpace(value)
		if key != "" && value != "" {
			named[key] = value
		}
	}

	for key, rawField := range fieldMap {
		value := strings.TrimSpace(groupFields[strings.TrimSpace(rawField)])
		if value == "" {
			continue
		}
		named[canonicalRuleField(key)] = value
	}

	extractKeys := sortedMapKeys(rf.Extract)
	for _, key := range extractKeys {
		extractRule := rf.Extract[key]
		sourceField := canonicalRuleField(extractRule.From)
		sourceValue := strings.TrimSpace(named[sourceField])
		if sourceValue == "" {
			sourceValue = strings.TrimSpace(groupFields[strings.TrimSpace(extractRule.From)])
		}
		if sourceValue == "" {
			continue
		}

		value, err := captureByRegex(sourceValue, extractRule.Regex)
		if err != nil {
			return RuleItem{}, false, fmt.Errorf("%s.%s 鎻愬彇澶辫触: %w", sectionName, key, err)
		}
		if strings.TrimSpace(value) == "" {
			continue
		}
		named[canonicalRuleField(key)] = normalizeExtractValue(value, extractRule.Type)
	}

	links := collectNamedLinks(named)
	if len(links) == 0 {
		return RuleItem{}, false, nil
	}

	name := strings.TrimSpace(named["Name"])
	fileName := strings.TrimSpace(named["FileName"])
	if fileName == "" {
		fileName = fileNameFromLink(links[0])
	}
	if name == "" {
		name = fileName
	}
	if name == "" {
		return RuleItem{}, false, nil
	}

	system := firstNonEmptyString(
		strings.TrimSpace(named["System"]),
		strings.TrimSpace(rf.System),
		deriveSystemFromName(name),
	)

	item := RuleItem{
		ID:          strings.TrimSpace(sectionName + ":" + groupID),
		System:      system,
		Name:        name,
		FileName:    fileName,
		Description: strings.TrimSpace(named["Description"]),
		PublishDate: strings.TrimSpace(named["PublishDate"]),
		Language:    strings.TrimSpace(named["Language"]),
		Arch:        strings.TrimSpace(named["Arch"]),
		Size:        floatValue(named["Size"]),
		SizeUnit:    strings.TrimSpace(rf.SizeUnit),
		Edition:     strings.TrimSpace(named["Edition"]),
		Ver:         strings.TrimSpace(named["Ver"]),
		Index:       intValue(named["Index"]),
		Offset:      strings.TrimSpace(named["Offset"]),
		Hash: RuleHash{
			Sha1:   strings.TrimSpace(named["Sha1"]),
			Sha256: strings.TrimSpace(named["Sha256"]),
			MD5:    strings.TrimSpace(named["MD5"]),
		},
		Link: RuleLink{
			Type:  defaultLinkType(firstNonEmptyString(named["LinkType"], named["Type"])),
			Links: links,
		},
	}

	if item.SizeUnit == "" {
		item.SizeUnit = "B"
	}
	if item.FileName == "" && sourceURL != "" {
		item.FileName = path.Base(sourceURL)
	}
	return item, true, nil
}

// captureByRegex 浠庢枃鏈腑鎻愬彇鐩爣鍊笺€?
func captureByRegex(source string, pattern string) (string, error) {
	source = strings.TrimSpace(source)
	pattern = strings.TrimSpace(pattern)
	if source == "" {
		return "", nil
	}
	if pattern == "" {
		return source, nil
	}

	rx, err := regexp.Compile(pattern)
	if err != nil {
		return "", err
	}
	matches := rx.FindStringSubmatch(source)
	if len(matches) == 0 {
		return "", nil
	}
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1]), nil
	}
	return strings.TrimSpace(matches[0]), nil
}

// normalizeExtractValue 鏍规嵁澹版槑绫诲瀷鏁寸悊鎻愬彇缁撴灉銆?
func normalizeExtractValue(value string, valueType string) string {
	value = strings.TrimSpace(value)
	switch strings.ToLower(strings.TrimSpace(valueType)) {
	case "int":
		return strconv.Itoa(intValue(value))
	case "float":
		return strconv.FormatFloat(floatValue(value), 'f', -1, 64)
	default:
		return value
	}
}

// canonicalRuleField 缁熶竴瀛楁鍛藉悕锛岄伩鍏嶈鍒欏ぇ灏忓啓涓嶄竴鑷淬€?
func canonicalRuleField(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "system":
		return "System"
	case "name":
		return "Name"
	case "filename", "file":
		return "FileName"
	case "description", "desc":
		return "Description"
	case "publishdate", "date":
		return "PublishDate"
	case "language":
		return "Language"
	case "arch":
		return "Arch"
	case "size":
		return "Size"
	case "edition":
		return "Edition"
	case "ver", "version":
		return "Ver"
	case "index":
		return "Index"
	case "offset":
		return "Offset"
	case "sha1":
		return "Sha1"
	case "sha256":
		return "Sha256"
	case "md5":
		return "MD5"
	case "link1":
		return "Link1"
	case "link2":
		return "Link2"
	case "linktype", "type":
		return "LinkType"
	case "meta", "ms":
		return "Meta"
	default:
		return strings.TrimSpace(name)
	}
}

// collectNamedLinks 鎸?link1/link2... 椤哄簭鎻愬彇閾炬帴銆?
func collectNamedLinks(named map[string]string) []string {
	keys := make([]string, 0)
	for key := range named {
		lower := strings.ToLower(strings.TrimSpace(key))
		if strings.HasPrefix(lower, "link") && lower != "linktype" {
			keys = append(keys, key)
		}
	}
	sort.SliceStable(keys, func(i, j int) bool {
		return numericSuffix(keys[i]) < numericSuffix(keys[j])
	})

	out := make([]string, 0, len(keys))
	seen := map[string]struct{}{}
	for _, key := range keys {
		value := strings.TrimSpace(named[key])
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

// deriveSystemFromName 灏濊瘯浠庡悕绉颁腑鎺ㄦ柇绯荤粺浠ｅ彿銆?
func deriveSystemFromName(name string) string {
	rx := regexp.MustCompile(`(?i)(?:windows|win)\s*(7|8|10|11)`)
	matches := rx.FindStringSubmatch(strings.TrimSpace(name))
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

// fileNameFromLink 浠庨摼鎺ヤ腑鎺ㄦ柇鏂囦欢鍚嶃€?
func fileNameFromLink(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	if u, err := url.Parse(raw); err == nil {
		name := path.Base(strings.TrimSpace(u.Path))
		if name != "." && name != "/" {
			return name
		}
	}
	return path.Base(raw)
}

// mapValue 灏嗕换鎰忓€煎畨鍏ㄨ浆鎹负 map銆?
func mapValue(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

// stringValue 灏嗕换鎰忓€艰浆鎴愬瓧绗︿覆銆?
func stringValue(v any) string {
	switch vv := v.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(vv)
	case json.Number:
		return vv.String()
	case float64:
		if vv == float64(int64(vv)) {
			return strconv.FormatInt(int64(vv), 10)
		}
		return strconv.FormatFloat(vv, 'f', -1, 64)
	case float32:
		return strconv.FormatFloat(float64(vv), 'f', -1, 64)
	case int:
		return strconv.Itoa(vv)
	case int64:
		return strconv.FormatInt(vv, 10)
	case int32:
		return strconv.FormatInt(int64(vv), 10)
	case bool:
		if vv {
			return "true"
		}
		return "false"
	default:
		return strings.TrimSpace(fmt.Sprint(v))
	}
}

// floatValue 灏嗕换鎰忓€艰浆鎴愭诞鐐规暟銆?
func floatValue(v any) float64 {
	switch vv := v.(type) {
	case nil:
		return 0
	case float64:
		return vv
	case float32:
		return float64(vv)
	case int:
		return float64(vv)
	case int64:
		return float64(vv)
	case int32:
		return float64(vv)
	case json.Number:
		f, _ := vv.Float64()
		return f
	default:
		f, _ := strconv.ParseFloat(strings.TrimSpace(stringValue(v)), 64)
		return f
	}
}

// intValue 灏嗕换鎰忓€艰浆鎴愭暣鏁般€?
func intValue(v any) int {
	switch vv := v.(type) {
	case nil:
		return 0
	case int:
		return vv
	case int64:
		return int(vv)
	case int32:
		return int(vv)
	case float64:
		return int(vv)
	case float32:
		return int(vv)
	case json.Number:
		n, _ := vv.Int64()
		return int(n)
	default:
		n, _ := strconv.Atoi(strings.TrimSpace(stringValue(v)))
		return n
	}
}

// defaultLinkType 杩斿洖鏍囧噯鍖栧悗鐨?link.type銆?
func defaultLinkType(tp string) string {
	tp = strings.ToLower(strings.TrimSpace(tp))
	if tp == "" {
		return "url"
	}
	return tp
}

// numericSuffix 瑙ｆ瀽 link1/link2 杩欑被瀛楁鐨勫悗缂€鏁板瓧銆?
func numericSuffix(s string) int {
	s = strings.ToLower(strings.TrimSpace(s))
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] < '0' || s[i] > '9' {
			if i == len(s)-1 {
				return 1
			}
			n, err := strconv.Atoi(s[i+1:])
			if err != nil {
				return 1
			}
			return n
		}
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return 1
	}
	return n
}

// firstNonEmptyString 杩斿洖绗竴涓潪绌哄瓧绗︿覆銆?
func firstNonEmptyString(vs ...string) string {
	for _, v := range vs {
		v = strings.TrimSpace(v)
		if v != "" {
			return v
		}
	}
	return ""
}
