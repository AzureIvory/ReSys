package main

import (
	"ReSys/src/config"
	"ReSys/src/data"
	"ReSys/src/image"
	"ReSys/src/windows"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
)

type argCfg struct {
	sys  string
	arch string
	lang string
	lim  int
}

type showRow struct {
	Ord  int
	Try  int
	Item data.RuleItem
}

type showView struct {
	Sys      string
	ArchWant string
	ArchSrc  string
	ArchMode string
	LangWant string
	LangSrc  string
	LangMode string
	Rows     []showRow
}

func main() {
	cfg, err := readArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	view, err := buildView(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "加载镜像候选失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Print(fmtView(view, cfg.lim))
}

// readArgs 解析命令行参数，同时支持位置参数 system。
func readArgs(args []string) (argCfg, error) {
	cfg := argCfg{sys: "7"}
	pos := ""
	if len(args) > 0 && !strings.HasPrefix(strings.TrimSpace(args[0]), "-") {
		pos = strings.TrimSpace(args[0])
		args = args[1:]
	}

	fs := flag.NewFlagSet("img_rank", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&cfg.sys, "system", cfg.sys, "系统号，例如 7/10/11")
	fs.StringVar(&cfg.arch, "arch", "", "目标架构，32 或 64，空表示按当前 ReSys 默认")
	fs.StringVar(&cfg.lang, "lang", "", "镜像语言偏好，例如 zh-cn/en-us，空表示按当前 ReSys 默认")
	fs.IntVar(&cfg.lim, "limit", 0, "最多显示多少条，0 表示全部")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "用法:")
		fmt.Fprintln(os.Stderr, "  img_rank 7")
		fmt.Fprintln(os.Stderr, "  img_rank 10 -limit 8")
		fmt.Fprintln(os.Stderr, "  img_rank -system 11 -arch 64 -lang zh-cn")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	if strings.TrimSpace(cfg.sys) == "7" && pos != "" {
		cfg.sys = pos
	}
	cfg.sys = strings.TrimSpace(cfg.sys)
	cfg.arch = strings.TrimSpace(cfg.arch)
	cfg.lang = strings.TrimSpace(cfg.lang)
	if cfg.sys == "" {
		return cfg, fmt.Errorf("system 不能为空")
	}
	if cfg.lim < 0 {
		return cfg, fmt.Errorf("limit 不能小于 0")
	}
	return cfg, nil
}

// buildView 构建与当前下载逻辑一致的筛选视图。
func buildView(cfg argCfg) (showView, error) {
	items, err := data.GetInstallImageItems(cfg.sys)
	if err != nil {
		return showView{}, err
	}

	archWant, archSrc := resolveArch(cfg.arch)
	items, archMode := applyArch(items, archWant)

	langWant, langSrc := resolveLang(cfg.lang)
	items = filterMSLang(items, langWant)

	return showView{
		Sys:      cfg.sys,
		ArchWant: archWant,
		ArchSrc:  archSrc,
		ArchMode: archMode,
		LangWant: langWant,
		LangSrc:  langSrc,
		LangMode: "ms-only",
		Rows:     makeRows(items),
	}, nil
}

// resolveArch 返回当前 ReSys 会使用的目标架构。
func resolveArch(raw string) (string, string) {
	raw = strings.TrimSpace(raw)
	if raw != "" {
		return raw, "flag"
	}
	return strings.TrimSpace(windows.DesiredArch()), "runtime"
}

// resolveLang 返回当前 ReSys 会使用的镜像语言偏好。
func resolveLang(raw string) (string, string) {
	raw = normLang(raw)
	if raw != "" {
		return raw, "flag"
	}

	langs, err := windows.GetUserPreferredUILanguages()
	if err == nil {
		for _, lang := range langs {
			lang = normLang(lang)
			if lang != "" {
				return lang, "system-ui"
			}
		}
	}

	cfg, err := config.LoadAppConfig()
	if err == nil {
		lang := normLang(cfg.Language.ImageDefaultLanguage)
		if lang != "" {
			return lang, "config"
		}
	}

	return normLang(config.DefaultAppImageLanguage), "default"
}

// applyArch 复刻 DownloadImage 的架构筛选逻辑。
func applyArch(items []data.RuleItem, arch string) ([]data.RuleItem, string) {
	arch = strings.TrimSpace(arch)
	if arch == "" {
		return items, "all"
	}

	out := image.FilterRuleItemsByArch(items, arch)
	if len(out) > 0 {
		return out, "exact"
	}
	if arch == "32" {
		out = image.FilterRuleItemsByArch(items, "64")
		if len(out) > 0 {
			return out, "fallback-64"
		}
	}
	return items, "all"
}

// filterMSLang 仅对 MS 规则源应用语言筛选。
func filterMSLang(items []data.RuleItem, want string) []data.RuleItem {
	want = normLang(want)
	if want == "" {
		return items
	}

	out := make([]data.RuleItem, 0, len(items))
	msCnt := 0
	hitCnt := 0
	for _, it := range items {
		if !isMS(it.Source) {
			out = append(out, it)
			continue
		}
		msCnt++
		if normLang(it.Language) == want {
			out = append(out, it)
			hitCnt++
		}
	}
	if msCnt > 0 && hitCnt == 0 {
		return items
	}
	return out
}

// makeRows 生成展示行，并计算实际尝试顺序。
func makeRows(items []data.RuleItem) []showRow {
	rows := make([]showRow, len(items))
	for i, it := range items {
		rows[i] = showRow{Ord: i + 1, Item: it}
	}

	try := 1
	for i := range rows {
		if strings.EqualFold(strings.TrimSpace(rows[i].Item.Link.Type), "url") {
			rows[i].Try = try
			try++
		}
	}
	for i := range rows {
		if rows[i].Try != 0 {
			continue
		}
		rows[i].Try = try
		try++
	}
	return rows
}

// fmtView 格式化筛选条件与最终候选列表。
func fmtView(view showView, lim int) string {
	show := len(view.Rows)
	if lim > 0 && lim < show {
		show = lim
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "system=%s total=%d shown=%d\n", view.Sys, len(view.Rows), show)
	fmt.Fprintf(&sb, "arch=%s source=%s mode=%s\n", trimOr(view.ArchWant, "-"), trimOr(view.ArchSrc, "-"), trimOr(view.ArchMode, "-"))
	fmt.Fprintf(&sb, "lang=%s source=%s scope=%s\n", trimOr(view.LangWant, "-"), trimOr(view.LangSrc, "-"), trimOr(view.LangMode, "-"))
	fmt.Fprintln(&sb, "try=url first, then non-url")

	tw := tabwriter.NewWriter(&sb, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ORD\tTRY\tSOURCE\tRANK\tTYPE\tLANG\tARCH\tFILE")
	for i := 0; i < show; i++ {
		row := view.Rows[i]
		fmt.Fprintf(
			tw,
			"%d\t%d\t%s\t%d\t%s\t%s\t%s\t%s\n",
			row.Ord,
			row.Try,
			trimOr(row.Item.Source, "-"),
			row.Item.Rank,
			trimOr(row.Item.Link.Type, "-"),
			trimOr(row.Item.Language, "-"),
			trimOr(row.Item.Arch, "-"),
			trimOr(row.Item.FileName, "-"),
		)
	}
	_ = tw.Flush()
	return sb.String()
}

func normLang(lang string) string {
	lang = strings.TrimSpace(lang)
	if lang == "" {
		return ""
	}
	return strings.ToLower(strings.ReplaceAll(lang, "_", "-"))
}

func isMS(src string) bool {
	src = strings.ToLower(strings.TrimSpace(src))
	return src == "win10-ms" || src == "win11-ms"
}

// trimOr 返回去空白后的值，空时回退默认值。
func trimOr(src string, def string) string {
	src = strings.TrimSpace(src)
	if src == "" {
		return def
	}
	return src
}
