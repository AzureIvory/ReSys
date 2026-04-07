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

// WinPEImg describes one WinPE download candidate after PE rules have been
// aggregated and normalized.
//
// It remains PE-specific because the PE flow still needs offset metadata
// and package-specific verification fields that do not belong on RuleItem.
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

// ruleItemsSource 闂備浇宕甸崑鐐电矙韫囨稑绀夐幖娣妼妗呭┑顔斤供閸橀箖鍩㈤弮鍫熺厓鐟滄粓宕滃杈╃煓濠㈣埖鍔﹂弫鍌炴煕閵夈劌鐓愮紓宥呯墦濮婃椽宕ㄦ繝鍌滅懖闂佽崵鍣︾粻鎾愁嚕閹间礁绀冮柍鍝勫枤濞村嫰姊虹拠鈥崇仸婵犮垹绻橀獮鎺懳旈埀顒勫礄閻樼粯鐓欓梺顓ㄧ畱婢ь垶鏌涙繝鍕毈闁哄矉缍佹俊鎼佸Ψ閵夘喕绱撳┑鐐差嚟婵敻鎯勯姘辨殾闁靛鏅涢柋鍥煏韫囧鐏悘蹇旂箞濮婃椽宕崟闈涘壉闂佹悶鍊曢柊锝夊春閳?
//
// Source / Rank / RulePath 闂傚倸鍊风欢锟犲窗濞戞瑦鍙忛柕鍫濇啒閿濆浼犻柕澶涚畱閺嬪倿姊洪崨濠冨闁稿瀚伴幃姗€鎮㈤崗鑲╁幐闂佺鏈喊宥夋儗濡や胶绠鹃柛鈩冨姇閻忣噣鏌ｉ妷顔绘捣妞わ附鐓￠弻娑樜熺紒妯洪瀺缂備礁鐭傛禍鍫曞春閸曨垰绀冪憸蹇曠矆閳ь剟姊绘担鐟邦嚋缂佸鍨块幃娲ㄧ弧绛竤 闂傚倷绀侀幖顐も偓姘卞厴瀹曞綊鎮介崜鍙夋櫔濠殿喗顭堟ご鎼佸窗閸℃稒鐓曢柡鍥ュ妼娴滄粓鏌ｈ箛鏇炴瀻闂囧绻濊婵挳宕鈶挎帗寰勯幇顓犲幗闂侀潧顭堥崕閬嶎敂椤愩倗纾兼い鏃€鍎抽崝瀣磼鐎ｎ亶妯€闁糕斁鍋撳銈嗗笒鐎氼剛鐥閺屻劌鈽夊Ο渚痪缂備焦鍔栭〃濠囧蓟濞戙垹绠抽柟鍨暞閻ｄ粙姊洪棃娑欘棞闁哥喎鐡ㄦ穱?
type ruleItemsSource struct {
	RulePath string
	Source   string
	Rank     int
	Items    []RuleItem
}

// imageRuleCandidate keeps one normalized image rule together with the
// source metadata used for ranking and de-duplication across rule files.
type imageRuleCandidate struct {
	Item     RuleItem
	RulePath string
	Source   string
	Rank     int
}

// peRuleCandidate 闂傚倷鐒﹀鍨焽閸ф绀夐悗锝庡墲婵?PE 闂備浇宕甸崰鎰版偡閵壯€鍋撳鐓庡⒋鐎规洖缍婇、娑㈡倷閼碱剦鍞洪梻浣告贡閸庛倝宕归崷顓炴瀳鐎广儱鎳夊Σ鍫ユ煙閹冩毐妞ゆ帇鍨介弻锝堢疀閵壯呮殼閻庢鍠楅幃鍌氱暦閻旂⒈鏁嶆俊銈傚亾濞存粍鍎抽…璺ㄦ崉娓氼垰鍓板銈呯箞閸庣敻寮?
type peRuleCandidate struct {
	Item     WinPEImg
	RulePath string
	Source   string
	Rank     int
}

// GetInstallImageItems loads, normalizes, de-duplicates, and sorts install
// image rules for one Windows target.
//
// The function preserves historical selection behavior while moving callers
// onto RuleItem:
//  1. only enabled rule files contribute candidates
//  2. every item is normalized before de-duplication
//  3. final ordering follows source rank, link type, rule index, and stable
//     file identity so callers can try the most preferred entries first
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
		log.LogWrite(0, "[GetInstallImageItems] failed to load image rules: system=%s err=%v", systemCode, err)
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

// RuleItemFileName returns the preferred filename for one image rule.
//
// Resolution order is intentionally simple and stable:
//  1. use the explicit FileName from the rule when present
//  2. otherwise derive the basename from the download URL or path
//  3. if only an extension is known, fall back to windows_image.<ext>
//  4. if nothing else is available, use windows_image.iso
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

func GetWinPE() ([]WinPEImg, error) {
	candidates, err := loadPERules()
	if err != nil {
		log.LogWrite(0, "[GetWinPE] 闂傚倷绀侀幉鈥愁潖缂佹ɑ鍙忛柟顖ｇ亹?PE 闂備浇宕甸崰鎰版偡閵壯€鍋撳鐓庡⒋鐎规洖缍婇、娑樷槈濡偐鐛梺鍝勵槸閻楁粓宕戞径搴澓: err=%v", err)
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

// splitPipeList 闂?"a | b" 闂?"a|b" 闂佽崵鍠愮划蹇涘春閸ヮ剙鍨傞柛锔诲幗椤洟鏌ㄩ悢鍝勑ｉ柛搴＄Ч閺屾盯寮撮妸銉ヮ潽闂佽瀵掗崳锝夊蓟閿熺姴閱囨い鎰╁灩椤亝绻濆▓鍨仩闁绘牕銈搁悰顔锯偓锝庡枛缁犳稒銇勯幒鍡椾壕闂佽绻戦悷鈺呭箖鐠鸿　妲堥柡宓吘鈺呮⒑?
//
// 闂傚倷鑳堕崕鐢稿疾閳哄懎绐楅柡宥冨妽濞呯娀鏌ｅΟ铏癸紞闁崇粯妫冮弻锟犲礋椤愶絿顩板┑鐐额嚋缂嶄線寮婚敐澶涚稏妞ゆ巻鍋撳┑陇娅ｇ槐鎺椻€﹂幋婵嗩潾闂佺懓寮堕幐鎶藉极閹版澘骞㈡繛鍡楄嫰娴?offset 闂傚倷绀侀幉锛勫垝瀹€鍕珘妞ゆ帒瀚崑鍌炴煕閵夛絽濡挎い鈺佸级缁绘盯骞嬮悙鐢电厾濠电偛鍚嬮崝娆撳蓟濞戙垹绠抽柟鎹愬煐閸ｄ即姊洪棃鈺冩偧闁稿繑锕㈤悰顔碱吋閸ワ絽浜鹃柨婵嗙凹缁ㄥ鏌￠崨顔藉€愰柡宀嬬秮婵℃悂濡烽妷顔绘偅婵＄偑鍊х粻鎴濐焽閳ュ磭鏆﹂柟鎵閸嬪倿骞栨潏鍓хɑ闁硅尪顕ч埞鎴︽倷閼碱剙鈪遍梺绋款儜缂嶄線宕洪埀?
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

// parseOffset 闂備浇宕甸崰鎰版偡鏉堚晛绶ゅΔ锝呭暞閸?"闂備浇宕垫慨宥夊礃閵娤€鈺侇渻?| 缂傚倸鍊搁崐鐑芥倿閿曞倸绠伴悹鍥ф▕閻? 闂佽崵鍠愮划蹇涘春閸ヮ剙鍨傞柛锔诲幗椤洟鏌ㄩ悢鍝勑ｉ柛搴＄Ч閺屾盯寮撮妸銉ょ暗闂佺粯甯掗敃锔炬閹烘挸绶為幖鎼枛濞堫參鏌ｈ箛鎾寸闁搞劏娉涢～蹇曟嫚閻剙閰ｉ、鏍寠婢跺顥?
//
// 闂備浇宕甸崰鎰版偡閵壯€鍋撳鐓庡⒋鐎规洖缍婇、娑㈡倷鐎电甯撻梺璇茬箳閸嬬姴螞閸曨厽鏆滈柟鐑橆殕閸嬶絽霉閿濆嫯顒熼柣鎺楃畺閺屾盯鎮㈤崨濠傜３閻庤娲嶉崜婵嬪箯閸涘瓨鍋╃€光偓閳ь剟顢欓幒妤佲拺闁告稑锕ょ粭鈺呮煕閳哄倻澧电€规洖缍婃俊姝岊槼闁哄棙绮撻弻銊╁即濡も偓娴滅偓绻濋埛鈧崨顓夈儳绱掓潏銊﹀磳闁糕斁鍋撳銈嗗笒鐎氼參宕曞澶嬬厱闁哄洢鍔屾晶顖涚箾閸繍鐓奸柡灞稿墲閹峰懐绮欑捄銊ф晨缂傚倷娴囩划鐐仈閸涘﹦鈹嶅┑鐘叉搐绾惧吋绻涢幋鐐电叝闁告垳绮欓弻锝嗘償閵忊懇濮囧銈冨妼濡繈銆佸▎鎴滄勃闁告挆鈧弸鏍⒑閹呯闁告ɑ绮撳顐﹀礋椤栨稓鍘甸柣搴㈢⊕椤洦鏅堕鍕厽婵°倕鍠氶悞鐐亜閺囶亞绉紒鐘崇⊕閹棃鏁愰崶銊ユ灀闂備浇顕уù鐑藉箠閹捐瀚夋い鎺戝濮规煡鏌ㄥ┑鍡╂Ч闁?
// 婵犵數鍋炲娆撳触鐎ｎ偆鈹嶉柧蹇氼潐瀹曟煡鏌熸潏鍓х暠闁?ok=false闂傚倷鐒︾€笛呯矙閹达附鍎楀〒姘ｅ亾闁糕斁鍋撳銈嗗坊閸嬫挸鈹戦崒娑欌拻缂侇噮鍘藉鍕箛椤掆偓瀵嘲顪冮妶鍡欏缂侇喖绉堕惀顏堫敍閻愬鍘甸梺璇″幗鐢帡宕濆鍐ｆ斀闁炽儴娅曢幉鎼佹煃瑜滈崜娑㈠箠閹捐鐤柟鑸垫灮缂嶆牠鎮楅敐搴′簽闁崇粯姊圭换娑橆啅椤旇崵鍑归梺鍝勬噳閺呯娀骞冭ぐ鎺戠倞閻犻缚娅ｆ禒婊堟⒑?
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

// PELnk 闂備礁鎼ˇ顐﹀疾濠婂牆钃熼柕濞垮剭濞差亜鍐€妞ゆ垵褰炲Ч妤呮⒑鐟欏嫬鍔ら柛鐔锋健璺柛娑卞灣绾惧吋銇勯弽銊х畵闁告艾婀辩槐鎺楊敊閼恒儯浠㈠Δ鐘靛仦鐢剝淇婇幖浣肝╅柕澹本袨婵犵數鍋犻幓顏嗙礊閳ь剚绻涙径瀣鐎殿噮鍋婃俊鑸靛緞鐎ｎ亜澹?PE 婵犵數鍋為崹鍫曞箰閹间緡鏁勯柛顐ｇ贩瑜版帒鐐婇柕濞р偓閺€鎶芥⒑閺傘儲娅呴柛鐔叉櫇濡叉劙寮介鐔哄帾?
//
// 闂傚倸鍊风欢锟犲磻閸曨垁鍥箥椤旂懓浜炬慨妯稿劚婵¤姤绻涢悡搴吋鐎规洖鐖奸崺鐐烘倷椤掑倸骞橀梻鍌欑閹诧紕鏁幒鎳虫盯寮崒娑樹粡闂佸憡顨堥崕鎰焽娴煎瓨鐓忓鑸得悘锝囩磼?
//  1. 闂傚倷鑳堕…鍫㈡崲閹扮増鍋嬪┑鐘插閸嬫捇宕归銈囩厒闂佺懓寮堕幐鍐茬暦閻旂⒈鏁冮柕蹇ｆ線閹?Rank闂傚倷绶氬褍螞閺冨牊鍤勯柤绋跨仛濞呯姵淇婇妶鍛櫣閻庢艾顦伴妵鍕箳閸℃ぞ澹曢柣鐔哥矋濠㈡ê顭囬埄鍐х箚閻庢稒蓱婵挳鏌涘☉姗堝伐闁逞屽墮绾绢厾妲愰幒鎾崇窞閻庯綆浜跺Λ鍡涙⒑閻戔晛澧查柛銊ユ贡濡叉劙骞掑Δ鈧痪褔鏌熺€涙绠ラ柛鐐存そ閹鎮介棃娑辨毉濡炪們鍔岄幊妯虹暦閸濆嫮鏆嗛柛鏇ㄥ亞椤ρ囨⒑闂堟侗鐒鹃柛搴″暱閿曘垺瀵肩€涙鍘搁梺鍓插亝缁诲秴危閸濄儳纾兼い顓熷灥瀵喚鈧娲橀懝鎹愮亙闂佸憡娲嶉弬渚€宕?
//  2. 闂傚倷绀侀幉锟犲礉閺囩姷鐭撻柛鎾茬閸ㄦ繈鏌曟繛鐐珔閻熸瑱绠撻弻娑㈩敃閿濆洨鐣肩紓浣割槸閵堟悂寮诲☉銏犵鐎规洖娉﹂妶澶嬧拺妞ゆ梻鈷堥崵鐔虹磼鏉堛劌娴柟顔哄灲瀹曨偊濡烽妶鍡╂晣闂傚倷绀侀幖顐︻敄閸涱垪鍋撳闂寸敖婵″弶鍔欓、姗€濮€閻樻妲梻浣稿閸嬪棝宕版惔顭戞晪闁绘绮埛鎴炪亜閹扳晛鐒烘俊鍙夋倐閺岀喖顢欓懞銉ョ３閻庢鍠楅幃鍌炲箠濠婂牊鍋ㄧ痪鐗埫禍鐐亜閺嶎偄浠滅紒鐙欏洦鐓ユ繛鎴灻顏嗙磼閹邦収娈滈柡灞诲妼閳藉螣缂佹ɑ瀚冲┑鐘灱椤鎽紓浣割儏椤︻垶顢樻總绋垮窛妞ゆ挾濮寸敮鎾绘⒒娴ｅ摜绉烘繛浣冲懐鐭撻柡澶嬪殮濞差亜鍐€妞ゆ挾鍠撻崝鐢告⒑闁偛鑻晶瀵糕偓瑙勬礃瀹€鎼佺嵁瀹ュ鏁嬮柛娑卞幖婢瑰鈹戦悙鏉戠仸闁瑰憡鎸冲畷鎴﹀箻閹颁焦瀵?
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

// loadPERules 闂傚倸鍊风欢锟犲磻閸涱垱鏆滈柟鐑樻⒒缁€濠傗攽閻樺弶鎼愮紒鐘劜閵囧嫰骞囬崜浣稿煂婵?pe-sources 闂傚倷鑳堕崕鐢稿疾閳哄懎绐楅柡宥庡亞缁€濠勨偓骞垮劚椤︿即寮查鍕€堕柣鎰ゴ閸嬫捇鎮㈡搴¤闂傚倷鑳堕、濠傗枖濞戙垺鏅濋柕澶涢檮濞呯姷鈧箍鍎遍ˇ顖溾偓姘槸椤法鎹勯崫鍕О濠电偛鍚嬮崝娆撳蓟濞戙垹绠抽柟鎹愬煐閸ｎ垰鈹戦悙瀛樼稇婵☆偅绻堥悰?WinPEImg 闂傚倷鑳堕…鍫ユ晝閵夆晜鍋￠柍鍝勬噹閻掑灚銇勯幒鍡椾壕濡炪倧濡囬弫缁樹繆閺夋埈鍚嬪璺好?
//
// 闂備礁鎼ˇ顐﹀疾濠婂牊鍋￠柍鍝勬噹闂傤垶姊洪崹顕呭剰妞ゆ洝椴搁幈銊ヮ潨閸℃鈷掑┑鈩冪叀娴滃爼寮婚敐澶嬪€烽柛娆忣樈濡稓绱撴担骞夸沪闁绘帪濡囩划瀣箳濡も偓鐎氬鏌ｉ姀銏℃毄婵炲牄鍊濆?
//  1. 闂備浇宕垫慨鎾敄閸涙潙鐤ù鍏兼綑閺嬩線鏌曢崼婵囧窛缁炬儳銈搁弻锝夊棘閸噮鏆㈠銈呯箻娴滃爼骞冨畡鎵虫瀻婵炲棙鍨硅摫闂備浇顕х花鑲╁垝濞嗗繒鏆﹂柟鎯版鎯熷銈庡幗閸ㄩ潧鈻撳ú顏呪拺闁告稑锕﹂幊鍕煟濡ゅ啫浠遍柨婵堝仦瀵板嫰骞囬鍌ゆТ?
//  2. 闂備浇宕甸崰鎰版偡鏉堚晛绶ゅΔ锝呭暞閸?offset闂傚倷鐒︾€笛呯矙閹达附鍎楀ù锝堝Г閿涘倸鈹?PE 婵犵數鍋為崹鍫曞箰婵犳艾绠伴柟闂寸劍閸庢挻淇婇姘辨癁闁稿鎸搁埥澶娾枎濡崵鏆︽俊?
//  3. 闂?Rank 闂傚倷绀侀幉锟犳晪濡炪値鍘鹃崗妯虹暦閹惰棄绠瑰ù锝呮憸椤斿﹪姊洪崷顓炲妺闁搞劌婀遍崰濠傤吋婢跺鍙嗗┑鐐村灦閿氭い銊︾懅缁?GetWinPE / PELnk 婵犵數濮伴崹鐓庘枖濞戞氨鐭撻柛顐ｆ礀閺?
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

// selectPE 闂傚倷绶氬鑽ゆ嫻閻旂厧绀夌€光偓閸曨偆顦╅梺璺ㄥ枔婵绮婚幎鑺ョ厵闁绘垶锚閻忊晝鐥弶璺ㄐ㈤柍瑙勫灴瀹曟帒顭ㄩ崟顒傚涧婵犵數鍋涢悧濠囧垂閸喚鏆﹂柟閭﹀厴閺嬪酣鏌熺紒銏犵仩濞存粍鍎抽…璺ㄦ崉閻氭潙浼愰梺璇茬箲閻熲晠骞冪捄琛℃闁哄诞鍐剧€遍梻浣哄帶閻忔岸宕归崸妤€钃熼柛娑卞枛缁剁偤鎮楅敐搴濇喚濞寸姵鎸冲娲传閸曨厼顣甸梺绋款儐閹瑰洤顫忓ú顏嶆晝闁靛繒濮崑鎾诲箹娴ｅ摜鐣洪柟鍏肩暘閸婃垶绂嶈ぐ鎺撶厵闁诡垎鍐╂瘣濡炪們鍊曢幊鎰閹烘鏁嶆繝闈涙閹偟绱撴笟鍥ф灍婵＄偠妫勯锝夊箹娴ｇ懓娈濋梺姹囧灮椤ｄ粙宕戦幘娲绘晬闁绘劖娼欓崜顓㈡⒑閸涘﹥澶勫ù婊呭仱椤㈡棃宕￠悜鍡樺瘜闂侀潧鐗嗛幊鎰版偩椤撱垺鐓?
//
// 闂傚倷绀侀幉锛勬暜濡ゅ懌鈧啯寰勯幇顑┿儵鏌涢幇闈涙灈閻庢艾顦伴妵鍕箳閹存繃娈婚梺缁樻尨閺呮繈鍩€椤掑喚娼愰柣鈩冩礈娴滅鈻庨幋婵嗙亰闂佽法鍠撴慨瀵哥不?Rank 闂傚倷绀侀幉锛勫垝瀹€鍕剶闁稿繐鍚嬪▍鐘充繆閵堝懏鍣归悗姘槹閵囧嫰骞嬮敐鍡欍€婇梺鍝ュУ閿曘垽寮诲☉婊呯杸闁规崘娉涢埅杈ㄤ繆閵堝洤孝婵炲樊鍙冮悰顕€骞掑Δ鈧粻鎶芥煙鐎涙鎳冨ù鐘虫そ閺岀喖宕楅崗鑲╃▏婵°倗濮寸换鎺懳ｉ幇顑芥斀閻庯綆浜為崐鐐烘⒑缂佹〞鎴﹀礈濮樿泛绀夐柛鎰靛枛缁狙囨煃閸濆嫬鈧骞婇崶顒佺厱闁挎繂娲ら崢瀵糕偓瑙勬穿缂嶄線銆侀弮鍫濈妞ゅ繐妫濋埞蹇涙⒒娴ｅ憡鎯堥柣妤€鍟村畷鎴﹀箻缂佹ê鈧爼鐓崶銊﹀暗缂佺姳鍗抽弻娑㈡偐閸欏娅х紓渚囧枤閺佽顕ｆ禒瀣仺闁汇垻鏁稿畷?
// 闂傚倷鑳堕…鍫㈡崲閹扮増鍋嬪┑鐘插暟閻濊埖鎱ㄥ璇蹭壕閻庤娲忛崕铏閿曞倸绀堢憸灞筋浖閹剧粯鈷戦柛婵嗗閸庡繘鎮楀顒佹喐婵″弶鍔曢埞鎴犫偓锝庝簽椤撳ジ姊洪崨濠勬噣闁稿孩濞婇幃宄扳攽鐎ｎ偆鍘遍梺鍦劋閹歌崵娆㈤崣澶嬪弿婵☆垳顭堟慨鍌溾偓瑙勬礀閻栧ジ骞冨▎鎴炲仒闁炽儱鍘栨竟鏇㈡⒑闁偛鑻晶瀵糕偓瑙勬礃瀹€鎼佺嵁瀹ュ鏁嬮柛娑卞幖婢瑰鈹戦悙鏉戠仸闁瑰憡鎸冲畷鎴﹀箻閹颁焦瀵岄梺闈涚墕閹虫劙鎮鹃銏＄厓?
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

// loadRules 闂傚倸鍊风欢锟犲磻閸涱垱鏆滈柟鐑樻⒒缁€濠傗攽閻樺弶鎼愮紒鐘劜閵囧嫰骞囬崜浣稿煂婵炲鍘ч柊锝夊蓟閿濆鐓涘┑鐘插€归悘鍫㈢磽閸屾氨孝缂佸鏁哥划娆愬緞閹板灚鏅ｉ梺缁樏壕顓㈠汲閻樼粯鈷戠紒瀣硶缁犵偤鏌涢弮鈧崹鍨暦?json 闂備浇宕甸崰鎰版偡閵壯€鍋撳鐓庡⒋鐎规洖缍婇、娑㈡倷閸欏妫熼梻浣规偠閸庡姊介崟顖ｆ晝濞寸姴顑嗛悡銉︾箾閹寸儐鐒鹃悗姘嵆閺屻倝鎳￠妶鍛€惧┑鐐靛帶椤嘲鐣烽崼鏇炍╅柨鏇楀亾鐞氭﹢姊绘担鐑樺殌闁圭⒈鍋婅棟闂侇剙绉查埀顒€鎳橀弫鍐磼濞戞ü缂撻梻渚€娼ц墝闁哄倸鍊块崺鈧い鎺嗗亾缂佸顫夋穱?
//
// 闂備礁鎼ˇ顐﹀疾濠婂牊鍋￠柕鍫濐槹閻撳倹绻濇繝鍌滃缂佲偓閸曨垱鐓犻柟顓熷笒閸旀粍绻涢崼婵堝煟闁?data.go 闂?parser.go 婵犵數鍋為崹鍫曞蓟閵娾晩鏁勫璺好″☉銏犻敜婵°倓绀侀崜顓㈡⒑閸涘﹥澶勯柛搴″级瀵板嫭绻濇惔銏㈢▉濠电偞鎸婚懝楣冩晝閿斿墽鐜?
// parser.go 闂備浇宕垫慨鐢稿礉濡ゅ懎绐楅柡鍥ュ灪閸庢淇婇妶鍛櫣闁诲繗娅曠换婵囩節閸屾稓鍘愰梺鍦劋椤ㄥ懘宕欓悩缁樼厵闂侇叏绠戞晶顔剧磼閳ь剛鈧綆浜栧Σ鍫ユ煙閸喖鏆曟繛鎾敱閵囧嫰顢曢姀鈺傗枅閻庤娲橀懝楣冨煝鎼淬劌绠涙い鎾跺Л閸嬫捇顢欏ù搴＄秺閹晠鎳犻鍧楀仐闂備線鈧偛鑻晶顖滅磼缂佹ê濮夋俊鍙夊姇閳规垿宕堕妸銈嗗攭婵犵數鍋涘Λ娆撳箰缁嬪簱鏋嶉柨鐔哄У閸嬶綁鏌熼柇锕€鏋涢柡瀣懇閺岋綁顢橀悤浣圭杹闂佹悶鍔嶉崕鎶解€﹂妸鈺佸窛妞ゆ柨澧藉畷鍫曟煟閻斿摜鐭屽褎顨呯叅婵犻潧娲ㄩ々閿嬬箾閹存瑥鐏╅悷娆欑畵閺屾盯顢曢敐鍥ｆ灁闂佺顑嗛幐濠氬箯閸涙潙绀堥柟缁樺笚濞呭秹姊婚崒娆戝妽閻庣瑳鍥ㄥ仭闁挎繂顦悞鍨亜閹达絾纭堕柛鏂跨Ч閹粙顢涘☉娆忛瀺闂佽鍨卞Λ浣虹不濞戞瑧绠鹃柟顖嗗倸顥氭繝鐢靛█濞佳呪偓姘€鍥х；?
//
// 闂備浇宕垫慨鎶芥倿閿曗偓閻ｅ嘲顫滈埀顒勩€佸鈧畷銊︾節閸曘劍鐏冨┑鐘垫暩婵挳宕愰崫銉︽殰闁圭儤顨嗛崑锝吤归敐鍛暈闁哥喓鍋ら弻锝夊箻閾忣偄顦╃紓浣割儏椤︾敻銆侀弮鍫濈倞闁煎摜鏁哥粔鐑芥⒒娴ｅ憡鍟為悽顖涱殜閹兘鏁冮崒姘殤闂佸憡鍔忛弲婵嬨€呴悜鑺ョ厵妞ゆ牜鍋炵欢鈺呮煙閻戞﹩娈旈柛鎴犲█閺岀喖鏌囬敃鈧崢闈浢瑰鍐﹀仮闁诡喖缍婇獮鍥煛娴ｇ顫掔紓鍌欑劍閻擄紕绮婚弽褏鏆︽俊銈呮噹鐎氬鏌ｉ姀銏℃毈闁圭鍔戦弻锝夋偄閸濄儲鍣ч柣搴㈠嚬閸撶喎鐣疯ぐ鎺濇晬婵犲﹤鎳愰敍婊堟偡濠婂啰绠婚柟顔炬櫕閹风姴顔忛鍏兼珚闂備線娼чˇ顓㈠磹濡ゅ啰鐭欏┑鐘叉处閻?
// 闂傚倷绀侀幉锟犳偡椤栨稓顩叉繝闈涙４閼板灝霉閿濆拋娼熷ù婊冪秺閺岀喖骞嗚閹界姵绻涢崼锝庡殭闁宠棄顦甸獮娆撳礃瑜忛弫鏍р攽閻愭彃绾у┑顖欑矙婵＄敻骞囬弶鍨祮闂侀潧绻掓慨鎾嵁鐎ｎ亖鏀介柣鎰絻椤︻剟鏌涢幘瀵哥畵闁挎洏鍨洪幏鍛村捶椤撗勭カ闂佽崵濮崇粈浣哄椤撶姷鐭撻柛褎顨嗛悡娑㈡煕椤愶絿绠ユ俊鎻掔秺閺岋繝宕ㄩ銏犲Б缂備浇椴哥敮锟犵嵁濡皷鍋撻悽鍛婃珳闁告垳绮欏娲传閸曨偅娈洪梺绯曟櫆閻楁寮查崼鏇熷亹闁惧浚鍋傚锕傛⒑閸濆嫬鈧湱鈧瑳鍛焼闁逞屽墴濮婄粯鎷呴悷閭﹀殝闂佽崵鍠嗛崝鎴︺€佸璺何у璺好?
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
			log.LogWrite(0, "[loadRules] 闂備浇宕甸崰鎰版偡鏉堚晛绶ゅΔ锝呭暞閸婄敻鏌ｉ敐鍛拱闁哥姴妫濋弻娑㈠即閵娿儰绨婚梺璇茬箳閸犳牠寮婚敓鐘茬＜婵﹩鍘鹃悡鎴濃攽閻愬弶顥撻柛銊ユ惈椤曘儵宕熼浣虹Ф濡炪倖鍔戦崕? file=%s err=%v", file, err)
			errs = append(errs, fmt.Sprintf("%s: %v", file, err))
			continue
		}
		if !res.Enabled {
			log.LogWrite(0, "[loadRules] 闂備浇宕垫慨鎾箹椤愶附鍋柛銉㈡櫆瀹曟煡鏌涢幇鐢靛帥闁哥喎鎳橀弻銈囧枈閸楃偛鈷掑┑鐐额嚋缂嶄線寮婚敐澶涚稏妞ゆ巻鍋撳┑顔瑰亾婵＄偑鍊ら崑鍕囬棃娑氭殾? file=%s source=%s", file, res.Source)
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
		return nil, fmt.Errorf("闂備浇宕甸崰鎰版偡閵壯€鍋撳鐓庡⒋鐎规洖缍婇、娑㈡倷閺夋垵澹嗘俊鐐€栧Λ渚€宕戦幇顔剧煋闁圭娴风粻楣冩倶閻愭鐒惧褍寮剁换婵嬪焵椤掍胶鐟归柍褜鍓熼悰顔锯偓锝庡枛缁犳稒銇勯幒鍡椾壕濡炪値鍋嗘繛鈧柡灞剧洴瀵噣宕掑В娆惧墯缁绘盯寮堕幋鐐差槱缂備礁鍊圭敮鐐哄箯鐎ｎ亞鏆﹂柛銉㈡暕椤撱垺鈷戦柛娑橈功閹虫劙鏌涢妸锕€鈻曠€殿噮鍋婃俊鍫曞炊閵娿儲鐎梻浣告啞濞诧箓宕戦崟顖涘€? %s", strings.Join(errs, " | "))
	}
	return nil, fmt.Errorf("规则目录下没有可用的规则结果: %s", dir)
}

// imageRulesDir 闂備礁鎼ˇ顐﹀疾濠婂牆钃熼柕濞垮剭濞差亜鍐€妞ゆ挾鍋熼鍥⒑閹肩偛鍔€闁告侗鍠楅惁鐐电磽閸屾瑧璐伴柛銊╂涧閻ｇ兘鎮介棃娑樼亰濠电偛妯婃禍婵嬪磿瀹ュ鐓曢柡鍥ュ妼閻忊剝绻涢崼鐔割棃闁哄本绋戦濂稿川椤栨粠鍟堟俊鐐€ら崑鍕囬棃娑氭殾婵﹩鍏橀弸搴ㄦ煙鐎电浠ч柣娑栧劦閹嘲顭ㄩ崨顓ф毉濠电偞褰冪换姗€宕洪埀?
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

// peRulesDir 闂備礁鎼ˇ顐﹀疾濠婂牆钃熼柕濞垮剭?PE 闂備浇宕甸崰鎰版偡閵壯€鍋撳鐓庡⒋鐎规洖缍婇、娑㈡倷閹绘帒鏁ら梻渚€娼荤€靛矂宕㈤悾宀€鐜绘俊銈呭暞閸犳劙鏌ｅΔ鈧悧濠勫閹间焦鐓?
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

// rulesCoreDir 闂傚倷绶氬鑽ゆ嫻閻旂厧绀夌€光偓閸愶缚姹楅梺鍝勮閸庤京绮婚妷褎鍠愰柟杈捐礋閳ь兛绶氶獮瀣晝閳ь剙螞濮椻偓閺屾盯濡烽鐐搭€嶅銈嗗姃缁瑩寮婚敐澶婄厸濠电姴鍊归悘鍫㈢磽閸屾氨孝缂佸鎳撻悾鐑筋敂閸℃洘鍕冮梺浼欑到閻吋鐡忛梻鍌欑閹诧繝骞愰崫銉х煋閻庢稒锚椤曢亶鏌熼柇锕€骞楀┑顖氱摠缁绘繃绻濋崒娑樻缂備焦鍔栭〃鍫ュ箟閹间焦鍋嬮柛顐ゅ枔椤︽澘鈹戦敍鍕闁哥姵顨呴…鍥ㄧ節濮橆剛顓哄┑鐘茬仛閸旀洖鈻撳ú顏呪拺?rules/core闂?
//
// 闂備礁鎼ˇ顐﹀疾濠婂牊鍋￠柨鏇炲€归崑瀣⒑椤掆偓缁夋挳鎯屽Δ浣典簻闁哄秲鍔庨幊浣虹磼閵娿倕宓嗛柡灞剧☉椤繈顢楁担瑙勫婵犵绱曢崑娑㈠磹閸喚鏆︽俊銈呮噺閸嬪倿骞栭幖顓炴灈闁哄拑缍佸?
//   - 闂傚倷鑳堕崕鐢稿疾濞戙垺鍋ら柕濞у嫭娈伴梺鍦檸閸犳牠骞戦崼鏇熺厪濠电姴绻愰々顒勬煟閺嶎厺鎲鹃柡宀嬬秮椤㈡瑩寮拌箛鎾冲腐婵犵數鍋涘鑸靛垔娴犲桅闁圭増婢橀崡鎶芥煥濞戞ê顏い鎾炽偢閺?
//   - 婵犵數鍋涢顓熸叏鐎电硶鍋撳☉鎺撴珚闁诡喗顨婇、娑橆潩閻撳孩鐣奸梺鍝勵槺閸嬫﹢宕￠幎鑺ュ仒闁瑰墽绮悡鐔镐繆閻愮數甯涙繛鍛处缁绘盯宕ｆ径濠庘偓婊堟煏閸ャ劌濮嶇€殿喗鎸抽弫宥夊礋椤撗冩倯闂?
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

// collectJSON 闂傚倸鍊风欢锟犲磻閸涱垱鏆滈柟鐑樻⒒缁€濠傗攽閻樺弶鎼愮紓浣叉櫊閺屾盯顢曢敐鍡欘槰闂佽壈灏欐繛鈧柡宀嬬秮閸┾剝绻濋崒娑氫邯缂傚倸鍊哥粔瀵哥矓閻㈢數鐭欏璺哄閸嬫捇鏁愭惔婵堢泿閻庢鍠栧鈥愁潖?json 闂傚倷绀侀幖顐﹀磹缁嬫５娲晲閸涱亝鐎婚梺闈涚箞閸婃牠寮查鍕€堕柣鎰ゴ閸嬫捇鎮㈡搴¤闂傚倷绀佸﹢閬嶁€﹂崼銉嬪洭骞庨懞銉ュ壒闂佽鍨庣仦鑺ヮ唫闂備礁鎲″ú锕傚礈濞嗘垹绠旈柟鎹愵嚙缁犲綊鏌℃径瀣仼缂佺姷鍋ら弻?
//
// 闂傚倷绀佸﹢閬嶅磿閵堝洦鏆滈柟鐑樻婵櫕銇勯幘鍗炵仼闁活厽顨嗛妵鍕冀閵娧勫櫏缂備降鍔嶅妯垮絹闂佹悶鍎崝搴ｇ不濮樿埖鐓熼柨鏇楀亾妞わ妇鏁婚獮鍡涘礋椤栵絾鏅╅梺鍏肩ゴ閺呮繂宕楅梻鍌欐祰椤顢欓弽顓炵；闁告侗鍙庨崵鏇㈡偣閹帒濡跨痪鎯с偢閺岀喖骞嗚閸ょ喎霉濠婂骸鐏ｇ紒杈ㄥ笧閳ь剨缍嗘禍婊堝汲闁秵鐓熼柨婵嗩槺閻ｆ椽鏌℃担鍝バ㈤柣锝嗙箞瀹曠喖顢旈崱娆戭槴闂傚倷鑳堕…鍫㈡崲閹邦喚鐭撻柟缁㈠枛缁?Rank 闂傚倷绀侀幖顐λ囬銏犵？闁肩⒈鍓濇慨铏亜閺囨浜鹃悗瑙勬礈閸忔ɑ淇婇幖浣肝ч柛銉㈡櫆閸犳帡姊绘担鍛婂暈闁煎綊绠栧鐢割敆閳ь剟鍩為崘顔肩劦妞ゆ帒瀚悡鏇㈡煥濠靛棗鏆欏┑陇娅ｇ槐鎺懳旈埀顒勫磹瑜版帒桅闁告洦鍨版导鐘绘煕閺囥劌骞樻い锝嗗絻閳规垿鎮╅搹顐ゎ槬闂佺锕ㄩ濠勮姳濞差亝鈷?
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

// normalizeSystemCode 闂傚倷鑳堕、濠傗枖濞戙垺鏅濋柕鍫濐槸缁犳牠鏌涢妷銏℃珖闁活厽鎸鹃埀顒€绠嶉崕鍗灻洪銏犵闁搞儮鏅濈壕钘壝归敐鍛儓闁哄閰ｉ弻娑㈡偄閸涘﹤纰嶉梺宕囩帛濡啫顕ｉ幘顔藉€烽柣銏℃櫕閵婏妇绠鹃柟瀵稿仦鐏忋劑鏌涚€ｎ偅宕岄柡宀€鍠撻埀顒佺⊕閿氬┑顔兼湰閵囧嫰顢曢姀鈺傗枅閻庤娲橀懝楣冨煝鎼淬劌绠ｉ柣鎰暩瀹曞爼鏌ｉ悢鍝ョ煂濠⒀勵殔鐓ら柟瀵稿仧缁犻箖鏌涢妷顔煎闁稿鍔戦弻鏇熺箾瑜嶇€氼噣寮抽悩缁樷拺閺夌偞澹嗛崝宥嗙節閵忊槄鑰块柟顕€缂氶ˇ宕囩磼閸屾稑娴柡浣瑰姍瀹曘劑顢橀悙鈺傜€奸梻?
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

// normalizeImageRuleItem prepares one image rule for de-duplication and
// download ordering.
//
// Only fields that influence selection or verification are normalized here
// so the aggregated list remains predictable for callers in other packages.
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

// buildImageRuleKey creates the stable de-duplication key for aggregated
// image rules.
//
// The key intentionally keeps the fields that historically distinguished
// image entries in the legacy image-selection flow, including hash, file name,
// index, link type, and the normalized link list.
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

// buildWinPEKey 闂傚倷鐒﹂惇褰掑垂婵犳艾绐楅柟鐗堟緲閸?PE 闂傚倷绀侀幉锟犳晪濡炪値鍘鹃崗妯虹暦閹惰棄绠瑰ù锝呮贡閸欏棗顪冮妶鍡橆梿闁靛棌鍋撻梺?
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

// sortRuleSources 闂備浇顕уù鐑藉极閹间降鈧焦绻濋崶椋庣◤婵犮垼鍩栭崝鏇犵矆閸℃绠鹃柛鈩兠慨鍫ユ煟鎼搭喖鏋涢棁澶愭煟濡绲绘い锝呯－缁辨帡顢欓崫鍕潎閻庢鍠氶…鍫モ€﹂妸鈺佺鐟滃繑銇欏畷鍥╃＝濞达絽澹婇崕蹇涙煕閻旈攱鍋ラ柟顔惧亾閵堬綁宕橀妸褜鍞洪梻浣告贡閸庛倝宕归崷顓炴瀳鐎广儱顦伴悡?
//
// 闂傚倷鑳堕…鍫㈡崲閹扮増鍋嬪┑鐘插閸?Rank 闂傚倸鍊搁崐鍝モ偓姘煎墰缁梻鈧灚鐡曟慨铏亜閹惧崬鐏柡鍜佸墴閹﹢鎮欓懜娈挎闂佸搫鎳忛悷鈺呭蓟閻旇櫣鐭欐繛鍡欏亾鏁堟繝鐢靛仜閵堢顭囪閸╃偤宕橀鑲╃杸濡炪倖甯婄粈渚€鍩€椤掍礁鈻曢柡灞剧☉椤劑宕橀鍡楀О闂備焦妞块崢浠嬪磿閹剁瓔鏁嬮柕澶嗘櫅缁€瀣亜閹板墎纾垮鐟扮－缁辨挻鎷呴崜鎻掑壈闂佸摜鍠庡锟犲箖閻愵兙鍋呴柛鎰╁妿椤斿﹪姊洪崷顓炲妺闁搞劌婀遍崰濠傤吋婢跺鍘?
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

// sortImageRuleCandidates orders aggregated image candidates from most to
// least preferred.
//
// Higher-ranked sources stay ahead, URL rules stay ahead of non-URL rules,
// and stable secondary keys keep iteration order deterministic across runs.
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

// sortPE 闂?PE 闂傚倷鑳堕…鍫ユ晝閵夆晜鍋￠柍鍝勬噹閻掑灚銇勯幒鍡椾壕濡炪倧濡囬弫缁樹繆閺夋埈鍚嬪璺猴功閿涙稑鈹戦鏂よ€块柦鍐枛瀵噣宕掑Δ鈧禍楣冩偡濞嗗繐顏い锝嗙叀閹粙顢涘☉娆忛瀺闂佽鍨卞Λ浣虹不濞戞埃鍋撻敍鍗炲暕婢?
//
// 闂傚倷鑳堕…鍫㈡崲閹扮増鍋嬮煫鍥ㄦ惈閼?Rank闂傚倷鐒︾€笛呯矙閹达附鍤愭い鏍仜閻ゎ噣鏌嶈閸撶喖寮婚敐澶樻晜闁告洟娼ч崜铏節閳封偓閸曞灚鐤侀悗娈垮枤閺佸銆佸Δ鍛劦妞ゆ帒鍟ㄦ禍褰掓煕瑜庨〃鍡涘疾椤掑嫭鍊堕柣鎰版涧娴滄儳霉閻樼鑰块柡灞剧☉椤繈顢楅崟纰樺亾濡や胶绠鹃柛娆忣槺婢х敻鏌熷畡鏉挎殻闁圭锕ュ鍕節閸曨偄绗撻梻鍌欑閹诧繝鎳濋崜褏鐭撻柟顖涘閸欏潡姊绘担鍛婂暈缂侇喖鐭傚鐢割敆閳ь剟鈥﹂崶顒侇棃婵炴垶甯楅弫鐘绘⒑鐟欏嫭绶插褍娴风划鍫熷緞婵炴閰ｅ畷鍫曞Ω瑜忛悾楣冩⒑娴兼瑧鐣辨い锔炬暬閻涱噣骞掑Δ鈧粻鎶芥煙鐎电啸妞わ絾鐓″娲川婵犲嫭鍣介梺鎼炲妼閻栧ジ濡撮崒鐐茬厸闁告侗鍘奸悵姗€姊虹紒妯烩拻閻炴稏鍎靛畷?
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

// hasImageRuleValue rejects empty image rules before they enter the
// candidate list.
//
// A rule is considered usable when it contributes either a file name or at
// least one download link after normalization.
func hasImageRuleValue(it RuleItem) bool {
	return strings.TrimSpace(it.FileName) != "" || len(it.Link.Links) > 0
}

// hasWinPEValue 闂傚倷绀侀幉锛勬暜閸ヮ剙纾归柡宥庡幖閽冪喖鏌涢妷顔煎缂佺嫏鍥ㄧ叆婵炴垶锚椤忣亞绱掗幇顓ф疁闁哄矉绻濆畷鐔兼濞戞矮鍝楅梻浣筋嚃閸垳娆㈠璺虹疇婵炴垯鍨圭粈鍐煠绾板崬澧柣锔界矒濮婅櫣绮欑捄銊ь唶闂佹悶鍨洪悡陇妫?PE 婵犵數鍋為崹鍫曞箰閹间緡鏁勯柛顐ｇ贩瑜版帒鐐婃い鎺嗗亾缂佺姰鍎甸弻宥堫檨闁告挾鍠庤灋濞撴埃鍋撻柛鈹惧亾濡炪倖甯掔€氼參宕曞澶嬬厱闁哄洢鍔屾晶顖毭归悩绛硅€块柟顔筋焾缁犳盯骞橀崜渚囧敹闂備胶鍎垫慨宥夊礃閿濆棛浜栭梻浣虹帛閸旀洟宕㈠鍫濈；?
func hasWinPEValue(it WinPEImg) bool {
	return strings.TrimSpace(it.Name) != "" && len(it.Links) > 0
}

// compactRuleLinks trims blanks, removes empty entries, and de-duplicates
// the link list while preserving the first-seen order.
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

// normalizeArch maps common architecture aliases onto the canonical values
// used by aggregated RuleItem entries.
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

// peGroupFromRule 闂傚倷绀侀幖顐ょ矓閻戞枻缍栧璺猴功閺嗐倕霉閿濆洤鍔嬮柛鐘叉閺屾盯寮撮妸銉ょ盎闂佽绻掗崰鏍蓟閿熺姴纾兼慨姗嗗幘閻撴垵鈹戦悙鍙夘棑闁搞劋绮欓獮鍡涘礋椤撶姷鐓撳┑鐐叉閸庡啿鈻撻幖浣圭厽闁绘绮鹃鐔兼煕閵婏箑顥嬫繛鍡愬灲閹瑩宕崟顓у敽闂備線娼ч…鍫ュ磿濞差亜鍚归柕鍫濐槹閻撴洟鏌熼悜妯虹仸妞ゃ儳濮风槐鎺楊敊閼测敩褏鈧娲忛崕閬嶎敇婵傜绀冮柨婵嗘噸婢?
//
// 婵犵數鍋為幐濠氭嚌妤ｅ喚鏁勯柛娑欑暘閳ь剙鎳撻ˇ褰掓煛?
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

// ruleVerScore 婵犵數鍋涢顓熸叏閺夋嚚褰掓煥鐎ｎ偅鐝峰┑掳鍊曢幊搴ｂ偓姘槹閵囧嫰骞掗崱妞惧闁荤喐绮嶅妯侯焽閳╁啩绻嗛悗娑櫳戞刊鎾煕濞戞﹫宸ラ柍褜鍓欑壕顓犳閹烘挸绶為悗锝庝憾濡棝姊洪悜鈺佸⒉闁搞劌缍婇崺鈧い鎺嶈兌閳洘銇勯妸銉уⅵ妞ゃ垺鐗楅幏鍛村捶椤撴稒鐏冮梻浣告惈鐞氼偊宕曢崡鐐╂瀺闁跨喓濮甸悡娆戠磽娴ｅ顏呮叏閸モ晜鍠愰柡澶嬪瀹告繄绱掗鍛籍妞ゃ垺鐗滈幑鍕€﹂幋婊呯婵犵數鍋為崹鍫曞箹閳哄倻顩叉繝濠傛娴滃綊鏌熺紒妯洪唶闁圭儤顨呯猾宥夋煕閵夈垺娅囬柣娑掓櫊濮婂搫效閸パ冾瀳闁诲孩鍑归崣鍐嚕閹惰姤鍋勯悶娑掆偓鍏呭濠电偞鍨堕悷顖氣枔濡警鐔嗙憸搴ㄣ€冩繝鍌ゅ殨闁汇垹澹婇弫鍕⒑濞嗘儳鐏犲ù?
//
// 闂備浇顕уù鐑藉箠閹捐鐤柍鍝勫暊閸嬫捇妫冨☉姘变紘闂佺灏欐晶妤呭箯閸涘瓨鍊绘俊顖滅帛椤撶懓鈹?PE 闂傚倷绀佸﹢閬嶅磿閵堝洦鏆滈柟鐑樻婵櫕銇勯幘鍗炵仾闁哄拋鍓熼幃姗€鎮欑捄杞版睏闂佽崵鍠愮换鍫濐嚕閸洖鐓涢柛鏇ㄥ€ｉ幘缁樼厽妞ゅ繐鍟畵鍡涙煙椤斻劌娲﹂崑锟犳煛婢跺孩纭堕柛鏂跨埣濮婃椽宕崟顒€娈楃紓鍌氬€瑰畝绋跨暦濡も偓椤粓鍩€椤掑嫬鏋佺€广儱娲ｅ▽顏堟煢濡警妲归梺娆惧弮閺岋綁鎮㈤崨濠勶紱濠电偞娼欏ú顓炵暦濡も偓椤粓鍩€椤掑嫮宓?2.3 闂傚倷绀佸﹢閬嶅磿閵堝洦鏆滈柟鐑樺煀閼?2.2 闂傚倷绀侀幉锟犲箰閸濄儳鐭撻柣鐔煎亰閻掕棄霉閸忓吋缍戠痪顓涘亾闂備礁鎲￠崝鏍亹閸愵亝濯奸柡灞诲劜閻?
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
