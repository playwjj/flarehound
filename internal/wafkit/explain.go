// Package wafkit makes WAF rule work approachable (v1.7): it explains
// Cloudflare rule expressions in plain words, builds correct skip rules,
// offers ready-made rule recipes for common needs, and turns WAF audit
// findings into concrete fixes. It never talks to Cloudflare itself: the
// rules it builds go through the execution module (show, confirm, back
// up, apply, read back, log).
package wafkit

import (
	"fmt"
	"sort"
	"strings"

	"github.com/playwjj/flarehound/internal/waf"
)

func tr(lang, en, zh string) string {
	if lang == "zh" {
		return zh
	}
	return en
}

// fieldNames are the fields people meet first, in plain words.
var fieldNames = map[string][2]string{
	"http.request.uri.path":          {"the path", "路径"},
	"http.request.uri":               {"the URI", "URI"},
	"http.request.uri.query":         {"the query string", "查询串"},
	"http.request.full_uri":          {"the full URL", "完整 URL"},
	"http.host":                      {"the host name", "主机名"},
	"http.user_agent":                {"the user agent", "UA"},
	"http.referer":                   {"the referer", "来源页（Referer）"},
	"http.request.method":            {"the method", "请求方法"},
	"http.cookie":                    {"the cookies", "Cookie"},
	"http.x_forwarded_for":           {"X-Forwarded-For", "X-Forwarded-For"},
	"ip.src":                         {"the client IP", "来源 IP"},
	"ip.geoip.asnum":                 {"the network (ASN)", "网络（ASN）"},
	"ip.src.asnum":                   {"the network (ASN)", "网络（ASN）"},
	"ip.geoip.country":               {"the country", "国家"},
	"ip.src.country":                 {"the country", "国家"},
	"ip.geoip.continent":             {"the continent", "大洲"},
	"cf.client.bot":                  {"a Cloudflare-verified bot (Googlebot, Bingbot …)", "Cloudflare 已核验的爬虫（Googlebot、Bingbot 等）"},
	"cf.verified_bot_category":       {"the verified-bot category", "已核验爬虫的类别"},
	"cf.threat_score":                {"the threat score", "威胁分"},
	"cf.bot_management.score":        {"the bot score", "机器人评分"},
	"cf.bot_management.verified_bot": {"a verified bot", "已核验爬虫"},
	"ssl":                            {"HTTPS", "HTTPS"},
	"http.request.version":           {"the HTTP version", "HTTP 版本"},
}

var opNames = map[string][2]string{
	"eq":              {"is", "等于"},
	"ne":              {"is not", "不等于"},
	"lt":              {"is below", "小于"},
	"le":              {"is at most", "不大于"},
	"gt":              {"is above", "大于"},
	"ge":              {"is at least", "不小于"},
	"contains":        {"contains", "包含"},
	"matches":         {"matches the pattern", "匹配正则"},
	"wildcard":        {"matches", "匹配通配符"},
	"strict_wildcard": {"matches (case-sensitive)", "匹配通配符（区分大小写）"},
	"in":              {"is one of", "属于"},
}

var negOpNames = map[string][2]string{
	"lt":              {"is not below", "不小于"},
	"le":              {"is above", "大于"},
	"gt":              {"is at most", "不大于"},
	"ge":              {"is below", "小于"},
	"contains":        {"does not contain", "不包含"},
	"matches":         {"does not match the pattern", "不匹配正则"},
	"wildcard":        {"does not match", "不匹配通配符"},
	"strict_wildcard": {"does not match (case-sensitive)", "不匹配通配符（区分大小写）"},
	"in":              {"is not one of", "不属于"},
}

func fieldWords(name, lang string) string {
	if v, ok := fieldNames[name]; ok {
		return tr(lang, v[0], v[1])
	}
	// http.request.headers["x-key"] and friends.
	if strings.HasPrefix(name, "http.request.headers[") {
		h := strings.TrimPrefix(name, "http.request.headers[")
		if i := strings.Index(h, "]"); i > 0 {
			h = strings.Trim(h[:i], `"`)
			return tr(lang, "header "+h, "请求头 "+h)
		}
	}
	if strings.HasPrefix(name, "http.request.cookies[") {
		return tr(lang, "a cookie", "某个 Cookie")
	}
	return name
}

func operandWords(o waf.Operand, lang string) string {
	switch x := o.(type) {
	case waf.Field:
		return fieldWords(x.Name, lang)
	case waf.Call:
		switch x.Name {
		case "lower", "upper", "url_decode", "len":
			if len(x.Args) == 1 {
				w := operandWords(x.Args[0], lang)
				switch x.Name {
				case "lower", "upper":
					return w + tr(lang, " (any case)", "（忽略大小写）")
				case "url_decode":
					return w + tr(lang, " (decoded)", "（解码后）")
				case "len":
					return tr(lang, "the length of ", "长度：") + w
				}
			}
		}
	case waf.Lit:
		if x.Quoted {
			return fmt.Sprintf("%q", x.S)
		}
		return x.S
	}
	return o.String()
}

func valueWords(v waf.Value, lang string) string {
	switch x := v.(type) {
	case waf.Scalar:
		return operandWords(x.Lit, lang)
	case waf.Set:
		items := make([]string, 0, len(x.Items))
		for _, it := range x.Items {
			items = append(items, operandWords(it, lang))
		}
		if len(items) > 6 {
			return fmt.Sprintf("{%s %s}", strings.Join(items[:5], ", "), tr(lang, fmt.Sprintf("and %d more", len(items)-5), fmt.Sprintf("等 %d 项", len(items))))
		}
		return "{" + strings.Join(items, ", ") + "}"
	case waf.ListRef:
		return tr(lang, "the list ", "名单 ") + "$" + x.Name
	}
	return v.String()
}

func cmpWords(c waf.Cmp, negate bool, lang string) string {
	l := operandWords(c.Left, lang)
	op := c.Op
	if negate {
		switch op {
		case "eq":
			op = "ne"
		case "ne":
			op = "eq"
		default:
			w, ok := negOpNames[op]
			if !ok {
				w = [2]string{"not " + op, "非 " + op}
			}
			return fmt.Sprintf("%s %s %s", l, tr(lang, w[0], w[1]), valueWords(c.Value, lang))
		}
	}
	w, ok := opNames[op]
	if !ok {
		w = [2]string{op, op}
	}
	return fmt.Sprintf("%s %s %s", l, tr(lang, w[0], w[1]), valueWords(c.Value, lang))
}

func truthyWords(o waf.Operand, negate bool, lang string) string {
	if c, ok := o.(waf.Call); ok && len(c.Args) == 2 {
		verb := map[string][2]string{"starts_with": {"starts with", "以 %s 开头"}, "ends_with": {"ends with", "以 %s 结尾"}}[c.Name]
		if verb[0] != "" {
			subj, arg := operandWords(c.Args[0], lang), operandWords(c.Args[1], lang)
			if lang == "zh" {
				s := subj + fmt.Sprintf(verb[1], arg)
				if negate {
					s = subj + "不" + fmt.Sprintf(verb[1], arg)
				}
				return s
			}
			if negate {
				return subj + " does not " + strings.TrimSuffix(verb[0], "s") + " " + arg
			}
			return subj + " " + verb[0] + " " + arg
		}
	}
	w := operandWords(o, lang)
	if f, ok := o.(waf.Field); ok && (f.Name == "cf.client.bot" || f.Name == "cf.bot_management.verified_bot") {
		if negate {
			return tr(lang, "not ", "不是 ") + w
		}
		return tr(lang, "", "是 ") + w
	}
	if negate {
		return tr(lang, "not ", "非") + w
	}
	return w
}

func nodeWords(n waf.Node, lang string, top bool) string {
	switch x := n.(type) {
	case waf.And:
		return join(lang, n, "and", top)
	case waf.Or:
		return join(lang, n, "or", top)
	case waf.Xor:
		return nodeWords(x.L, lang, false) + tr(lang, " xor ", " 异或 ") + nodeWords(x.R, lang, false)
	case waf.Not:
		switch y := x.X.(type) {
		case waf.Cmp:
			return cmpWords(y, true, lang)
		case waf.Truthy:
			return truthyWords(y.X, true, lang)
		}
		return tr(lang, "not (", "非（") + nodeWords(x.X, lang, true) + tr(lang, ")", "）")
	case waf.Cmp:
		return cmpWords(x, false, lang)
	case waf.Truthy:
		return truthyWords(x.X, false, lang)
	}
	return n.String()
}

// join flattens a chain of the same operator.
func join(lang string, n waf.Node, op string, top bool) string {
	var parts []string
	var walk func(n waf.Node)
	walk = func(n waf.Node) {
		switch x := n.(type) {
		case waf.And:
			if op == "and" {
				walk(x.L)
				walk(x.R)
				return
			}
		case waf.Or:
			if op == "or" {
				walk(x.L)
				walk(x.R)
				return
			}
		}
		parts = append(parts, nodeWords(n, lang, false))
	}
	walk(n)
	sep := map[string][2]string{"and": {" and ", "，且"}, "or": {" or ", "，或"}}[op]
	s := strings.Join(parts, tr(lang, sep[0], sep[1]))
	if !top {
		return tr(lang, "(", "（") + s + tr(lang, ")", "）")
	}
	return s
}

// Explain renders an expression in plain words. Expressions that do not
// parse are returned as they are.
func Explain(expr, lang string) string {
	n, err := waf.Parse(expr)
	if err != nil {
		return expr
	}
	return nodeWords(n, lang, true)
}

// actionWords names an action and, for skip rules, what it skips.
func actionWords(action string, ap map[string]any, lang string) string {
	switch action {
	case "block":
		return tr(lang, "block", "拦截")
	case "managed_challenge":
		return tr(lang, "managed challenge (bots stopped, people pass)", "托管质询（拦住机器人，真人可通过）")
	case "js_challenge":
		return tr(lang, "JavaScript challenge", "JS 质询")
	case "challenge":
		return tr(lang, "interactive challenge", "交互式质询")
	case "log":
		return tr(lang, "log only", "仅记录")
	case "skip":
		return tr(lang, "let through, skipping ", "放行，跳过") + SkipWords(ap, lang)
	case "set_cache_settings":
		return tr(lang, "cache", "缓存")
	}
	return action
}

// Sentence explains a whole rule: "if <condition> → <action>".
func Sentence(action, expr string, actionParams map[string]any, lang string) string {
	return tr(lang, "If ", "如果") + Explain(expr, lang) + " → " + actionWords(action, actionParams, lang)
}

// RuleSentence explains a raw rule as the API returns it.
func RuleSentence(r map[string]any, lang string) string {
	action, _ := r["action"].(string)
	expr, _ := r["expression"].(string)
	ap, _ := r["action_parameters"].(map[string]any)
	s := Sentence(action, expr, ap, lang)
	if rl, ok := r["ratelimit"].(map[string]any); ok {
		req, _ := rl["requests_per_period"].(float64)
		per, _ := rl["period"].(float64)
		to, _ := rl["mitigation_timeout"].(float64)
		s += tr(lang, fmt.Sprintf(" when one IP sends more than %.0f requests in %.0f s (for %.0f s)", req, per, to),
			fmt.Sprintf("，当单个 IP 在 %.0f 秒内超过 %.0f 次请求时（持续 %.0f 秒）", per, req, to))
	}
	return s
}

// ---- skip ----

// Skip scopes, from narrowest to widest.
const (
	SkipRules     = "rules"     // the remaining custom rules (this phase)
	SkipRateLimit = "ratelimit" // rate-limiting rules
	SkipManaged   = "managed"   // managed WAF rules (Pro and above)
	SkipBots      = "bots"      // Super Bot Fight Mode
	SkipLegacy    = "legacy"    // legacy features: security level, browser integrity check, UA blocking, zone lockdown …
)

var skipPhase = map[string]string{
	SkipRateLimit: "http_ratelimit",
	SkipManaged:   "http_request_firewall_managed",
	SkipBots:      "http_request_sbfm",
}

var legacyProducts = []string{"bic", "hot", "rateLimit", "securityLevel", "uaBlock", "waf", "zoneLockdown"}

// SkipScopes lists the accepted scopes in display order.
func SkipScopes() []string {
	return []string{SkipRules, SkipRateLimit, SkipManaged, SkipBots, SkipLegacy}
}

// SkipParams builds a skip rule's action_parameters. Cloudflare rejects a
// skip rule without them: they say what is skipped.
func SkipParams(scopes []string) (map[string]any, error) {
	if len(scopes) == 0 {
		scopes = []string{SkipRules}
	}
	ap := map[string]any{}
	var phases []any
	seen := map[string]bool{}
	for _, s := range scopes {
		s = strings.TrimSpace(strings.ToLower(s))
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		switch s {
		case SkipRules:
			ap["ruleset"] = "current"
		case SkipLegacy:
			ps := make([]any, len(legacyProducts))
			for i, p := range legacyProducts {
				ps[i] = p
			}
			ap["products"] = ps
		default:
			ph, ok := skipPhase[s]
			if !ok {
				return nil, fmt.Errorf("unknown skip scope %q (use %s)", s, strings.Join(SkipScopes(), ", "))
			}
			phases = append(phases, ph)
		}
	}
	if len(phases) > 0 {
		ap["phases"] = phases
	}
	if len(ap) == 0 {
		return nil, fmt.Errorf("nothing to skip")
	}
	return ap, nil
}

// SkipWords says in plain words what action_parameters skip.
func SkipWords(ap map[string]any, lang string) string {
	var parts []string
	if ap["ruleset"] == "current" {
		parts = append(parts, tr(lang, "the remaining custom rules", "其后的自定义规则"))
	}
	if ph, ok := ap["phases"].([]any); ok {
		names := map[string][2]string{
			"http_ratelimit":                {"rate limiting", "限速规则"},
			"http_request_firewall_managed": {"managed rules", "托管规则"},
			"http_request_sbfm":             {"Super Bot Fight Mode", "超级机器人对抗模式"},
		}
		var ps []string
		for _, p := range ph {
			s, _ := p.(string)
			if n, ok := names[s]; ok {
				ps = append(ps, tr(lang, n[0], n[1]))
			} else {
				ps = append(ps, s)
			}
		}
		sort.Strings(ps)
		parts = append(parts, ps...)
	}
	if _, ok := ap["products"]; ok {
		parts = append(parts, tr(lang, "legacy security features", "旧版安全功能"))
	}
	if len(parts) == 0 {
		return tr(lang, "(nothing specified)", "（未指定）")
	}
	return strings.Join(parts, tr(lang, ", ", "、"))
}
