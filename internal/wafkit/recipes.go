package wafkit

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/playwjj/flarehound/internal/suggest"
)

// Phases a recipe can write to.
const (
	PhaseCustom    = "http_request_firewall_custom"
	PhaseRateLimit = "http_ratelimit"
)

// Where a recipe's rule goes.
const (
	PlaceTop         = "top"          // ahead of everything (skip rules)
	PlaceAfterSkips  = "after_skips"  // after the skip rules, ahead of the rest (blocks)
	PlaceAfterBlocks = "after_blocks" // after skips and blocks (challenges)
	PlaceEnd         = "end"
)

// Param is one input of a recipe.
type Param struct {
	Name     string
	Label    [2]string // en, zh
	Help     [2]string
	Default  string
	Required bool
	Choices  []string // fixed choices (first is the default)
	Secret   bool     // shown as a password field
}

// Recipe is a ready-made rule for a common need, explained for people
// who do not write rule expressions.
type Recipe struct {
	Name    string
	Title   [2]string
	Summary [2]string // what it does
	Why     [2]string // why it is written this way, and what it does not do
	Phase   string
	Place   string
	Params  []Param
	build   func(v map[string]string, plan string) (Built, error)
}

// Built is a recipe's output.
type Built struct {
	Rule     map[string]any // the rule as the API takes it
	Phase    string
	Place    string
	Warnings [][2]string
}

func (r Recipe) T(f [2]string, lang string) string { return tr(lang, f[0], f[1]) }

// ---- input parsing ----

func splitList(s string) []string {
	var out []string
	for _, x := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '\n' || r == ' ' || r == ';' }) {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

func quote(s string) string { return strconv.Quote(s) }

// pathsExpr turns "/login*, /admin*" into one expression.
func pathsExpr(s string) (string, []string, error) {
	paths := splitList(s)
	if len(paths) == 0 {
		return "", nil, fmt.Errorf("give at least one path, e.g. /login*")
	}
	var parts []string
	for _, p := range paths {
		if !strings.HasPrefix(p, "/") || strings.ContainsAny(p, `"\`) {
			return "", nil, fmt.Errorf("path %q must start with / (use * as wildcard)", p)
		}
		parts = append(parts, suggest.PathExpression(p))
	}
	if len(parts) == 1 {
		return parts[0], paths, nil
	}
	return "(" + strings.Join(parts, " or ") + ")", paths, nil
}

func ipsExpr(s string) (string, error) {
	var items []string
	for _, x := range splitList(s) {
		if p, err := netip.ParsePrefix(x); err == nil {
			items = append(items, p.Masked().String())
			continue
		}
		a, err := netip.ParseAddr(x)
		if err != nil {
			return "", fmt.Errorf("%q is not an IP address or range", x)
		}
		items = append(items, a.String())
	}
	if len(items) == 0 {
		return "", nil
	}
	return "ip.src in {" + strings.Join(items, " ") + "}", nil
}

func asnsExpr(s string) (string, error) {
	var items []string
	for _, x := range splitList(s) {
		n, err := strconv.Atoi(strings.TrimPrefix(strings.ToUpper(x), "AS"))
		if err != nil || n <= 0 {
			return "", fmt.Errorf("%q is not an ASN", x)
		}
		items = append(items, strconv.Itoa(n))
	}
	if len(items) == 0 {
		return "", nil
	}
	return "ip.geoip.asnum in {" + strings.Join(items, " ") + "}", nil
}

var headerName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,63}$`)

func headerExpr(name, value string) (string, error) {
	if name == "" && value == "" {
		return "", nil
	}
	if !headerName.MatchString(name) {
		return "", fmt.Errorf("header name %q: letters, digits and - only", name)
	}
	if len(value) < 16 || strings.ContainsAny(value, `"\`) {
		return "", fmt.Errorf("the secret header value must be at least 16 characters (no quotes or backslashes): a short secret can be guessed")
	}
	return fmt.Sprintf(`any(http.request.headers[%s][*] eq %s)`, quote(strings.ToLower(name)), quote(value)), nil
}

func intParam(v map[string]string, k string, def, lo, hi int) (int, error) {
	s := strings.TrimSpace(v[k])
	if s == "" {
		return def, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < lo || n > hi {
		return 0, fmt.Errorf("%s must be a number from %d to %d", k, lo, hi)
	}
	return n, nil
}

func custom(desc, expr, action string, ap map[string]any) map[string]any {
	r := map[string]any{"description": desc, "expression": expr, "action": action, "enabled": true}
	if ap != nil {
		r["action_parameters"] = ap
	}
	return r
}

func challengeAction(v map[string]string) (string, error) {
	switch a := v["action"]; a {
	case "", "managed_challenge":
		return "managed_challenge", nil
	case "block":
		return "block", nil
	default:
		return "", fmt.Errorf("action must be managed_challenge or block")
	}
}

var actionParam = Param{Name: "action", Label: [2]string{"Action", "动作"}, Choices: []string{"managed_challenge", "block"},
	Help: [2]string{"Managed challenge stops bots and lets people through; block stops everyone.", "托管质询拦住机器人、放真人通过；拦截则所有人都进不来。"}}

// ---- the recipes ----

var recipes = []Recipe{
	{
		Name:    "allow-verified-bots",
		Title:   [2]string{"Let verified search-engine bots through", "放行已核验的搜索引擎爬虫"},
		Summary: [2]string{"Requests from bots Cloudflare has verified (Googlebot, Bingbot …) skip your other custom rules.", "Cloudflare 已核验的爬虫（Googlebot、Bingbot 等）跳过你的其它自定义规则。"},
		Why: [2]string{
			"It uses cf.client.bot, which Cloudflare sets only after checking the bot's IP and reverse DNS — never the user agent, which anyone can fake (\"Googlebot\" in a user agent proves nothing). Often you do not need it at all: writing \"and not cf.client.bot\" into your block and challenge rules (as FlareHound's own rules do) is narrower. Use it when you have broad rules that would otherwise hit search engines.",
			"它使用 cf.client.bot：只有 Cloudflare 核验过爬虫的 IP 与反向 DNS 才为真；绝不按 UA 放行——UA 谁都能伪造，UA 里写着 Googlebot 什么也证明不了。很多时候根本不需要这条：在你的拦截 / 质询规则里加上「and not cf.client.bot」（FlareHound 生成的规则都这么写）范围更窄。当你有大范围规则可能误伤搜索引擎时再用它。"},
		Phase: PhaseCustom, Place: PlaceTop,
		Params: []Param{{Name: "skip", Label: [2]string{"Also skip", "同时跳过"}, Choices: []string{"rules", "rules,ratelimit", "rules,ratelimit,bots"},
			Help: [2]string{"rules: the remaining custom rules; ratelimit: rate limiting; bots: Super Bot Fight Mode (Pro and above).", "rules：其后的自定义规则；ratelimit：限速规则；bots：超级机器人对抗模式（Pro 及以上）。"}}},
		build: func(v map[string]string, _ string) (Built, error) {
			ap, err := SkipParams(splitList(v["skip"]))
			if err != nil {
				return Built{}, err
			}
			return Built{Rule: custom("FlareHound recipe: let verified bots through", "cf.client.bot", "skip", ap)}, nil
		},
	},
	{
		Name:    "protect-paths",
		Title:   [2]string{"Protect login / admin paths", "保护登录、后台等敏感路径"},
		Summary: [2]string{"Challenges (or blocks) every request to the paths you name, except verified bots.", "对你指定的路径上的每个请求做质询（或拦截），已核验爬虫除外。"},
		Why: [2]string{
			"Sensitive paths are where credential stuffing and scraping concentrate. A managed challenge stops automated clients and costs a person one click; choose block only for paths no outsider should reach. Combine it with a rate limit on the same paths.",
			"撞库与抓取集中在敏感路径上。托管质询能拦住自动化客户端，真人只需点一下；只有外人根本不该访问的路径才选「拦截」。建议同时给这些路径加限速。"},
		Phase: PhaseCustom, Place: PlaceAfterSkips,
		Params: []Param{
			{Name: "paths", Label: [2]string{"Paths", "路径"}, Required: true, Default: "/login*, /wp-login.php, /admin*",
				Help: [2]string{"Comma-separated; * is a wildcard (/login* covers /login and /login/reset).", "逗号分隔；* 为通配符（/login* 覆盖 /login 与 /login/reset）。"}},
			actionParam,
		},
		build: func(v map[string]string, _ string) (Built, error) {
			pe, paths, err := pathsExpr(v["paths"])
			if err != nil {
				return Built{}, err
			}
			a, err := challengeAction(v)
			if err != nil {
				return Built{}, err
			}
			b := Built{Rule: custom("FlareHound recipe: protect "+strings.Join(paths, ", "), pe+" and not cf.client.bot", a, nil)}
			if a == "block" {
				b.Warnings = append(b.Warnings, [2]string{"Block stops people too: you will not reach these paths yourself unless an earlier skip rule lets you in.",
					"拦截对真人同样生效：除非前面有放行规则，你自己也进不去这些路径。"})
			}
			return b, nil
		},
	},
	{
		Name:    "ratelimit-paths",
		Title:   [2]string{"Rate-limit sensitive paths", "给敏感路径限速"},
		Summary: [2]string{"An IP that sends more than N requests in the period to these paths is challenged (or blocked) for a while.", "单个 IP 在周期内对这些路径请求超过 N 次，就在一段时间内被质询（或拦截）。"},
		Why: [2]string{
			"Counts per IP and Cloudflare data center. It catches brute force and fast scrapers that a one-time challenge does not slow down. The Free plan allows one rate-limit rule with a 10-second period and a 10-second timeout.",
			"按 IP 与 Cloudflare 数据中心计数，能抓住一次性质询拦不住的暴力破解与高速抓取。Free 套餐只能有 1 条限速规则，周期与持续时间都必须是 10 秒。"},
		Phase: PhaseRateLimit, Place: PlaceEnd,
		Params: []Param{
			{Name: "paths", Label: [2]string{"Paths", "路径"}, Required: true, Default: "/login*",
				Help: [2]string{"Comma-separated; * is a wildcard.", "逗号分隔；* 为通配符。"}},
			{Name: "requests", Label: [2]string{"Requests per period", "每周期请求数"}, Default: "20"},
			{Name: "period", Label: [2]string{"Period (seconds)", "周期（秒）"}, Default: "10"},
			{Name: "timeout", Label: [2]string{"Then for (seconds)", "触发后持续（秒）"}, Default: "10"},
			actionParam,
		},
		build: func(v map[string]string, plan string) (Built, error) {
			pe, paths, err := pathsExpr(v["paths"])
			if err != nil {
				return Built{}, err
			}
			a, err := challengeAction(v)
			if err != nil {
				return Built{}, err
			}
			req, err := intParam(v, "requests", 20, 1, 100000)
			if err != nil {
				return Built{}, err
			}
			per, err := intParam(v, "period", 10, 10, 3600)
			if err != nil {
				return Built{}, err
			}
			to, err := intParam(v, "timeout", 10, 0, 86400)
			if err != nil {
				return Built{}, err
			}
			if (plan == "free" || plan == "") && (per != 10 || to != 10) {
				return Built{}, fmt.Errorf("on the Free plan the period and the timeout must both be 10 seconds")
			}
			rule := map[string]any{
				"description": "FlareHound recipe: rate-limit " + strings.Join(paths, ", "), "expression": pe + " and not cf.client.bot", "action": a, "enabled": true,
				"ratelimit": map[string]any{"characteristics": []any{"ip.src", "cf.colo.id"}, "period": float64(per),
					"requests_per_period": float64(req), "mitigation_timeout": float64(to)},
			}
			return Built{Rule: rule}, nil
		},
	},
	{
		Name:    "allow-service",
		Title:   [2]string{"Let a monitor / webhook through", "放行监控探针或 Webhook 回调"},
		Summary: [2]string{"Requests from the IPs or networks you name — and, if you give one, carrying your secret header — skip your other custom rules.", "来自你指定的 IP 或网络（如填写，还须带上你的密钥请求头）的请求，跳过其它自定义规则。"},
		Why: [2]string{
			"An exemption must be tied to something a stranger cannot fake: the source IP or network, or a secret header only your service sends. A path or a user agent alone would let anyone in. Narrow it with paths when the service only calls a few URLs.",
			"放行条件必须绑定外人伪造不了的东西：来源 IP / 网络，或只有你的服务才会发送的密钥请求头。只按路径或 UA 放行等于对所有人开门。如果服务只访问少数几个 URL，再用路径收窄。"},
		Phase: PhaseCustom, Place: PlaceTop,
		Params: []Param{
			{Name: "ips", Label: [2]string{"IPs or ranges", "IP 或网段"}, Help: [2]string{"e.g. 203.0.113.10, 198.51.100.0/24", "例如 203.0.113.10, 198.51.100.0/24"}},
			{Name: "asns", Label: [2]string{"Networks (ASN)", "网络（ASN）"}, Help: [2]string{"e.g. AS13335 — only for a service whose whole network you trust", "例如 AS13335——仅当你信任对方整个网络时使用"}},
			{Name: "header", Label: [2]string{"Secret header name", "密钥请求头名称"}, Help: [2]string{"e.g. x-hook-key", "例如 x-hook-key"}},
			{Name: "secret", Label: [2]string{"Secret header value", "密钥请求头的值"}, Secret: true, Help: [2]string{"At least 16 random characters, configured in the sending service.", "至少 16 位随机字符，在发送方配置。"}},
			{Name: "paths", Label: [2]string{"Only these paths (optional)", "仅限这些路径（可选）"}, Help: [2]string{"e.g. /webhooks/*", "例如 /webhooks/*"}},
			{Name: "skip", Label: [2]string{"Skip", "跳过"}, Choices: []string{"rules", "rules,ratelimit", "rules,ratelimit,bots"},
				Help: [2]string{"rules: the remaining custom rules; ratelimit: rate limiting; bots: Super Bot Fight Mode (Pro and above).", "rules：其后的自定义规则；ratelimit：限速规则；bots：超级机器人对抗模式（Pro 及以上）。"}},
		},
		build: func(v map[string]string, _ string) (Built, error) {
			ipE, err := ipsExpr(v["ips"])
			if err != nil {
				return Built{}, err
			}
			asE, err := asnsExpr(v["asns"])
			if err != nil {
				return Built{}, err
			}
			hE, err := headerExpr(strings.TrimSpace(v["header"]), strings.TrimSpace(v["secret"]))
			if err != nil {
				return Built{}, err
			}
			if ipE == "" && asE == "" && hE == "" {
				return Built{}, fmt.Errorf("give the service's IPs, its network (ASN) or a secret header — a rule without them would let anyone through")
			}
			var conds []string
			switch {
			case ipE != "" && asE != "":
				conds = append(conds, "("+ipE+" or "+asE+")")
			case ipE != "":
				conds = append(conds, ipE)
			case asE != "":
				conds = append(conds, asE)
			}
			if hE != "" {
				conds = append(conds, hE)
			}
			if strings.TrimSpace(v["paths"]) != "" {
				pe, _, err := pathsExpr(v["paths"])
				if err != nil {
					return Built{}, err
				}
				conds = append(conds, pe)
			}
			ap, err := SkipParams(splitList(v["skip"]))
			if err != nil {
				return Built{}, err
			}
			b := Built{Rule: custom("FlareHound recipe: let a trusted service through", strings.Join(conds, " and "), "skip", ap)}
			if asE != "" && ipE == "" && hE == "" {
				b.Warnings = append(b.Warnings, [2]string{"A whole network is trusted: anyone renting a server there gets in. Prefer IPs or a secret header.",
					"信任了整个网络：任何在该网络租服务器的人都能进来。优先使用 IP 或密钥请求头。"})
			}
			return b, nil
		},
	},
	{
		Name:    "challenge-cloud-on-paths",
		Title:   [2]string{"Challenge cloud servers on sensitive paths", "敏感路径上质询来自云服务器的流量"},
		Summary: [2]string{"Requests to these paths from the big cloud and hosting networks (AWS, Google Cloud, Azure, Alibaba, Tencent, Hetzner, OVH …) are challenged, verified bots excepted.", "来自主流云 / 机房网络（AWS、Google Cloud、Azure、阿里云、腾讯云、Hetzner、OVH 等）访问这些路径的请求要过质询，已核验爬虫除外。"},
		Why: [2]string{
			"People browse from home and mobile networks; scrapers and credential stuffers rent cloud servers. The list includes Google's network (AS15169), which is why the rule keeps \"not cf.client.bot\": Googlebot is verified and passes. Uses FlareHound's built-in list of hosting networks.",
			"真人多从家庭宽带与移动网络访问，抓取与撞库则多租用云服务器。名单里包含 Google 的网络（AS15169），所以规则保留了「not cf.client.bot」：Googlebot 已核验，会被放行。使用 FlareHound 内置的机房网络名单。"},
		Phase: PhaseCustom, Place: PlaceAfterSkips,
		Params: []Param{
			{Name: "paths", Label: [2]string{"Paths", "路径"}, Required: true, Default: "/login*, /api/*",
				Help: [2]string{"Comma-separated; * is a wildcard. Use /* for the whole site.", "逗号分隔；* 为通配符。全站用 /*。"}},
			actionParam,
		},
		build: func(v map[string]string, _ string) (Built, error) {
			pe, paths, err := pathsExpr(v["paths"])
			if err != nil {
				return Built{}, err
			}
			a, err := challengeAction(v)
			if err != nil {
				return Built{}, err
			}
			var asns []string
			for _, n := range suggest.HostingASNs() {
				asns = append(asns, strconv.Itoa(n))
			}
			expr := pe + " and ip.geoip.asnum in {" + strings.Join(asns, " ") + "} and not cf.client.bot"
			b := Built{Rule: custom("FlareHound recipe: challenge cloud servers on "+strings.Join(paths, ", "), expr, a, nil)}
			b.Warnings = append(b.Warnings, [2]string{"Your own servers, CI and API clients hosted in these clouds are affected too: let them through first (recipe allow-service).",
				"你自己部署在这些云上的服务器、CI 与 API 客户端也会受影响：请先用「放行监控探针或 Webhook」配方放行它们。"})
			return b, nil
		},
	},
}

// Recipes lists the recipes in display order.
func Recipes() []Recipe { return recipes }

// RecipeByName finds a recipe.
func RecipeByName(name string) (Recipe, bool) {
	for _, r := range recipes {
		if r.Name == name {
			return r, true
		}
	}
	return Recipe{}, false
}

// Build makes the rule from the inputs; plan is the zone's plan
// ("free", "pro" …, "" when unknown).
func (r Recipe) Build(v map[string]string, plan string) (Built, error) {
	vals := map[string]string{}
	for _, p := range r.Params {
		x := strings.TrimSpace(v[p.Name])
		if x == "" {
			x = p.Default
			if x == "" && len(p.Choices) > 0 {
				x = p.Choices[0]
			}
		}
		if p.Required && x == "" {
			return Built{}, fmt.Errorf("%s is required", p.Name)
		}
		if len(p.Choices) > 0 && x != "" {
			ok := false
			for _, c := range p.Choices {
				ok = ok || c == x
			}
			if !ok && p.Name != "skip" {
				return Built{}, fmt.Errorf("%s must be one of %s", p.Name, strings.Join(p.Choices, ", "))
			}
		}
		vals[p.Name] = x
	}
	b, err := r.build(vals, plan)
	if err != nil {
		return b, err
	}
	b.Phase, b.Place = r.Phase, r.Place
	// Skips first, then blocks, then challenges: a recipe that challenges
	// goes after the blocks, one that blocks goes right after the skips.
	if b.Place == PlaceAfterSkips && b.Rule["action"] != "block" {
		b.Place = PlaceAfterBlocks
	}
	return b, nil
}

// Before picks the insert position for a placement from a phase's rules
// (raw API objects): the id to insert before, or "" for the end.
func Before(rules []map[string]any, place string) string {
	switch place {
	case PlaceTop:
		if len(rules) > 0 {
			id, _ := rules[0]["id"].(string)
			return id
		}
	case PlaceAfterSkips:
		for _, r := range rules {
			if a, _ := r["action"].(string); a != "skip" {
				id, _ := r["id"].(string)
				return id
			}
		}
	case PlaceAfterBlocks:
		for _, r := range rules {
			if a, _ := r["action"].(string); a != "skip" && a != "block" {
				id, _ := r["id"].(string)
				return id
			}
		}
	}
	return ""
}

// Names returns the recipe names, sorted (for usage text).
func Names() []string {
	var out []string
	for _, r := range recipes {
		out = append(out, r.Name)
	}
	sort.Strings(out)
	return out
}
