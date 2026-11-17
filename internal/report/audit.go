package report

import (
	"fmt"
	"strings"

	"github.com/playwjj/flarehound/internal/waf"
)

// AuditData is one WAF audit for rendering.
type AuditData struct {
	Zone   string
	Plan   string
	Result waf.Result
	NA     string // non-empty: the audit could not run, and why
}

func (l lang) ruleRef(r waf.RuleRef) string {
	d := r.Description
	if d == "" {
		d = r.ID
		if len(d) > 8 {
			d = d[:8]
		}
	}
	return fmt.Sprintf(l.t("#%d %q (%s)", "#%d「%s」（%s）"), r.Pos, clip(d, 48), r.Action)
}

// auditBody renders the audit. full=false (daily report) lists only
// what needs attention; full=true (CLI, change re-audit) lists all.
func (l lang) auditBody(b *strings.Builder, d AuditData, full bool) {
	r := d.Result
	if d.NA != "" {
		fmt.Fprintf(b, l.t("WAF audit: not available — %s\n", "WAF 体检：不可用——%s\n"), d.NA)
		return
	}
	probs := r.Problems()
	covered := 0
	for _, c := range r.Coverage {
		if c.Status == waf.Covered && c.MaySkipBy == nil {
			covered++
		}
	}
	head := fmt.Sprintf(l.t("WAF audit: %d custom rules", "WAF 体检：%d 条自定义规则"), r.Rules)
	if r.Disabled > 0 {
		head += fmt.Sprintf(l.t(" (%d disabled)", "（%d 条停用）"), r.Disabled)
	}
	switch {
	case probs == 0 && covered > 0:
		fmt.Fprintf(b, l.t("%s, no problems (all %d sensitive path probes covered).\n", "%s，无问题（%d 项敏感路径探测均已覆盖）。\n"), head, covered)
	case probs == 0:
		fmt.Fprintf(b, l.t("%s, no problems.\n", "%s，无问题。\n"), head)
	default:
		fmt.Fprintf(b, l.t("%s, %d item(s) need attention.\n", "%s，%d 项需要关注。\n"), head, probs)
	}
	if probs == 0 && !full {
		return
	}
	if full && len(r.RuleRefs) > 0 {
		b.WriteString(l.t("Rules, in evaluation order:\n", "规则（按执行顺序）：\n"))
		for _, ref := range r.RuleRefs {
			fmt.Fprintf(b, "- %s\n", l.ruleRef(ref))
		}
	}

	// coverage
	if len(r.Coverage) == 0 {
		if full {
			b.WriteString(l.t("Coverage: no sensitive paths configured (path_rules, daily.paths, waf_audit.sensitive_paths).\n",
				"覆盖：未配置敏感路径（path_rules、daily.paths、waf_audit.sensitive_paths）。\n"))
		}
	} else {
		hosts := map[string]bool{}
		for _, c := range r.Coverage {
			hosts[c.Host] = true
		}
		var lines []string
		for _, c := range r.Coverage {
			where := c.Path.Pattern
			if len(hosts) > 1 {
				where += " @" + c.Host
			}
			var line string
			switch c.Status {
			case waf.Gap:
				line = fmt.Sprintf(l.t("⚠ %s: no challenge/block rule covers it", "⚠ %s：没有任何挑战 / 封禁规则覆盖"), where)
			case waf.Exempted:
				line = fmt.Sprintf(l.t("⚠ %s: always exempted by skip rule %s ahead of every protection", "⚠ %s：被前置跳过规则 %s 整体豁免，防护全部失效"), where, l.ruleRef(*c.By))
			case waf.Partial:
				line = fmt.Sprintf(l.t("◐ %s: covered only conditionally by %s (depends on UA/IP/other fields)", "◐ %s：仅在部分条件下覆盖，%s（取决于 UA / IP 等其他字段）"), where, l.ruleRef(*c.By))
			case waf.Covered:
				if c.MaySkipBy == nil && !full {
					continue
				}
				line = fmt.Sprintf(l.t("✓ %s: %s", "✓ %s：%s"), where, l.ruleRef(*c.By))
			}
			if c.MaySkipBy != nil && (c.Status == waf.Covered || c.Status == waf.Partial) {
				line += fmt.Sprintf(l.t("; skip rule %s ahead may exempt some of its requests", "；前置跳过规则 %s 可能豁免其中部分请求"), l.ruleRef(*c.MaySkipBy))
			}
			lines = append(lines, line)
		}
		if len(lines) > 0 {
			b.WriteString(l.t("Coverage of sensitive paths:\n", "敏感路径覆盖：\n"))
			for _, x := range lines {
				fmt.Fprintf(b, "- %s\n", x)
			}
		}
	}

	// order
	if len(r.Order) > 0 {
		b.WriteString(l.t("Ordering and redundancy:\n", "顺序与冗余：\n"))
		for _, f := range r.Order {
			switch f.Kind {
			case waf.Shadowed:
				fmt.Fprintf(b, l.t("- %s never fires: earlier block rule %s already matches everything it matches\n",
					"- %s 永不触发：前面的 Block 规则 %s 已覆盖它匹配的全部请求\n"), l.ruleRef(f.Rule), l.ruleRef(f.Cause))
			case waf.Duplicate:
				fmt.Fprintf(b, l.t("- %s duplicates %s (same condition, same action) — one can go\n",
					"- %s 与 %s 条件相同、动作相同（重复），可删其一\n"), l.ruleRef(f.Rule), l.ruleRef(f.Cause))
			case waf.SkipShadows:
				fmt.Fprintf(b, l.t("- %s never applies: skip rule %s ahead exempts every request it matches\n",
					"- %s 永不生效：前置跳过规则 %s 豁免了它匹配的全部请求\n"), l.ruleRef(f.Rule), l.ruleRef(f.Cause))
			case waf.SkipOverlap:
				fmt.Fprintf(b, l.t("- %s can be bypassed on %s: skip rule %s sits ahead of it and can match the same requests\n",
					"- %s 在 %s 上可被绕过：前置跳过规则 %s 能匹配同样的请求\n"), l.ruleRef(f.Rule), f.Path, l.ruleRef(f.Cause))
			}
		}
	}

	// exemptions
	var ex []string
	for _, e := range r.Exemptions {
		fields := strings.Join(e.Fields, ", ")
		if e.Forgeable {
			ex = append(ex, fmt.Sprintf(l.t("⚠ %s skips %s on a condition using only %s — anyone can forge it. Bind it to ip.src / ip.geoip.asnum or a secret header; for crawlers use cf.client.bot",
				"⚠ %s 跳过 %s，条件只用到 %s——任何人都能伪造。建议绑定 ip.src / ip.geoip.asnum 或秘密请求头；爬虫请用 cf.client.bot"), l.ruleRef(e.Rule), l.skipScope(e.Skips), fields))
		} else if full {
			ex = append(ex, fmt.Sprintf(l.t("%s skips %s (condition: %s)", "%s 跳过 %s（条件字段：%s）"), l.ruleRef(e.Rule), l.skipScope(e.Skips), fields))
		}
	}
	for _, a := range r.Access {
		ex = append(ex, fmt.Sprintf(l.t("⚠ IP Access Rule allows %s %s (%s) — it bypasses the WAF entirely", "⚠ IP 访问规则放行 %s %s（%s）——它整体绕过 WAF"),
			a.Configuration.Target, a.Configuration.Value, clip(a.Notes, 40)))
	}
	if r.AccessNA && full {
		ex = append(ex, l.t("IP Access Rules not checked (token lacks Zone → WAF: Read; older accounts: Firewall Services: Read)", "未检查 IP 访问规则（Token 缺 Zone → WAF: Read；老账号上叫 Firewall Services: Read）"))
	}
	if len(ex) > 0 {
		b.WriteString(l.t("Exemptions:\n", "豁免面：\n"))
		for _, x := range ex {
			fmt.Fprintf(b, "- %s\n", x)
		}
	}

	// hits
	if r.HitsNA {
		if full {
			b.WriteString(l.t("Hit statistics: not available (no firewall events dataset on this plan, or no access).\n",
				"命中统计：不可用（本套餐无防火墙事件数据集，或无权限）。\n"))
		}
	} else {
		if full {
			b.WriteString(l.t("Hits (7d / 30d):\n", "命中（7 天 / 30 天）：\n"))
			for _, ref := range r.RuleRefs {
				h := r.Hits[ref.ID]
				fmt.Fprintf(b, "- %s: %s / %s\n", l.ruleRef(ref), n(h.D7), n(h.D30))
			}
		}
		for _, z := range r.Zombies {
			age := l.t("age unknown", "存在时长未知")
			if z.AgeDays >= 0 {
				age = fmt.Sprintf(l.t("unchanged for %d days", "已 %d 天未改动"), z.AgeDays)
			}
			fmt.Fprintf(b, l.t("- zombie: %s has had zero hits in 30 days (%s). Quiet is not useless — decide by what it protects against\n",
				"- 僵尸规则：%s 30 天零命中（%s）。安静不等于没用——按其防护意图决定去留\n"), l.ruleRef(z.Rule), age)
		}
	}

	// quota
	q := r.Quota
	if q.Limit > 0 && (q.Near || full) {
		fmt.Fprintf(b, l.t("Quota: %d of %d custom rules (%s plan)", "额度：自定义规则 %d / %d（%s 套餐）"), q.Used, q.Limit, d.Plan)
		if q.Near {
			b.WriteString(l.t(" — close to the limit", "——接近上限"))
		}
		b.WriteString("\n")
		for _, g := range q.Mergeable {
			refs := make([]string, len(g))
			for i, x := range g {
				refs[i] = fmt.Sprintf("#%d", x.Pos)
			}
			fmt.Fprintf(b, l.t("- %s share action %s and can be merged into one rule by OR-ing their conditions (frees %d)\n",
				"- %s 动作同为 %s，可用 or 合并为一条（省出 %d 条）\n"), strings.Join(refs, " "), g[0].Action, len(g)-1)
		}
	}

	for _, pe := range r.ParseErrors {
		fmt.Fprintf(b, l.t("- could not parse %s: %s (excluded from the checks above)\n", "- 无法解析 %s：%s（未纳入以上检查）\n"), l.ruleRef(pe.Rule), pe.Err)
	}
}

func (l lang) skipScope(s string) string {
	if l == "zh" {
		s = strings.ReplaceAll(s, "all remaining custom rules", "其后全部自定义规则")
		s = strings.ReplaceAll(s, "unspecified", "（未指定）")
	}
	return s
}

// Audit renders a standalone audit message (CLI, ruleset-change re-audit).
func Audit(language string, d AuditData, reason string) string {
	l := lang(language)
	var b strings.Builder
	fmt.Fprintf(&b, l.t("FlareHound · %s — WAF rule audit", "FlareHound · %s — WAF 规则体检"), d.Zone)
	if reason != "" {
		b.WriteString(" (" + reason + ")")
	}
	b.WriteString("\n")
	l.auditBody(&b, d, true)
	b.WriteString(l.t("Read-only: FlareHound never edits these rules.", "只读：FlareHound 不会修改这些规则。"))
	return b.String()
}
