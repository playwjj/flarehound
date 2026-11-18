package wafkit

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/playwjj/flarehound/internal/waf"
)

// Fix is one way to resolve an audit finding: words, and either a recipe
// (with its inputs) or a command to run.
type Fix struct {
	Problem string
	Advice  string
	Recipe  string     // recipe name, or ""
	Inputs  url.Values // recipe inputs
	Command string     // CLI command, or ""
}

func ruleLabel(r waf.RuleRef, lang string) string {
	d := r.Description
	if d == "" {
		d = tr(lang, "(no description)", "（无描述）")
	}
	return fmt.Sprintf("#%d %q", r.Pos, d)
}

// Fixes turns an audit result into concrete next steps, most important first.
func Fixes(res waf.Result, lang string) []Fix {
	var out []Fix
	// Coverage: one fix for all unprotected paths.
	var gaps, partial []string
	seen := map[string]bool{}
	for _, c := range res.Coverage {
		p := c.Path.Pattern
		if seen[p] {
			continue
		}
		switch c.Status {
		case waf.Gap:
			gaps = append(gaps, p)
			seen[p] = true
		case waf.Partial:
			partial = append(partial, p)
			seen[p] = true
		}
	}
	if len(gaps)+len(partial) > 0 {
		all := append(append([]string{}, gaps...), partial...)
		out = append(out, Fix{
			Problem: tr(lang, "Sensitive paths without a protecting rule: ", "敏感路径没有防护规则：") + strings.Join(all, ", "),
			Advice:  tr(lang, "Add a managed challenge for them (verified bots excepted), and a rate limit for login-like paths.", "为它们加一条托管质询（已核验爬虫除外）；登录类路径再加限速。"),
			Recipe:  "protect-paths", Inputs: url.Values{"paths": {strings.Join(all, ", ")}},
		})
	}
	for _, c := range res.Coverage {
		if c.Status == waf.Exempted && c.By != nil && !seen["x"+c.Path.Pattern] {
			seen["x"+c.Path.Pattern] = true
			out = append(out, Fix{
				Problem: fmt.Sprintf(tr(lang, "%s is always let through by skip rule %s", "%s 总是被放行规则 %s 放过"), c.Path.Pattern, ruleLabel(*c.By, lang)),
				Advice:  tr(lang, "Narrow that skip rule (source IP, network or a secret header, and only the paths it needs), or move your protective rule ahead of it if the exemption is not meant for this path.", "收窄这条放行规则（限定来源 IP / 网络或密钥请求头，并只放行需要的路径）；如果它本不该覆盖此路径，把防护规则移到它前面。"),
			})
		}
	}
	for _, e := range res.Exemptions {
		if !e.Forgeable {
			continue
		}
		out = append(out, Fix{
			Problem: fmt.Sprintf(tr(lang, "Skip rule %s depends only on fields anyone can forge (%s)", "放行规则 %s 只依赖任何人都能伪造的字段（%s）"), ruleLabel(e.Rule, lang), strings.Join(e.Fields, ", ")),
			Advice: tr(lang, "Replace it with a rule tied to the source IP, network or a secret header. For search engines use cf.client.bot instead of a user-agent match.",
				"改成绑定来源 IP、网络或密钥请求头的规则；搜索引擎请用 cf.client.bot，而不是匹配 UA。"),
			Recipe: "allow-service",
		})
	}
	for _, o := range res.Order {
		f := Fix{}
		switch o.Kind {
		case waf.SkipShadows:
			f.Problem = fmt.Sprintf(tr(lang, "%s never takes effect: skip rule %s ahead of it always matches first", "%s 永远不会生效：前面的放行规则 %s 总是先匹配"), ruleLabel(o.Rule, lang), ruleLabel(o.Cause, lang))
			f.Advice = tr(lang, "Move the protective rule ahead of the skip rule, or narrow the skip rule.", "把防护规则移到放行规则之前，或收窄放行规则。")
			f.Command = fmt.Sprintf("flarehound rules move %d --before %d", o.Rule.Pos, o.Cause.Pos)
		case waf.SkipOverlap:
			f.Problem = fmt.Sprintf(tr(lang, "Skip rule %s can exempt part of %s's traffic on %s", "放行规则 %s 会让 %s 在 %s 上的部分流量被放过"), ruleLabel(o.Cause, lang), ruleLabel(o.Rule, lang), o.Path)
			f.Advice = tr(lang, "Check the skip condition can only be met by the service it is for (IP, network, secret header).", "确认放行条件只有它服务的对象才能满足（IP、网络、密钥请求头）。")
		case waf.Shadowed:
			f.Problem = fmt.Sprintf(tr(lang, "%s never fires: %s blocks everything it matches first", "%s 永远不会触发：%s 已先拦截了它匹配的全部请求"), ruleLabel(o.Rule, lang), ruleLabel(o.Cause, lang))
			f.Advice = tr(lang, "Delete it to free a rule slot, or move it ahead if it should act first.", "删除它以腾出规则额度；如果它应先生效，就把它移到前面。")
			f.Command = fmt.Sprintf("flarehound rules delete %d", o.Rule.Pos)
		case waf.Duplicate:
			f.Problem = fmt.Sprintf(tr(lang, "%s duplicates %s", "%s 与 %s 重复"), ruleLabel(o.Rule, lang), ruleLabel(o.Cause, lang))
			f.Advice = tr(lang, "Delete the duplicate.", "删除重复的那条。")
			f.Command = fmt.Sprintf("flarehound rules delete %d", o.Rule.Pos)
		default:
			continue
		}
		out = append(out, f)
	}
	for _, z := range res.Zombies {
		out = append(out, Fix{
			Problem: fmt.Sprintf(tr(lang, "%s had no hits in 30 days", "%s 30 天内没有命中"), ruleLabel(z.Rule, lang)),
			Advice:  tr(lang, "If the threat it was written for is gone, disable it (you can re-enable it any time).", "如果它针对的威胁已经消失，可以先停用（随时可重新启用）。"),
			Command: fmt.Sprintf("flarehound rules edit %d --enabled false", z.Rule.Pos),
		})
	}
	if len(res.Access) > 0 {
		out = append(out, Fix{
			Problem: fmt.Sprintf(tr(lang, "%d IP Access Rule allow entries bypass the whole WAF", "%d 条 IP 访问规则的放行项会绕过整个 WAF"), len(res.Access)),
			Advice:  tr(lang, "Replace each with a skip rule that skips only what it must.", "把它们换成只跳过必要部分的放行规则。"),
			Recipe:  "allow-service",
		})
	}
	if res.Quota.Near {
		f := Fix{
			Problem: fmt.Sprintf(tr(lang, "Custom rules nearly full: %d of %d", "自定义规则额度将满：%d / %d"), res.Quota.Used, res.Quota.Limit),
			Advice:  tr(lang, "Rules with the same action can be merged into one with \"or\".", "动作相同的规则可以用「or」合并为一条。"),
		}
		for _, g := range res.Quota.Mergeable {
			var ps []string
			for _, r := range g {
				ps = append(ps, fmt.Sprintf("#%d", r.Pos))
			}
			f.Advice += tr(lang, " Candidates: ", " 可合并：") + strings.Join(ps, " + ") + "."
		}
		out = append(out, f)
	}
	for _, p := range res.ParseErrors {
		out = append(out, Fix{
			Problem: fmt.Sprintf(tr(lang, "%s could not be read by FlareHound's parser", "FlareHound 无法解析 %s"), ruleLabel(p.Rule, lang)),
			Advice:  tr(lang, "Its coverage is not judged; check it by hand.", "它的覆盖情况未被评估，请人工检查。"),
		})
	}
	return out
}
