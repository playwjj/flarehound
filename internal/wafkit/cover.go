package wafkit

import (
	"strconv"
	"strings"

	"github.com/playwjj/flarehound/internal/analyze"
	"github.com/playwjj/flarehound/internal/waf"
)

// RuleLite is the part of a custom rule coverage needs.
type RuleLite struct {
	Action, Expr, Desc string
	Enabled            bool
}

func protective(a string) bool {
	switch a {
	case "block", "managed_challenge", "challenge", "js_challenge":
		return true
	}
	return false
}

// Cover finds the first enabled rule, in execution order, that acts on a
// user agent (dim "ua") or an ASN (dim "asn") seen on host: a rule that
// always applies, else the first that may apply depending on other
// conditions (path …). Verified-bot exceptions are assumed not to apply
// (a new face is not a verified bot until proven). ok is false when no
// rule acts on it.
func Cover(rules []RuleLite, dim, name, host string) (analyze.RuleCover, bool) {
	p := waf.Probe{"cf.client.bot": "false", "cf.bot_management.verified_bot": "false"}
	if host != "" {
		p["http.host"] = host
	}
	switch dim {
	case "asn":
		n, err := strconv.Atoi(strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(name)), "AS"))
		if err != nil || n <= 0 {
			return analyze.RuleCover{}, false
		}
		p["ip.geoip.asnum"], p["ip.src.asnum"] = strconv.Itoa(n), strconv.Itoa(n)
	case "ua":
		if name == "" {
			return analyze.RuleCover{}, false
		}
		p["http.user_agent"] = name
	default:
		return analyze.RuleCover{}, false
	}
	// Only rules that look at this dimension act on this face: a path rule
	// is undecided for every face and says nothing about any of them.
	fields := map[string][]string{"asn": {"ip.geoip.asnum", "ip.src.asnum"}, "ua": {"http.user_agent"}}[dim]
	var partial *analyze.RuleCover
	for i, r := range rules {
		if !r.Enabled || (!protective(r.Action) && r.Action != "skip") {
			continue
		}
		n, err := waf.Parse(r.Expr)
		if err != nil {
			continue
		}
		refs := waf.Fields(n)
		mentions := false
		for _, f := range fields {
			mentions = mentions || refs[f]
		}
		if !mentions {
			continue
		}
		switch waf.Eval(n, p) {
		case waf.True:
			return analyze.RuleCover{Pos: i + 1, Action: r.Action, Desc: r.Desc}, true
		case waf.Unknown:
			if partial == nil && protective(r.Action) {
				partial = &analyze.RuleCover{Pos: i + 1, Action: r.Action, Desc: r.Desc, Partial: true}
			}
		}
	}
	if partial != nil {
		return *partial, true
	}
	return analyze.RuleCover{}, false
}
