package sim

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/waf"
)

// The translator turns a rules-language expression into a GraphQL filter
// over Cloudflare's aggregated analytics. There is no replay API: the
// simulator can only ask "how many requests had these dimension values",
// so each comparison is mapped onto a dimension filter, in three tiers:
//
//  1. exact: fields that are dimensions (client IP, ASN, country, user
//     agent, path, host, method, verified bot) with eq / ne / in /
//     contains / starts_with / ends_with;
//  2. approximate: the referer — only its host is a dimension, so a
//     comparison on the full referer is widened to its host. That is a
//     superset, so it is only allowed where widening widens the result
//     (not under a negation), and the report becomes an upper bound;
//  3. not evaluable: headers, cookies, bodies, regular expressions,
//     scores, rates, functions, $lists, CIDR ranges … — named, never
//     silently ignored.
//
// Negations are pushed down to the comparisons (De Morgan), where every
// operator has a negated GraphQL form (_neq, _notin, _notlike).

// dataset selects the field names and the capability check.
type dataset int

const (
	dsHTTP dataset = iota
	dsFirewall
)

// kind is how a field's values are written and compared.
type kind int

const (
	kString kind = iota
	kIP
	kASN
	kCountry
	kBot     // cf.client.bot: a boolean, "verified bot category is set"
	kReferer // http.referer: approximated by its host
)

type fieldDef struct {
	dim  string // GraphQL dimension (same name in both datasets)
	kind kind
	like bool // contains / starts_with / ends_with allowed (string fields)
}

// fields are the tier-1 and tier-2 fields, by rules-language name.
var fields = map[string]fieldDef{
	"ip.src":                       {dim: "clientIP", kind: kIP},
	"ip.geoip.asnum":               {dim: "clientAsn", kind: kASN},
	"ip.src.asnum":                 {dim: "clientAsn", kind: kASN},
	"ip.geoip.country":             {dim: "clientCountryName", kind: kCountry},
	"ip.src.country":               {dim: "clientCountryName", kind: kCountry},
	"http.user_agent":              {dim: "userAgent", kind: kString, like: true},
	"http.request.uri.path":        {dim: "clientRequestPath", kind: kString, like: true},
	"http.request.uri.query":       {dim: "clientRequestQuery", kind: kString, like: true},
	"http.host":                    {dim: "clientRequestHTTPHost", kind: kString, like: true},
	"http.request.method":          {dim: "clientRequestHTTPMethodName", kind: kString},
	"cf.client.bot":                {dim: "verifiedBotCategory", kind: kBot},
	"cf.verified_bot_category":     {dim: "verifiedBotCategory", kind: kString},
	"http.referer":                 {dim: "clientRefererHost", kind: kReferer},
	"http.request.headers.referer": {dim: "clientRefererHost", kind: kReferer},
}

// Item is one sub-expression the report has to name: why it cannot be
// evaluated, or how it was approximated.
type Item struct {
	Expr string `json:"expr"`
	Why  string `json:"why"` // a reason code (see reasonText)
	Dim  string `json:"dim,omitempty"`
}

// Reason codes.
const (
	whyField     = "field"       // not a dimension in the analytics datasets
	whyOperator  = "operator"    // operator has no analytics equivalent
	whyFunction  = "function"    // functions other than starts_with/ends_with
	whyList      = "list"        // $list references (phase 2)
	whyCIDR      = "cidr"        // IP ranges cannot be filtered
	whyPlan      = "plan"        // the zone's plan does not expose the dimension
	whyWildcard  = "like_char"   // a literal % in a contains value
	whyRefNeg    = "referer_neg" // referer approximated under a negation
	whyRefHost   = "referer_nohost"
	whyRefWiden  = "referer_host" // approximation: widened to the host (upper bound)
	whyValue     = "value"
	whyParse     = "parse"
	whyBareField = "bare_field"
)

// gnode is a GraphQL filter tree in negation normal form.
type gnode struct {
	and, or []gnode
	leaf    string // "clientAsn:\"30633\""
	all     bool   // matches everything (an empty conjunction)
}

func (g gnode) render() string {
	switch {
	case g.leaf != "":
		return g.leaf
	case len(g.and) > 0:
		return "AND:[" + renderList(g.and) + "]"
	case len(g.or) > 0:
		return "OR:[" + renderList(g.or) + "]"
	}
	return ""
}

func renderList(gs []gnode) string {
	parts := make([]string, 0, len(gs))
	for _, g := range gs {
		parts = append(parts, "{"+g.render()+"}")
	}
	return strings.Join(parts, ",")
}

func and(a, b gnode) gnode {
	if a.all {
		return b
	}
	if b.all {
		return a
	}
	var out []gnode
	for _, x := range []gnode{a, b} {
		if len(x.and) > 0 {
			out = append(out, x.and...)
		} else {
			out = append(out, x)
		}
	}
	return gnode{and: out}
}

func or(a, b gnode) gnode {
	var out []gnode
	for _, x := range []gnode{a, b} {
		if len(x.or) > 0 {
			out = append(out, x.or...)
		} else {
			out = append(out, x)
		}
	}
	return gnode{or: out}
}

// q renders a GraphQL string literal (JSON escaping is a valid subset).
func q(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func qlist(vs []string) string {
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = q(v)
	}
	return "[" + strings.Join(parts, ",") + "]"
}

// compiler translates one expression for one dataset.
type compiler struct {
	ds     dataset
	caps   cfapi.Caps
	bad    []Item // tier 3
	approx []Item // tier 2
	asn    bool   // an ASN comparison appears (the expression is bound to networks)
	lists  map[string]listRes
}

func (c *compiler) has(dim string) bool {
	if c.ds == dsFirewall {
		return c.caps.HasFirewallDim(dim)
	}
	return c.caps.HasDim(dim)
}

func (c *compiler) fail(n fmt.Stringer, why, dim string) gnode {
	c.bad = append(c.bad, Item{Expr: n.String(), Why: why, Dim: dim})
	return gnode{leaf: "x"} // placeholder; a failed compile is never rendered
}

// compile translates n; neg is true under an odd number of negations.
func (c *compiler) compile(n waf.Node, neg bool) gnode {
	switch x := n.(type) {
	case waf.And:
		if neg {
			return or(c.compile(x.L, true), c.compile(x.R, true))
		}
		return and(c.compile(x.L, false), c.compile(x.R, false))
	case waf.Or:
		if neg {
			return and(c.compile(x.L, true), c.compile(x.R, true))
		}
		return or(c.compile(x.L, false), c.compile(x.R, false))
	case waf.Xor:
		// a xor b = (a and not b) or (not a and b); negated: equal values.
		if neg {
			return or(and(c.compile(x.L, false), c.compile(x.R, false)), and(c.compile(x.L, true), c.compile(x.R, true)))
		}
		return or(and(c.compile(x.L, false), c.compile(x.R, true)), and(c.compile(x.L, true), c.compile(x.R, false)))
	case waf.Not:
		return c.compile(x.X, !neg)
	case waf.Truthy:
		return c.truthy(x, neg)
	case waf.Cmp:
		return c.cmp(x, neg)
	}
	return c.fail(n, whyParse, "")
}

func (c *compiler) truthy(t waf.Truthy, neg bool) gnode {
	switch o := t.X.(type) {
	case waf.Field:
		def, ok := fields[o.Name]
		if !ok || def.kind != kBot {
			if ok {
				return c.fail(t, whyBareField, "")
			}
			return c.fail(t, whyField, "")
		}
		if !c.has(def.dim) {
			return c.fail(t, whyPlan, def.dim)
		}
		// Verified bot ⇔ a verified-bot category is set.
		if neg {
			return gnode{leaf: def.dim + ":" + q("")}
		}
		return gnode{leaf: def.dim + "_neq:" + q("")}
	case waf.Call:
		if (o.Name == "starts_with" || o.Name == "ends_with") && len(o.Args) == 2 {
			f, ok1 := o.Args[0].(waf.Field)
			l, ok2 := o.Args[1].(waf.Lit)
			if ok1 && ok2 {
				return c.leaf(t, f.Name, o.Name, []string{l.S}, neg)
			}
		}
		return c.fail(t, whyFunction, "")
	}
	return c.fail(t, whyParse, "")
}

func (c *compiler) cmp(x waf.Cmp, neg bool) gnode {
	f, ok := x.Left.(waf.Field)
	if !ok {
		if _, isCall := x.Left.(waf.Call); isCall {
			return c.fail(x, whyFunction, "")
		}
		return c.fail(x, whyParse, "")
	}
	op := x.Op
	if op == "ne" {
		op, neg = "eq", !neg
	}
	var vals []string
	switch v := x.Value.(type) {
	case waf.ListRef:
		res, ok := c.lists[v.Name]
		switch {
		case !ok:
			return c.fail(x, whyList, "")
		case res.why != "":
			return c.fail(x, res.why, v.Name)
		case op != "in":
			return c.fail(x, whyOperator, "")
		case len(res.vals) == 0:
			// An empty list matches nothing: "in" is false, "not in" true.
			if neg {
				return gnode{all: true}
			}
			return c.fail(x, whyValue, v.Name)
		}
		vals = append([]string(nil), res.vals...)
	case waf.Set:
		if op != "in" {
			return c.fail(x, whyOperator, "")
		}
		for _, it := range v.Items {
			vals = append(vals, it.S)
		}
	case waf.Scalar:
		if op == "in" {
			return c.fail(x, whyOperator, "")
		}
		vals = []string{v.S}
	}
	return c.leaf(x, f.Name, op, vals, neg)
}

// leaf maps one comparison: field op values.
func (c *compiler) leaf(n fmt.Stringer, field, op string, vals []string, neg bool) gnode {
	def, ok := fields[field]
	if !ok {
		return c.fail(n, whyField, "")
	}
	switch op {
	case "eq", "in", "contains", "starts_with", "ends_with":
	default:
		return c.fail(n, whyOperator, "")
	}
	if !c.has(def.dim) {
		return c.fail(n, whyPlan, def.dim)
	}
	switch def.kind {
	case kBot:
		return c.fail(n, whyOperator, "")
	case kIP:
		if op != "eq" && op != "in" {
			return c.fail(n, whyOperator, "")
		}
		for i, v := range vals {
			a, err := netip.ParseAddr(v)
			if err != nil {
				if _, perr := netip.ParsePrefix(v); perr == nil {
					return c.fail(n, whyCIDR, "")
				}
				return c.fail(n, whyValue, "")
			}
			vals[i] = a.Unmap().String()
		}
	case kASN:
		c.asn = true
		if op != "eq" && op != "in" {
			return c.fail(n, whyOperator, "")
		}
		for i, v := range vals {
			k, err := strconv.ParseUint(strings.TrimPrefix(strings.ToUpper(v), "AS"), 10, 32)
			if err != nil {
				return c.fail(n, whyValue, "")
			}
			vals[i] = strconv.FormatUint(k, 10) // clientAsn is a String
		}
	case kCountry:
		if op != "eq" && op != "in" {
			return c.fail(n, whyOperator, "")
		}
		for i, v := range vals {
			vals[i] = strings.ToUpper(v)
		}
	case kReferer:
		return c.referer(n, def, op, vals, neg)
	case kString:
		if op != "eq" && op != "in" && !def.like {
			return c.fail(n, whyOperator, "")
		}
	}
	return c.render(n, def.dim, op, vals, neg)
}

// render writes the GraphQL leaf for dim op vals (negated when neg).
func (c *compiler) render(n fmt.Stringer, dim, op string, vals []string, neg bool) gnode {
	switch op {
	case "eq":
		if neg {
			return gnode{leaf: dim + "_neq:" + q(vals[0])}
		}
		return gnode{leaf: dim + ":" + q(vals[0])}
	case "in":
		if len(vals) == 0 {
			return c.fail(n, whyValue, "")
		}
		if neg {
			return gnode{leaf: dim + "_notin:" + qlist(vals)}
		}
		return gnode{leaf: dim + "_in:" + qlist(vals)}
	}
	v := vals[0]
	if strings.Contains(v, "%") {
		return c.fail(n, whyWildcard, "")
	}
	var pat string
	switch op {
	case "contains":
		pat = "%" + v + "%"
	case "starts_with":
		pat = v + "%"
	case "ends_with":
		pat = "%" + v
	}
	if neg {
		return gnode{leaf: dim + "_notlike:" + q(pat)}
	}
	return gnode{leaf: dim + "_like:" + q(pat)}
}

// referer widens a comparison on the full referer to its host: only the
// host is a dimension. "eq \"\"" (no referer) is exact.
func (c *compiler) referer(n fmt.Stringer, def fieldDef, op string, vals []string, neg bool) gnode {
	if op == "eq" && vals[0] == "" {
		return c.render(n, def.dim, "eq", []string{""}, neg)
	}
	var hosts []string
	for _, v := range vals {
		h := refHost(v, op)
		if h == "" {
			return c.fail(n, whyRefHost, "")
		}
		hosts = append(hosts, h)
	}
	if neg {
		// not(superset) is a subset: the result would be neither exact
		// nor an upper bound.
		return c.fail(n, whyRefNeg, "")
	}
	c.approx = append(c.approx, Item{Expr: n.String(), Why: whyRefWiden, Dim: strings.Join(hosts, " ")})
	if len(hosts) == 1 {
		return c.render(n, def.dim, "eq", hosts, false)
	}
	return c.render(n, def.dim, "in", hosts, false)
}

// refHost is the host a referer comparison pins down ("" when it does
// not: contains "x.com" also matches "https://evil/?u=x.com").
func refHost(v, op string) string {
	if op != "eq" && op != "in" && op != "starts_with" {
		return ""
	}
	u, err := url.Parse(v)
	if err != nil || u.Host == "" {
		return ""
	}
	// starts_with "https://exa" would also match "https://example.com":
	// the host must be followed by a path, port, query or fragment.
	if op == "starts_with" && strings.TrimPrefix(v, u.Scheme+"://"+u.Host) == "" {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// compiled is an expression translated for both datasets.
type compiled struct {
	http, fw     gnode
	httpOK, fwOK bool
	bad, approx  []Item
	fwBad        []Item
	asn          bool
}

// translate compiles n for the HTTP dataset (required) and the firewall
// dataset (for "already handled"; optional).
func translate(n waf.Node, caps cfapi.Caps, lists map[string]listRes) compiled {
	h := &compiler{ds: dsHTTP, caps: caps, lists: lists}
	gh := h.compile(n, false)
	f := &compiler{ds: dsFirewall, caps: caps, lists: lists}
	gf := f.compile(n, false)
	return compiled{http: gh, fw: gf, httpOK: len(h.bad) == 0, fwOK: len(f.bad) == 0,
		bad: dedupe(h.bad), approx: dedupe(h.approx), fwBad: dedupe(f.bad), asn: h.asn}
}

func dedupe(items []Item) []Item {
	seen := map[string]bool{}
	var out []Item
	for _, it := range items {
		k := it.Expr + "\x00" + it.Why
		if !seen[k] {
			seen[k] = true
			out = append(out, it)
		}
	}
	return out
}

// where renders a compiled filter as a cfapi.Filter fragment.
func where(g gnode) string {
	if g.all {
		return ""
	}
	return "AND:[{" + g.render() + "}]"
}

// extra conjoins a plain leaf ("cacheStatus:\"dynamic\"") with g.
func withLeaf(g gnode, leaf string) gnode { return and(g, gnode{leaf: leaf}) }
