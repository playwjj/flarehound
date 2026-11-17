// Package block implements one-click blocking (SPEC 13.1): IPs / CIDRs,
// ASNs, countries and user agents, each kept in a FlareHound-owned rule or
// list ("flarehound-" prefix) so the user's own rules are never touched
// and the blast radius stays fixed.
//
// The remote objects are the source of truth for what is blocked; the
// local audit log (package store) records who blocked what, why, and
// until when.
package block

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type Type string

const (
	IP      Type = "ip" // single address or CIDR
	ASN     Type = "asn"
	Country Type = "country"
	UA      Type = "ua"
)

type Action string

const (
	Block     Action = "block"
	Challenge Action = "challenge"
)

// CF returns the Cloudflare action name.
func (a Action) CF() string {
	if a == Challenge {
		return "managed_challenge"
	}
	return "block"
}

func ParseAction(s string) (Action, error) {
	switch strings.ToLower(s) {
	case "block":
		return Block, nil
	case "challenge", "managed_challenge":
		return Challenge, nil
	}
	return "", fmt.Errorf("action must be block or challenge, got %q", s)
}

// DefaultAction per SPEC 13.1: IP and UA block; ASN and country challenge
// (wide blast radius).
func DefaultAction(t Type) Action {
	if t == ASN || t == Country {
		return Challenge
	}
	return Block
}

// Target is one blockable object, normalised.
type Target struct {
	Type  Type
	Value string // "203.0.113.7", "198.51.100.0/24", "207990", "XX", "BadBot/1.0"
}

func (t Target) String() string {
	switch t.Type {
	case ASN:
		return "AS" + t.Value
	case UA:
		return fmt.Sprintf("UA %q", t.Value)
	case Country:
		return "country " + t.Value
	}
	return t.Value
}

// Prefix returns an IP target as a prefix (single address → /32 or /128).
func (t Target) Prefix() (netip.Prefix, bool) {
	if t.Type != IP {
		return netip.Prefix{}, false
	}
	if p, err := netip.ParsePrefix(t.Value); err == nil {
		return p, true
	}
	if a, err := netip.ParseAddr(t.Value); err == nil {
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

// ASNumber returns an ASN target's number.
func (t Target) ASNumber() int {
	n, _ := strconv.Atoi(t.Value)
	return n
}

var countryRe = regexp.MustCompile(`^[A-Z][A-Z0-9]$`) // ISO 3166-1 alpha-2, plus T1 (Tor)

// Parse validates and normalises a target from CLI input.
func Parse(typ, value string) (Target, error) {
	value = strings.TrimSpace(value)
	switch Type(strings.ToLower(typ)) {
	case IP, "cidr":
		if a, err := netip.ParseAddr(value); err == nil {
			if a.Zone() != "" {
				return Target{}, fmt.Errorf("IP %q: zones are not allowed", value)
			}
			return Target{IP, a.Unmap().String()}, nil
		}
		p, err := netip.ParsePrefix(value)
		if err != nil {
			return Target{}, fmt.Errorf("not an IP address or CIDR: %q", value)
		}
		p = p.Masked()
		if p.Addr().Is4() && p.Bits() < 8 || p.Addr().Is6() && p.Bits() < 16 {
			return Target{}, fmt.Errorf("CIDR %s is too wide to be a sensible block (use an ASN or country block)", p)
		}
		if p.IsSingleIP() {
			return Target{IP, p.Addr().String()}, nil
		}
		return Target{IP, p.String()}, nil
	case ASN:
		v := strings.TrimPrefix(strings.ToUpper(value), "AS")
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil || n == 0 {
			return Target{}, fmt.Errorf("not an AS number: %q", value)
		}
		return Target{ASN, strconv.FormatUint(n, 10)}, nil
	case Country:
		v := strings.ToUpper(value)
		if !countryRe.MatchString(v) {
			return Target{}, fmt.Errorf("country must be a 2-letter ISO code, got %q", value)
		}
		return Target{Country, v}, nil
	case UA, "user-agent", "useragent":
		if len(value) < 3 || len(value) > 200 {
			return Target{}, fmt.Errorf("user-agent fragment must be 3..200 characters")
		}
		for _, r := range value {
			if r < 0x20 || r == 0x7f {
				return Target{}, fmt.Errorf("user-agent fragment contains control characters")
			}
		}
		return Target{UA, value}, nil
	}
	return Target{}, fmt.Errorf("unknown target type %q (ip, asn, country, ua)", typ)
}

// ---- rule expressions ----
//
// Each FlareHound rule holds one set of one type, rendered in a fixed
// format so it can be parsed back. If a user edits a rule by hand into a
// shape this parser does not recognise, FlareHound refuses to touch it.

// RuleRef names the FlareHound rule for a type and action.
func RuleRef(t Type, a Action) string { return "flarehound-" + string(t) + "-" + string(a) }

// ListName is the account IP list behind IP blocks.
const ListName = "flarehound_block"

// ListExpression is the rule that applies the IP list.
const ListExpression = "ip.src in $" + ListName

func cfString(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// Expression renders the merged rule for a set of values of one type.
// ASN and country rules keep verified bots allowed (SPEC 13.1): a cloud
// ASN or a whole country can host Googlebot.
func Expression(t Type, values []string) string {
	vs := append([]string(nil), values...)
	sort.Strings(vs)
	switch t {
	case IP:
		return "(ip.src in {" + strings.Join(vs, " ") + "})"
	case ASN:
		sort.Slice(vs, func(i, j int) bool { a, _ := strconv.Atoi(vs[i]); b, _ := strconv.Atoi(vs[j]); return a < b })
		return "(ip.geoip.asnum in {" + strings.Join(vs, " ") + "}) and not cf.client.bot"
	case Country:
		q := make([]string, len(vs))
		for i, v := range vs {
			q[i] = cfString(v)
		}
		return "(ip.geoip.country in {" + strings.Join(q, " ") + "}) and not cf.client.bot"
	case UA:
		parts := make([]string, len(vs))
		for i, v := range vs {
			parts[i] = "http.user_agent contains " + cfString(v)
		}
		return "(" + strings.Join(parts, " or ") + ")"
	}
	return ""
}

// MaxExpression is Cloudflare's expression length limit.
const MaxExpression = 4096

var (
	setRe    = regexp.MustCompile(`^\((ip\.src|ip\.geoip\.asnum|ip\.geoip\.country) in \{([^}]*)\}\)( and not cf\.client\.bot)?$`)
	uaRe     = regexp.MustCompile(`http\.user_agent contains "((?:[^"\\]|\\.)*)"`)
	uaWhole  = regexp.MustCompile(`^\((http\.user_agent contains "(?:[^"\\]|\\.)*"(?: or )?)+\)$`)
	unescape = strings.NewReplacer(`\\`, `\`, `\"`, `"`)
)

// ParseExpression recovers the value set from a FlareHound rule.
func ParseExpression(t Type, expr string) ([]string, error) {
	bad := fmt.Errorf("rule expression was modified outside FlareHound; refusing to edit it: %s", expr)
	if t == UA {
		if !uaWhole.MatchString(expr) {
			return nil, bad
		}
		var out []string
		for _, m := range uaRe.FindAllStringSubmatch(expr, -1) {
			out = append(out, unescape.Replace(m[1]))
		}
		return out, nil
	}
	m := setRe.FindStringSubmatch(expr)
	want := map[Type]string{IP: "ip.src", ASN: "ip.geoip.asnum", Country: "ip.geoip.country"}[t]
	if m == nil || m[1] != want || (t != IP) != (m[3] != "") {
		return nil, bad
	}
	var out []string
	for _, f := range strings.Fields(m[2]) {
		out = append(out, strings.Trim(f, `"`))
	}
	return out, nil
}

func itoaASN(n int) string { return strconv.Itoa(n) }

func parseAddr(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	return a.Unmap(), err
}

// Command renders the CLI line that applies a candidate, for alerts.
func Command(t Target, a Action, ttl, reason string) string {
	s := fmt.Sprintf("flarehound block %s %s", t.Type, quoteArg(t.Value))
	if a != DefaultAction(t.Type) {
		s += " --action " + string(a)
	}
	if ttl != "" {
		s += " --for " + ttl
	}
	if reason != "" {
		s += " --reason " + quoteArg(reason)
	}
	return s
}

// ShellQuote quotes s for a POSIX shell when needed.
func ShellQuote(s string) string { return quoteArg(s) }

func quoteArg(s string) string {
	if s == "" || strings.ContainsAny(s, " \t\"'$`\\;&|<>()*?![]{}#~") {
		return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
	}
	return s
}
