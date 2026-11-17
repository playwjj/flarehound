package block

import (
	"fmt"
	"net/netip"
)

// Fallback copy of Cloudflare's published ranges (https://www.cloudflare.com/ips/),
// used only when the live list cannot be fetched.
var cloudflareFallback = []string{
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
	"108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
	"162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
	"2a06:98c0::/29", "2c0f:f248::/32",
}

// CloudflareFallback returns the embedded Cloudflare ranges.
func CloudflareFallback() []netip.Prefix {
	out := make([]netip.Prefix, 0, len(cloudflareFallback))
	for _, s := range cloudflareFallback {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

// Special-purpose ranges that are never meaningful block targets.
var reserved = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
		"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"::/8", "fc00::/7", "fe80::/10", "ff00::/8", "2001:db8::/32", "64:ff9b::/96",
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// Cloudflare's own ASNs: blocking them blocks Cloudflare Workers/WARP
// egress and can break the zone itself.
var protectedASNs = map[int]string{13335: "Cloudflare", 209242: "Cloudflare (WARP/Spectrum)"}

// Protected is everything that must never be blocked (SPEC 13.1).
type Protected struct {
	Cloudflare []netip.Prefix
	Origins    []netip.Addr
	Allow      []netip.Prefix // user allowlist (config blocking.never_block)
	AllowASNs  map[int]bool   // user allowlist (config blocking.never_block_asns)
}

// Check returns an error if blocking t would hit a protected object.
func (p Protected) Check(t Target) error {
	switch t.Type {
	case IP:
		pf, ok := t.Prefix()
		if !ok {
			return fmt.Errorf("invalid IP target %q", t.Value)
		}
		for _, r := range reserved {
			if r.Overlaps(pf) {
				return fmt.Errorf("%s overlaps reserved/private range %s — not a real client address", t.Value, r)
			}
		}
		for _, r := range p.Cloudflare {
			if r.Overlaps(pf) {
				return fmt.Errorf("%s overlaps Cloudflare's own range %s — blocking it would break your site", t.Value, r)
			}
		}
		for _, o := range p.Origins {
			if pf.Contains(o) {
				return fmt.Errorf("%s contains your origin IP %s (from DNS) — blocking it would cut off your own server", t.Value, o)
			}
		}
		for _, r := range p.Allow {
			if r.Overlaps(pf) {
				return fmt.Errorf("%s overlaps your allowlist entry %s (blocking.never_block)", t.Value, r)
			}
		}
	case ASN:
		n := t.ASNumber()
		if name, ok := protectedASNs[n]; ok {
			return fmt.Errorf("AS%d is %s — never blocked", n, name)
		}
		if p.AllowASNs[n] {
			return fmt.Errorf("AS%d is on your allowlist (blocking.never_block_asns)", n)
		}
	}
	return nil
}

// AccessRuleTarget maps a target to an IP Access Rule configuration, or
// reports why it cannot be expressed as one. IPv4 ranges only as /16 or
// /24 and IPv6 ranges only as /48 or /64 (Cloudflare's limits); no UA and
// no country (country block there is Enterprise-only).
func AccessRuleTarget(t Target) (target, value string, err error) {
	switch t.Type {
	case ASN:
		return "asn", "AS" + t.Value, nil
	case IP:
		pf, _ := t.Prefix()
		if pf.IsSingleIP() {
			return "ip", pf.Addr().String(), nil
		}
		b := pf.Bits()
		if pf.Addr().Is4() && (b == 16 || b == 24) || pf.Addr().Is6() && (b == 48 || b == 64) {
			return "ip_range", pf.String(), nil
		}
		return "", "", fmt.Errorf("IP Access Rules accept IPv4 /16, /24 and IPv6 /48, /64 only; %s is /%d", pf, b)
	}
	return "", "", fmt.Errorf("%s targets cannot use IP Access Rules", t.Type)
}

// Warnings are shown before the user confirms (SPEC 13.1 guard rails:
// low friction must not mean easy mistakes).
func Warnings(t Target, a Action, network string, share float64, shareKnown bool) []string {
	var w []string
	if shareKnown && share < 0.01 {
		w = append(w, fmt.Sprintf("this target carried only %.2f%% of the last hour's excess traffic — blocking it will not resolve the anomaly; look at ASN or path-level action instead", share*100))
	}
	switch t.Type {
	case ASN:
		switch network {
		case "eyeball":
			w = append(w, "this is a residential/mobile/backbone network: real people browse from it. Blocking it WILL hit real users — prefer --action challenge and watch the attempts first")
		case "unknown":
			w = append(w, "network type unknown: it may carry real users. Prefer --action challenge")
		}
	case Country:
		w = append(w, "a whole-country rule has the widest blast radius of all; every real visitor from that country is affected (per-country traffic is not measurable from adaptive analytics, so FlareHound cannot show the human share)")
	case UA:
		w = append(w, "user agents are trivially forged and crawlers rotate them (three batches in one day in the field); this only holds against bots with a stable fingerprint")
	}
	if a == Block && (t.Type == ASN || t.Type == Country) && network != "hosting" {
		w = append(w, "you chose Block where Challenge is the default; a challenge stops bots but lets humans through")
	}
	return w
}

// NeedsStrongConfirm is true for blocks that can hurt real users at
// scale: the user must retype the target to confirm.
func NeedsStrongConfirm(t Target, a Action, network string) (bool, string) {
	if a != Block {
		return false, ""
	}
	switch {
	case t.Type == ASN && network != "hosting":
		return true, t.Value
	case t.Type == Country:
		return true, t.Value
	}
	return false, ""
}
