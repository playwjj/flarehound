// Package suggest is the suggestion engine (SPEC 9). It turns findings,
// attribution and hypotheses into concrete, read-only action candidates:
// block or challenge an ASN, challenge a sensitive path, rate-limit a hot
// path, cache a static asset, or look at a Worker's CPU cost.
//
// Every suggestion carries its evidence, expected gain, blast radius and
// rollback, plus a ready-to-paste Cloudflare rule expression. Nothing
// here executes anything. Like analyze, it is deterministic and I/O-free.
package suggest

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/playwjj/flarehound/internal/analyze"
)

type Kind string

const (
	BlockASN      Kind = "block_asn"
	ChallengeASN  Kind = "challenge_asn"
	ChallengePath Kind = "challenge_path"
	RateLimit     Kind = "rate_limit"
	Cache         Kind = "cache"
	CostHint      Kind = "cost_hint"
)

// Suggestion is one action candidate.
type Suggestion struct {
	Kind       Kind    `json:"kind"`
	Target     string  `json:"target"`               // "AS207990", "/login*", "/rank", worker name
	ASN        int     `json:"asn,omitempty"`        // ASN kinds
	ASNName    string  `json:"asn_name,omitempty"`   // registered name, if known
	Network    Network `json:"network,omitempty"`    // ASN kinds
	Expression string  `json:"expression,omitempty"` // Cloudflare rules language
	Count      int64   `json:"count"`                // target's volume in the current window
	Base       int64   `json:"base"`                 // ... and in the baseline window
	Share      float64 `json:"share,omitempty"`      // of the excess it explains, 0..1
	// Gain estimates, per window. Expensive gain is derived from the
	// window's expensive fraction and is always labelled an estimate.
	GainRequests  int64 `json:"gain_requests,omitempty"`
	GainExpensive int64 `json:"gain_expensive,omitempty"`
	// Rate-limit starting point.
	RLRequests  int `json:"rl_requests,omitempty"`
	RLPeriodSec int `json:"rl_period_sec,omitempty"`
	// CostHint only.
	CPUPct float64 `json:"cpu_pct,omitempty"`
}

// Input is everything one round knows.
type Input struct {
	Cur, Base  analyze.Metrics
	Findings   []analyze.Finding
	Attr       analyze.Attribution
	Hypotheses []analyze.Hypothesis
	Block      analyze.BlockAdvice
	ASNNames   map[int]string
	// Sensitive maps path-rule names to their patterns ("/login*"); every
	// pattern listed is a sensitive path (login, signup, ranking …).
	Sensitive map[string]string
	MinCount  int64
}

// Tunables (SPEC 9; documented there).
const (
	asnShare      = 0.2 // an ASN must explain >= 20% of the excess
	pathShare     = 0.3 // a sensitive path must explain >= 30% of the dynamic excess
	hotPathShare  = 0.5 // one path explaining >= 50% of the dynamic excess is "hot"
	rlRequests    = 20  // rate-limit starting point: 20 requests / 10 s per IP
	rlPeriodSec   = 10  // (10 s is the only period on every plan)
	maxSuggestion = 6
)

// evidenced reports whether at least one mechanism hypothesis has medium
// or high confidence. Without one, SPEC 8.4 says: numbers only — no
// block/challenge/rate-limit advice.
func evidenced(hs []analyze.Hypothesis) bool {
	for _, h := range hs {
		if h.Confidence == analyze.High || h.Confidence == analyze.Medium {
			if h.ID != analyze.HypCheapVolume {
				return true
			}
		}
	}
	return false
}

func cheapOnly(hs []analyze.Hypothesis) bool {
	for _, h := range hs {
		if h.ID == analyze.HypCheapVolume {
			return true
		}
	}
	return false
}

// expensiveFraction is the share of the current window that is expensive
// (Worker / origin). Without a cache breakdown it falls back to
// dynamic/total, and to 1 (pessimistic) without either.
func expensiveFraction(in Input) float64 {
	if len(in.Attr.CacheCur) > 0 {
		c := analyze.SplitCost(in.Attr.CacheCur, nil)
		if t := c.ExpCur + c.CheapCur; t > 0 {
			return float64(c.ExpCur) / float64(t)
		}
	}
	if in.Cur.Total > 0 {
		return float64(in.Cur.Dynamic) / float64(in.Cur.Total)
	}
	return 1
}

// Suggest derives the action candidates for one round, most valuable
// first. An empty result is a valid answer.
func Suggest(in Input) []Suggestion {
	var out []Suggestion
	if evidenced(in.Hypotheses) && !cheapOnly(in.Hypotheses) {
		out = append(out, asnSuggestions(in)...)
		paths := pathSuggestions(in)
		out = append(out, paths...)
		out = append(out, rateLimit(in, paths)...)
	}
	out = append(out, CacheOpportunities(in.Attr.DynamicPaths, in.MinCount)...)
	for _, h := range in.Hypotheses {
		if h.ID == analyze.HypSlowPath {
			c, b := in.Cur.Worker(h.Subject), in.Base.Worker(h.Subject)
			out = append(out, Suggestion{Kind: CostHint, Target: h.Subject, Count: c.Calls, Base: b.Calls,
				CPUPct: analyze.PctChange(c.CPUP50ms, b.CPUP50ms)})
		}
	}
	if len(out) > maxSuggestion {
		out = out[:maxSuggestion]
	}
	return out
}

func asnSuggestions(in Input) []Suggestion {
	delta := in.Cur.Total - in.Base.Total
	if delta <= 0 {
		return nil
	}
	base := map[int]int64{}
	for _, f := range in.Base.TopASN {
		base[f.ASN] = f.Count
	}
	frac := expensiveFraction(in)
	var out []Suggestion
	for _, f := range in.Cur.TopASN {
		if f.ASN == 0 {
			continue
		}
		diff := f.Count - base[f.ASN]
		share := float64(diff) / float64(delta)
		if diff <= 0 || share < asnShare {
			continue
		}
		name := in.ASNNames[f.ASN]
		net := Classify(f.ASN, name)
		s := Suggestion{
			Kind: ChallengeASN, Target: f.Name, ASN: f.ASN, ASNName: name, Network: net,
			Expression: ASNExpression(f.ASN),
			Count:      f.Count, Base: base[f.ASN], Share: min(share, 1),
		}
		if net == Hosting {
			s.Kind = BlockASN
			s.GainRequests = diff
			s.GainExpensive = int64(float64(diff) * frac)
		} else {
			// A challenge stops automated clients but lets humans through;
			// the gain is the automated part, which we cannot size.
			s.GainRequests = 0
		}
		out = append(out, s)
	}
	return out
}

func pathSuggestions(in Input) []Suggestion {
	seen := map[string]bool{}
	var out []Suggestion
	add := func(pattern string, cur, base int64, share float64) {
		if seen[pattern] {
			return
		}
		seen[pattern] = true
		out = append(out, Suggestion{Kind: ChallengePath, Target: pattern, Expression: PathExpression(pattern),
			Count: cur, Base: base, Share: share})
	}
	for _, f := range in.Findings {
		if f.Rule == analyze.RulePathUp {
			if p, ok := in.Sensitive[f.Subject]; ok {
				add(p, int64(f.Cur), int64(f.Base), 0)
			}
		}
	}
	dynDelta := in.Cur.Dynamic - in.Base.Dynamic
	if dynDelta > 0 {
		names := make([]string, 0, len(in.Sensitive))
		for n := range in.Sensitive {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, p := range in.Attr.DynamicPaths {
			d := p.Cur - p.Base
			if d <= 0 || float64(d)/float64(dynDelta) < pathShare {
				continue
			}
			for _, n := range names {
				if Match(in.Sensitive[n], p.Path) {
					add(in.Sensitive[n], p.Cur, p.Base, min(float64(d)/float64(dynDelta), 1))
				}
			}
		}
	}
	return out
}

// rateLimit suggests a per-IP rate limit on a hot dynamic path when the
// sources are dispersed (per-IP blocking useless) and the path is not
// already covered by a challenge suggestion.
func rateLimit(in Input, challenged []Suggestion) []Suggestion {
	dynDelta := in.Cur.Dynamic - in.Base.Dynamic
	if dynDelta <= 0 || len(in.Block.Candidates) > 0 || !in.Block.Dispersed {
		return nil
	}
	for _, p := range in.Attr.DynamicPaths {
		d := p.Cur - p.Base
		if d <= 0 || float64(d)/float64(dynDelta) < hotPathShare {
			continue
		}
		covered := false
		for _, c := range challenged {
			if Match(c.Target, p.Path) {
				covered = true
			}
		}
		if covered {
			continue
		}
		return []Suggestion{{Kind: RateLimit, Target: p.Path, Expression: PathExpression(p.Path),
			Count: p.Cur, Base: p.Base, Share: min(float64(d)/float64(dynDelta), 1),
			RLRequests: rlRequests, RLPeriodSec: rlPeriodSec}}
	}
	return nil
}

var staticExt = regexp.MustCompile(`(?i)\.(js|mjs|css|png|jpe?g|gif|webp|avif|svg|ico|woff2?|ttf|otf|eot|mp4|webm|mp3|pdf|txt|xml|wasm|map)$`)

// CacheOpportunities flags dynamic (uncached) paths that look like static
// assets. It needs no anomaly: an uncached stylesheet is a standing cost.
func CacheOpportunities(paths []analyze.PathDelta, minCount int64) []Suggestion {
	var out []Suggestion
	for _, p := range paths {
		if p.Cur < minCount || !staticExt.MatchString(p.Path) {
			continue
		}
		// Dynamic responses are expensive by definition: every one served
		// from cache instead is a Worker/origin hit saved.
		out = append(out, Suggestion{Kind: Cache, Target: p.Path, Expression: PathExpression(p.Path),
			Count: p.Cur, Base: p.Base, GainRequests: p.Cur, GainExpensive: p.Cur})
	}
	return out
}

// ---- expressions ----

// cfString renders s as a Cloudflare rules-language string literal.
func cfString(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// ASNExpression is the block/challenge expression for one ASN. Verified
// bots are always exempt (SPEC 13.1): a cloud ASN can host Googlebot.
func ASNExpression(asn int) string {
	return "(ip.geoip.asnum in {" + strconv.Itoa(asn) + "}) and not cf.client.bot"
}

// PathExpression turns a config path pattern into an expression:
// "/login" → eq, "/login*" → starts_with, anything else → wildcard.
func PathExpression(pattern string) string {
	star := strings.Count(pattern, "*")
	switch {
	case star == 0:
		return "http.request.uri.path eq " + cfString(pattern)
	case star == 1 && strings.HasSuffix(pattern, "*"):
		return "starts_with(http.request.uri.path, " + cfString(strings.TrimSuffix(pattern, "*")) + ")"
	}
	return "http.request.uri.path wildcard " + cfString(pattern)
}

// Match reports whether path matches a config pattern (* = any run of
// characters, including /).
func Match(pattern, path string) bool {
	re := "^" + strings.ReplaceAll(regexp.QuoteMeta(pattern), `\*`, ".*") + "$"
	ok, _ := regexp.MatchString(re, path)
	return ok
}
