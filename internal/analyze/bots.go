package analyze

import (
	"strings"

	"github.com/playwjj/flarehound/internal/cfapi"
)

// crawler is a well-known search crawler with the ASNs it genuinely
// crawls from. A UA that claims to be one of these is only accepted as
// such when its traffic actually comes from those networks.
type crawler struct {
	Name    string
	Markers []string // lower-case UA substrings
	ASNs    []int
}

var crawlers = []crawler{
	{"Googlebot", []string{"googlebot", "adsbot-google", "mediapartners-google", "google-inspectiontool", "storebot-google"}, []int{15169}},
	{"Bingbot", []string{"bingbot", "adidxbot", "bingpreview"}, []int{8075}},
	{"Applebot", []string{"applebot"}, []int{714, 6185}},
	{"YandexBot", []string{"yandexbot", "yandex.com/bots"}, []int{13238, 208722}},
	{"Baiduspider", []string{"baiduspider"}, []int{55967, 38365}},
}

// ClaimedBot returns the crawler a UA claims to be, if any.
func ClaimedBot(ua string) (name string, asns []int, ok bool) {
	l := strings.ToLower(ua)
	for _, c := range crawlers {
		for _, m := range c.Markers {
			if strings.Contains(l, m) {
				return c.Name, c.ASNs, true
			}
		}
	}
	return "", nil, false
}

// VerifiedShare is the minimum share of a claimed crawler's requests
// that must come from its own ASNs for the claim to be accepted.
const VerifiedShare = 0.9

// Verdict is the outcome of checking a crawler claim.
type Verdict struct {
	Crawler  string  // claimed crawler ("Googlebot"); empty: no claim
	Share    float64 // share of the UA's requests that passed the check
	Verified bool    // Share >= VerifiedShare
	Known    bool    // there was data to judge on
}

// Impostor is a conclusive failed claim: the UA says it is a known
// crawler, but its traffic does not come from that crawler — high-value
// intelligence on its own (SPEC 7.3).
func (v Verdict) Impostor() bool { return v.Crawler != "" && v.Known && !v.Verified }

func verdict(ua string, rows []cfapi.Face, good func(cfapi.Face) bool) Verdict {
	name, _, ok := ClaimedBot(ua)
	if !ok {
		return Verdict{}
	}
	var total, g int64
	for _, f := range rows {
		total += f.Count
		if good(f) {
			g += f.Count
		}
	}
	v := Verdict{Crawler: name}
	if total > 0 {
		v.Known = true
		v.Share = float64(g) / float64(total)
		v.Verified = v.Share >= VerifiedShare
	}
	return v
}

// VerifiedByCategory checks a crawler claim against Cloudflare's own
// verified-bot classification (verifiedBotCategory breakdown of the UA).
func VerifiedByCategory(ua string, cats []cfapi.Face) Verdict {
	return verdict(ua, cats, func(f cfapi.Face) bool { return f.Name != "" && f.Name != "<nil>" })
}

// VerifiedBot checks a crawler claim against the crawler's own ASNs
// (the Top ASNs of requests with that UA). An impostor — Googlebot UA
// from a residential proxy network — fails.
func VerifiedBot(ua string, asnBreakdown []cfapi.Face) Verdict {
	_, asns, _ := ClaimedBot(ua)
	allowed := map[int]bool{}
	for _, a := range asns {
		allowed[a] = true
	}
	return verdict(ua, asnBreakdown, func(f cfapi.Face) bool { return allowed[f.ASN] })
}
