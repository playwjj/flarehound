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

// VerifiedByCategory reports whether a UA claiming to be a known crawler
// is backed by Cloudflare's own verified-bot classification: at least
// VerifiedShare of its requests carry a non-empty verifiedBotCategory.
func VerifiedByCategory(ua string, cats []cfapi.Face) (string, bool) {
	name, _, ok := ClaimedBot(ua)
	if !ok {
		return "", false
	}
	var total, good int64
	for _, f := range cats {
		total += f.Count
		if f.Name != "" && f.Name != "<nil>" {
			good += f.Count
		}
	}
	if total == 0 {
		return name, false
	}
	return name, float64(good)/float64(total) >= VerifiedShare
}

// VerifiedBot reports whether a UA claiming to be a known crawler is
// backed by its ASN breakdown (the Top ASNs of requests with that UA).
// An impostor — Googlebot UA from a residential proxy network — fails.
func VerifiedBot(ua string, asnBreakdown []cfapi.Face) (string, bool) {
	name, asns, ok := ClaimedBot(ua)
	if !ok {
		return "", false
	}
	allowed := map[int]bool{}
	for _, a := range asns {
		allowed[a] = true
	}
	var total, good int64
	for _, f := range asnBreakdown {
		total += f.Count
		if allowed[f.ASN] {
			good += f.Count
		}
	}
	if total == 0 {
		return name, false
	}
	return name, float64(good)/float64(total) >= VerifiedShare
}
