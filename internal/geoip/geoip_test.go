package geoip

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLabel(t *testing.T) {
	cases := []struct{ code, lang, want string }{
		{"IN", "en", "IN · India"},
		{"IN", "zh", "印度 (IN)"},
		{"US", "en", "US · United States"},
		{"CN", "zh", "中国 (CN)"},
		{"", "en", ""},
		{"QQ", "en", "QQ"}, // unknown code: the code alone
	}
	for _, c := range cases {
		if got := Label(c.code, c.lang); got != c.want {
			t.Errorf("Label(%q, %q) = %q, want %q", c.code, c.lang, got, c.want)
		}
	}
	if len(names) < 240 {
		t.Errorf("name table has %d entries, want the full country list", len(names))
	}
}

func TestCandidates(t *testing.T) {
	if got := Candidates("/x/c.mmdb", "data"); len(got) != 1 || got[0] != "/x/c.mmdb" {
		t.Errorf("configured path: %v", got)
	}
	got := Candidates("", "data")
	if len(got) != 2 || got[0] != filepath.Join("data", FileName) || got[1] != BuiltinPath {
		t.Errorf("default candidates: %v", got)
	}
}

// No library: the feature is off, nothing fails, every lookup is "".
func TestMissingLibraryIsSilent(t *testing.T) {
	defer Reset()
	st := Setup([]string{filepath.Join(t.TempDir(), "none.mmdb")})
	if st.DB != nil || st.Err != nil || st.Path != "" {
		t.Fatalf("missing file: %+v", st)
	}
	if Enabled() || Country("8.8.8.8") != "" || Text("8.8.8.8", "en") != "" || Suffix("8.8.8.8", "zh") != "" {
		t.Error("lookups must be empty without a library")
	}
}

// A damaged file (truncated, or not MMDB at all) is reported, never fatal.
func TestDamagedLibrary(t *testing.T) {
	defer Reset()
	dir := t.TempDir()
	for name, body := range map[string][]byte{
		"text.mmdb":  []byte("this is not a library\n"),
		"empty.mmdb": {},
		"trunc.mmdb": append([]byte{0, 0, 0, 1, 2, 3}, []byte("\xab\xcd\xefMaxMind.com")...),
	} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, body, 0o644); err != nil {
			t.Fatal(err)
		}
		st := Setup([]string{p, filepath.Join(dir, "never-reached.mmdb")})
		if st.DB != nil || st.Err == nil || st.Path != p {
			t.Errorf("%s: want an error and no library, got %+v", name, st)
		}
		if Country("8.8.8.8") != "" {
			t.Errorf("%s: lookup must be empty", name)
		}
	}
}

func TestUseFunc(t *testing.T) {
	defer Reset()
	UseFunc(func(s string) string {
		if s == "106.201.104.211" {
			return "IN"
		}
		return ""
	})
	if got := Text("106.201.104.211", "en"); got != "IN · India" {
		t.Errorf("Text = %q", got)
	}
	if got := Suffix("106.201.104.211", "zh"); got != " [印度 (IN)]" {
		t.Errorf("Suffix = %q", got)
	}
	if Suffix("10.0.0.1", "en") != "" {
		t.Error("unplaced address must have no suffix")
	}
}

// The acceptance samples, against a real library:
// FLAREHOUND_TEST_MMDB=/path/to/dbip-country-lite.mmdb go test ./internal/geoip
func TestRealLibrary(t *testing.T) {
	p := os.Getenv("FLAREHOUND_TEST_MMDB")
	if p == "" {
		t.Skip("FLAREHOUND_TEST_MMDB not set")
	}
	d, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	for ip, want := range map[string]string{
		"8.8.8.8":                "US",
		"223.5.5.5":              "CN",
		"2400:3200::1":           "CN", // AliDNS over IPv6
		"2606:4700:4700::1111":   "US", // Cloudflare's resolver over IPv6
		"106.201.104.211":        "IN",
		"::ffff:106.201.104.211": "IN",
		"106.201.104.0/24":       "IN",
		"2400:3200::/64":         "CN",
		"10.0.0.1":               "",
		"not an address":         "",
	} {
		for range 2 { // second round from the cache
			if got := d.Country(ip); got != want {
				t.Errorf("%s: got %q, want %q", ip, got, want)
			}
		}
	}
	// Google's IPv6 resolver: GeoLite2 says US, DB-IP lite (2026-10 and
	// -11) says CA. Either way the IPv6 tree must place it.
	if got := d.Country("2001:4860:4860::8888"); got == "" {
		t.Error("2001:4860:4860::8888 not placed")
	}
	if in := d.Info(); in.Networks == 0 || in.Built.IsZero() {
		t.Errorf("info: %+v", in)
	}
}
