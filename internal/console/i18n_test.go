package console

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every UI string key used in templates and code exists in both
// languages; a missing key would show its raw name on the page.
func TestI18nKeys(t *testing.T) {
	used := map[string]string{}
	add := func(k, where string) { used[k] = where }

	tmpls, _ := filepath.Glob("templates/*.html")
	static := regexp.MustCompile(`\b(?:t|tf) "([a-z0-9_]+)"`)
	for _, f := range tmpls {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range static.FindAllStringSubmatch(string(b), -1) {
			add(m[1], f)
		}
	}
	gofiles, _ := filepath.Glob("*.go")
	code := regexp.MustCompile(`lang\.t\("([a-z0-9_]+)"\)`)
	for _, f := range gofiles {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, _ := os.ReadFile(f)
		for _, m := range code.FindAllStringSubmatch(string(b), -1) {
			add(m[1], f)
		}
	}
	// Keys built at run time: (print "prefix_" value), evName, roleName.
	for _, k := range []string{"dim_ua", "dim_asn", "dim_path", "st_ok", "st_watch", "st_alert", "st_na",
		"tt_ip", "tt_asn", "tt_country", "tt_ua", "role_admin", "role_viewer",
		"ev_alert", "ev_recovered", "ev_block", "ev_unblock", "ev_expire", "ev_renew", "ev_rule", "net_hosting", "net_eyeball", "net_unknown"} {
		add(k, "dynamic")
	}
	// Keys passed through page fields / helpers.
	for _, k := range []string{"m_total", "m_worker_calls", "m_worker_cpu", "m_dynamic", "m_origin5xx",
		"m_unreachable", "m_origin_ttfb", "m_origin_total"} {
		add(k, "data.go")
	}
	if len(used) < 100 {
		t.Fatalf("only %d keys found: the scan is broken", len(used))
	}
	for k, where := range used {
		v, ok := dict[k]
		if !ok {
			t.Errorf("missing UI string %q (used in %s)", k, where)
			continue
		}
		if v[0] == "" || v[1] == "" {
			t.Errorf("UI string %q lacks a translation", k)
		}
		if strings.Count(v[0], "%") != strings.Count(v[1], "%") {
			t.Errorf("UI string %q: English and Chinese take different arguments", k)
		}
	}
}
