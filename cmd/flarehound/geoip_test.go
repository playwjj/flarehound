package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/playwjj/flarehound/internal/config"
)

// doctor: no library is a note (the feature is off), a broken one an error.
func TestDoctorGeoIP(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{StateFile: filepath.Join(dir, "state.json"), Location: time.UTC}
	cfg.GeoIP.CountryDB = filepath.Join(dir, "country.mmdb")

	var out bytes.Buffer
	d := &doctorOut{w: &out}
	doctorGeoIP(d, cfg)
	if d.problems != 0 || !strings.Contains(out.String(), "! IP location off: no country library") {
		t.Fatalf("missing library: %d problem(s)\n%s", d.problems, out.String())
	}

	os.WriteFile(cfg.GeoIP.CountryDB, []byte("truncated"), 0o644)
	out.Reset()
	doctorGeoIP(d, cfg)
	if d.problems != 1 || !strings.Contains(out.String(), "✗ IP location off: "+cfg.GeoIP.CountryDB+" cannot be used") {
		t.Fatalf("broken library: %d problem(s)\n%s", d.problems, out.String())
	}
}

func TestGeoIPPathFromConfig(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	os.WriteFile(p, []byte(`{"state_file": "/srv/fh/state.json"}`), 0o644)
	if got, _ := geoipPathFromConfig(p); got != "/srv/fh/country.mmdb" {
		t.Errorf("default path: %s", got)
	}
	os.WriteFile(p, []byte(`{"geoip": {"country_db": "/x/GeoLite2-Country.mmdb"}}`), 0o644)
	if got, _ := geoipPathFromConfig(p); got != "/x/GeoLite2-Country.mmdb" {
		t.Errorf("configured path: %s", got)
	}
}
