package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/playwjj/flarehound/internal/geoip"
)

const geoipUsage = `Usage: flarehound geoip update [-o PATH]

Downloads the newest free DB-IP country library (dbip-country-lite, CC BY 4.0),
checks that it reads as a country library, and atomically replaces the file.
Without -o it writes geoip.country_db from the config, else <data dir>/country.mmdb
(which takes precedence over the library the Docker image ships). Running watch and
console processes pick the new file up within 10 minutes; nothing else changes.

The library is only used to show each IP's country ("IP location"); it never takes
part in alerts or block plans. ` + geoip.Attribution + `.
`

// runGeoIP runs `flarehound geoip …`. It needs no token: it only reads
// the config for the library path (or takes -o).
func runGeoIP(ctx context.Context, cfgPath string, args []string) int {
	if len(args) == 0 || args[0] != "update" {
		fmt.Fprint(os.Stderr, geoipUsage)
		if len(args) > 0 && (args[0] == "help" || args[0] == "-h" || args[0] == "--help") {
			return 0
		}
		return 2
	}
	fs := flag.NewFlagSet("geoip update", flag.ContinueOnError)
	out := fs.String("o", "", "write the library here instead of the configured path")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	dest := *out
	if dest == "" {
		var err error
		if dest, err = geoipPathFromConfig(cfgPath); err != nil {
			fmt.Fprintf(os.Stderr, "geoip: %v (or pass -o PATH)\n", err)
			return 1
		}
	}
	url, info, err := geoip.Update(ctx, nil, dest, time.Now())
	if err != nil {
		fmt.Fprintf(os.Stderr, "geoip update failed, %s left as it was:\n%v\n", dest, err)
		return 1
	}
	fmt.Printf("geoip: %s updated from %s\n  %s, built %s, %d networks\n  %s\n",
		dest, url, info.Type, info.Built.Format("2006-01-02"), info.Networks, geoip.Attribution)
	return 0
}

// geoipPathFromConfig reads only the two fields the path depends on, so
// the command works without the API token in the environment.
func geoipPathFromConfig(cfgPath string) (string, error) {
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		return "", err
	}
	var c struct {
		StateFile string `json:"state_file"`
		GeoIP     struct {
			CountryDB string `json:"country_db"`
		} `json:"geoip"`
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return "", fmt.Errorf("parse config: %w", err)
	}
	if c.StateFile == "" {
		c.StateFile = "data/state.json"
	}
	return geoip.Candidates(c.GeoIP.CountryDB, filepath.Dir(c.StateFile))[0], nil
}
