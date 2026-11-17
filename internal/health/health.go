// Package health is the dead-man switch: a watchdog that died and a quiet
// site look the same from outside, unless the watchdog says "I am alive"
// on every round — anomaly or not.
package health

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// Beat is one round's proof of life.
type Beat struct {
	At      time.Time `json:"at"`
	Version string    `json:"version"`
	Role    string    `json:"role"` // "watch" | "enforce"
	Zones   int       `json:"zones"`
	Errors  []string  `json:"errors,omitempty"`
	Next    time.Time `json:"next,omitzero"`
}

// File names of the two roles' heartbeats in the data directory.
const (
	WatchFile   = "heartbeat"
	EnforceFile = "heartbeat-enforce"
)

// Write stores a beat atomically.
func Write(dir, name string, b Beat) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return err
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p+".tmp", raw, 0o644); err != nil {
		return err
	}
	return os.Rename(p+".tmp", p)
}

// Read loads the last beat.
func Read(dir, name string) (Beat, error) {
	var b Beat
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return b, err
	}
	return b, json.Unmarshal(raw, &b)
}

// Check reports whether the last beat is younger than maxAge.
func Check(dir, name string, maxAge time.Duration, now time.Time) (Beat, error) {
	b, err := Read(dir, name)
	if errors.Is(err, os.ErrNotExist) {
		return b, fmt.Errorf("no heartbeat yet (%s)", name)
	}
	if err != nil {
		return b, err
	}
	if age := now.Sub(b.At); age > maxAge {
		return b, fmt.Errorf("heartbeat is %s old (limit %s): the %s loop is not running", age.Round(time.Second), maxAge, b.Role)
	}
	return b, nil
}

var client = &http.Client{Timeout: 15 * time.Second}

// Ping calls a healthchecks.io-style URL: GET url on success, url + "/fail"
// when the round had errors. Errors never contain the URL (it is a secret).
func Ping(ctx context.Context, rawURL string, failed bool) error {
	u := rawURL
	if failed {
		u = rawURL + "/fail"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return errors.New("heartbeat ping: invalid URL")
	}
	resp, err := client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			return fmt.Errorf("heartbeat ping: %v", ue.Err)
		}
		return errors.New("heartbeat ping failed")
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("heartbeat ping: HTTP %d", resp.StatusCode)
	}
	return nil
}
