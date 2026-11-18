// Package control is the console ↔ watch handshake (v1.9), through files
// in <data dir>/control/ — the two processes share the data volume and
// nothing else (no port, no token):
//
//   - the console asks for a test notification (req-<id>.json); the watch,
//     which holds the real notification secrets, sends it through each
//     channel and answers (res-<id>.json) with the outcome per channel;
//   - the watch reports which settings version it runs, whether a newer
//     one was accepted or rejected (and why), and for every channel which
//     environment variables are set in its process (never their values).
package control

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/playwjj/flarehound/internal/config"
)

const (
	dirName    = "control"
	statusFile = "status.json"
	// RequestTTL: requests the watch has not picked up by then are dropped.
	RequestTTL = 2 * time.Minute
)

// Dir is the control directory in a data directory.
func Dir(dataDir string) string { return filepath.Join(dataDir, dirName) }

// TestRequest asks the watch to send a test notification.
type TestRequest struct {
	ID      string    `json:"id"`
	Channel string    `json:"channel"` // a channel name, or "all"
	By      string    `json:"by"`
	At      time.Time `json:"at"`
}

// ChannelResult is one channel's outcome.
type ChannelResult struct {
	Channel string `json:"channel"`
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
}

// TestResult is the watch's answer.
type TestResult struct {
	ID      string          `json:"id"`
	At      time.Time       `json:"at"`
	Results []ChannelResult `json:"results"`
	// Settings is the settings version the test used; SettingsError is
	// set when the current settings do not load in the watch.
	Settings      int    `json:"settings"`
	SettingsError string `json:"settings_error,omitempty"`
}

// Status is what the watch reports about its settings and channels.
type Status struct {
	At             time.Time            `json:"at"`
	Version        string               `json:"version"`         // FlareHound version
	Applied        int                  `json:"applied"`         // settings version in use
	Pending        int                  `json:"pending"`         // newer version seen, applies at the next round
	Rejected       int                  `json:"rejected"`        // newer version that does not load
	RejectedReason string               `json:"rejected_reason"` // why
	NextRound      time.Time            `json:"next_round"`
	Channels       []config.ChannelInfo `json:"channels"`
}

func writeJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readJSON(path string, v any) (bool, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal(raw, v)
}

var validChannel = func(ch string) bool {
	if ch == "all" {
		return true
	}
	for _, c := range config.AllChannels() {
		if c == ch {
			return true
		}
	}
	return false
}

// RequestTest queues a test notification and returns its id.
func RequestTest(dataDir, channel, by string, now time.Time) (string, error) {
	if !validChannel(channel) {
		return "", fmt.Errorf("unknown channel %q", channel)
	}
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	id := hex.EncodeToString(b)
	return id, writeJSON(filepath.Join(Dir(dataDir), "req-"+id+".json"), TestRequest{ID: id, Channel: channel, By: by, At: now})
}

var idRE = func(id string) bool {
	if len(id) != 16 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

// Result returns a test's answer, if the watch has written it.
func Result(dataDir, id string) (TestResult, bool, error) {
	var r TestResult
	if !idRE(id) {
		return r, false, errors.New("bad id")
	}
	ok, err := readJSON(filepath.Join(Dir(dataDir), "res-"+id+".json"), &r)
	return r, ok, err
}

// Waiting reports whether a request is still queued (not yet picked up).
func Waiting(dataDir, id string) bool {
	if !idRE(id) {
		return false
	}
	_, err := os.Stat(filepath.Join(Dir(dataDir), "req-"+id+".json"))
	return err == nil
}

// ReadStatus returns the watch's last status report.
func ReadStatus(dataDir string) (Status, bool, error) {
	var s Status
	ok, err := readJSON(filepath.Join(Dir(dataDir), statusFile), &s)
	return s, ok, err
}

// WriteStatus is the watch's report.
func WriteStatus(dataDir string, s Status) error {
	return writeJSON(filepath.Join(Dir(dataDir), statusFile), s)
}

// Handler answers one test request.
type Handler func(ctx context.Context, req TestRequest) TestResult

// Poll handles queued requests once: each is removed before it is
// handled (one answer per request), stale ones are dropped, and answers
// older than a day are cleaned up.
func Poll(ctx context.Context, dataDir string, now time.Time, h Handler) error {
	dir := Dir(dataDir)
	reqs, err := filepath.Glob(filepath.Join(dir, "req-*.json"))
	if err != nil {
		return err
	}
	sort.Strings(reqs)
	for _, f := range reqs {
		var r TestRequest
		ok, err := readJSON(f, &r)
		os.Remove(f)
		if !ok || err != nil || !idRE(r.ID) || !strings.HasSuffix(f, "req-"+r.ID+".json") {
			continue
		}
		if now.Sub(r.At) > RequestTTL {
			continue
		}
		res := h(ctx, r)
		res.ID, res.At = r.ID, now
		if err := writeJSON(filepath.Join(dir, "res-"+r.ID+".json"), res); err != nil {
			return err
		}
	}
	old, _ := filepath.Glob(filepath.Join(dir, "res-*.json"))
	for _, f := range old {
		if st, err := os.Stat(f); err == nil && now.Sub(st.ModTime()) > 24*time.Hour {
			os.Remove(f)
		}
	}
	return nil
}
