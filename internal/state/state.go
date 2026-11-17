// Package state persists the anomaly state machine across runs:
// whether an anomaly episode is active, which signals it has shown, the
// peak values already reported, and how many consecutive clean rounds
// have passed.
//
// The discipline (SPEC.md 7.3): the same anomaly never alerts twice;
// it escalates only when a signal grows another +25% over its reported
// peak; recovery is announced once, after two clean rounds.
package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/playwjj/flarehound/internal/analyze"
)

type State struct {
	Active       bool               `json:"active"`
	Fingerprint  string             `json:"fingerprint,omitempty"`
	Keys         map[string]bool    `json:"keys,omitempty"` // every signal seen in this episode
	FirstAlertAt time.Time          `json:"first_alert_at,omitzero"`
	Peak         map[string]float64 `json:"peak,omitempty"` // signal key -> reported peak
	CleanRounds  int                `json:"clean_rounds"`
	// LastWindow is the end of the last evaluated window; a restart must
	// not evaluate (and count) the same window twice.
	LastWindow time.Time `json:"last_window,omitzero"`
}

type Decision int

const (
	DecNone      Decision = iota
	DecAlert              // a new episode starts
	DecChanged            // active episode shows a signal it has not shown before
	DecEscalate           // a reported signal grew past peak + escalation %
	DecRecovered          // enough clean rounds: episode over
)

func (d Decision) String() string {
	return [...]string{"none", "alert", "changed", "escalate", "recovered"}[d]
}

// Notify reports whether the decision produces a message.
func (d Decision) Notify() bool { return d != DecNone }

func Load(path string) (*State, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &State{}, nil
	}
	if err != nil {
		return nil, err
	}
	var st State
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// Save writes atomically (temp file + rename) so a crash mid-write never
// leaves a truncated state file that would reset the episode.
func (s *State) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Decide advances the state machine for one check round.
func Decide(st *State, findings []analyze.Finding, escPct float64, cleanRoundsNeeded int, now time.Time) Decision {
	if cleanRoundsNeeded < 1 {
		cleanRoundsNeeded = 1
	}
	if len(findings) == 0 {
		if !st.Active {
			return DecNone
		}
		st.CleanRounds++
		if st.CleanRounds >= cleanRoundsNeeded {
			lw := st.LastWindow
			*st = State{LastWindow: lw}
			return DecRecovered
		}
		return DecNone
	}

	st.CleanRounds = 0
	if !st.Active {
		st.Active = true
		st.FirstAlertAt = now
		st.Keys = map[string]bool{}
		st.Peak = map[string]float64{}
		st.record(findings)
		return DecAlert
	}

	novel := false
	for _, f := range findings {
		if !st.Keys[f.Key()] {
			novel = true
		}
	}
	if novel {
		st.record(findings)
		return DecChanged
	}

	escalated := false
	for _, f := range findings {
		if f.Down {
			continue
		}
		if p, ok := st.Peak[f.Key()]; ok && p > 0 && f.Cur >= p*(1+escPct/100) {
			escalated = true
		}
	}
	if escalated {
		st.record(findings)
		return DecEscalate
	}
	return DecNone
}

// record marks findings as reported: their keys join the episode and
// their values become the reported peaks.
func (st *State) record(findings []analyze.Finding) {
	if st.Keys == nil {
		st.Keys = map[string]bool{}
	}
	if st.Peak == nil {
		st.Peak = map[string]float64{}
	}
	for _, f := range findings {
		k := f.Key()
		st.Keys[k] = true
		if !f.Down && f.Cur > st.Peak[k] {
			st.Peak[k] = f.Cur
		}
	}
	all := make([]analyze.Finding, 0, len(st.Keys))
	for k := range st.Keys {
		all = append(all, analyze.Finding{Rule: k})
	}
	st.Fingerprint = analyze.Fingerprint(all)
}
