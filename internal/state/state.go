// Package state persists the anomaly state machine across runs:
// whether an anomaly is active, its fingerprint, the peak values already
// reported, and how many consecutive clean rounds have passed.
//
// The discipline (SPEC.md 7.3): the same anomaly never alerts twice;
// it escalates only when a key metric grows another +25% over the
// reported peak; recovery is announced once, after two clean rounds.
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
	Fingerprint  string             `json:"fingerprint"`
	FirstAlertAt time.Time          `json:"first_alert_at"`
	Peak         map[string]float64 `json:"peak"`
	CleanRounds  int                `json:"clean_rounds"`
}

type Decision int

const (
	DecNone Decision = iota
	DecAlert
	DecEscalate
	DecRecovered
)

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

func (s *State) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o644)
}

// Decide advances the state machine for one check round. total and
// worker are the current window's key metrics, used for escalation.
func Decide(st *State, findings []analyze.Finding, total, worker float64, escPct float64, cleanRoundsNeeded int) Decision {
	if len(findings) == 0 {
		if !st.Active {
			return DecNone
		}
		st.CleanRounds++
		if st.CleanRounds >= cleanRoundsNeeded {
			*st = State{}
			return DecRecovered
		}
		return DecNone
	}

	st.CleanRounds = 0
	fp := analyze.Fingerprint(findings)
	if !st.Active || st.Fingerprint != fp {
		st.Active = true
		st.Fingerprint = fp
		st.FirstAlertAt = time.Now()
		st.Peak = map[string]float64{"total": total, "worker": worker}
		return DecAlert
	}
	if total >= st.Peak["total"]*(1+escPct/100) || worker >= st.Peak["worker"]*(1+escPct/100) {
		if total > st.Peak["total"] {
			st.Peak["total"] = total
		}
		if worker > st.Peak["worker"] {
			st.Peak["worker"] = worker
		}
		return DecEscalate
	}
	return DecNone
}
