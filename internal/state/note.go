package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// StatusNote remembers what the daily report last said about FlareHound's
// own status (plan limits, permissions, archive, counting basis), so the
// report repeats it only when it changes, or once a week — not every day.
type StatusNote struct {
	Key     string    `json:"key"`
	ShownAt time.Time `json:"shown_at"`
}

// StatusRepeat is how often an unchanged status is said again.
const StatusRepeat = 7 * 24 * time.Hour

// LoadNote reads a status note; a missing or unreadable file is an empty
// note (the status is then shown).
func LoadNote(path string) StatusNote {
	var n StatusNote
	raw, err := os.ReadFile(path)
	if err != nil {
		return n
	}
	_ = json.Unmarshal(raw, &n)
	return n
}

// Due reports whether the status with this key should be shown now.
func (n StatusNote) Due(key string, now time.Time) bool {
	return n.Key != key || n.ShownAt.IsZero() || now.Sub(n.ShownAt) >= StatusRepeat
}

// Save writes the note atomically.
func (n StatusNote) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(n, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
