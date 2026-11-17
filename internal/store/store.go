// Package store is FlareHound's local archive (SPEC 5 / 6): a single
// SQLite file that keeps what Cloudflare forgets after ~31 days.
//
//   - snapshots: one row per zone per window (hourly, and daily rollups)
//     holding the full query set of SPEC 6 as JSON;
//   - faces: first/last time each UA and ASN appeared in a Top list;
//   - alerts: every message-producing decision of the state machine.
//
// It is an archive of aggregates, never of individual requests. The state
// machine lives elsewhere (package state); this is history, not control.
package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure Go: keeps CGO_ENABLED=0 builds

	"github.com/playwjj/flarehound/internal/analyze"
	"github.com/playwjj/flarehound/internal/cfapi"
)

// Kind is the granularity of a snapshot.
type Kind string

const (
	Hour Kind = "hour"
	Day  Kind = "day"
)

// Snapshot is one window's archived facts: the detection metrics plus the
// breakdowns that make long-range questions answerable later.
type Snapshot struct {
	analyze.Metrics
	Cache        []cfapi.Face `json:"cache,omitempty"`
	DynamicPaths []cfapi.Face `json:"dynamic_paths,omitempty"`
	Firewall     []cfapi.Face `json:"firewall,omitempty"`
	FirewallNA   bool         `json:"firewall_na,omitempty"`
}

type Store struct{ db *sql.DB }

const schema = `
CREATE TABLE IF NOT EXISTS snapshots (
	zone       TEXT    NOT NULL,
	kind       TEXT    NOT NULL,
	from_ts    INTEGER NOT NULL,
	to_ts      INTEGER NOT NULL,
	total      INTEGER NOT NULL,
	dynamic    INTEGER NOT NULL,
	origin_5xx INTEGER NOT NULL,
	data       TEXT    NOT NULL,
	saved_at   INTEGER NOT NULL,
	PRIMARY KEY (zone, kind, from_ts)
);
CREATE TABLE IF NOT EXISTS faces (
	zone       TEXT    NOT NULL,
	dim        TEXT    NOT NULL,
	name       TEXT    NOT NULL,
	first_seen INTEGER NOT NULL,
	last_seen  INTEGER NOT NULL,
	max_count  INTEGER NOT NULL,
	PRIMARY KEY (zone, dim, name)
);
CREATE TABLE IF NOT EXISTS alerts (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	zone        TEXT    NOT NULL,
	window_to   INTEGER NOT NULL,
	decision    TEXT    NOT NULL,
	fingerprint TEXT    NOT NULL,
	findings    TEXT    NOT NULL,
	sent_at     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS alerts_zone ON alerts (zone, window_to);
`

// Open opens (creating if needed) the archive at path.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // one writer; the process is single-threaded per round anyway
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("archive schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// PutSnapshot stores (or replaces) the snapshot of one window.
func (s *Store) PutSnapshot(zone string, kind Kind, from, to time.Time, snap Snapshot) error {
	raw, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO snapshots (zone, kind, from_ts, to_ts, total, dynamic, origin_5xx, data, saved_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (zone, kind, from_ts) DO UPDATE SET
			to_ts = excluded.to_ts, total = excluded.total, dynamic = excluded.dynamic,
			origin_5xx = excluded.origin_5xx, data = excluded.data, saved_at = excluded.saved_at`,
		zone, string(kind), from.Unix(), to.Unix(), snap.Total, snap.Dynamic, snap.Origin5xx, string(raw), time.Now().Unix())
	return err
}

// Snapshot returns one window's snapshot, if archived.
func (s *Store) Snapshot(zone string, kind Kind, from time.Time) (Snapshot, bool, error) {
	var raw string
	err := s.db.QueryRow(`SELECT data FROM snapshots WHERE zone = ? AND kind = ? AND from_ts = ?`,
		zone, string(kind), from.Unix()).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return Snapshot{}, false, nil
	}
	if err != nil {
		return Snapshot{}, false, err
	}
	var snap Snapshot
	if err := json.Unmarshal([]byte(raw), &snap); err != nil {
		return Snapshot{}, false, err
	}
	return snap, true, nil
}

// SameHour returns the archived hourly snapshots whose window starts at
// from − k·24h for k = 1..days and has the same length — the samples for
// the long baseline. Missing days are simply absent.
func (s *Store) SameHour(zone string, from, to time.Time, days int) ([]analyze.Metrics, error) {
	length := to.Unix() - from.Unix()
	var starts []any
	for k := 1; k <= days; k++ {
		starts = append(starts, from.Add(-time.Duration(k)*24*time.Hour).Unix())
	}
	if len(starts) == 0 {
		return nil, nil
	}
	q := `SELECT data FROM snapshots WHERE zone = ? AND kind = 'hour' AND to_ts - from_ts = ? AND from_ts IN (?` +
		strings.Repeat(",?", len(starts)-1) + `) ORDER BY from_ts DESC`
	args := append([]any{zone, length}, starts...)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []analyze.Metrics
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var snap Snapshot
		if err := json.Unmarshal([]byte(raw), &snap); err != nil {
			return nil, err
		}
		out = append(out, snap.Metrics)
	}
	return out, rows.Err()
}

// FaceRecord is when a UA or ASN was first and last seen in a Top list.
type FaceRecord struct {
	Name      string
	FirstSeen time.Time
	LastSeen  time.Time
	MaxCount  int64
}

// Face dims.
const (
	DimUA  = "ua"
	DimASN = "asn"
)

// TouchFaces records that faces appeared in a Top list of the window
// starting at `at`. Backfilled (older) windows can move first_seen back.
func (s *Store) TouchFaces(zone, dim string, faces []cfapi.Face, at time.Time) error {
	if len(faces) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT INTO faces (zone, dim, name, first_seen, last_seen, max_count) VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT (zone, dim, name) DO UPDATE SET
			first_seen = MIN(first_seen, excluded.first_seen),
			last_seen  = MAX(last_seen, excluded.last_seen),
			max_count  = MAX(max_count, excluded.max_count)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, f := range faces {
		if _, err := stmt.Exec(zone, dim, f.Name, at.Unix(), at.Unix(), f.Count); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Face looks up one face's record.
func (s *Store) Face(zone, dim, name string) (FaceRecord, bool, error) {
	var first, last, maxc int64
	err := s.db.QueryRow(`SELECT first_seen, last_seen, max_count FROM faces WHERE zone = ? AND dim = ? AND name = ?`,
		zone, dim, name).Scan(&first, &last, &maxc)
	if errors.Is(err, sql.ErrNoRows) {
		return FaceRecord{}, false, nil
	}
	if err != nil {
		return FaceRecord{}, false, err
	}
	return FaceRecord{Name: name, FirstSeen: time.Unix(first, 0).UTC(), LastSeen: time.Unix(last, 0).UTC(), MaxCount: maxc}, true, nil
}

// RecordAlert appends one message-producing decision to the history.
func (s *Store) RecordAlert(zone string, windowTo time.Time, decision, fingerprint string, findings []analyze.Finding) error {
	raw, err := json.Marshal(findings)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO alerts (zone, window_to, decision, fingerprint, findings, sent_at) VALUES (?, ?, ?, ?, ?, ?)`,
		zone, windowTo.Unix(), decision, fingerprint, string(raw), time.Now().Unix())
	return err
}

// Alert is one archived decision.
type Alert struct {
	WindowTo    time.Time
	Decision    string
	Fingerprint string
}

// Alerts returns a zone's decisions with windows ending in [from, to).
func (s *Store) Alerts(zone string, from, to time.Time) ([]Alert, error) {
	rows, err := s.db.Query(`SELECT window_to, decision, fingerprint FROM alerts WHERE zone = ? AND window_to >= ? AND window_to < ? ORDER BY window_to`,
		zone, from.Unix(), to.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Alert
	for rows.Next() {
		var a Alert
		var ts int64
		if err := rows.Scan(&ts, &a.Decision, &a.Fingerprint); err != nil {
			return nil, err
		}
		a.WindowTo = time.Unix(ts, 0).UTC()
		out = append(out, a)
	}
	return out, rows.Err()
}

// Prune drops hourly snapshots whose window started before `before`.
// Daily rollups, faces and alerts are kept for good (they are tiny).
func (s *Store) Prune(before time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM snapshots WHERE kind = 'hour' AND from_ts < ?`, before.Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// Stats summarises the archive for one zone.
type Stats struct {
	Hours, Days, Faces, Alerts int64
	Oldest                     time.Time
}

func (s *Store) Stats(zone string) (Stats, error) {
	var st Stats
	var oldest sql.NullInt64
	err := s.db.QueryRow(`SELECT
		(SELECT COUNT(*) FROM snapshots WHERE zone = ?1 AND kind = 'hour'),
		(SELECT COUNT(*) FROM snapshots WHERE zone = ?1 AND kind = 'day'),
		(SELECT COUNT(*) FROM faces WHERE zone = ?1),
		(SELECT COUNT(*) FROM alerts WHERE zone = ?1),
		(SELECT MIN(from_ts) FROM snapshots WHERE zone = ?1)`, zone).
		Scan(&st.Hours, &st.Days, &st.Faces, &st.Alerts, &oldest)
	if oldest.Valid {
		st.Oldest = time.Unix(oldest.Int64, 0).UTC()
	}
	return st, err
}
