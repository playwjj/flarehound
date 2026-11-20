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
	// The hour's top client IPs (with their ASN where the plan has it) and
	// top IPs stopped at the edge — the console's IP board. nil before
	// v1.14 and on rounds where the query failed. From v1.14.1 TopIPs
	// leaves out Cloudflare-verified bots, which are kept in BotIPs.
	TopIPs     []cfapi.Face `json:"top_ips,omitempty"`
	BlockedIPs []cfapi.Face `json:"blocked_ips,omitempty"`
	BotIPs     []cfapi.Face `json:"bot_ips,omitempty"`
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
CREATE TABLE IF NOT EXISTS block_events (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	at         INTEGER NOT NULL,
	zone       TEXT    NOT NULL,
	op         TEXT    NOT NULL, -- block | unblock | expire
	type       TEXT    NOT NULL,
	value      TEXT    NOT NULL,
	action     TEXT    NOT NULL,
	mechanism  TEXT    NOT NULL,
	rule_id    TEXT    NOT NULL,
	reason     TEXT    NOT NULL,
	expires_at INTEGER NOT NULL, -- 0: no expiry
	actor      TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS block_events_target ON block_events (zone, type, value, id);
CREATE TABLE IF NOT EXISTS asn_names (
	asn     INTEGER PRIMARY KEY,
	name    TEXT    NOT NULL,
	seen_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS calibration_days (
	zone TEXT    NOT NULL,
	date INTEGER NOT NULL, -- UTC midnight
	data TEXT    NOT NULL, -- calibrate.Day as JSON
	PRIMARY KEY (zone, date)
);
CREATE TABLE IF NOT EXISTS rule_backups (
	id       INTEGER PRIMARY KEY AUTOINCREMENT,
	at       INTEGER NOT NULL,
	zone     TEXT    NOT NULL,
	phase    TEXT    NOT NULL,
	version  TEXT    NOT NULL,
	reason   TEXT    NOT NULL,
	data     TEXT    NOT NULL, -- the phase's rules as Cloudflare returned them (JSON array)
	file     TEXT    NOT NULL  -- the same snapshot as a JSON file, for humans
);
CREATE TABLE IF NOT EXISTS rule_changes (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	at         INTEGER NOT NULL,
	zone       TEXT    NOT NULL,
	phase      TEXT    NOT NULL,
	op         TEXT    NOT NULL, -- add | edit | delete | move | restore
	rule       TEXT    NOT NULL, -- rule id or ref
	before     TEXT    NOT NULL, -- JSON
	after      TEXT    NOT NULL, -- JSON
	backup_id  INTEGER NOT NULL,
	verified   INTEGER NOT NULL, -- 1: read-back matched
	detail     TEXT    NOT NULL,
	actor      TEXT    NOT NULL
);
`

// Open opens (creating if needed) the archive at path.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	// auto_vacuum comes first: it only takes on a database that has no
	// tables yet, so a new archive gets it and an existing one (created
	// before v1.18, auto_vacuum NONE) keeps its mode — no migration.
	dsn := "file:" + path + "?_pragma=auto_vacuum(INCREMENTAL)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)"
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
	// DimPath records top uncached (dynamic) paths — the expensive ones.
	// Recorded since v1.3; older archives have no path history.
	DimPath = "path"
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

// PruneStats says what Prune removed.
type PruneStats struct {
	Hours, Faces, Alerts int64
	Reclaimed            bool // incremental_vacuum ran (archive created with auto_vacuum)
}

// Total is the number of rows removed.
func (p PruneStats) Total() int64 { return p.Hours + p.Faces + p.Alerts }

// VacuumAfter is how many rows one prune must remove before it also
// hands the freed pages back to the file system: a routine round frees a
// handful of pages that the next inserts reuse anyway; a shortened
// retention frees thousands at once.
const VacuumAfter = 1000

// Prune applies the archive retention at one cut point (`before`, from
// archive.hourly_retention_days): hourly snapshots whose window started
// before it, faces last seen before it and archived alerts whose window
// ended before it. Daily rollups, the block audit log and the rule
// backups and change records are kept for good (small, and the audit is
// their point). When many rows went, the freed space is returned to the
// file system — on archives created with auto_vacuum (v1.18+); older
// files keep their size and reuse the pages.
func (s *Store) Prune(before time.Time) (PruneStats, error) {
	var ps PruneStats
	cut := before.Unix()
	tx, err := s.db.Begin()
	if err != nil {
		return ps, err
	}
	defer tx.Rollback()
	for _, q := range []struct {
		n   *int64
		sql string
	}{
		{&ps.Hours, `DELETE FROM snapshots WHERE kind = 'hour' AND from_ts < ?`},
		{&ps.Faces, `DELETE FROM faces WHERE last_seen < ?`},
		{&ps.Alerts, `DELETE FROM alerts WHERE window_to < ?`},
	} {
		res, err := tx.Exec(q.sql, cut)
		if err != nil {
			return PruneStats{}, err
		}
		*q.n, _ = res.RowsAffected()
	}
	if err := tx.Commit(); err != nil {
		return PruneStats{}, err
	}
	if ps.Total() >= VacuumAfter {
		ok, err := IncrementalVacuum(s.db)
		if err != nil {
			return ps, fmt.Errorf("incremental vacuum: %w", err)
		}
		ps.Reclaimed = ok
	}
	return ps, nil
}

// IncrementalVacuum returns a database's free pages to the file system
// when it was created with auto_vacuum=INCREMENTAL (false otherwise: the
// pages stay in the file for reuse), then checkpoints the WAL so the
// main file actually shrinks.
func IncrementalVacuum(db *sql.DB) (bool, error) {
	var mode int
	if err := db.QueryRow(`PRAGMA auto_vacuum`).Scan(&mode); err != nil {
		return false, err
	}
	if mode != 2 {
		return false, nil
	}
	// The pragma frees pages as it is stepped: drain it.
	rows, err := db.Query(`PRAGMA incremental_vacuum`)
	if err != nil {
		return false, err
	}
	for rows.Next() {
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return false, err
	}
	rows.Close()
	_, err = db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	return true, err
}

// AutoVacuum reports the archive's auto_vacuum mode (0 none, 1 full,
// 2 incremental).
func (s *Store) AutoVacuum() (int, error) {
	var mode int
	err := s.db.QueryRow(`PRAGMA auto_vacuum`).Scan(&mode)
	return mode, err
}

// OldestHour returns the start of the oldest archived hourly snapshot,
// across zones (zero when there is none).
func (s *Store) OldestHour() (time.Time, error) {
	var v sql.NullInt64
	if err := s.db.QueryRow(`SELECT MIN(from_ts) FROM snapshots WHERE kind = 'hour'`).Scan(&v); err != nil || !v.Valid {
		return time.Time{}, err
	}
	return time.Unix(v.Int64, 0).UTC(), nil
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

// BlockEvent is one append-only audit record of the blocking module
// (SPEC 13.1: time, object, mechanism, reason / linked finding, TTL).
type BlockEvent struct {
	ID        int64
	At        time.Time
	Zone      string
	Op        string // block | renew | unblock | expire
	Type      string
	Value     string
	Action    string
	Mechanism string
	RuleID    string
	Reason    string
	ExpiresAt time.Time // zero: permanent
	Actor     string
}

// AddBlockEvent appends an audit record. There is no update or delete.
func (s *Store) AddBlockEvent(e BlockEvent) error {
	var exp int64
	if !e.ExpiresAt.IsZero() {
		exp = e.ExpiresAt.Unix()
	}
	if e.At.IsZero() {
		e.At = time.Now()
	}
	_, err := s.db.Exec(`INSERT INTO block_events (at, zone, op, type, value, action, mechanism, rule_id, reason, expires_at, actor)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.At.Unix(), e.Zone, e.Op, e.Type, e.Value, e.Action, e.Mechanism, e.RuleID, e.Reason, exp, e.Actor)
	return err
}

func scanEvents(rows *sql.Rows) ([]BlockEvent, error) {
	defer rows.Close()
	var out []BlockEvent
	for rows.Next() {
		var e BlockEvent
		var at, exp int64
		if err := rows.Scan(&e.ID, &at, &e.Zone, &e.Op, &e.Type, &e.Value, &e.Action, &e.Mechanism, &e.RuleID, &e.Reason, &exp, &e.Actor); err != nil {
			return nil, err
		}
		e.At = time.Unix(at, 0).UTC()
		if exp > 0 {
			e.ExpiresAt = time.Unix(exp, 0).UTC()
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

const eventCols = `id, at, zone, op, type, value, action, mechanism, rule_id, reason, expires_at, actor`

// ActiveBlocks returns, per target, the latest event when it is a block
// or a renewal (a changed expiry) — i.e. what the audit log believes is
// currently blocked in a zone.
func (s *Store) ActiveBlocks(zone string) ([]BlockEvent, error) {
	rows, err := s.db.Query(`SELECT `+eventCols+` FROM block_events e
		WHERE zone = ? AND id = (SELECT MAX(id) FROM block_events WHERE zone = e.zone AND type = e.type AND value = e.value)
		AND op IN ('block', 'renew') ORDER BY type, value`, zone)
	if err != nil {
		return nil, err
	}
	return scanEvents(rows)
}

// BlockHistory returns a zone's audit log, oldest first.
func (s *Store) BlockHistory(zone string) ([]BlockEvent, error) {
	rows, err := s.db.Query(`SELECT `+eventCols+` FROM block_events WHERE zone = ? ORDER BY id`, zone)
	if err != nil {
		return nil, err
	}
	return scanEvents(rows)
}

// RuleBackup is one pre-change snapshot of a phase ruleset (SPEC 13.2).
type RuleBackup struct {
	ID      int64
	At      time.Time
	Zone    string
	Phase   string
	Version string
	Reason  string
	Data    string // JSON array of raw rules
	File    string
}

// AddRuleBackup stores a snapshot and returns its id.
func (s *Store) AddRuleBackup(b RuleBackup) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO rule_backups (at, zone, phase, version, reason, data, file) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		b.At.Unix(), b.Zone, b.Phase, b.Version, b.Reason, b.Data, b.File)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// RuleBackup loads one snapshot.
func (s *Store) RuleBackup(id int64) (RuleBackup, bool, error) {
	var b RuleBackup
	var at int64
	err := s.db.QueryRow(`SELECT id, at, zone, phase, version, reason, data, file FROM rule_backups WHERE id = ?`, id).
		Scan(&b.ID, &at, &b.Zone, &b.Phase, &b.Version, &b.Reason, &b.Data, &b.File)
	if errors.Is(err, sql.ErrNoRows) {
		return b, false, nil
	}
	b.At = time.Unix(at, 0).UTC()
	return b, err == nil, err
}

// RuleBackups lists a zone's snapshots, newest first (data omitted).
func (s *Store) RuleBackups(zone, phase string, limit int) ([]RuleBackup, error) {
	rows, err := s.db.Query(`SELECT id, at, zone, phase, version, reason, file FROM rule_backups
		WHERE zone = ? AND (? = '' OR phase = ?) ORDER BY id DESC LIMIT ?`, zone, phase, phase, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RuleBackup
	for rows.Next() {
		var b RuleBackup
		var at int64
		if err := rows.Scan(&b.ID, &at, &b.Zone, &b.Phase, &b.Version, &b.Reason, &b.File); err != nil {
			return nil, err
		}
		b.At = time.Unix(at, 0).UTC()
		out = append(out, b)
	}
	return out, rows.Err()
}

// RuleChange is one append-only execution record (SPEC 13.2).
type RuleChange struct {
	ID       int64
	At       time.Time
	Zone     string
	Phase    string
	Op       string
	Rule     string
	Before   string
	After    string
	BackupID int64
	Verified bool
	Detail   string
	Actor    string
}

// AddRuleChange appends an execution record. There is no update.
func (s *Store) AddRuleChange(c RuleChange) error {
	v := 0
	if c.Verified {
		v = 1
	}
	_, err := s.db.Exec(`INSERT INTO rule_changes (at, zone, phase, op, rule, before, after, backup_id, verified, detail, actor)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.At.Unix(), c.Zone, c.Phase, c.Op, c.Rule, c.Before, c.After, c.BackupID, v, c.Detail, c.Actor)
	return err
}

// RuleChanges returns a zone's execution log, newest first.
func (s *Store) RuleChanges(zone string, limit int) ([]RuleChange, error) {
	rows, err := s.db.Query(`SELECT id, at, zone, phase, op, rule, before, after, backup_id, verified, detail, actor
		FROM rule_changes WHERE zone = ? ORDER BY id DESC LIMIT ?`, zone, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RuleChange
	for rows.Next() {
		var c RuleChange
		var at int64
		var v int
		if err := rows.Scan(&c.ID, &at, &c.Zone, &c.Phase, &c.Op, &c.Rule, &c.Before, &c.After, &c.BackupID, &v, &c.Detail, &c.Actor); err != nil {
			return nil, err
		}
		c.At, c.Verified = time.Unix(at, 0).UTC(), v == 1
		out = append(out, c)
	}
	return out, rows.Err()
}

// PutCalibrationDay stores (or replaces) one calibration day.
func (s *Store) PutCalibrationDay(zone string, date time.Time, data []byte) error {
	_, err := s.db.Exec(`INSERT INTO calibration_days (zone, date, data) VALUES (?, ?, ?)
		ON CONFLICT (zone, date) DO UPDATE SET data = excluded.data`, zone, date.UTC().Unix(), string(data))
	return err
}

// CalibrationDays returns the newest n calibration days, newest first.
func (s *Store) CalibrationDays(zone string, n int) ([][]byte, error) {
	rows, err := s.db.Query(`SELECT data FROM calibration_days WHERE zone = ? ORDER BY date DESC LIMIT ?`, zone, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][]byte
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		out = append(out, []byte(d))
	}
	return out, rows.Err()
}

// Window is an archived hourly snapshot with its timing.
type Window struct {
	From, To time.Time
	SavedAt  time.Time
	Snapshot
}

// LatestHour returns the newest hourly snapshot of a zone.
func (s *Store) LatestHour(zone string) (Window, bool, error) {
	var from, to, saved int64
	var raw string
	err := s.db.QueryRow(`SELECT from_ts, to_ts, saved_at, data FROM snapshots WHERE zone = ? AND kind = 'hour'
		ORDER BY from_ts DESC LIMIT 1`, zone).Scan(&from, &to, &saved, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return Window{}, false, nil
	}
	if err != nil {
		return Window{}, false, err
	}
	w := Window{From: time.Unix(from, 0).UTC(), To: time.Unix(to, 0).UTC(), SavedAt: time.Unix(saved, 0).UTC()}
	if err := json.Unmarshal([]byte(raw), &w.Snapshot); err != nil {
		return Window{}, false, err
	}
	return w, true, nil
}

// HourAt returns the hourly snapshot starting at from, if archived.
func (s *Store) HourAt(zone string, from time.Time) (Window, bool, error) {
	var to, saved int64
	var raw string
	err := s.db.QueryRow(`SELECT to_ts, saved_at, data FROM snapshots WHERE zone = ? AND kind = 'hour' AND from_ts = ?`,
		zone, from.Unix()).Scan(&to, &saved, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return Window{}, false, nil
	}
	if err != nil {
		return Window{}, false, err
	}
	w := Window{From: from.UTC(), To: time.Unix(to, 0).UTC(), SavedAt: time.Unix(saved, 0).UTC()}
	if err := json.Unmarshal([]byte(raw), &w.Snapshot); err != nil {
		return Window{}, false, err
	}
	return w, true, nil
}

// SameHourSnapshots is SameHour with the full snapshots (breakdowns
// included), for per-entry baselines.
func (s *Store) SameHourSnapshots(zone string, from, to time.Time, days int) ([]Snapshot, error) {
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
	rows, err := s.db.Query(q, append([]any{zone, length}, starts...)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Snapshot
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var snap Snapshot
		if err := json.Unmarshal([]byte(raw), &snap); err != nil {
			return nil, err
		}
		out = append(out, snap)
	}
	return out, rows.Err()
}

// HourSnapshot is one archived hour with its breakdowns.
type HourSnapshot struct {
	From, To time.Time
	Snapshot
}

// HourSnapshots returns the archived hourly snapshots with windows
// starting in [from, to), oldest first.
func (s *Store) HourSnapshots(zone string, from, to time.Time) ([]HourSnapshot, error) {
	rows, err := s.db.Query(`SELECT from_ts, to_ts, data FROM snapshots
		WHERE zone = ? AND kind = 'hour' AND from_ts >= ? AND from_ts < ? ORDER BY from_ts`, zone, from.Unix(), to.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HourSnapshot
	for rows.Next() {
		var f, t int64
		var raw string
		if err := rows.Scan(&f, &t, &raw); err != nil {
			return nil, err
		}
		h := HourSnapshot{From: time.Unix(f, 0).UTC(), To: time.Unix(t, 0).UTC()}
		if err := json.Unmarshal([]byte(raw), &h.Snapshot); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// HourPoint is one archived hour's headline numbers (no breakdowns).
type HourPoint struct {
	From                      time.Time
	Total, Dynamic, Origin5xx int64
}

// HourSeries returns the hourly headline numbers with windows starting
// in [from, to), oldest first.
func (s *Store) HourSeries(zone string, from, to time.Time) ([]HourPoint, error) {
	rows, err := s.db.Query(`SELECT from_ts, total, dynamic, origin_5xx FROM snapshots
		WHERE zone = ? AND kind = 'hour' AND from_ts >= ? AND from_ts < ? ORDER BY from_ts`, zone, from.Unix(), to.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HourPoint
	for rows.Next() {
		var p HourPoint
		var ts int64
		if err := rows.Scan(&ts, &p.Total, &p.Dynamic, &p.Origin5xx); err != nil {
			return nil, err
		}
		p.From = time.Unix(ts, 0).UTC()
		out = append(out, p)
	}
	return out, rows.Err()
}

// FacesSince returns faces of one dim first seen at or after since,
// newest first.
func (s *Store) FacesSince(zone, dim string, since time.Time, limit int) ([]FaceRecord, error) {
	rows, err := s.db.Query(`SELECT name, first_seen, last_seen, max_count FROM faces
		WHERE zone = ? AND dim = ? AND first_seen >= ? ORDER BY first_seen DESC, max_count DESC LIMIT ?`,
		zone, dim, since.Unix(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FaceRecord
	for rows.Next() {
		var f FaceRecord
		var first, last int64
		if err := rows.Scan(&f.Name, &first, &last, &f.MaxCount); err != nil {
			return nil, err
		}
		f.FirstSeen, f.LastSeen = time.Unix(first, 0).UTC(), time.Unix(last, 0).UTC()
		out = append(out, f)
	}
	return out, rows.Err()
}

// OldestFace returns when a dim was first recorded at all (zero if never)
// — the path dim only exists since v1.3.
func (s *Store) OldestFace(zone, dim string) (time.Time, error) {
	var v sql.NullInt64
	err := s.db.QueryRow(`SELECT MIN(first_seen) FROM faces WHERE zone = ? AND dim = ?`, zone, dim).Scan(&v)
	if err != nil || !v.Valid {
		return time.Time{}, err
	}
	return time.Unix(v.Int64, 0).UTC(), nil
}

// AlertRecord is an archived decision with its findings.
type AlertRecord struct {
	Alert
	Findings []analyze.Finding
	SentAt   time.Time
}

// AlertsDetailed is Alerts with findings, newest first.
func (s *Store) AlertsDetailed(zone string, from, to time.Time, limit int) ([]AlertRecord, error) {
	rows, err := s.db.Query(`SELECT window_to, decision, fingerprint, findings, sent_at FROM alerts
		WHERE zone = ? AND window_to >= ? AND window_to < ? ORDER BY window_to DESC, id DESC LIMIT ?`,
		zone, from.Unix(), to.Unix(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AlertRecord
	for rows.Next() {
		var a AlertRecord
		var ts, sent int64
		var raw string
		if err := rows.Scan(&ts, &a.Decision, &a.Fingerprint, &raw, &sent); err != nil {
			return nil, err
		}
		a.WindowTo, a.SentAt = time.Unix(ts, 0).UTC(), time.Unix(sent, 0).UTC()
		_ = json.Unmarshal([]byte(raw), &a.Findings)
		out = append(out, a)
	}
	return out, rows.Err()
}

// BlockEventsBetween returns a zone's block audit events in [from, to), newest first.
func (s *Store) BlockEventsBetween(zone string, from, to time.Time, limit int) ([]BlockEvent, error) {
	rows, err := s.db.Query(`SELECT `+eventCols+` FROM block_events WHERE zone = ? AND at >= ? AND at < ?
		ORDER BY id DESC LIMIT ?`, zone, from.Unix(), to.Unix(), limit)
	if err != nil {
		return nil, err
	}
	return scanEvents(rows)
}

// BlockEventByID returns one audit record.
func (s *Store) BlockEventByID(id int64) (BlockEvent, bool, error) {
	rows, err := s.db.Query(`SELECT `+eventCols+` FROM block_events WHERE id = ?`, id)
	if err != nil {
		return BlockEvent{}, false, err
	}
	evs, err := scanEvents(rows)
	if err != nil || len(evs) == 0 {
		return BlockEvent{}, false, err
	}
	return evs[0], true, nil
}

// LatestBlockEvent returns the newest record for one target.
func (s *Store) LatestBlockEvent(zone, typ, value string) (BlockEvent, bool, error) {
	return s.blockEventBefore(zone, typ, value, 1<<62)
}

// PrevBlockEvent returns the record for the same target just before id.
func (s *Store) PrevBlockEvent(zone, typ, value string, id int64) (BlockEvent, bool, error) {
	return s.blockEventBefore(zone, typ, value, id)
}

func (s *Store) blockEventBefore(zone, typ, value string, id int64) (BlockEvent, bool, error) {
	rows, err := s.db.Query(`SELECT `+eventCols+` FROM block_events WHERE zone = ? AND type = ? AND value = ? AND id < ?
		ORDER BY id DESC LIMIT 1`, zone, typ, value, id)
	if err != nil {
		return BlockEvent{}, false, err
	}
	evs, err := scanEvents(rows)
	if err != nil || len(evs) == 0 {
		return BlockEvent{}, false, err
	}
	return evs[0], true, nil
}

// PutASNNames records registered ASN names (clientASNDescription).
func (s *Store) PutASNNames(names map[int]string, at time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT INTO asn_names (asn, name, seen_at) VALUES (?, ?, ?)
		ON CONFLICT (asn) DO UPDATE SET name = excluded.name, seen_at = excluded.seen_at`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for asn, name := range names {
		if asn <= 0 || strings.TrimSpace(name) == "" {
			continue
		}
		if _, err := stmt.Exec(asn, strings.TrimSpace(name), at.Unix()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ASNNames returns every recorded registered ASN name.
func (s *Store) ASNNames() (map[int]string, error) {
	rows, err := s.db.Query(`SELECT asn, name FROM asn_names`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int]string{}
	for rows.Next() {
		var a int
		var n string
		if err := rows.Scan(&a, &n); err != nil {
			return nil, err
		}
		out[a] = n
	}
	return out, rows.Err()
}
