package console

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/playwjj/flarehound/internal/store"
)

// The console keeps its accounts in its own SQLite file, apart from the
// traffic archive: the watch process never opens it.
//
// Local accounts are the identity anchor (docs/web-console-revision.md
// §5.2). external_identities is reserved from day one so that third-party
// sign-in (v1.5) binds to an existing account without migrating users.
const dbSchema = `
CREATE TABLE IF NOT EXISTS users (
	id             INTEGER PRIMARY KEY AUTOINCREMENT,
	username       TEXT    NOT NULL UNIQUE COLLATE NOCASE,
	email          TEXT    NOT NULL DEFAULT '',
	pw_hash        TEXT    NOT NULL,
	role           TEXT    NOT NULL,
	disabled       INTEGER NOT NULL DEFAULT 0,
	must_change    INTEGER NOT NULL DEFAULT 0,
	totp_secret    TEXT    NOT NULL DEFAULT '',
	totp_enabled   INTEGER NOT NULL DEFAULT 0,
	totp_last_step INTEGER NOT NULL DEFAULT 0,
	failed         INTEGER NOT NULL DEFAULT 0,
	locked_until   INTEGER NOT NULL DEFAULT 0,
	created_at     INTEGER NOT NULL,
	updated_at     INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS external_identities (
	provider   TEXT    NOT NULL,
	subject    TEXT    NOT NULL,
	user_id    INTEGER NOT NULL REFERENCES users(id),
	created_at INTEGER NOT NULL,
	PRIMARY KEY (provider, subject)
);
CREATE TABLE IF NOT EXISTS sessions (
	token_hash TEXT    PRIMARY KEY,
	user_id    INTEGER NOT NULL REFERENCES users(id),
	csrf       TEXT    NOT NULL,
	mfa_ok     INTEGER NOT NULL,
	created_at INTEGER NOT NULL,
	last_seen  INTEGER NOT NULL,
	expires_at INTEGER NOT NULL,
	stepup_at  INTEGER NOT NULL DEFAULT 0,
	ip         TEXT    NOT NULL,
	ua         TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions (user_id);
CREATE TABLE IF NOT EXISTS invites (
	token_hash TEXT    PRIMARY KEY,
	role       TEXT    NOT NULL,
	created_by INTEGER NOT NULL,
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL,
	used_at    INTEGER NOT NULL DEFAULT 0,
	used_by    INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS password_resets (
	token_hash TEXT    PRIMARY KEY,
	user_id    INTEGER NOT NULL REFERENCES users(id),
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL,
	used_at    INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS oauth_states (
	state_hash TEXT    PRIMARY KEY,
	provider   TEXT    NOT NULL,
	intent     TEXT    NOT NULL, -- login | link
	user_id    INTEGER NOT NULL, -- link: the signed-in account
	verifier   TEXT    NOT NULL, -- PKCE
	nonce      TEXT    NOT NULL,
	next       TEXT    NOT NULL,
	expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS effects (
	zone       TEXT    NOT NULL,
	event_id   INTEGER NOT NULL, -- archive block_events.id
	computed   INTEGER NOT NULL,
	data       TEXT    NOT NULL, -- Effect as JSON
	PRIMARY KEY (zone, event_id)
);
CREATE TABLE IF NOT EXISTS snapshots (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	token_hash TEXT    NOT NULL UNIQUE,
	created_by INTEGER NOT NULL,
	creator    TEXT    NOT NULL,
	title      TEXT    NOT NULL,
	zone       TEXT    NOT NULL,
	html       TEXT    NOT NULL,
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL,
	revoked    INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS flags (
	name  TEXT    PRIMARY KEY,
	value TEXT    NOT NULL,
	at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
	id     INTEGER PRIMARY KEY AUTOINCREMENT,
	at     INTEGER NOT NULL,
	actor  TEXT    NOT NULL,
	ip     TEXT    NOT NULL,
	action TEXT    NOT NULL,
	target TEXT    NOT NULL,
	detail TEXT    NOT NULL
);
`

// Roles.
const (
	RoleAdmin  = "admin"
	RoleViewer = "viewer"
)

// Login throttling: after maxFailures consecutive failures an account is
// locked for lockFor; the per-IP limiter in the server adds a second net.
const (
	maxFailures = 5
	lockFor     = 15 * time.Minute
)

// DB is the console's account store.
type DB struct {
	db  *sql.DB
	now func() time.Time
}

// OpenDB opens (creating if needed) the console database.
func OpenDB(path string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	// auto_vacuum first: it takes on a new file only (v1.18+); an older
	// console.db keeps its mode.
	dsn := "file:" + path + "?_pragma=auto_vacuum(INCREMENTAL)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(dbSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("console schema: %w", err)
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("console schema: %w", err)
	}
	_ = os.Chmod(path, 0o600) // password hashes and TOTP secrets
	return &DB{db: db, now: time.Now}, nil
}

func (d *DB) Close() error { return d.db.Close() }

// User is one console account.
type User struct {
	ID           int64
	Username     string
	Email        string
	PWHash       string
	Role         string
	Disabled     bool
	MustChange   bool
	TOTPSecret   string
	TOTPEnabled  bool
	TOTPLastStep int64
	Failed       int
	LockedUntil  time.Time
	CreatedAt    time.Time
	Lang         string // preferred UI language: "en", "zh" or "" (console default)
}

func (u User) Admin() bool { return u.Role == RoleAdmin }

var usernameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{1,63}$`)

// ValidUsername reports whether name is an acceptable username.
func ValidUsername(name string) bool { return usernameRE.MatchString(name) }

// ValidRole reports whether r is a known role.
func ValidRole(r string) bool { return r == RoleAdmin || r == RoleViewer }

var ErrExists = errors.New("username is taken")

const userCols = `id, username, email, pw_hash, role, disabled, must_change, totp_secret, totp_enabled, totp_last_step, failed, locked_until, created_at, lang`

func scanUser(sc interface{ Scan(...any) error }) (User, error) {
	var u User
	var dis, mc, te int
	var locked, created int64
	err := sc.Scan(&u.ID, &u.Username, &u.Email, &u.PWHash, &u.Role, &dis, &mc, &u.TOTPSecret, &te, &u.TOTPLastStep, &u.Failed, &locked, &created, &u.Lang)
	u.Disabled, u.MustChange, u.TOTPEnabled = dis == 1, mc == 1, te == 1
	if locked > 0 {
		u.LockedUntil = time.Unix(locked, 0)
	}
	u.CreatedAt = time.Unix(created, 0)
	return u, err
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// CreateUser adds an account. The password must already satisfy the policy.
func (d *DB) CreateUser(username, email, password, role string, mustChange bool) (User, error) {
	if !ValidUsername(username) {
		return User{}, errors.New("username: 2–64 characters, letters, digits and . _ @ -")
	}
	if !ValidRole(role) {
		return User{}, fmt.Errorf("unknown role %q", role)
	}
	if err := CheckPasswordPolicy(password); err != nil {
		return User{}, err
	}
	hash, err := HashPassword(password)
	if err != nil {
		return User{}, err
	}
	now := d.now().Unix()
	res, err := d.db.Exec(`INSERT INTO users (username, email, pw_hash, role, must_change, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		username, strings.TrimSpace(email), hash, role, b2i(mustChange), now, now)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return User{}, ErrExists
		}
		return User{}, err
	}
	id, _ := res.LastInsertId()
	return d.UserByID(id)
}

func (d *DB) UserByID(id int64) (User, error) {
	return scanUser(d.db.QueryRow(`SELECT `+userCols+` FROM users WHERE id = ?`, id))
}

// UserByName looks up by username (case-insensitive).
func (d *DB) UserByName(name string) (User, bool, error) {
	u, err := scanUser(d.db.QueryRow(`SELECT `+userCols+` FROM users WHERE username = ?`, name))
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, false, nil
	}
	return u, err == nil, err
}

// UserByIdentity matches a proxy-asserted identity to a local account by
// username or e-mail (case-insensitive).
func (d *DB) UserByIdentity(id string) (User, bool, error) {
	u, err := scanUser(d.db.QueryRow(`SELECT `+userCols+` FROM users WHERE username = ?1 OR (email != '' AND lower(email) = lower(?1)) LIMIT 1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, false, nil
	}
	return u, err == nil, err
}

func (d *DB) Users() ([]User, error) {
	rows, err := d.db.Query(`SELECT ` + userCols + ` FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (d *DB) CountUsers() (int, error) {
	var n int
	err := d.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// CountActiveAdmins counts enabled admins — the last one may not be
// demoted or disabled.
func (d *DB) CountActiveAdmins() (int, error) {
	var n int
	err := d.db.QueryRow(`SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = 0`).Scan(&n)
	return n, err
}

// SetPassword replaces a password and ends every session of the account
// except keepSession (the caller's own, when changing one's own password).
func (d *DB) SetPassword(id int64, password string, mustChange bool, keepSession string) error {
	if err := CheckPasswordPolicy(password); err != nil {
		return err
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	if _, err := d.db.Exec(`UPDATE users SET pw_hash = ?, must_change = ?, failed = 0, locked_until = 0, updated_at = ? WHERE id = ?`,
		hash, b2i(mustChange), d.now().Unix(), id); err != nil {
		return err
	}
	_, err = d.db.Exec(`DELETE FROM sessions WHERE user_id = ? AND token_hash != ?`, id, hashToken(keepSession))
	return err
}

func (d *DB) SetRole(id int64, role string) error {
	if !ValidRole(role) {
		return fmt.Errorf("unknown role %q", role)
	}
	_, err := d.db.Exec(`UPDATE users SET role = ?, updated_at = ? WHERE id = ?`, role, d.now().Unix(), id)
	return err
}

// SetDisabled disables (and signs out) or re-enables an account.
func (d *DB) SetDisabled(id int64, disabled bool) error {
	if _, err := d.db.Exec(`UPDATE users SET disabled = ?, updated_at = ? WHERE id = ?`, b2i(disabled), d.now().Unix(), id); err != nil {
		return err
	}
	if disabled {
		return d.EndUserSessions(id, "")
	}
	return nil
}

// SetTOTP stores (enabled=false: pending enrolment) or clears a secret.
func (d *DB) SetTOTP(id int64, secret string, enabled bool, lastStep int64) error {
	_, err := d.db.Exec(`UPDATE users SET totp_secret = ?, totp_enabled = ?, totp_last_step = ?, updated_at = ? WHERE id = ?`,
		secret, b2i(enabled), lastStep, d.now().Unix(), id)
	return err
}

// UseTOTPStep records the last accepted step (replay protection).
// It only moves forward; a false result means the step was already used.
func (d *DB) UseTOTPStep(id, step int64) (bool, error) {
	res, err := d.db.Exec(`UPDATE users SET totp_last_step = ? WHERE id = ? AND totp_last_step < ?`, step, id, step)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// LoginFailed counts a failure and locks the account after maxFailures.
func (d *DB) LoginFailed(id int64) error {
	now := d.now()
	_, err := d.db.Exec(`UPDATE users SET failed = failed + 1,
		locked_until = CASE WHEN failed + 1 >= ? THEN ? ELSE locked_until END WHERE id = ?`,
		maxFailures, now.Add(lockFor).Unix(), id)
	return err
}

func (d *DB) LoginOK(id int64) error {
	_, err := d.db.Exec(`UPDATE users SET failed = 0, locked_until = 0 WHERE id = ?`, id)
	return err
}

// Unlock clears a lockout (admin action).
func (d *DB) Unlock(id int64) error { return d.LoginOK(id) }

// --- sessions ---

// Session is a server-side, revocable login session. Only the SHA-256
// of the cookie token is stored.
type Session struct {
	Token     string // cookie value; set only when created
	Hash      string
	UserID    int64
	CSRF      string
	MFAOK     bool // false: password accepted, second factor pending
	CreatedAt time.Time
	LastSeen  time.Time
	ExpiresAt time.Time
	StepUpAt  time.Time
	IP, UA    string
}

func randToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashToken(t string) string {
	if t == "" {
		return ""
	}
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

// CreateSession starts a session that lives for ttl since its last use.
func (d *DB) CreateSession(userID int64, mfaOK bool, ttl time.Duration, ip, ua string) (Session, error) {
	now := d.now()
	s := Session{Token: randToken(32), UserID: userID, CSRF: randToken(24), MFAOK: mfaOK,
		CreatedAt: now, LastSeen: now, ExpiresAt: now.Add(ttl), IP: ip, UA: truncate(ua, 200)}
	s.Hash = hashToken(s.Token)
	_, err := d.db.Exec(`INSERT INTO sessions (token_hash, user_id, csrf, mfa_ok, created_at, last_seen, expires_at, ip, ua)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, s.Hash, userID, s.CSRF, b2i(mfaOK), now.Unix(), now.Unix(), s.ExpiresAt.Unix(), ip, s.UA)
	return s, err
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

const sessCols = `token_hash, user_id, csrf, mfa_ok, created_at, last_seen, expires_at, stepup_at, ip, ua`

func scanSession(sc interface{ Scan(...any) error }) (Session, error) {
	var s Session
	var mfa int
	var c, l, e, st int64
	err := sc.Scan(&s.Hash, &s.UserID, &s.CSRF, &mfa, &c, &l, &e, &st, &s.IP, &s.UA)
	s.MFAOK = mfa == 1
	s.CreatedAt, s.LastSeen, s.ExpiresAt = time.Unix(c, 0), time.Unix(l, 0), time.Unix(e, 0)
	if st > 0 {
		s.StepUpAt = time.Unix(st, 0)
	}
	return s, err
}

// SessionByToken returns a live session; expired ones are deleted.
func (d *DB) SessionByToken(token string) (Session, bool, error) {
	if token == "" {
		return Session{}, false, nil
	}
	s, err := scanSession(d.db.QueryRow(`SELECT `+sessCols+` FROM sessions WHERE token_hash = ?`, hashToken(token)))
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, false, nil
	}
	if err != nil {
		return Session{}, false, err
	}
	if !d.now().Before(s.ExpiresAt) {
		_, _ = d.db.Exec(`DELETE FROM sessions WHERE token_hash = ?`, s.Hash)
		return Session{}, false, nil
	}
	s.Token = token
	return s, true, nil
}

// TouchSession slides the idle expiry, at most once a minute, and
// reports whether it did (the caller then refreshes the cookie). Sessions
// still waiting for their second factor keep their short fixed lifetime.
func (d *DB) TouchSession(s Session, ttl time.Duration) (bool, error) {
	now := d.now()
	if !s.MFAOK || now.Sub(s.LastSeen) < time.Minute {
		return false, nil
	}
	_, err := d.db.Exec(`UPDATE sessions SET last_seen = ?, expires_at = ? WHERE token_hash = ?`, now.Unix(), now.Add(ttl).Unix(), s.Hash)
	return err == nil, err
}

// PromoteSession marks the second factor as passed and rotates the token
// (a pre-MFA token must not become a full session).
func (d *DB) PromoteSession(s Session, ttl time.Duration) (Session, error) {
	if _, err := d.db.Exec(`DELETE FROM sessions WHERE token_hash = ?`, s.Hash); err != nil {
		return Session{}, err
	}
	ns, err := d.CreateSession(s.UserID, true, ttl, s.IP, s.UA)
	if err != nil {
		return Session{}, err
	}
	_, err = d.db.Exec(`UPDATE sessions SET stepup_at = ? WHERE token_hash = ?`, d.now().Unix(), ns.Hash)
	ns.StepUpAt = d.now()
	return ns, err
}

// MarkStepUp records a fresh second-factor check on a session.
func (d *DB) MarkStepUp(hash string) error {
	_, err := d.db.Exec(`UPDATE sessions SET stepup_at = ? WHERE token_hash = ?`, d.now().Unix(), hash)
	return err
}

func (d *DB) EndSession(token string) error {
	_, err := d.db.Exec(`DELETE FROM sessions WHERE token_hash = ?`, hashToken(token))
	return err
}

// EndSessionByHash ends one session (from a session list).
func (d *DB) EndSessionByHash(userID int64, hash string) error {
	_, err := d.db.Exec(`DELETE FROM sessions WHERE user_id = ? AND token_hash = ?`, userID, hash)
	return err
}

// EndUserSessions signs an account out everywhere except keepToken.
func (d *DB) EndUserSessions(userID int64, keepToken string) error {
	_, err := d.db.Exec(`DELETE FROM sessions WHERE user_id = ? AND token_hash != ?`, userID, hashToken(keepToken))
	return err
}

func (d *DB) UserSessions(userID int64) ([]Session, error) {
	rows, err := d.db.Query(`SELECT `+sessCols+` FROM sessions WHERE user_id = ? AND expires_at > ? ORDER BY last_seen DESC`,
		userID, d.now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		s, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// PruneSessions drops expired sessions and invites.
func (d *DB) PruneSessions() error {
	now := d.now().Unix()
	if _, err := d.db.Exec(`DELETE FROM sessions WHERE expires_at <= ?`, now); err != nil {
		return err
	}
	_, err := d.db.Exec(`DELETE FROM invites WHERE used_at = 0 AND expires_at <= ?`, now-7*24*3600)
	return err
}

// --- invites ---

// Invite is a single-use sign-up link issued by an admin.
type Invite struct {
	Hash      string
	Role      string
	CreatedBy int64
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    time.Time
}

// CreateInvite returns the token to put in the link.
func (d *DB) CreateInvite(role string, by int64, ttl time.Duration) (string, error) {
	if !ValidRole(role) {
		return "", fmt.Errorf("unknown role %q", role)
	}
	t := randToken(24)
	now := d.now()
	_, err := d.db.Exec(`INSERT INTO invites (token_hash, role, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`,
		hashToken(t), role, by, now.Unix(), now.Add(ttl).Unix())
	return t, err
}

// InviteByToken returns a usable (unused, unexpired) invite.
func (d *DB) InviteByToken(t string) (Invite, bool, error) {
	var inv Invite
	var c, e, u int64
	err := d.db.QueryRow(`SELECT token_hash, role, created_by, created_at, expires_at, used_at FROM invites WHERE token_hash = ?`,
		hashToken(t)).Scan(&inv.Hash, &inv.Role, &inv.CreatedBy, &c, &e, &u)
	if errors.Is(err, sql.ErrNoRows) {
		return inv, false, nil
	}
	if err != nil {
		return inv, false, err
	}
	inv.CreatedAt, inv.ExpiresAt = time.Unix(c, 0), time.Unix(e, 0)
	if u > 0 || !d.now().Before(inv.ExpiresAt) {
		return inv, false, nil
	}
	return inv, true, nil
}

// AcceptInvite atomically consumes an invite and creates the account.
func (d *DB) AcceptInvite(t, username, email, password string) (User, error) {
	inv, ok, err := d.InviteByToken(t)
	if err != nil {
		return User{}, err
	}
	if !ok {
		return User{}, errors.New("this invitation link is invalid, used or expired")
	}
	res, err := d.db.Exec(`UPDATE invites SET used_at = ? WHERE token_hash = ? AND used_at = 0`, d.now().Unix(), inv.Hash)
	if err != nil {
		return User{}, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return User{}, errors.New("this invitation link was already used")
	}
	u, err := d.CreateUser(username, email, password, inv.Role, false)
	if err != nil {
		// Give the link back: the name was taken or the password too short.
		_, _ = d.db.Exec(`UPDATE invites SET used_at = 0 WHERE token_hash = ?`, inv.Hash)
		return User{}, err
	}
	_, _ = d.db.Exec(`UPDATE invites SET used_by = ? WHERE token_hash = ?`, u.ID, inv.Hash)
	return u, nil
}

// PendingInvites lists unused, unexpired invites.
func (d *DB) PendingInvites() ([]Invite, error) {
	rows, err := d.db.Query(`SELECT token_hash, role, created_by, created_at, expires_at FROM invites
		WHERE used_at = 0 AND expires_at > ? ORDER BY created_at DESC`, d.now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Invite
	for rows.Next() {
		var inv Invite
		var c, e int64
		if err := rows.Scan(&inv.Hash, &inv.Role, &inv.CreatedBy, &c, &e); err != nil {
			return nil, err
		}
		inv.CreatedAt, inv.ExpiresAt = time.Unix(c, 0), time.Unix(e, 0)
		out = append(out, inv)
	}
	return out, rows.Err()
}

// RevokeInvite expires a pending invite.
func (d *DB) RevokeInvite(hash string) error {
	_, err := d.db.Exec(`UPDATE invites SET expires_at = ? WHERE token_hash = ? AND used_at = 0`, d.now().Unix(), hash)
	return err
}

// --- audit ---

// AuditEntry is one console account event (sign-ins, account changes).
// Traffic-side write operations (v1.4) go to the archive's block log.
type AuditEntry struct {
	At                                time.Time
	Actor, IP, Action, Target, Detail string
}

// Flag returns a console flag (a one-off choice an admin made, such as
// dismissing a hint).
func (d *DB) Flag(name string) (string, bool, error) {
	var v string
	err := d.db.QueryRow(`SELECT value FROM flags WHERE name = ?`, name).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return v, err == nil, err
}

// SetFlag records a console flag.
func (d *DB) SetFlag(name, value string) error {
	_, err := d.db.Exec(`INSERT INTO flags (name, value, at) VALUES (?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET value = excluded.value, at = excluded.at`, name, value, d.now().Unix())
	return err
}

func (d *DB) Audit(actor, ip, action, target, detail string) error {
	_, err := d.db.Exec(`INSERT INTO audit (at, actor, ip, action, target, detail) VALUES (?, ?, ?, ?, ?, ?)`,
		d.now().Unix(), actor, ip, action, target, truncate(detail, 500))
	return err
}

func (d *DB) AuditLog(limit int) ([]AuditEntry, error) {
	rows, err := d.db.Query(`SELECT at, actor, ip, action, target, detail FROM audit ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var at int64
		if err := rows.Scan(&at, &e.Actor, &e.IP, &e.Action, &e.Target, &e.Detail); err != nil {
			return nil, err
		}
		e.At = time.Unix(at, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}

// --- block effects (cache) ---

// PutEffect caches a computed before/after comparison.
func (d *DB) PutEffect(zone string, eventID int64, data []byte) error {
	_, err := d.db.Exec(`INSERT INTO effects (zone, event_id, computed, data) VALUES (?, ?, ?, ?)
		ON CONFLICT (zone, event_id) DO UPDATE SET computed = excluded.computed, data = excluded.data`,
		zone, eventID, d.now().Unix(), string(data))
	return err
}

// Effect returns a cached comparison.
func (d *DB) Effect(zone string, eventID int64) ([]byte, bool, error) {
	var raw string
	err := d.db.QueryRow(`SELECT data FROM effects WHERE zone = ? AND event_id = ?`, zone, eventID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	return []byte(raw), err == nil, err
}

// --- read-only snapshots ---

// Snapshot is a self-contained HTML export of one view, optionally
// shared through a signed, expiring, revocable link.
type Snapshot struct {
	ID        int64
	CreatedBy int64
	Creator   string
	Title     string
	Zone      string
	HTML      string
	CreatedAt time.Time
	ExpiresAt time.Time
	Revoked   bool
}

// Pruned reports a listed snapshot whose page was dropped by retention
// (in listings HTML is only a marker, never the page).
func (s Snapshot) Pruned() bool { return s.HTML == "" }

// Live reports whether the share link still works.
func (s Snapshot) Live(now time.Time) bool { return !s.Revoked && now.Before(s.ExpiresAt) }

// CreateSnapshot stores a snapshot and returns the link token.
func (d *DB) CreateSnapshot(by int64, creator, title, zone, html string, ttl time.Duration) (string, int64, error) {
	t := randToken(24)
	now := d.now()
	res, err := d.db.Exec(`INSERT INTO snapshots (token_hash, created_by, creator, title, zone, html, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		hashToken(t), by, creator, title, zone, html, now.Unix(), now.Add(ttl).Unix())
	if err != nil {
		return "", 0, err
	}
	id, _ := res.LastInsertId()
	return t, id, nil
}

const snapCols = `id, created_by, creator, title, zone, html, created_at, expires_at, revoked`

func scanSnapshot(sc interface{ Scan(...any) error }) (Snapshot, error) {
	var s Snapshot
	var c, e int64
	var r int
	err := sc.Scan(&s.ID, &s.CreatedBy, &s.Creator, &s.Title, &s.Zone, &s.HTML, &c, &e, &r)
	s.CreatedAt, s.ExpiresAt, s.Revoked = time.Unix(c, 0), time.Unix(e, 0), r == 1
	return s, err
}

// SnapshotByToken returns a snapshot whose link is still live.
func (d *DB) SnapshotByToken(t string) (Snapshot, bool, error) {
	s, err := scanSnapshot(d.db.QueryRow(`SELECT `+snapCols+` FROM snapshots WHERE token_hash = ?`, hashToken(t)))
	if errors.Is(err, sql.ErrNoRows) {
		return Snapshot{}, false, nil
	}
	if err != nil {
		return Snapshot{}, false, err
	}
	return s, s.Live(d.now()), nil
}

func (d *DB) SnapshotByID(id int64) (Snapshot, bool, error) {
	s, err := scanSnapshot(d.db.QueryRow(`SELECT `+snapCols+` FROM snapshots WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Snapshot{}, false, nil
	}
	return s, err == nil, err
}

// Snapshots lists snapshots (all when by is 0), newest first, without HTML.
func (d *DB) Snapshots(by int64, limit int) ([]Snapshot, error) {
	rows, err := d.db.Query(`SELECT id, created_by, creator, title, zone, CASE WHEN html = '' THEN '' ELSE 'x' END, created_at, expires_at, revoked FROM snapshots
		WHERE ? = 0 OR created_by = ? ORDER BY id DESC LIMIT ?`, by, by, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Snapshot
	for rows.Next() {
		s, err := scanSnapshot(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (d *DB) RevokeSnapshot(id int64) error {
	_, err := d.db.Exec(`UPDATE snapshots SET revoked = 1 WHERE id = ?`, id)
	return err
}

// addColumns adds missing columns to a table.
func addColumns(db *sql.DB, table string, cols map[string]string) error {
	have := map[string]bool{}
	rows, err := db.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return err
	}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return err
		}
		have[n] = true
	}
	rows.Close()
	for col, ddl := range cols {
		if !have[col] {
			if _, err := db.Exec(ddl); err != nil {
				return err
			}
		}
	}
	return nil
}

// migrate adds columns introduced after a table was first created.
func migrate(db *sql.DB) error {
	if err := addColumns(db, "users", map[string]string{
		"lang": `ALTER TABLE users ADD COLUMN lang TEXT NOT NULL DEFAULT ''`, // v1.8: preferred UI language
	}); err != nil {
		return err
	}
	cols := map[string]bool{}
	rows, err := db.Query(`SELECT name FROM pragma_table_info('external_identities')`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return err
		}
		cols[n] = true
	}
	rows.Close()
	for col, ddl := range map[string]string{
		"display":   `ALTER TABLE external_identities ADD COLUMN display TEXT NOT NULL DEFAULT ''`,
		"last_used": `ALTER TABLE external_identities ADD COLUMN last_used INTEGER NOT NULL DEFAULT 0`,
	} {
		if !cols[col] {
			if _, err := db.Exec(ddl); err != nil {
				return err
			}
		}
	}
	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS external_identities_user ON external_identities (user_id)`)
	return err
}

// --- external identities (v1.5) ---

// Identity is a third-party account linked to a local one.
type Identity struct {
	Provider  string
	Subject   string // the provider's stable user ID
	UserID    int64
	Display   string // e-mail or login, for people
	CreatedAt time.Time
	LastUsed  time.Time
}

var ErrIdentityTaken = errors.New("this account is already linked to another FlareHound user")

// LinkIdentity binds (provider, subject) to a local account.
func (d *DB) LinkIdentity(provider, subject string, userID int64, display string) error {
	var owner int64
	err := d.db.QueryRow(`SELECT user_id FROM external_identities WHERE provider = ? AND subject = ?`, provider, subject).Scan(&owner)
	switch {
	case err == nil && owner != userID:
		return ErrIdentityTaken
	case err == nil:
		_, err = d.db.Exec(`UPDATE external_identities SET display = ? WHERE provider = ? AND subject = ?`, display, provider, subject)
		return err
	case !errors.Is(err, sql.ErrNoRows):
		return err
	}
	_, err = d.db.Exec(`INSERT INTO external_identities (provider, subject, user_id, created_at, display) VALUES (?, ?, ?, ?, ?)`,
		provider, subject, userID, d.now().Unix(), truncate(display, 200))
	return err
}

// IdentityOwner finds the local account an identity is linked to.
func (d *DB) IdentityOwner(provider, subject string) (int64, bool, error) {
	var id int64
	err := d.db.QueryRow(`SELECT user_id FROM external_identities WHERE provider = ? AND subject = ?`, provider, subject).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	return id, err == nil, err
}

// TouchIdentity records a sign-in through an identity.
func (d *DB) TouchIdentity(provider, subject, display string) error {
	_, err := d.db.Exec(`UPDATE external_identities SET last_used = ?, display = CASE WHEN ? = '' THEN display ELSE ? END
		WHERE provider = ? AND subject = ?`, d.now().Unix(), display, truncate(display, 200), provider, subject)
	return err
}

// Identities lists an account's linked identities (all when userID is 0).
func (d *DB) Identities(userID int64) ([]Identity, error) {
	rows, err := d.db.Query(`SELECT provider, subject, user_id, display, created_at, last_used FROM external_identities
		WHERE ? = 0 OR user_id = ? ORDER BY provider, created_at`, userID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Identity
	for rows.Next() {
		var i Identity
		var c, l int64
		if err := rows.Scan(&i.Provider, &i.Subject, &i.UserID, &i.Display, &c, &l); err != nil {
			return nil, err
		}
		i.CreatedAt = time.Unix(c, 0)
		if l > 0 {
			i.LastUsed = time.Unix(l, 0)
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// UnlinkIdentity removes one of an account's identities (any account's when userID is 0).
func (d *DB) UnlinkIdentity(userID int64, provider, subject string) (bool, error) {
	res, err := d.db.Exec(`DELETE FROM external_identities WHERE provider = ? AND subject = ? AND (? = 0 OR user_id = ?)`,
		provider, subject, userID, userID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// --- OAuth flow state ---

// OAuthState is one pending authorization, single use.
type OAuthState struct {
	Provider, Intent string
	UserID           int64
	Verifier, Nonce  string
	Next             string
}

// PutOAuthState stores a pending authorization under the state value.
func (d *DB) PutOAuthState(state string, st OAuthState, ttl time.Duration) error {
	now := d.now().Unix()
	_, _ = d.db.Exec(`DELETE FROM oauth_states WHERE expires_at <= ?`, now)
	_, err := d.db.Exec(`INSERT INTO oauth_states (state_hash, provider, intent, user_id, verifier, nonce, next, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		hashToken(state), st.Provider, st.Intent, st.UserID, st.Verifier, st.Nonce, st.Next, d.now().Add(ttl).Unix())
	return err
}

// TakeOAuthState consumes a pending authorization (it cannot be replayed).
func (d *DB) TakeOAuthState(state string) (OAuthState, bool, error) {
	var st OAuthState
	var exp int64
	h := hashToken(state)
	err := d.db.QueryRow(`SELECT provider, intent, user_id, verifier, nonce, next, expires_at FROM oauth_states WHERE state_hash = ?`, h).
		Scan(&st.Provider, &st.Intent, &st.UserID, &st.Verifier, &st.Nonce, &st.Next, &exp)
	if errors.Is(err, sql.ErrNoRows) {
		return st, false, nil
	}
	if err != nil {
		return st, false, err
	}
	res, err := d.db.Exec(`DELETE FROM oauth_states WHERE state_hash = ?`, h)
	if err != nil {
		return st, false, err
	}
	if n, _ := res.RowsAffected(); n != 1 || d.now().Unix() >= exp {
		return st, false, nil
	}
	return st, true, nil
}

// Retention of console data (sessions and invites: see PruneSessions).
const (
	snapshotKeep = 30 * 24 * time.Hour  // a dead snapshot's page, after its link died
	auditKeep    = 365 * 24 * time.Hour // account audit log
	effectKeep   = 90 * 24 * time.Hour  // cached before/after comparisons
)

// PruneStats says what Prune removed.
type PruneStats struct {
	Sessions, Snapshots, Audit, Effects, OAuth int64
}

// Prune applies the retention rules. Snapshot rows stay (who shared what,
// when) but the page of a snapshot whose link expired or was revoked more
// than 30 days ago is dropped.
func (d *DB) Prune() (PruneStats, error) {
	var ps PruneStats
	now := d.now()
	exec := func(n *int64, q string, args ...any) error {
		res, err := d.db.Exec(q, args...)
		if err != nil {
			return err
		}
		*n, _ = res.RowsAffected()
		return nil
	}
	if err := exec(&ps.Sessions, `DELETE FROM sessions WHERE expires_at <= ?`, now.Unix()); err != nil {
		return ps, err
	}
	_, _ = d.db.Exec(`DELETE FROM invites WHERE used_at = 0 AND expires_at <= ?`, now.Add(-7*24*time.Hour).Unix())
	cut := now.Add(-snapshotKeep).Unix()
	if err := exec(&ps.Snapshots, `UPDATE snapshots SET html = '' WHERE html != '' AND created_at < ? AND (expires_at < ? OR revoked = 1)`, cut, cut); err != nil {
		return ps, err
	}
	if err := exec(&ps.Audit, `DELETE FROM audit WHERE at < ?`, now.Add(-auditKeep).Unix()); err != nil {
		return ps, err
	}
	if err := exec(&ps.Effects, `DELETE FROM effects WHERE computed < ?`, now.Add(-effectKeep).Unix()); err != nil {
		return ps, err
	}
	_, _ = d.db.Exec(`DELETE FROM password_resets WHERE expires_at <= ?`, now.Add(-7*24*time.Hour).Unix())
	if err := exec(&ps.OAuth, `DELETE FROM oauth_states WHERE expires_at <= ?`, now.Unix()); err != nil {
		return ps, err
	}
	// A big sweep (a year of audit at once, many dropped snapshot pages)
	// returns its space to the file system on files created with
	// auto_vacuum; routine hourly sweeps leave the pages for reuse.
	if ps.Sessions+ps.Snapshots+ps.Audit+ps.Effects+ps.OAuth >= store.VacuumAfter {
		if _, err := store.IncrementalVacuum(d.db); err != nil {
			return ps, fmt.Errorf("incremental vacuum: %w", err)
		}
	}
	return ps, nil
}

// --- password reset by e-mail (v1.7.2) ---

// LastResetAt returns when the account's newest reset link was issued.
func (d *DB) LastResetAt(userID int64) (time.Time, error) {
	var v sql.NullInt64
	err := d.db.QueryRow(`SELECT MAX(created_at) FROM password_resets WHERE user_id = ?`, userID).Scan(&v)
	if err != nil || !v.Valid {
		return time.Time{}, err
	}
	return time.Unix(v.Int64, 0), nil
}

// CreateReset issues a single-use reset token for an account.
func (d *DB) CreateReset(userID int64, ttl time.Duration) (string, error) {
	t := randToken(32)
	now := d.now()
	_, err := d.db.Exec(`INSERT INTO password_resets (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		hashToken(t), userID, now.Unix(), now.Add(ttl).Unix())
	return t, err
}

// ResetUser returns the account of a usable (unused, unexpired) reset token.
func (d *DB) ResetUser(t string) (User, bool, error) {
	var uid, exp, used int64
	err := d.db.QueryRow(`SELECT user_id, expires_at, used_at FROM password_resets WHERE token_hash = ?`, hashToken(t)).Scan(&uid, &exp, &used)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, false, nil
	}
	if err != nil {
		return User{}, false, err
	}
	if used > 0 || d.now().Unix() >= exp {
		return User{}, false, nil
	}
	u, err := d.UserByID(uid)
	if err != nil || u.Disabled {
		return User{}, false, err
	}
	return u, true, nil
}

var ErrResetInvalid = errors.New("this reset link is invalid, used or expired")

// UseReset consumes a token and sets the new password: every session of
// the account ends, a lockout is lifted, and its other reset links die.
// Two-factor sign-in is untouched.
func (d *DB) UseReset(t, password string) (User, error) {
	if err := CheckPasswordPolicy(password); err != nil {
		return User{}, err
	}
	u, ok, err := d.ResetUser(t)
	if err != nil {
		return User{}, err
	}
	if !ok {
		return User{}, ErrResetInvalid
	}
	now := d.now().Unix()
	res, err := d.db.Exec(`UPDATE password_resets SET used_at = ? WHERE token_hash = ? AND used_at = 0`, now, hashToken(t))
	if err != nil {
		return User{}, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return User{}, ErrResetInvalid
	}
	if err := d.SetPassword(u.ID, password, false, ""); err != nil {
		return User{}, err
	}
	_, _ = d.db.Exec(`UPDATE password_resets SET used_at = ? WHERE user_id = ? AND used_at = 0`, now, u.ID)
	return u, nil
}

// SetLang stores an account's preferred UI language ("" = console default).
func (d *DB) SetLang(id int64, l string) error {
	if l != "" && l != "en" && l != "zh" {
		return fmt.Errorf("unknown language %q", l)
	}
	_, err := d.db.Exec(`UPDATE users SET lang = ? WHERE id = ?`, l, id)
	return err
}
