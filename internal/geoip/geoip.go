// Package geoip says which country an IP address is registered or routed
// in ("IP location"), from a local MMDB country library (DB-IP's free
// dbip-country-lite by default, GeoLite2-Country works too).
//
// It is reference information for the person reading a list of
// addresses, never an input to detection, alerts or block plans. The
// result is looked up when shown and never stored: a newer library may
// place an address differently, and what is shown is always the current
// library's reading.
//
// A missing or unreadable library turns the feature off silently: every
// lookup returns "" and every address is shown as before. `doctor` is
// where the library's state is reported.
package geoip

import (
	"container/list"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"
)

// FileName is the library's file name in the data directory.
const FileName = "country.mmdb"

// BuiltinPath is where the Docker image keeps the library it ships with;
// a file in the data directory (or the configured path) takes precedence.
const BuiltinPath = "/usr/share/flarehound/" + FileName

// Attribution is the credit DB-IP's licence (CC BY 4.0) asks for.
const Attribution = "IP geolocation by DB-IP (db-ip.com)"

// recheck is how often the default library looks for a replaced file
// (`flarehound geoip update` in another process, a new mounted file).
const recheck = 10 * time.Minute

// cacheSize bounds the per-library lookup cache.
const cacheSize = 4096

// DB is one opened country library.
type DB struct {
	r    *maxminddb.Reader
	path string
	mod  time.Time
	size int64

	mu    sync.Mutex
	cache map[string]*list.Element
	order *list.List // front: most recently used
}

type cached struct{ key, code string }

type record struct {
	Country struct {
		ISO string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	// GeoLite2 places anycast and satellite ranges only by the
	// registered country.
	Registered struct {
		ISO string `maxminddb:"iso_code"`
	} `maxminddb:"registered_country"`
}

// probe is an address every country library places (Google's resolver).
var probe = netip.MustParseAddr("8.8.8.8")

// Open opens and checks a library: it must be a readable MMDB whose
// records carry a country code. A truncated or foreign file is an error.
func Open(path string) (*DB, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	r, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("not a readable MMDB file: %w", err)
	}
	if err := r.Verify(); err != nil {
		r.Close()
		return nil, fmt.Errorf("damaged MMDB file: %w", err)
	}
	var rec record
	if err := r.Lookup(probe).Decode(&rec); err != nil || rec.Country.ISO == "" && rec.Registered.ISO == "" {
		r.Close()
		if err == nil {
			err = errors.New("its records carry no country code")
		}
		return nil, fmt.Errorf("not a country library (%s): %w", r.Metadata.DatabaseType, err)
	}
	return &DB{r: r, path: path, mod: fi.ModTime(), size: fi.Size(), cache: map[string]*list.Element{}, order: list.New()}, nil
}

// Close releases the library.
func (d *DB) Close() error { return d.r.Close() }

// Path is the file the library was read from.
func (d *DB) Path() string { return d.path }

// Info describes an opened library, for `doctor`.
type Info struct {
	Type     string    // e.g. DBIP-Country-Lite, GeoLite2-Country
	Built    time.Time // the library's build date
	Networks int       // networks in the library
}

// Info walks the library once (a few tens of milliseconds).
func (d *DB) Info() Info {
	n := 0
	for range d.r.Networks() {
		n++
	}
	return Info{Type: d.r.Metadata.DatabaseType, Built: time.Unix(int64(d.r.Metadata.BuildEpoch), 0).UTC(), Networks: n}
}

// addr parses an address, or the network address of a CIDR ("" input or
// garbage: not ok).
func addr(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap(), true
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked().Addr().Unmap(), true
	}
	return netip.Addr{}, false
}

// Country returns the ISO 3166-1 alpha-2 code of an address or a CIDR
// (its first address), or "" when the library does not place it
// (private and reserved ranges, malformed input).
func (d *DB) Country(s string) string {
	if d == nil {
		return ""
	}
	d.mu.Lock()
	if e, ok := d.cache[s]; ok {
		d.order.MoveToFront(e)
		code := e.Value.(*cached).code
		d.mu.Unlock()
		return code
	}
	d.mu.Unlock()
	code := ""
	if a, ok := addr(s); ok {
		var rec record
		if err := d.r.Lookup(a).Decode(&rec); err == nil {
			code = rec.Country.ISO
			if code == "" {
				code = rec.Registered.ISO
			}
			code = strings.ToUpper(code)
		}
	}
	d.mu.Lock()
	if _, ok := d.cache[s]; !ok {
		d.cache[s] = d.order.PushFront(&cached{s, code})
		if d.order.Len() > cacheSize {
			old := d.order.Remove(d.order.Back()).(*cached)
			delete(d.cache, old.key)
		}
	}
	d.mu.Unlock()
	return code
}

// Name is a country's name in the language ("zh" or English); the code
// itself when the built-in table does not know it.
func Name(code, lang string) string {
	n, ok := names[strings.ToUpper(code)]
	if !ok {
		return code
	}
	if lang == "zh" && n[1] != "" {
		return n[1]
	}
	return n[0]
}

// Label is the plain-text form of a code: "IN · India", or in Chinese
// "印度 (IN)"; "" for "".
func Label(code, lang string) string {
	if code == "" {
		return ""
	}
	name := Name(code, lang)
	if name == code {
		return code
	}
	if lang == "zh" {
		return name + " (" + code + ")"
	}
	return code + " · " + name
}

// Candidates are the files tried, in order: the configured path alone
// when set, else the data directory's country.mmdb, then the one the
// Docker image ships.
func Candidates(configured, dataDir string) []string {
	if configured != "" {
		return []string{configured}
	}
	return []string{filepath.Join(dataDir, FileName), BuiltinPath}
}

// Status is what loading found.
type Status struct {
	Path string // the file in use, or the first candidate that exists
	DB   *DB    // nil: feature off
	Err  error  // why an existing file was not used
	// Tried lists every candidate (none existing: "not found").
	Tried []string
}

// Load opens the first candidate that exists. A candidate that exists
// but does not open stops the search (Err set): a broken file the
// operator put there should be reported, not silently skipped.
func Load(candidates []string) Status {
	st := Status{Tried: candidates}
	for _, p := range candidates {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		st.Path = p
		st.DB, st.Err = Open(p)
		return st
	}
	return st
}

// The process-wide library: each process (watch, console, CLI) opens the
// same file read-only on its own.
var std struct {
	sync.Mutex
	candidates []string
	db         *DB
	checked    time.Time
	on         bool // Setup was called
	fake       func(string) string
}

// Setup loads the process-wide library from the candidates and returns
// what it found. It never fails: without a library, lookups return "".
func Setup(candidates []string) Status {
	st := Load(candidates)
	std.Lock()
	defer std.Unlock()
	std.candidates, std.db, std.checked, std.on, std.fake = candidates, st.DB, time.Now(), true, nil
	return st
}

// Reset turns the process-wide library off (tests).
func Reset() {
	std.Lock()
	defer std.Unlock()
	std.candidates, std.db, std.on, std.fake = nil, nil, false, nil
}

// Use installs an opened library as the process-wide one (tests).
func Use(d *DB) {
	std.Lock()
	defer std.Unlock()
	std.candidates, std.db, std.checked, std.on, std.fake = nil, d, time.Now(), true, nil
}

// UseFunc replaces the process-wide lookup by a function (tests of the
// places that show IP locations, without a library file).
func UseFunc(f func(string) string) {
	std.Lock()
	defer std.Unlock()
	std.candidates, std.db, std.on, std.fake = nil, nil, f != nil, f
}

// current returns the process-wide library, picking up a replaced or
// newly placed file every few minutes. The replaced reader is left open
// (another goroutine may be reading it); a monthly update leaks one
// mapping at most.
func current() *DB {
	std.Lock()
	defer std.Unlock()
	if !std.on || len(std.candidates) == 0 || time.Since(std.checked) < recheck {
		return std.db
	}
	std.checked = time.Now()
	for _, p := range std.candidates {
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		if d := std.db; d != nil && d.path == p && d.mod.Equal(fi.ModTime()) && d.size == fi.Size() {
			return d
		}
		if d, err := Open(p); err == nil {
			std.db = d
		}
		return std.db
	}
	return std.db
}

func fake() func(string) string {
	std.Lock()
	defer std.Unlock()
	return std.fake
}

// Enabled reports whether a library is loaded.
func Enabled() bool { return fake() != nil || current() != nil }

// Country is the process-wide library's code for an address or CIDR
// ("" when unknown or no library).
func Country(s string) string {
	if f := fake(); f != nil {
		return f(s)
	}
	return current().Country(s)
}

// Text is the plain-text IP location for reports and the CLI: "IN · India"
// or "印度 (IN)"; "" when unknown.
func Text(s, lang string) string { return Label(Country(s), lang) }

// Suffix is Text in brackets to follow an address: " [IN · India]",
// " [印度 (IN)]", or "".
func Suffix(s, lang string) string {
	if t := Text(s, lang); t != "" {
		return " [" + t + "]"
	}
	return ""
}
