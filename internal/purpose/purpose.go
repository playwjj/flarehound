// Package purpose classifies traffic by why it comes (docs/traffic-purpose.md):
// training crawlers, search indexers, fetches a person triggered in an
// assistant, data tools fetching for their customers, mixed crawlers, and
// undeclared automation (browser user agents with automation traits).
//
// The named classes come from a built-in UA table (a snapshot of the
// community ai.robots.txt list, shipped with each release — never fetched
// at run time) merged with the operator's overrides. The table is applied
// when a report or page is rendered, never stored: the archive keeps the
// raw user agent, so a revised table re-labels history consistently.
//
// Undeclared automation is never named after an AI operator: it is a
// conclusion about traits (a browser UA served from hosting networks, a
// headless browser), and reports say exactly that.
package purpose

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Class is a purpose.
type Class string

const (
	Training   Class = "training"    // collects corpus for model training
	Search     Class = "search"      // indexes for search, AI search included
	UserAction Class = "user_action" // fetches live while a person asks an assistant
	Tool       Class = "tool"        // a fetch API / platform fetching for its customers
	Mixed      Class = "mixed"       // search and training in one crawler, not separated by its operator
	Undeclared Class = "undeclared"  // browser UA with automation traits
	// None is an override that removes a UA from every class.
	None Class = "none"
)

// Classes in display order.
var Classes = []Class{Undeclared, Search, Training, Tool, UserAction, Mixed}

// Valid reports whether c is a class an override may set (None included).
func Valid(c Class) bool {
	if c == None {
		return true
	}
	for _, x := range Classes {
		if x == c {
			return true
		}
	}
	return false
}

// Trust is how a label is known.
type Trust string

const (
	Verified  Trust = "verified"  // Cloudflare's verified-bot check passed (cf.client.bot)
	Claimed   Trust = "claimed"   // the UA names itself; not verified
	Behaviour Trust = "behaviour" // judged from traits (undeclared automation)
)

// VerifiedShare is the share of a UA's requests that must pass the
// verified-bot check for its label to count as verified.
const VerifiedShare = 0.9

// ShiftPP is the day-over-day change of a class's share, in percentage
// points, that the daily report names in its conclusion.
const ShiftPP = 10.0

// Entry maps a UA marker to a class.
type Entry struct {
	Match    string `json:"match"` // case-insensitive substring of the UA
	Class    Class  `json:"class"`
	Operator string `json:"operator,omitempty"`
	Override bool   `json:"-"` // from the operator's overrides
}

// Label is a UA's purpose with how it is known.
type Label struct {
	Class    Class  `json:"class"`
	Name     string `json:"name,omitempty"` // the matched marker ("GPTBot")
	Operator string `json:"operator,omitempty"`
	Trust    Trust  `json:"trust,omitempty"`
	Override bool   `json:"override,omitempty"`
}

//go:embed purposes.json
var builtinRaw []byte

type tableFile struct {
	Version string  `json:"version"`
	Source  string  `json:"source"`
	Entries []Entry `json:"entries"`
}

var (
	builtinOnce sync.Once
	builtinTab  tableFile
	builtinErr  error
)

// parse reads a table file; a broken or empty table is an error.
func parse(raw []byte) (tableFile, error) {
	var tf tableFile
	if len(raw) == 0 {
		return tf, errors.New("purpose table missing")
	}
	if err := json.Unmarshal(raw, &tf); err != nil {
		return tf, fmt.Errorf("purpose table: %w", err)
	}
	if tf.Version == "" || len(tf.Entries) == 0 {
		return tf, errors.New("purpose table: no version or no entries")
	}
	for i, e := range tf.Entries {
		if strings.TrimSpace(e.Match) == "" || e.Class == None || !Valid(e.Class) || e.Class == Undeclared {
			return tf, fmt.Errorf("purpose table: entry %d (%q): bad match or class %q", i, e.Match, e.Class)
		}
	}
	return tf, nil
}

func builtin() (tableFile, error) {
	builtinOnce.Do(func() { builtinTab, builtinErr = parse(builtinRaw) })
	return builtinTab, builtinErr
}

// Table is the built-in table merged with overrides.
type Table struct {
	version   string
	entries   []Entry // built-in
	overrides []Entry
	err       error
}

// New returns the built-in table with the operator's overrides
// (UA substring → class). A broken built-in table yields a table that is
// off (OK false): the facet then disappears and nothing else changes.
func New(overrides map[string]string) *Table {
	tf, err := builtin()
	return build(tf, err, overrides)
}

func build(tf tableFile, err error, overrides map[string]string) *Table {
	t := &Table{err: err}
	if err != nil {
		return t
	}
	t.version, t.entries = tf.Version, tf.Entries
	keys := make([]string, 0, len(overrides))
	for k := range overrides {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		m, c := strings.TrimSpace(k), Class(strings.TrimSpace(overrides[k]))
		if m == "" || !Valid(c) {
			continue
		}
		t.overrides = append(t.overrides, Entry{Match: m, Class: c, Override: true, Operator: operatorOf(tf.Entries, m)})
	}
	return t
}

// operatorOf keeps the operator when an override re-files a listed UA.
func operatorOf(es []Entry, m string) string {
	l := strings.ToLower(m)
	if e, ok := longest(es, l); ok { // the override is more specific
		return e.Operator
	}
	for _, e := range es { // the override is a part of a listed marker
		if strings.Contains(strings.ToLower(e.Match), l) {
			return e.Operator
		}
	}
	return ""
}

// OK reports whether the table is usable.
func (t *Table) OK() bool { return t != nil && t.err == nil }

// Err is why the table is off.
func (t *Table) Err() error {
	if t == nil {
		return errors.New("purpose table not loaded")
	}
	return t.err
}

// Version is the built-in table's version (its snapshot date).
func (t *Table) Version() string { return t.version }

// Size is the number of built-in entries.
func (t *Table) Size() int { return len(t.entries) }

// Overrides is the number of operator overrides in effect.
func (t *Table) Overrides() int { return len(t.overrides) }

// longest returns the entry with the longest marker contained in l
// (lower-cased UA); an exact match wins outright.
func longest(es []Entry, l string) (Entry, bool) {
	var best Entry
	found := false
	for _, e := range es {
		m := strings.ToLower(e.Match)
		if l == m {
			return e, true
		}
		if strings.Contains(l, m) && (!found || len(m) > len(best.Match)) {
			best, found = e, true
		}
	}
	return best, found
}

// Lookup finds the entry for a UA: overrides first, then the built-in
// table; within each, an exact match first, then the longest contained
// marker. An entry of class None means "explicitly untagged".
func (t *Table) Lookup(ua string) (Entry, bool) {
	if !t.OK() || ua == "" {
		return Entry{}, false
	}
	l := strings.ToLower(ua)
	if e, ok := longest(t.overrides, l); ok {
		return e, true
	}
	return longest(t.entries, l)
}

// Named returns the label of a UA from the table alone (no traffic
// evidence): trust is Claimed — the UA names itself. Undeclared
// automation needs traffic (Classify) and is never returned here, except
// through an override.
func (t *Table) Named(ua string) (Label, bool) {
	e, ok := t.Lookup(ua)
	if !ok || e.Class == None {
		return Label{}, false
	}
	return Label{Class: e.Class, Name: e.Match, Operator: e.Operator, Trust: trustOf(e, false), Override: e.Override}, true
}

func trustOf(e Entry, verified bool) Trust {
	switch {
	case verified:
		return Verified
	case e.Class == Undeclared:
		return Behaviour
	}
	return Claimed
}

// BrowserLike reports a UA that presents as an ordinary browser.
func BrowserLike(ua string) bool {
	l := strings.ToLower(ua)
	if !strings.HasPrefix(l, "mozilla/") {
		return false
	}
	for _, w := range []string{"bot", "spider", "crawl", "compatible;", "http://", "https://", "+http"} {
		if strings.Contains(l, w) {
			return false
		}
	}
	for _, w := range []string{"chrome/", "firefox/", "safari/", "edg/"} {
		if strings.Contains(l, w) {
			return true
		}
	}
	return false
}

// Headless reports a headless-browser UA (automation by construction).
func Headless(ua string) bool {
	l := strings.ToLower(ua)
	return strings.Contains(l, "headlesschrome") || strings.Contains(l, "headless chrome")
}

// Row is one traffic group: a UA, its network and whether it passed the
// verified-bot check.
type Row struct {
	UA       string
	ASN      int // 0: unknown (plan without the ASN dimension)
	Verified bool
	Count    int64
}

// Options carries what the plan exposes and the network judgement.
type Options struct {
	HasASN  bool               // rows carry ASNs
	HasBot  bool               // rows carry the verified-bot category
	Hosting func(asn int) bool // hosting / cloud network
}

func (o Options) hosting(asn int) bool {
	return o.HasASN && asn > 0 && o.Hosting != nil && o.Hosting(asn)
}

// undeclared reports whether one row is undeclared automation and why.
func (o Options) undeclared(ua string, asn int) (bool, string) {
	if !BrowserLike(ua) && !Headless(ua) {
		return false, ""
	}
	switch {
	case Headless(ua):
		return true, TraitHeadless
	case o.hosting(asn):
		return true, TraitHosting
	}
	return false, ""
}

// Traits of undeclared automation, as reports name them.
const (
	TraitHosting  = "hosting"  // browser UA served from a hosting / cloud network
	TraitHeadless = "headless" // headless browser UA
)

// Actor is one UA within a class.
type Actor struct {
	UA       string
	Name     string // matched marker; "" for undeclared
	Operator string
	Count    int64
	Verified int64           // requests that passed the verified-bot check
	Override bool            // labelled by an operator override
	Traits   map[string]bool // undeclared: why
	ASNs     map[int]int64   // undeclared: where from
}

// Trust is how the actor's label is known.
func (a Actor) Trust(c Class, hasBot bool) Trust {
	if c == Undeclared {
		return Behaviour
	}
	if hasBot && a.Count > 0 && float64(a.Verified) >= VerifiedShare*float64(a.Count) {
		return Verified
	}
	return Claimed
}

// TopASN is the network most of an undeclared actor's requests came from.
func (a Actor) TopASN() (int, int64) {
	var best int
	var n int64
	for k, v := range a.ASNs {
		if v > n || (v == n && k < best) {
			best, n = k, v
		}
	}
	return best, n
}

// Stat is one class in a window.
type Stat struct {
	Class  Class
	Count  int64
	Actors []Actor // largest first
}

// Facet is a window's traffic by purpose.
type Facet struct {
	Version string
	Rows    int64 // requests in the rows looked at (the covered part)
	HasASN  bool  // undeclared automation could be judged
	HasBot  bool  // verified-bot trust could be judged
	Stats   map[Class]*Stat
}

// Count is a class's requests (0 when absent).
func (f Facet) Count(c Class) int64 {
	if s := f.Stats[c]; s != nil {
		return s.Count
	}
	return 0
}

// Tagged is the requests in any class.
func (f Facet) Tagged() int64 {
	var n int64
	for _, s := range f.Stats {
		n += s.Count
	}
	return n
}

// Facet classifies traffic rows. Rows whose UA the table names go to its
// class; browser-like rows with automation traits go to Undeclared;
// everything else stays untagged.
func (t *Table) Facet(rows []Row, o Options) Facet {
	f := Facet{Version: t.Version(), HasASN: o.HasASN, HasBot: o.HasBot, Stats: map[Class]*Stat{}}
	if !t.OK() {
		return f
	}
	actors := map[Class]map[string]*Actor{}
	for _, r := range rows {
		f.Rows += r.Count
		var c Class
		var e Entry
		trait := ""
		if x, ok := t.Lookup(r.UA); ok {
			if x.Class == None {
				continue
			}
			c, e = x.Class, x
		} else if u, why := o.undeclared(r.UA, r.ASN); u {
			c, trait = Undeclared, why
		} else {
			continue
		}
		s := f.Stats[c]
		if s == nil {
			s = &Stat{Class: c}
			f.Stats[c] = s
			actors[c] = map[string]*Actor{}
		}
		s.Count += r.Count
		a := actors[c][r.UA]
		if a == nil {
			a = &Actor{UA: r.UA, Name: e.Match, Operator: e.Operator, Override: e.Override}
			actors[c][r.UA] = a
		}
		a.Count += r.Count
		if r.Verified {
			a.Verified += r.Count
		}
		if c == Undeclared {
			if a.Traits == nil {
				a.Traits, a.ASNs = map[string]bool{}, map[int]int64{}
			}
			if trait != "" {
				a.Traits[trait] = true
			}
			if r.ASN > 0 {
				a.ASNs[r.ASN] += r.Count
			}
		}
	}
	for c, m := range actors {
		s := f.Stats[c]
		for _, a := range m {
			s.Actors = append(s.Actors, *a)
		}
		sort.Slice(s.Actors, func(i, j int) bool {
			if s.Actors[i].Count != s.Actors[j].Count {
				return s.Actors[i].Count > s.Actors[j].Count
			}
			return s.Actors[i].UA < s.Actors[j].UA
		})
	}
	return f
}

// Classify labels one UA from its traffic rows (all rows of that UA):
// the table first (verified when the rows pass the verified-bot check),
// else undeclared automation when most of its requests carry the traits.
func (t *Table) Classify(ua string, rows []Row, o Options) (Label, bool) {
	if !t.OK() {
		return Label{}, false
	}
	var total, verified, auto int64
	for _, r := range rows {
		total += r.Count
		if r.Verified {
			verified += r.Count
		}
		if u, _ := o.undeclared(ua, r.ASN); u {
			auto += r.Count
		}
	}
	if e, ok := t.Lookup(ua); ok {
		if e.Class == None {
			return Label{}, false
		}
		v := o.HasBot && total > 0 && float64(verified) >= VerifiedShare*float64(total)
		return Label{Class: e.Class, Name: e.Match, Operator: e.Operator, Trust: trustOf(e, v), Override: e.Override}, true
	}
	if Headless(ua) || (total > 0 && auto*2 > total) {
		return Label{Class: Undeclared, Trust: Behaviour}, true
	}
	return Label{}, false
}

// Shift is one class whose share moved by at least ShiftPP.
type Shift struct {
	Class           Class
	CurPct, BasePct float64 // share of the window's requests, in percent
}

// PP is the change in percentage points.
func (s Shift) PP() float64 { return s.CurPct - s.BasePct }

// Shifts compares two windows' facets (shares of each window's total
// requests) and returns the classes that moved by ShiftPP or more.
func Shifts(cur, base Facet, curTotal, baseTotal int64) []Shift {
	if curTotal <= 0 || baseTotal <= 0 {
		return nil
	}
	var out []Shift
	for _, c := range Classes {
		cp := 100 * float64(cur.Count(c)) / float64(curTotal)
		bp := 100 * float64(base.Count(c)) / float64(baseTotal)
		if cp-bp >= ShiftPP || bp-cp >= ShiftPP {
			out = append(out, Shift{Class: c, CurPct: cp, BasePct: bp})
		}
	}
	return out
}
