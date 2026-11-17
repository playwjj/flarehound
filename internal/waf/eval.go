package waf

import (
	"regexp"
	"sort"
	"strings"
)

// Tri is three-valued logic: a probe request only fixes some fields, so a
// rule may match always, never, or "depending on the rest".
type Tri int

const (
	False Tri = iota
	Unknown
	True
)

func (t Tri) String() string { return [...]string{"false", "unknown", "true"}[t] }

func triAnd(a, b Tri) Tri {
	if a == False || b == False {
		return False
	}
	if a == True && b == True {
		return True
	}
	return Unknown
}

func triOr(a, b Tri) Tri {
	if a == True || b == True {
		return True
	}
	if a == False && b == False {
		return False
	}
	return Unknown
}

func triNot(a Tri) Tri { return 2 - a }

func of(b bool) Tri {
	if b {
		return True
	}
	return False
}

// Probe is a partial request: the fields it fixes. Everything else is
// unknown.
type Probe map[string]string

// Eval evaluates n against the probe.
func Eval(n Node, p Probe) Tri {
	switch x := n.(type) {
	case And:
		return triAnd(Eval(x.L, p), Eval(x.R, p))
	case Or:
		return triOr(Eval(x.L, p), Eval(x.R, p))
	case Xor:
		a, b := Eval(x.L, p), Eval(x.R, p)
		if a == Unknown || b == Unknown {
			return Unknown
		}
		return of(a != b)
	case Not:
		return triNot(Eval(x.X, p))
	case Truthy:
		return evalTruthy(x.X, p)
	case Cmp:
		return evalCmp(x, p)
	}
	return Unknown
}

// value resolves an operand to a string, if the probe determines it.
func value(o Operand, p Probe) (string, bool) {
	switch x := o.(type) {
	case Lit:
		return x.S, true
	case Field:
		v, ok := p[x.Name]
		return v, ok
	case Call:
		if len(x.Args) == 0 {
			return "", false
		}
		v, ok := value(x.Args[0], p)
		if !ok {
			return "", false
		}
		switch x.Name {
		case "lower":
			return strings.ToLower(v), true
		case "upper":
			return strings.ToUpper(v), true
		}
	}
	return "", false
}

func evalTruthy(o Operand, p Probe) Tri {
	c, ok := o.(Call)
	if !ok || len(c.Args) != 2 {
		return Unknown
	}
	switch c.Name {
	case "starts_with", "ends_with":
		a, ok1 := value(c.Args[0], p)
		b, ok2 := value(c.Args[1], p)
		if !ok1 || !ok2 {
			return Unknown
		}
		if c.Name == "starts_with" {
			return of(strings.HasPrefix(a, b))
		}
		return of(strings.HasSuffix(a, b))
	}
	return Unknown
}

func evalCmp(c Cmp, p Probe) Tri {
	v, ok := value(c.Left, p)
	if !ok {
		return Unknown
	}
	switch val := c.Value.(type) {
	case ListRef:
		return Unknown
	case Set:
		if c.Op != "in" {
			return Unknown
		}
		for _, it := range val.Items {
			if !it.Quoted {
				return Unknown // numbers, IPs, ranges: not string membership
			}
			if it.S == v {
				return True
			}
		}
		return False
	case Scalar:
		s := val.S
		switch c.Op {
		case "eq":
			return of(v == s)
		case "ne":
			return of(v != s)
		case "contains":
			return of(strings.Contains(v, s))
		case "wildcard":
			return of(wildMatch(strings.ToLower(s), strings.ToLower(v)))
		case "strict_wildcard":
			return of(wildMatch(s, v))
		case "matches":
			re, err := regexp.Compile(s)
			if err != nil {
				return Unknown
			}
			return of(re.MatchString(v))
		}
	}
	return Unknown
}

// wildMatch matches * (any run, including /) against s.
func wildMatch(pattern, s string) bool {
	re := "^" + strings.ReplaceAll(regexp.QuoteMeta(pattern), `\*`, ".*") + "$"
	ok, _ := regexp.MatchString(re, s)
	return ok
}

// ---- structural reasoning ----

func disjuncts(n Node) []Node {
	if o, ok := n.(Or); ok {
		return append(disjuncts(o.L), disjuncts(o.R)...)
	}
	return []Node{n}
}

func conjuncts(n Node) []Node {
	if a, ok := n.(And); ok {
		return append(conjuncts(a.L), conjuncts(a.R)...)
	}
	return []Node{n}
}

// key is a canonical string for a node: commutative and/or operands are
// sorted, so "a and b" and "b and a" compare equal.
func key(n Node) string {
	switch x := n.(type) {
	case And:
		cs := conjuncts(x)
		ks := make([]string, len(cs))
		for i, c := range cs {
			ks[i] = key(c)
		}
		sort.Strings(ks)
		return "and(" + strings.Join(ks, ",") + ")"
	case Or:
		ds := disjuncts(x)
		ks := make([]string, len(ds))
		for i, d := range ds {
			ks[i] = key(d)
		}
		sort.Strings(ks)
		return "or(" + strings.Join(ks, ",") + ")"
	case Not:
		return "not(" + key(x.X) + ")"
	}
	return n.String()
}

// maxTerms bounds DNF expansion; bigger expressions are not reasoned
// about structurally (Implies then answers "not shown").
const maxTerms = 256

// dnf expands n into disjunctive normal form: a list of conjunct sets
// (canonical keys). ok is false if the expansion would exceed maxTerms.
func dnf(n Node) (terms []map[string]bool, ok bool) {
	switch x := n.(type) {
	case Or:
		l, ok1 := dnf(x.L)
		r, ok2 := dnf(x.R)
		if !ok1 || !ok2 || len(l)+len(r) > maxTerms {
			return nil, false
		}
		return append(l, r...), true
	case And:
		l, ok1 := dnf(x.L)
		r, ok2 := dnf(x.R)
		if !ok1 || !ok2 || len(l)*len(r) > maxTerms {
			return nil, false
		}
		var out []map[string]bool
		for _, a := range l {
			for _, b := range r {
				m := make(map[string]bool, len(a)+len(b))
				for k := range a {
					m[k] = true
				}
				for k := range b {
					m[k] = true
				}
				out = append(out, m)
			}
		}
		return out, true
	}
	return []map[string]bool{{key(n): true}}, true
}

// Implies reports whether every request matching a also matches b, as far
// as can be shown structurally: in DNF, each term of a must contain all
// the conjuncts of some term of b. False means "not shown", not "no".
func Implies(a, b Node) bool {
	ta, ok1 := dnf(a)
	tb, ok2 := dnf(b)
	if !ok1 || !ok2 {
		return key(a) == key(b)
	}
	for _, x := range ta {
		found := false
		for _, y := range tb {
			sub := true
			for k := range y {
				if !x[k] {
					sub = false
					break
				}
			}
			if sub {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
