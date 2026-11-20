// Package waf is the WAF rule audit (SPEC 10): it parses Cloudflare
// rules-language expressions, evaluates them against probe requests with
// three-valued logic, and checks a zone's custom rules for coverage gaps,
// ordering problems, shadowed rules, over-broad exemptions, dead rules and
// quota pressure. It only reads; it never changes a rule.
package waf

import (
	"fmt"
	"strings"
	"unicode"
)

// ---- AST ----

// Node is a boolean expression.
type Node interface{ String() string }

type (
	And struct{ L, R Node }
	Or  struct{ L, R Node }
	Xor struct{ L, R Node }
	Not struct{ X Node }
	// Cmp is "operand op value".
	Cmp struct {
		Left  Operand
		Op    string // eq ne lt le gt ge contains matches wildcard strict_wildcard in
		Value Value
	}
	// Truthy is a bare boolean operand (cf.client.bot, starts_with(...)).
	Truthy struct{ X Operand }
)

// Operand is a field, a function call or a literal.
type Operand interface{ String() string }

type (
	Field struct{ Name string } // includes map/array access, verbatim
	Call  struct {
		Name string
		Args []Operand
	}
	Lit struct {
		S      string
		Quoted bool
	}
	// ExprArg is a boolean expression passed as an argument (any(...)).
	ExprArg struct{ N Node }
)

func (e ExprArg) String() string { return e.N.String() }

// Value is the right-hand side of a comparison.
type Value interface{ String() string }

type (
	Scalar  struct{ Lit }
	Set     struct{ Items []Lit }
	ListRef struct{ Name string } // $name
)

func (n And) String() string    { return "(" + n.L.String() + " and " + n.R.String() + ")" }
func (n Or) String() string     { return "(" + n.L.String() + " or " + n.R.String() + ")" }
func (n Xor) String() string    { return "(" + n.L.String() + " xor " + n.R.String() + ")" }
func (n Not) String() string    { return "not " + n.X.String() }
func (n Cmp) String() string    { return n.Left.String() + " " + n.Op + " " + n.Value.String() }
func (n Truthy) String() string { return n.X.String() }
func (f Field) String() string  { return f.Name }
func (c Call) String() string {
	a := make([]string, len(c.Args))
	for i, x := range c.Args {
		a[i] = x.String()
	}
	return c.Name + "(" + strings.Join(a, ", ") + ")"
}
func (l Lit) String() string {
	if l.Quoted {
		return fmt.Sprintf("%q", l.S)
	}
	return l.S
}
func (s Set) String() string {
	a := make([]string, len(s.Items))
	for i, x := range s.Items {
		a[i] = x.String()
	}
	return "{" + strings.Join(a, " ") + "}"
}
func (l ListRef) String() string { return "$" + l.Name }

// ---- lexer ----

type tokKind int

const (
	tEOF    tokKind = iota
	tWord           // identifiers, fields, numbers, IPs, keywords
	tString         // quoted or raw string
	tOp             // == != < <= > >= ~ && || ! ^^
	tLParen
	tRParen
	tLBrace
	tRBrace
	tComma
	tList // $name
)

type token struct {
	kind tokKind
	s    string
	pos  int
}

func isWordRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune("._:/-*[]", r)
}

func lex(src string) ([]token, error) {
	var out []token
	rs := []rune(src)
	i := 0
	for i < len(rs) {
		r := rs[i]
		switch {
		case unicode.IsSpace(r):
			i++
		case r == '(':
			out = append(out, token{tLParen, "(", i})
			i++
		case r == ')':
			out = append(out, token{tRParen, ")", i})
			i++
		case r == '{':
			out = append(out, token{tLBrace, "{", i})
			i++
		case r == '}':
			out = append(out, token{tRBrace, "}", i})
			i++
		case r == ',':
			out = append(out, token{tComma, ",", i})
			i++
		case r == '"':
			var b strings.Builder
			j := i + 1
			for ; j < len(rs) && rs[j] != '"'; j++ {
				if rs[j] == '\\' && j+1 < len(rs) {
					j++
				}
				b.WriteRune(rs[j])
			}
			if j >= len(rs) {
				return nil, fmt.Errorf("unterminated string at %d", i)
			}
			out = append(out, token{tString, b.String(), i})
			i = j + 1
		case r == 'r' && i+1 < len(rs) && (rs[i+1] == '"' || rs[i+1] == '#'):
			// raw string r"..." or r#"..."#
			j := i + 1
			hashes := 0
			for j < len(rs) && rs[j] == '#' {
				hashes++
				j++
			}
			if j >= len(rs) || rs[j] != '"' {
				// not a raw string after all: an identifier starting with r
				goto word
			}
			end := "\"" + strings.Repeat("#", hashes)
			rest := string(rs[j+1:])
			k := strings.Index(rest, end)
			if k < 0 {
				return nil, fmt.Errorf("unterminated raw string at %d", i)
			}
			out = append(out, token{tString, rest[:k], i})
			i = j + 1 + len([]rune(rest[:k+len(end)]))
		case r == '$':
			j := i + 1
			for j < len(rs) && (unicode.IsLetter(rs[j]) || unicode.IsDigit(rs[j]) || rs[j] == '_' || rs[j] == '.') {
				j++
			}
			out = append(out, token{tList, string(rs[i+1 : j]), i})
			i = j
		case strings.ContainsRune("=!<>~&|^", r):
			two := ""
			if i+1 < len(rs) {
				two = string(rs[i : i+2])
			}
			switch two {
			case "==", "!=", "<=", ">=", "&&", "||", "^^":
				out = append(out, token{tOp, two, i})
				i += 2
			default:
				out = append(out, token{tOp, string(r), i})
				i++
			}
		default:
			goto word
		}
		continue
	word:
		{
			j := i
			for j < len(rs) && (isWordRune(rs[j]) || (rs[j] == '"' && j > i && rs[j-1] == '[')) {
				if rs[j] == '"' { // map access: http.request.headers["x-a"]
					k := j + 1
					for k < len(rs) && rs[k] != '"' {
						k++
					}
					j = k + 1
					continue
				}
				j++
			}
			if j == i {
				return nil, fmt.Errorf("unexpected %q at %d", r, i)
			}
			out = append(out, token{tWord, string(rs[i:j]), i})
			i = j
		}
	}
	return append(out, token{tEOF, "", len(rs)}), nil
}

// ---- parser ----

type parser struct {
	toks []token
	p    int
}

func (p *parser) peek() token { return p.toks[p.p] }
func (p *parser) next() token { t := p.toks[p.p]; p.p++; return t }

func (p *parser) word(ws ...string) bool {
	t := p.peek()
	if t.kind != tWord && t.kind != tOp {
		return false
	}
	for _, w := range ws {
		if strings.EqualFold(t.s, w) {
			return true
		}
	}
	return false
}

// Parse parses a rules-language expression.
func Parse(src string) (Node, error) {
	toks, err := lex(src)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	n, err := p.or()
	if err != nil {
		return nil, err
	}
	if p.peek().kind != tEOF {
		return nil, fmt.Errorf("unexpected %q at %d", p.peek().s, p.peek().pos)
	}
	return n, nil
}

func (p *parser) or() (Node, error) {
	l, err := p.xor()
	if err != nil {
		return nil, err
	}
	for p.word("or", "||") {
		p.next()
		r, err := p.xor()
		if err != nil {
			return nil, err
		}
		l = Or{l, r}
	}
	return l, nil
}

func (p *parser) xor() (Node, error) {
	l, err := p.and()
	if err != nil {
		return nil, err
	}
	for p.word("xor", "^^") {
		p.next()
		r, err := p.and()
		if err != nil {
			return nil, err
		}
		l = Xor{l, r}
	}
	return l, nil
}

func (p *parser) and() (Node, error) {
	l, err := p.not()
	if err != nil {
		return nil, err
	}
	for p.word("and", "&&") {
		p.next()
		r, err := p.not()
		if err != nil {
			return nil, err
		}
		l = And{l, r}
	}
	return l, nil
}

func (p *parser) not() (Node, error) {
	if p.word("not", "!") {
		p.next()
		x, err := p.not()
		if err != nil {
			return nil, err
		}
		return Not{x}, nil
	}
	return p.primary()
}

var cmpOps = map[string]string{
	"eq": "eq", "==": "eq", "ne": "ne", "!=": "ne",
	"lt": "lt", "<": "lt", "le": "le", "<=": "le", "gt": "gt", ">": "gt", "ge": "ge", ">=": "ge",
	"contains": "contains", "matches": "matches", "~": "matches", "wildcard": "wildcard", "in": "in",
	// Infix forms of starts_with()/ends_with(), as people write them in
	// notes and proposals; Cloudflare itself only takes the function form.
	"starts_with": "starts_with", "ends_with": "ends_with",
}

func (p *parser) primary() (Node, error) {
	if p.peek().kind == tLParen {
		p.next()
		n, err := p.or()
		if err != nil {
			return nil, err
		}
		if p.next().kind != tRParen {
			return nil, fmt.Errorf("missing )")
		}
		return n, nil
	}
	left, err := p.operand()
	if err != nil {
		return nil, err
	}
	t := p.peek()
	op := ""
	if t.kind == tWord || t.kind == tOp {
		if strings.EqualFold(t.s, "strict") {
			p.next()
			if !p.word("wildcard") {
				return nil, fmt.Errorf("expected wildcard after strict")
			}
			op = "strict_wildcard"
		} else if o, ok := cmpOps[strings.ToLower(t.s)]; ok {
			op = o
		}
	}
	if op == "" {
		return Truthy{left}, nil
	}
	p.next()
	v, err := p.value(op)
	if err != nil {
		return nil, err
	}
	return Cmp{Left: left, Op: op, Value: v}, nil
}

func (p *parser) operand() (Operand, error) {
	t := p.next()
	switch t.kind {
	case tString:
		return Lit{S: t.s, Quoted: true}, nil
	case tWord:
		if p.peek().kind == tLParen { // function call
			p.next()
			var args []Operand
			for p.peek().kind != tRParen {
				n, err := p.or()
				if err != nil {
					return nil, err
				}
				var a Operand = ExprArg{n}
				if tr, ok := n.(Truthy); ok {
					a = tr.X // a plain field, literal or call
				}
				args = append(args, a)
				if p.peek().kind == tComma {
					p.next()
				} else if p.peek().kind != tRParen {
					return nil, fmt.Errorf("expected , or ) in call to %s", t.s)
				}
			}
			p.next()
			return Call{Name: strings.ToLower(t.s), Args: args}, nil
		}
		if strings.ContainsAny(t.s[:1], "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") && !looksLiteral(t.s) {
			return Field{Name: t.s}, nil
		}
		return Lit{S: t.s}, nil
	}
	return nil, fmt.Errorf("unexpected %q at %d", t.s, t.pos)
}

// looksLiteral tells an unquoted literal (IP, IPv6, number) from a field.
func looksLiteral(s string) bool {
	return strings.Contains(s, ":") && !strings.Contains(s, ".") || strings.HasPrefix(s, "::")
}

func (p *parser) value(op string) (Value, error) {
	t := p.peek()
	switch {
	case t.kind == tList:
		p.next()
		return ListRef{t.s}, nil
	case t.kind == tLBrace:
		p.next()
		var s Set
		for p.peek().kind != tRBrace {
			x := p.next()
			switch x.kind {
			case tString:
				s.Items = append(s.Items, Lit{S: x.s, Quoted: true})
			case tWord:
				s.Items = append(s.Items, Lit{S: x.s})
			default:
				return nil, fmt.Errorf("unexpected %q in set", x.s)
			}
		}
		p.next()
		return s, nil
	case t.kind == tString || t.kind == tWord:
		p.next()
		return Scalar{Lit{S: t.s, Quoted: t.kind == tString}}, nil
	}
	return nil, fmt.Errorf("expected a value after %s, got %q", op, t.s)
}

// Fields returns every field an expression references (inside calls too).
func Fields(n Node) map[string]bool {
	out := map[string]bool{}
	var walk func(Node)
	var op func(Operand)
	op = func(o Operand) {
		switch x := o.(type) {
		case Field:
			out[baseField(x.Name)] = true
		case Call:
			for _, a := range x.Args {
				op(a)
			}
		case ExprArg:
			walk(x.N)
		}
	}
	walk = func(n Node) {
		switch x := n.(type) {
		case And:
			walk(x.L)
			walk(x.R)
		case Or:
			walk(x.L)
			walk(x.R)
		case Xor:
			walk(x.L)
			walk(x.R)
		case Not:
			walk(x.X)
		case Cmp:
			op(x.Left)
		case Truthy:
			op(x.X)
		}
	}
	walk(n)
	return out
}

// baseField strips map/array access: http.request.headers["x"][0] →
// http.request.headers.
func baseField(f string) string {
	if i := strings.IndexByte(f, '['); i >= 0 {
		return f[:i]
	}
	return f
}
