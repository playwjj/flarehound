// Package logx keeps secrets out of logs (SPEC 12): every log line passes
// through a writer that masks registered secret values and anything
// shaped like a bearer token or Telegram bot URL.
package logx

import (
	"io"
	"log"
	"regexp"
	"strings"
	"sync"
)

var patterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9_\-\.]{20,}`),
	regexp.MustCompile(`(/bot)\d+:[A-Za-z0-9_\-]{20,}`),
}

// Redactor masks secrets in everything written through it.
type Redactor struct {
	mu      sync.Mutex
	out     io.Writer
	secrets []string
}

func NewRedactor(out io.Writer) *Redactor { return &Redactor{out: out} }

// Add registers secret values; empty and very short values are ignored
// (masking "a" would shred every line).
func (r *Redactor) Add(secrets ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range secrets {
		if len(s) >= 8 {
			r.secrets = append(r.secrets, s)
		}
	}
}

// Redact returns s with every secret masked.
func (r *Redactor) Redact(s string) string {
	r.mu.Lock()
	secrets := r.secrets
	r.mu.Unlock()
	for _, sec := range secrets {
		s = strings.ReplaceAll(s, sec, "[REDACTED]")
	}
	for _, p := range patterns {
		s = p.ReplaceAllString(s, "${1}[REDACTED]")
	}
	return s
}

func (r *Redactor) Write(p []byte) (int, error) {
	if _, err := io.WriteString(r.out, r.Redact(string(p))); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Install routes the standard logger through a redactor and returns it.
func Install(out io.Writer) *Redactor {
	r := NewRedactor(out)
	log.SetOutput(r)
	return r
}
