package logx

import (
	"bytes"
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	var buf bytes.Buffer
	r := NewRedactor(&buf)
	r.Add("cf-token-abcdefghijklmnop", "", "short")
	r.Write([]byte("auth cf-token-abcdefghijklmnop failed; Bearer abcdefghijklmnopqrstuvwxyz0123; " +
		"POST https://api.telegram.org/bot123456:AAAbbbCCCdddEEEfffGGGhhh/sendMessage; short stays\n"))
	out := buf.String()
	for _, leak := range []string{"cf-token-abcdefghijklmnop", "abcdefghijklmnopqrstuvwxyz0123", "AAAbbbCCCdddEEEfffGGGhhh"} {
		if strings.Contains(out, leak) {
			t.Errorf("leaked %q: %s", leak, out)
		}
	}
	if !strings.Contains(out, "short stays") {
		t.Error("short values must not be registered as secrets")
	}
}
