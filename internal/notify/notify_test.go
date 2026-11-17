package notify

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type flaky struct {
	name  string
	fails int32
	calls atomic.Int32
	got   []string
}

func (f *flaky) Name() string { return f.name }
func (f *flaky) Send(_ context.Context, m Message) error {
	text := m.body()
	if f.calls.Add(1) <= f.fails {
		return errors.New("down")
	}
	f.got = append(f.got, text)
	return nil
}

func TestRetrySucceeds(t *testing.T) {
	f := &flaky{name: "x", fails: 2}
	if err := (Retry{N: f, Attempts: 3, Backoff: time.Millisecond}).Send(context.Background(), Plain("hi")); err != nil {
		t.Fatal(err)
	}
	if f.calls.Load() != 3 {
		t.Fatalf("calls = %d", f.calls.Load())
	}
}

func TestOutboxRoundTrip(t *testing.T) {
	ob := filepath.Join(t.TempDir(), "outbox.json")
	good := &flaky{name: "good"}
	bad := &flaky{name: "bad", fails: 3}
	d := &Dispatcher{Outbox: ob, Channels: []Notifier{
		Retry{N: good, Attempts: 3, Backoff: time.Millisecond},
		Retry{N: bad, Attempts: 3, Backoff: time.Millisecond},
	}}
	if err := d.Send(context.Background(), Plain("alert")); err == nil {
		t.Fatal("expected error for failing channel")
	}
	if len(good.got) != 1 {
		t.Fatal("healthy channel must still deliver")
	}
	// Channel recovers: flush delivers once, only to the failed channel.
	if err := d.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(bad.got) != 1 || !strings.Contains(bad.got[0], "alert") || len(good.got) != 1 {
		t.Fatalf("flush: good=%v bad=%v", good.got, bad.got)
	}
	if q, _ := d.load(); len(q) != 0 {
		t.Fatalf("outbox not drained: %v", q)
	}
}

func TestErrorsNeverLeakURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	tg := Telegram{BotToken: "123456:SECRET-bot-token-value", ChatID: "1", APIBase: srv.URL}
	err := tg.Send(context.Background(), Plain("x"))
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("err = %v", err)
	}
	// Connection failure path (url.Error carries the URL).
	tg.APIBase = "http://127.0.0.1:1"
	err = tg.Send(context.Background(), Plain("x"))
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("err = %v", err)
	}
}

func TestFileChannel(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "alerts.jsonl")
	f := File{Path: p}
	m := Message{Kind: "intraday", Zone: "example.com", Decision: "alert", Rules: []string{"total_up"}, Text: "line1\nline2"}
	if err := f.Send(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	m.Delayed = true
	if err := f.Send(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(p)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 JSONL records, got %d:\n%s", len(lines), raw)
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatal(err)
	}
	if rec["source"] != "flarehound" || rec["kind"] != "intraday" || rec["text"] != "line1\nline2" || rec["ts"] == nil {
		t.Fatalf("record %v", rec)
	}
	if !strings.Contains(lines[1], `"delayed":true`) {
		t.Fatal("delayed flag missing")
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
}

func TestLegacyOutboxStillFlushes(t *testing.T) {
	ob := filepath.Join(t.TempDir(), "outbox.json")
	os.WriteFile(ob, []byte(`[{"channel":"x","text":"old alert","queued":"`+time.Now().Format(time.RFC3339)+`"}]`), 0o600)
	got := &flaky{name: "x"}
	d := &Dispatcher{Outbox: ob, Channels: []Notifier{got}}
	if err := d.Flush(context.Background()); err != nil || len(got.got) != 1 || got.got[0] != "[delayed] old alert" {
		t.Fatalf("legacy outbox: %v %v", err, got.got)
	}
}

func TestTelegramSplitsLongReports(t *testing.T) {
	var n int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { n++ }))
	defer srv.Close()
	long := strings.Repeat(strings.Repeat("x", 99)+"\n", 100) // 10,000 characters
	if err := (Telegram{BotToken: "1:a", ChatID: "1", APIBase: srv.URL}).Send(context.Background(), Plain(long)); err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("sent %d messages, want 3", n)
	}
}
