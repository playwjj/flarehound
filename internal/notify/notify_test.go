package notify

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
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
func (f *flaky) Send(_ context.Context, text string) error {
	if f.calls.Add(1) <= f.fails {
		return errors.New("down")
	}
	f.got = append(f.got, text)
	return nil
}

func TestRetrySucceeds(t *testing.T) {
	f := &flaky{name: "x", fails: 2}
	if err := (Retry{N: f, Attempts: 3, Backoff: time.Millisecond}).Send(context.Background(), "hi"); err != nil {
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
	if err := d.Send(context.Background(), "alert"); err == nil {
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
	err := tg.Send(context.Background(), "x")
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("err = %v", err)
	}
	// Connection failure path (url.Error carries the URL).
	tg.APIBase = "http://127.0.0.1:1"
	err = tg.Send(context.Background(), "x")
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("err = %v", err)
	}
}
