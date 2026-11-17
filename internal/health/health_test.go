package health

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBeatAndCheck(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 11, 17, 14, 7, 0, 0, time.UTC)
	if _, err := Check(dir, WatchFile, time.Hour, now); err == nil {
		t.Fatal("missing heartbeat must fail")
	}
	if err := Write(dir, WatchFile, Beat{At: now, Role: "watch", Zones: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := Check(dir, WatchFile, time.Hour, now.Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := Check(dir, WatchFile, time.Hour, now.Add(2*time.Hour)); err == nil || !strings.Contains(err.Error(), "not running") {
		t.Fatalf("stale heartbeat: %v", err)
	}
}

func TestPing(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { paths = append(paths, r.URL.Path) }))
	defer srv.Close()
	_ = Ping(context.Background(), srv.URL+"/uuid-SECRET", false)
	_ = Ping(context.Background(), srv.URL+"/uuid-SECRET", true)
	if len(paths) != 2 || paths[0] != "/uuid-SECRET" || paths[1] != "/uuid-SECRET/fail" {
		t.Fatalf("%v", paths)
	}
	if err := Ping(context.Background(), "http://127.0.0.1:1/uuid-SECRET", false); err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("error must not leak the URL: %v", err)
	}
}
