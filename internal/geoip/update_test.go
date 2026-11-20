package geoip

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func gz(b []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write(b)
	w.Close()
	return buf.Bytes()
}

func serve(t *testing.T, files map[string][]byte) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, ok := files[strings.TrimPrefix(r.URL.Path, "/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	}))
	t.Cleanup(srv.Close)
	old := DownloadBase
	DownloadBase = srv.URL + "/"
	t.Cleanup(func() { DownloadBase = old })
}

var day = time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)

// A download that is not a country library leaves the old file alone.
func TestUpdateKeepsOldFileOnBadDownload(t *testing.T) {
	serve(t, map[string][]byte{"dbip-country-lite-2026-11.mmdb.gz": gz([]byte("garbage"))})
	dest := filepath.Join(t.TempDir(), "country.mmdb")
	os.WriteFile(dest, []byte("old"), 0o644)
	if _, _, err := Update(context.Background(), nil, dest, day); err == nil {
		t.Fatal("garbage accepted")
	}
	if b, _ := os.ReadFile(dest); string(b) != "old" {
		t.Fatalf("dest changed: %q", b)
	}
	if m, _ := filepath.Glob(filepath.Join(filepath.Dir(dest), ".country-*")); len(m) != 0 {
		t.Fatalf("temp files left: %v", m)
	}
}

// This month's file not out yet: last month's is used. Needs a real
// library: FLAREHOUND_TEST_MMDB=/path/to/dbip-country-lite.mmdb.
func TestUpdateFallsBackToLastMonth(t *testing.T) {
	p := os.Getenv("FLAREHOUND_TEST_MMDB")
	if p == "" {
		t.Skip("FLAREHOUND_TEST_MMDB not set")
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	serve(t, map[string][]byte{"dbip-country-lite-2026-10.mmdb.gz": gz(raw)})
	dest := filepath.Join(t.TempDir(), "sub", "country.mmdb")
	url, info, err := Update(context.Background(), nil, dest, day)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(url, "2026-10.mmdb.gz") || info.Networks == 0 {
		t.Fatalf("url %s info %+v", url, info)
	}
	st := Setup([]string{dest})
	defer Reset()
	if st.DB == nil || Country("106.201.104.211") != "IN" {
		t.Fatalf("updated library: %+v", st)
	}
}
