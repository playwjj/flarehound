package notify

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var png1 = []byte("\\x89PNG fake chart bytes")

func visual() Message {
	return Message{Kind: "daily", Zone: "example.com", Text: "FlareHound daily · example.com\\nall clear",
		HTML:   `<html><body><h1>FlareHound</h1><img src="cid:requests"></body></html>`,
		Images: []Image{{Name: "requests", Caption: "requests per hour", PNG: png1}}}
}

type multipartHit struct {
	path, file string
	fields     map[string]string
	data       []byte
}

func multipartServer(t *testing.T, hits *[]multipartHit, reply string) string {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := multipartHit{path: r.URL.Path, fields: map[string]string{}}
		if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/") {
			_ = r.ParseMultipartForm(1 << 20)
			for k, v := range r.MultipartForm.Value {
				h.fields[k] = v[0]
			}
			for k, fhs := range r.MultipartForm.File {
				f, _ := fhs[0].Open()
				h.file, h.data = k, mustRead(f)
			}
		}
		*hits = append(*hits, h)
		io.WriteString(w, reply)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func mustRead(r io.Reader) []byte { b, _ := io.ReadAll(r); return b }

func TestTelegramSendsPhotos(t *testing.T) {
	var hits []multipartHit
	base := multipartServer(t, &hits, `{"ok":true}`)
	if err := (Telegram{BotToken: "1:a", ChatID: "42", APIBase: base}).Send(context.Background(), visual()); err != nil {
		t.Fatal(err)
	}
	if len(hits) != 2 || !strings.HasSuffix(hits[1].path, "/sendPhoto") || hits[1].file != "photo" ||
		!bytes.Equal(hits[1].data, png1) || hits[1].fields["chat_id"] != "42" || hits[1].fields["caption"] != "requests per hour" {
		t.Fatalf("%+v", hits)
	}
}

func TestDiscordSendsFiles(t *testing.T) {
	var hits []multipartHit
	u := multipartServer(t, &hits, ``)
	if err := (Discord{URL: u}).Send(context.Background(), visual()); err != nil {
		t.Fatal(err)
	}
	if len(hits) != 2 || hits[1].file != "files[0]" || !strings.Contains(hits[1].fields["payload_json"], "requests per hour") {
		t.Fatalf("%+v", hits)
	}
}

func TestWeComSendsImage(t *testing.T) {
	c := &capture{reply: `{"errcode":0}`}
	if err := (WeCom{URL: c.server(t)}).Send(context.Background(), visual()); err != nil {
		t.Fatal(err)
	}
	img := c.bodies[1]["image"].(map[string]any)
	sum := md5.Sum(png1)
	if c.bodies[1]["msgtype"] != "image" || img["md5"] != hex.EncodeToString(sum[:]) || img["base64"] != base64.StdEncoding.EncodeToString(png1) {
		t.Fatalf("%v", c.bodies[1])
	}
}

func TestEmailHTMLWithInlineChart(t *testing.T) {
	raw := Email{From: "fh@example.com", To: []string{"ops@example.com"}}.BuildMail(visual(), time.Now())
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	mt, params, _ := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if mt != "multipart/alternative" {
		t.Fatalf("top type %s", mt)
	}
	mr := multipart.NewReader(msg.Body, params["boundary"])
	text, _ := mr.NextPart()
	if !strings.HasPrefix(text.Header.Get("Content-Type"), "text/plain") {
		t.Fatal("first alternative must be plain text")
	}
	rel, _ := mr.NextPart()
	_, rp, _ := mime.ParseMediaType(rel.Header.Get("Content-Type"))
	rr := multipart.NewReader(rel, rp["boundary"])
	html, _ := rr.NextPart()
	hb, _ := base64.StdEncoding.DecodeString(strings.ReplaceAll(string(mustRead(html)), "\\r\\n", ""))
	if !strings.Contains(string(hb), `src="cid:requests"`) {
		t.Fatalf("html %s", hb)
	}
	img, _ := rr.NextPart()
	ib, _ := base64.StdEncoding.DecodeString(strings.ReplaceAll(string(mustRead(img)), "\\r\\n", ""))
	if img.Header.Get("Content-ID") != "<requests>" || !bytes.Equal(ib, png1) {
		t.Fatalf("inline image %v", img.Header)
	}
}

func TestFileSavesCharts(t *testing.T) {
	p := filepath.Join(t.TempDir(), "alerts.jsonl")
	if err := (File{Path: p}).Send(context.Background(), visual()); err != nil {
		t.Fatal(err)
	}
	var rec map[string]any
	_ = json.Unmarshal(bytes.TrimSpace(mustRead(must(os.Open(p)))), &rec)
	paths, _ := rec["images"].([]any)
	if len(paths) != 1 || rec["html"] != nil {
		t.Fatalf("record %v", rec)
	}
	if b, err := os.ReadFile(paths[0].(string)); err != nil || !bytes.Equal(b, png1) {
		t.Fatalf("chart file: %v", err)
	}
}

func must(f *os.File, err error) *os.File {
	if err != nil {
		panic(err)
	}
	return f
}
