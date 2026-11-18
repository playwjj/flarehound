package notify

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

type capture struct {
	mu     sync.Mutex
	bodies []map[string]any
	reply  string
}

func (c *capture) server(t *testing.T) string {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		c.mu.Lock()
		c.bodies = append(c.bodies, m)
		c.mu.Unlock()
		if c.reply != "" {
			io.WriteString(w, c.reply)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/hook/SECRET"
}

func long(lines, width int) string {
	var b strings.Builder
	for i := 0; i < lines; i++ {
		b.WriteString(strings.Repeat("告", width) + "\n")
	}
	return b.String()
}

func TestSplit(t *testing.T) {
	if got := Split("short", 100, runes); len(got) != 1 || got[0] != "short" {
		t.Fatalf("%v", got)
	}
	parts := Split(long(30, 100), 2000, runes)
	if len(parts) < 2 {
		t.Fatal("not split")
	}
	for i, p := range parts {
		if utf8.RuneCountInString(p) > 2000 || !strings.HasPrefix(p, "("+strconv.Itoa(i+1)+"/") {
			t.Fatalf("part %d: %d runes, %q…", i, utf8.RuneCountInString(p), p[:20])
		}
	}
	// a single over-long line is hard-cut on rune boundaries, by bytes
	for _, p := range Split(strings.Repeat("告", 3000), 2048, bytesLen) {
		if len(p) > 2048 || !utf8.ValidString(p) {
			t.Fatalf("bad chunk: %d bytes, valid=%v", len(p), utf8.ValidString(p))
		}
	}
}

func TestSlackAndDiscord(t *testing.T) {
	c := &capture{}
	u := c.server(t)
	if err := (Slack{URL: u}).Send(context.Background(), Plain("hello")); err != nil {
		t.Fatal(err)
	}
	if c.bodies[0]["text"] != "hello" {
		t.Fatalf("slack %v", c.bodies[0])
	}
	c.bodies = nil
	if err := (Discord{URL: u}).Send(context.Background(), Plain(long(40, 100))); err != nil {
		t.Fatal(err)
	}
	if len(c.bodies) < 2 {
		t.Fatalf("discord not split: %d", len(c.bodies))
	}
	for _, b := range c.bodies {
		if utf8.RuneCountInString(b["content"].(string)) > 2000 || b["allowed_mentions"] == nil {
			t.Fatalf("discord payload %v", b)
		}
	}
}

func TestWeComErrcode(t *testing.T) {
	c := &capture{reply: `{"errcode":93000,"errmsg":"invalid webhook url"}`}
	err := (WeCom{URL: c.server(t)}).Send(context.Background(), Plain("x"))
	if err == nil || !strings.Contains(err.Error(), "93000") || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("HTTP 200 with errcode must fail without leaking the URL: %v", err)
	}
	c2 := &capture{reply: `{"errcode":0,"errmsg":"ok"}`}
	if err := (WeCom{URL: c2.server(t)}).Send(context.Background(), Plain("告警")); err != nil {
		t.Fatal(err)
	}
	if c2.bodies[0]["msgtype"] != "text" {
		t.Fatalf("wecom %v", c2.bodies[0])
	}
}

func TestFeishuSignature(t *testing.T) {
	c := &capture{reply: `{"code":0}`}
	ts := time.Unix(1700000000, 0)
	f := Feishu{URL: c.server(t), Secret: "s3cret", Now: func() time.Time { return ts }}
	if err := f.Send(context.Background(), Plain("告警")); err != nil {
		t.Fatal(err)
	}
	b := c.bodies[0]
	if b["timestamp"] != "1700000000" || b["sign"] != FeishuSign(1700000000, "s3cret") || b["msg_type"] != "text" {
		t.Fatalf("feishu %v", b)
	}
	// reference value: HMAC-SHA256 keyed with "1700000000\ns3cret" over an empty message
	if FeishuSign(1700000000, "s3cret") == FeishuSign(1700000001, "s3cret") {
		t.Fatal("signature must depend on the timestamp")
	}
	bad := &capture{reply: `{"code":19021,"msg":"sign match fail"}`}
	if err := (Feishu{URL: bad.server(t), Secret: "x"}).Send(context.Background(), Plain("x")); err == nil || !strings.Contains(err.Error(), "19021") {
		t.Fatalf("feishu error code: %v", err)
	}
}

// fakeSMTP speaks just enough SMTP to accept one message.
func fakeSMTP(t *testing.T) (port int, got chan string) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got = make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		say := func(s string) { io.WriteString(conn, s+"\r\n") }
		say("220 fake ESMTP")
		var data strings.Builder
		inData := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			if inData {
				if line == ".\r\n" {
					inData = false
					got <- data.String()
					say("250 ok")
					continue
				}
				data.WriteString(line)
				continue
			}
			switch cmd := strings.ToUpper(strings.TrimSpace(line)); {
			case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
				say("250 fake")
			case cmd == "DATA":
				inData = true
				say("354 go")
			case cmd == "QUIT":
				say("221 bye")
				return
			default:
				say("250 ok")
			}
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, got
}

func TestEmail(t *testing.T) {
	port, got := fakeSMTP(t)
	e := Email{Host: "127.0.0.1", Port: port, From: "fh@example.com", To: []string{"ops@example.com"}, TLS: "none"}
	m := Message{Kind: "intraday", Text: "FlareHound · example.com — 异常\nline 2"}
	if err := e.Send(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	mail := <-got
	if !strings.Contains(mail, "Subject: =?UTF-8?B?") || !strings.Contains(mail, "X-FlareHound-Kind: intraday") {
		t.Fatalf("headers:\n%s", mail)
	}
	_, body, _ := strings.Cut(mail, "\r\n\r\n")
	dec, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(strings.TrimSpace(body), "\r\n", ""))
	if err != nil || string(dec) != m.Text {
		t.Fatalf("body %q %v", dec, err)
	}
	// credentials are never sent in clear text
	e.Username, e.Password = "u", "p"
	port2, _ := fakeSMTP(t)
	e.Port = port2
	if err := e.Send(context.Background(), m); err == nil || !strings.Contains(err.Error(), "without TLS") {
		t.Fatalf("plaintext auth: %v", err)
	}
}

func TestEmailResend(t *testing.T) {
	type req struct {
		auth string
		body map[string]any
	}
	got := make(chan req, 1)
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		got <- req{r.Header.Get("Authorization"), m}
		w.WriteHeader(status)
		if status != http.StatusOK {
			_, _ = w.Write([]byte(`{"statusCode":403,"name":"validation_error","message":"The example.com domain is not verified."}`))
			return
		}
		_, _ = w.Write([]byte(`{"id":"x"}`))
	}))
	t.Cleanup(srv.Close)
	e := Email{Provider: "resend", APIURL: srv.URL, Password: "re_key", From: "FlareHound <fh@example.com>", To: []string{"ops@example.com"}}
	m := Message{Kind: "daily", Text: "FlareHound · example.com — 日报\nline 2", HTML: `<img src="cid:traffic">`,
		Images: []Image{{Name: "traffic", PNG: []byte("png")}}}
	if err := e.Send(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	r := <-got
	if r.auth != "Bearer re_key" || r.body["subject"] != "FlareHound · example.com — 日报" || r.body["text"] != m.Text || r.body["html"] != m.HTML {
		t.Fatalf("request %+v", r)
	}
	if h, _ := r.body["headers"].(map[string]any); h["X-FlareHound-Kind"] != "daily" {
		t.Fatalf("headers %v", r.body["headers"])
	}
	att, _ := r.body["attachments"].([]any)
	if len(att) != 1 {
		t.Fatalf("attachments %v", r.body["attachments"])
	}
	a := att[0].(map[string]any)
	if a["content_id"] != "traffic" || a["content"] != base64.StdEncoding.EncodeToString([]byte("png")) || a["filename"] != "traffic.png" {
		t.Fatalf("attachment %v", a)
	}
	// errors carry the API's message, never the key
	status = http.StatusForbidden
	err := e.Send(context.Background(), Message{Text: "x"})
	<-got
	if err == nil || !strings.Contains(err.Error(), "not verified") || strings.Contains(err.Error(), "re_key") {
		t.Fatalf("error: %v", err)
	}
	if err := (Email{Provider: "resend", From: "a@b", To: []string{"c@d"}}).Send(context.Background(), Message{Text: "x"}); err == nil {
		t.Fatal("resend without a key")
	}
}
