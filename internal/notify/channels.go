package notify

// Chat and mail channels (SPEC 11, v0.8). Each speaks its service's own
// payload, splits messages over the service's size limit, and checks the
// service's in-body error code — several bots answer HTTP 200 with an
// error inside, which must not count as delivered.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// postChecked posts JSON and, when check is set, validates the response
// body. Errors never contain the URL (it embeds a secret).
func postChecked(ctx context.Context, endpoint string, payload any, check func([]byte) error) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return errors.New("invalid endpoint URL")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			return fmt.Errorf("request failed: %v", ue.Err)
		}
		return errors.New("request failed")
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if check != nil {
		return check(body)
	}
	return nil
}

// postMultipart posts a form with one file. Errors never contain the URL.
func postMultipart(ctx context.Context, endpoint string, fields map[string]string, fileField, fileName string, data []byte, check func([]byte) error) error {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for k, v := range fields {
		_ = mw.WriteField(k, v)
	}
	fw, err := mw.CreateFormFile(fileField, fileName)
	if err != nil {
		return err
	}
	_, _ = fw.Write(data)
	_ = mw.Close()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, &body)
	if err != nil {
		return errors.New("invalid endpoint URL")
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			return fmt.Errorf("request failed: %v", ue.Err)
		}
		return errors.New("request failed")
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if check != nil {
		return check(b)
	}
	return nil
}

func clipRunes(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

// Split cuts text into chunks of at most max units (measured by size),
// preferring line breaks, and numbers them "(i/n)" when there is more
// than one. size is utf8.RuneCountInString or a byte length.
func Split(text string, max int, size func(string) int) []string {
	const reserve = 10 // room for the "(i/n) " prefix
	limit := max - reserve
	if size(text) <= max {
		return []string{text}
	}
	var chunks []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			chunks = append(chunks, strings.TrimRight(cur.String(), "\n"))
			cur.Reset()
		}
	}
	for _, line := range strings.SplitAfter(text, "\n") {
		for size(line) > limit { // a single over-long line: hard cut
			cut := line
			for size(cut) > limit {
				_, w := utf8.DecodeLastRuneInString(cut)
				cut = cut[:len(cut)-w]
			}
			flush()
			chunks = append(chunks, cut)
			line = line[len(cut):]
		}
		if size(cur.String())+size(line) > limit {
			flush()
		}
		cur.WriteString(line)
	}
	flush()
	for i := range chunks {
		chunks[i] = fmt.Sprintf("(%d/%d) %s", i+1, len(chunks), chunks[i])
	}
	return chunks
}

func runes(s string) int    { return utf8.RuneCountInString(s) }
func bytesLen(s string) int { return len(s) }

// ---- Slack (incoming webhook) ----

type Slack struct{ URL string }

func (Slack) Name() string { return "slack" }
func (s Slack) Send(ctx context.Context, m Message) error {
	for _, part := range Split(m.body(), 39000, runes) {
		if err := postChecked(ctx, s.URL, map[string]any{"text": part, "unfurl_links": false}, nil); err != nil {
			return err
		}
	}
	return nil
}

// ---- Discord (webhook) ----

type Discord struct{ URL string }

func (Discord) Name() string { return "discord" }
func (d Discord) Send(ctx context.Context, m Message) error {
	for _, part := range Split(m.body(), 2000, runes) {
		// allowed_mentions: never ping @everyone from an alert body.
		if err := postChecked(ctx, d.URL, map[string]any{"content": part, "allowed_mentions": map[string]any{"parse": []string{}}}, nil); err != nil {
			return err
		}
	}
	for _, img := range m.Images {
		payload, _ := json.Marshal(map[string]any{"content": clipRunes(img.Caption, 1900), "allowed_mentions": map[string]any{"parse": []string{}}})
		if err := postMultipart(ctx, d.URL, map[string]string{"payload_json": string(payload)}, "files[0]", img.Name+".png", img.PNG, nil); err != nil {
			return fmt.Errorf("image: %w", err)
		}
	}
	return nil
}

// ---- WeCom / 企业微信 group bot ----

type WeCom struct{ URL string }

func (WeCom) Name() string { return "wecom" }
func wecomCheck(b []byte) error {
	var r struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
	}
	if json.Unmarshal(b, &r) == nil && r.ErrCode != 0 {
		return fmt.Errorf("wecom errcode %d: %s", r.ErrCode, r.ErrMsg)
	}
	return nil
}

func (w WeCom) Send(ctx context.Context, m Message) error {
	for _, part := range Split(m.body(), 2048, bytesLen) {
		if err := postChecked(ctx, w.URL, map[string]any{"msgtype": "text", "text": map[string]string{"content": part}}, wecomCheck); err != nil {
			return err
		}
	}
	for _, img := range m.Images {
		if len(img.PNG) > 2<<20 { // the bot's image limit
			continue
		}
		sum := md5.Sum(img.PNG)
		if err := postChecked(ctx, w.URL, map[string]any{"msgtype": "image", "image": map[string]string{
			"base64": base64.StdEncoding.EncodeToString(img.PNG), "md5": hex.EncodeToString(sum[:]),
		}}, wecomCheck); err != nil {
			return fmt.Errorf("image: %w", err)
		}
	}
	return nil
}

// ---- Feishu / Lark custom bot (optional signature) ----

type Feishu struct {
	URL    string
	Secret string // signing secret; empty if the bot has no signature check
	Now    func() time.Time
}

func (Feishu) Name() string { return "feishu" }

// FeishuSign computes the bot signature: base64(HMAC-SHA256(key =
// "timestamp\nsecret", message = "")).
func FeishuSign(ts int64, secret string) string {
	mac := hmac.New(sha256.New, []byte(strconv.FormatInt(ts, 10)+"\n"+secret))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func (f Feishu) Send(ctx context.Context, m Message) error {
	now := time.Now
	if f.Now != nil {
		now = f.Now
	}
	for _, part := range Split(m.body(), 4000, runes) {
		payload := map[string]any{"msg_type": "text", "content": map[string]string{"text": part}}
		if f.Secret != "" {
			ts := now().Unix()
			payload["timestamp"] = strconv.FormatInt(ts, 10)
			payload["sign"] = FeishuSign(ts, f.Secret)
		}
		err := postChecked(ctx, f.URL, payload, func(b []byte) error {
			var r struct {
				Code int    `json:"code"`
				Msg  string `json:"msg"`
			}
			if json.Unmarshal(b, &r) == nil && r.Code != 0 {
				return fmt.Errorf("feishu code %d: %s", r.Code, r.Msg)
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// ---- Email (SMTP) ----

type Email struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	To       []string
	// TLS: "starttls" (default, port 587), "tls" (implicit, port 465) or
	// "none" (local relays only).
	TLS string
}

func (Email) Name() string { return "email" }

// subject is the message's first line (already "FlareHound · zone — …").
func subject(m Message) string {
	first, _, _ := strings.Cut(m.body(), "\n")
	if r := []rune(first); len(r) > 120 {
		first = string(r[:120]) + "…"
	}
	return first
}

func encodeHeader(s string) string {
	for _, r := range s {
		if r > 127 {
			return "=?UTF-8?B?" + base64.StdEncoding.EncodeToString([]byte(s)) + "?="
		}
	}
	return s
}

func b64Lines(b *bytes.Buffer, data []byte) {
	enc := base64.StdEncoding.EncodeToString(data)
	for len(enc) > 76 {
		b.WriteString(enc[:76] + "\r\n")
		enc = enc[76:]
	}
	b.WriteString(enc + "\r\n")
}

// BuildMail renders an RFC 5322 message. With HTML it is
// multipart/alternative (plain text for any client, HTML for the rest) and
// the charts ride inline as multipart/related parts referenced by cid:.
func (e Email) BuildMail(m Message, now time.Time) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "From: %s\r\n", e.From)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(e.To, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", encodeHeader(subject(m)))
	fmt.Fprintf(&b, "Date: %s\r\n", now.Format(time.RFC1123Z))
	b.WriteString("MIME-Version: 1.0\r\n")
	if m.Kind != "" {
		fmt.Fprintf(&b, "X-FlareHound-Kind: %s\r\n", m.Kind)
	}
	if m.HTML == "" {
		b.WriteString("Content-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n")
		b64Lines(&b, []byte(m.body()))
		return b.Bytes()
	}
	alt, rel := "fh-alt-"+strconv.FormatInt(now.UnixNano(), 36), "fh-rel-"+strconv.FormatInt(now.UnixNano()+1, 36)
	fmt.Fprintf(&b, "Content-Type: multipart/alternative; boundary=%q\r\n\r\n", alt)
	fmt.Fprintf(&b, "--%s\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n", alt)
	b64Lines(&b, []byte(m.body()))
	fmt.Fprintf(&b, "--%s\r\nContent-Type: multipart/related; boundary=%q\r\n\r\n", alt, rel)
	fmt.Fprintf(&b, "--%s\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n", rel)
	b64Lines(&b, []byte(m.HTML))
	for _, img := range m.Images {
		fmt.Fprintf(&b, "--%s\r\nContent-Type: image/png\r\nContent-Transfer-Encoding: base64\r\nContent-ID: <%s>\r\nContent-Disposition: inline; filename=%q\r\n\r\n",
			rel, img.Name, img.Name+".png")
		b64Lines(&b, img.PNG)
	}
	fmt.Fprintf(&b, "--%s--\r\n--%s--\r\n", rel, alt)
	return b.Bytes()
}

func (e Email) Send(ctx context.Context, m Message) error {
	if len(e.To) == 0 || e.From == "" || e.Host == "" {
		return errors.New("email: host, from and to are required")
	}
	port := e.Port
	mode := strings.ToLower(e.TLS)
	if mode == "" {
		mode = "starttls"
	}
	if port == 0 {
		port = map[string]int{"starttls": 587, "tls": 465, "none": 25}[mode]
	}
	addr := net.JoinHostPort(e.Host, strconv.Itoa(port))
	d := net.Dialer{Timeout: 30 * time.Second}
	var conn net.Conn
	var err error
	if mode == "tls" {
		conn, err = tls.DialWithDialer(&d, "tcp", addr, &tls.Config{ServerName: e.Host})
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("email: connect: %w", err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(time.Minute))
	}
	c, err := smtp.NewClient(conn, e.Host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("email: %w", err)
	}
	defer c.Close()
	if mode == "starttls" {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("email: server does not offer STARTTLS (set tls to \"tls\" or, for a local relay only, \"none\")")
		}
		if err := c.StartTLS(&tls.Config{ServerName: e.Host}); err != nil {
			return fmt.Errorf("email: starttls: %w", err)
		}
	}
	if e.Username != "" {
		if mode == "none" {
			return errors.New("email: refusing to send credentials without TLS")
		}
		if err := c.Auth(smtp.PlainAuth("", e.Username, e.Password, e.Host)); err != nil {
			return errors.New("email: authentication failed")
		}
	}
	if err := c.Mail(e.From); err != nil {
		return fmt.Errorf("email: MAIL FROM: %w", err)
	}
	for _, to := range e.To {
		if err := c.Rcpt(to); err != nil {
			return fmt.Errorf("email: RCPT TO %s: %w", to, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("email: DATA: %w", err)
	}
	if _, err := w.Write(e.BuildMail(m, time.Now())); err != nil {
		return fmt.Errorf("email: write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("email: %w", err)
	}
	return c.Quit()
}
