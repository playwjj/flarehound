// Package notify delivers rendered reports to the user's channels:
// generic webhook, Telegram, JSONL file, Slack, Discord, WeCom, Feishu
// and SMTP email (SPEC.md section 11).
//
// Delivery is never silently dropped: each send is retried 3 times, and
// a message that still fails goes to an on-disk outbox that is flushed
// at the start of the next round.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Message is one notification: the rendered text plus the structured
// facts a machine consumer (bridge, log pipeline) can route on.
type Message struct {
	Kind       string    `json:"kind"`               // "intraday" | "daily"
	Zone       string    `json:"zone"`               // zone name
	Decision   string    `json:"decision,omitempty"` // intraday: alert | changed | escalate | recovered
	WindowFrom time.Time `json:"window_from"`
	WindowTo   time.Time `json:"window_to"`
	Rules      []string  `json:"rules,omitempty"` // signal keys that fired
	Delayed    bool      `json:"delayed,omitempty"`
	Text       string    `json:"text"`
}

// Plain wraps bare text (tests, ad-hoc messages).
func Plain(text string) Message { return Message{Text: text} }

func (m Message) body() string {
	if m.Delayed {
		return "[delayed] " + m.Text
	}
	return m.Text
}

type Notifier interface {
	Send(ctx context.Context, m Message) error
	Name() string
}

var client = &http.Client{Timeout: 30 * time.Second}

// postJSON posts payload to endpoint. Errors deliberately never contain the
// URL: webhook URLs and the Telegram endpoint embed secrets.
func postJSON(ctx context.Context, endpoint string, payload any) error {
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
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

// Webhook posts {"text": "...", "kind": ..., "zone": ..., ...} to any
// endpoint that accepts JSON POSTs. "text" stays the primary field, so
// receivers that only read it keep working.
type Webhook struct{ URL string }

func (w Webhook) Name() string { return "webhook" }
func (w Webhook) Send(ctx context.Context, m Message) error {
	payload := m
	payload.Text = m.body()
	return postJSON(ctx, w.URL, payload)
}

// Telegram sends via a Bot API token (from the environment) and chat ID.
type Telegram struct {
	BotToken string
	ChatID   string
	APIBase  string // tests only; default https://api.telegram.org
}

func (t Telegram) Name() string { return "telegram" }
func (t Telegram) Send(ctx context.Context, m Message) error {
	text := m.body()
	base := t.APIBase
	if base == "" {
		base = "https://api.telegram.org"
	}
	// Telegram rejects messages over 4096 characters: split, like every
	// other channel, rather than cutting the report short.
	for _, part := range Split(text, 4096, runes) {
		if err := postJSON(ctx, base+"/bot"+t.BotToken+"/sendMessage", map[string]any{
			"chat_id": t.ChatID, "text": part, "disable_web_page_preview": true,
		}); err != nil {
			return err
		}
	}
	return nil
}

// Stdout prints messages instead of sending them (dry runs).
type Stdout struct{}

func (Stdout) Name() string { return "stdout" }
func (Stdout) Send(_ context.Context, m Message) error {
	fmt.Println(m.body())
	fmt.Println(strings.Repeat("-", 40))
	return nil
}

// File appends one JSON object per message to a local JSONL file — the
// channel for consumers that live next to FlareHound (a bridge that
// tails the file into a chat, a log shipper). Lines are appended with
// O_APPEND in a single write, so a reader never sees half a record.
type File struct{ Path string }

func (f File) Name() string { return "file" }
func (f File) Send(_ context.Context, m Message) error {
	rec := struct {
		TS     time.Time `json:"ts"`
		Source string    `json:"source"`
		Message
	}{time.Now().UTC(), "flarehound", m}
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(f.Path), 0o755); err != nil {
		return err
	}
	fh, err := os.OpenFile(f.Path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	if _, err := fh.Write(append(raw, '\n')); err != nil {
		fh.Close()
		return err
	}
	return fh.Close()
}

// Retry wraps a notifier with bounded retries and backoff.
type Retry struct {
	N        Notifier
	Attempts int
	Backoff  time.Duration
}

func (r Retry) Name() string { return r.N.Name() }
func (r Retry) Send(ctx context.Context, m Message) error {
	attempts := max(r.Attempts, 1)
	var err error
	for i := 0; i < attempts; i++ {
		if err = r.N.Send(ctx, m); err == nil {
			return nil
		}
		if i < attempts-1 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(r.Backoff * time.Duration(1<<i)):
			}
		}
	}
	return fmt.Errorf("%s: %w", r.N.Name(), err)
}

type pending struct {
	Channel string    `json:"channel"`
	Message Message   `json:"message"`
	Text    string    `json:"text,omitempty"` // outbox files written before structured messages
	Queued  time.Time `json:"queued"`
}

// Dispatcher fans a message out to every channel, retrying each, and
// parks per-channel failures in the outbox for the next round.
type Dispatcher struct {
	Channels []Notifier
	Outbox   string // path of the outbox JSON file
	MaxAge   time.Duration

	mu sync.Mutex
}

// NewDispatcher wraps each channel with 3 attempts and exponential backoff.
func NewDispatcher(outbox string, channels ...Notifier) *Dispatcher {
	d := &Dispatcher{Outbox: outbox, MaxAge: 48 * time.Hour}
	for _, c := range channels {
		d.Channels = append(d.Channels, Retry{N: c, Attempts: 3, Backoff: 2 * time.Second})
	}
	return d
}

// Send delivers a message everywhere; failures are queued, and the
// returned error lists them.
func (d *Dispatcher) Send(ctx context.Context, m Message) error {
	var errs []error
	var failed []pending
	for _, c := range d.Channels {
		if err := c.Send(ctx, m); err != nil {
			errs = append(errs, err)
			failed = append(failed, pending{Channel: c.Name(), Message: m, Queued: time.Now()})
		}
	}
	if len(failed) > 0 {
		d.mu.Lock()
		defer d.mu.Unlock()
		q, _ := d.load()
		if err := d.save(append(q, failed...)); err != nil {
			errs = append(errs, fmt.Errorf("outbox: %w", err))
		}
	}
	return errors.Join(errs...)
}

// Flush retries queued messages. Messages older than MaxAge are dropped
// (with an error), since a two-day-old alert is noise, not news.
func (d *Dispatcher) Flush(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	q, err := d.load()
	if err != nil || len(q) == 0 {
		return err
	}
	byName := map[string]Notifier{}
	for _, c := range d.Channels {
		byName[c.Name()] = c
	}
	var keep []pending
	var errs []error
	for _, p := range q {
		c, ok := byName[p.Channel]
		if !ok {
			continue // channel no longer configured
		}
		if d.MaxAge > 0 && time.Since(p.Queued) > d.MaxAge {
			errs = append(errs, fmt.Errorf("%s: dropped undeliverable message queued at %s", p.Channel, p.Queued.Format(time.RFC3339)))
			continue
		}
		m := p.Message
		if m.Text == "" {
			m.Text = p.Text
		}
		m.Delayed = true
		if err := c.Send(ctx, m); err != nil {
			keep = append(keep, p)
			errs = append(errs, err)
		}
	}
	if err := d.save(keep); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (d *Dispatcher) load() ([]pending, error) {
	if d.Outbox == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(d.Outbox)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var q []pending
	if err := json.Unmarshal(raw, &q); err != nil {
		return nil, fmt.Errorf("outbox corrupt: %w", err)
	}
	return q, nil
}

func (d *Dispatcher) save(q []pending) error {
	if d.Outbox == "" {
		return nil
	}
	if len(q) == 0 {
		err := os.Remove(d.Outbox)
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if err := os.MkdirAll(filepath.Dir(d.Outbox), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(q, "", "  ")
	if err != nil {
		return err
	}
	tmp := d.Outbox + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, d.Outbox)
}
