// Package notify delivers rendered reports to the user's channels.
// v1 ships a generic webhook and Telegram; Slack/Discord/mail are
// webhook-template variants on the roadmap (SPEC.md section 11).
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type Notifier interface {
	Send(ctx context.Context, text string) error
}

type httpPoster struct{ client *http.Client }

func poster() *httpPoster { return &httpPoster{client: &http.Client{Timeout: 30 * time.Second}} }

func (p *httpPoster) postJSON(ctx context.Context, url string, payload any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("notify: HTTP %d from %s", resp.StatusCode, url)
	}
	return nil
}

// Webhook posts {"text": "..."} to any endpoint that accepts JSON POSTs.
type Webhook struct{ URL string }

func (w Webhook) Send(ctx context.Context, text string) error {
	return poster().postJSON(ctx, w.URL, map[string]string{"text": text})
}

// Telegram sends via a Bot API token (from the environment) and chat ID.
type Telegram struct {
	BotToken string
	ChatID   string
}

func (t Telegram) Send(ctx context.Context, text string) error {
	url := "https://api.telegram.org/bot" + t.BotToken + "/sendMessage"
	return poster().postJSON(ctx, url, map[string]string{"chat_id": t.ChatID, "text": text})
}

// Multi fans out to every configured notifier and reports all failures.
type Multi []Notifier

func (m Multi) Send(ctx context.Context, text string) error {
	var errs []string
	for _, n := range m {
		if err := n.Send(ctx, text); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("notify: %s", strings.Join(errs, "; "))
	}
	return nil
}
