package formatters

import (
	"bytes"
	"encoding/json"
	"fmt"
	neturl "net/url"
	"os"
	"time"

	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/httpclient"
)

type WebhookStyle string

const (
	WebhookSlack   WebhookStyle = "slack"
	WebhookDiscord WebhookStyle = "discord"
	WebhookJSON    WebhookStyle = "json"
)

type WebhookOption func(*webhookConfig)

type webhookConfig struct {
	proxyURL string
}

func WithProxy(url string) WebhookOption {
	return func(c *webhookConfig) { c.proxyURL = url }
}

func PostWebhook(url string, style WebhookStyle, findings []finding.Finding, opts ...WebhookOption) error {
	var cfg webhookConfig
	for _, opt := range opts {
		opt(&cfg)
	}

	if parsedURL, err := neturl.Parse(url); err == nil && parsedURL.Scheme == "http" {
		fmt.Fprintf(os.Stderr, "[warning] webhook URL uses HTTP — secrets will be sent in plaintext\n")
	}

	var body []byte
	var err error

	switch style {
	case WebhookSlack:
		body, err = slackPayload(findings)
	case WebhookDiscord:
		body, err = discordPayload(findings)
	default:
		body, err = jsonPayload(findings)
	}
	if err != nil {
		return err
	}

	client := httpclient.NewClient(10*time.Second, cfg.proxyURL, false)
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}

type slackMsg struct {
	Text     string `json:"text"`
	Username string `json:"username,omitempty"`
	Mrkdwn   bool   `json:"mrkdwn"`
}

func slackPayload(findings []finding.Finding) ([]byte, error) {
	msg := fmt.Sprintf("*Syck Scan Results* — %d finding(s)\n", len(findings))
	for i, f := range findings {
		if i >= 10 {
			msg += fmt.Sprintf("... and %d more\n", len(findings)-10)
			break
		}
		msg += fmt.Sprintf("• [%s] %s — %s\n", finding.SeverityNames[f.Severity], f.RuleName, f.Secret)
	}
	return json.Marshal(slackMsg{Text: msg, Mrkdwn: true})
}

type discordEmbed struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Color       int    `json:"color"`
}

type discordMsg struct {
	Content string         `json:"content"`
	Embeds  []discordEmbed `json:"embeds,omitempty"`
}

func discordPayload(findings []finding.Finding) ([]byte, error) {
	var embeds []discordEmbed
	for i, f := range findings {
		if i >= 10 {
			break
		}
		description := f.RuleName + "\n" + f.Context
		if len(description) > 4096 {
			description = description[:4093] + "..."
		}
		embeds = append(embeds, discordEmbed{
			Title:       fmt.Sprintf("[%s] %s", finding.SeverityNames[f.Severity], f.RuleName),
			Description: description,
			Color:       15158332,
		})
	}
	return json.Marshal(discordMsg{
		Content: fmt.Sprintf("**Syck Scan** — %d finding(s)", len(findings)),
		Embeds:  embeds,
	})
}

func jsonPayload(findings []finding.Finding) ([]byte, error) {
	summary := BuildSummary(findings)
	output := map[string]interface{}{
		"summary":  summary,
		"findings": findings,
		"source":   "syck",
	}
	return json.Marshal(output)
}
