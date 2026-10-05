package formatters

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/RA000WL/syck/internal/finding"
)

func TestPostWebhook_JSON(t *testing.T) {
	findings := []finding.Finding{
		{RuleName: "test", Severity: finding.SeverityHigh, Secret: "abc123"},
	}

	var received map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&received)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	err := PostWebhook(srv.URL, WebhookJSON, findings, WithAllowInsecure(true))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if received["source"] != "syck" {
		t.Fatalf("expected source=syck, got %v", received["source"])
	}
}

func TestPostWebhook_BadURL(t *testing.T) {
	err := PostWebhook("http://localhost:19999/nonexistent", WebhookJSON, nil, WithAllowInsecure(true))
	if err == nil {
		t.Fatal("expected error for bad URL")
	}
}

func TestPostWebhookRefusesPlainHTTP(t *testing.T) {
	err := PostWebhook("http://127.0.0.1:1/x", WebhookJSON, nil)
	if err == nil {
		t.Fatal("expected refusal of plain HTTP webhook URL without allow-insecure")
	}
	if !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("expected an explicit refusal error, got: %v", err)
	}
}

func TestPostWebhookAllowsPlainHTTPWithOptIn(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	// httptest serves plain http:// — only reachable via WithAllowInsecure.
	if err := PostWebhook(srv.URL, WebhookJSON, nil, WithAllowInsecure(true)); err != nil {
		t.Fatalf("expected opt-in to allow plain HTTP, got: %v", err)
	}
}

func TestSlackPayloadRedacts(t *testing.T) {
	const secret = "AKIAIOSFODNN7EXAMPLE"
	findings := []finding.Finding{
		{RuleName: "aws_key", Severity: finding.SeverityHigh, Secret: secret,
			Context: "line 7: aws_key = " + secret},
	}

	body := postWebhookCapturedBody(t, WebhookSlack, findings, WithRedact(true), WithAllowInsecure(true))
	if bytes.Contains(body, []byte(secret)) {
		t.Fatalf("full secret leaked in slack payload: %s", body)
	}
	if want := RedactSecret(secret); !bytes.Contains(body, []byte(want)) {
		t.Fatalf("expected redacted secret %q in slack payload: %s", want, body)
	}
}

func TestDiscordPayloadRedacts(t *testing.T) {
	const secret = "ghp_EXAMPLESECRETVALUE1234567890abcd"
	findings := []finding.Finding{
		{RuleName: "github_token", Severity: finding.SeverityCritical, Secret: secret,
			Context: "config.yml: token: " + secret},
	}

	body := postWebhookCapturedBody(t, WebhookDiscord, findings, WithRedact(true), WithAllowInsecure(true))
	if bytes.Contains(body, []byte(secret)) {
		t.Fatalf("full secret leaked in discord payload: %s", body)
	}
	if want := RedactSecret(secret); !bytes.Contains(body, []byte(want)) {
		t.Fatalf("expected redacted secret %q in discord payload: %s", want, body)
	}
}

func TestJSONPayloadRedacts(t *testing.T) {
	const secret = "sk_live_51EXAMPLEEXAMPLEEXAMPLE"
	findings := []finding.Finding{
		{RuleName: "stripe_key", Severity: finding.SeverityHigh, Secret: secret,
			Context: "payments.js: " + secret, ContextBefore: "before " + secret},
	}

	body := postWebhookCapturedBody(t, WebhookJSON, findings, WithRedact(true), WithAllowInsecure(true))
	if bytes.Contains(body, []byte(secret)) {
		t.Fatalf("full secret leaked in json payload: %s", body)
	}
	if want := RedactSecret(secret); !bytes.Contains(body, []byte(want)) {
		t.Fatalf("expected redacted secret %q in json payload: %s", want, body)
	}
}

func TestPostWebhookNoRedactByDefault(t *testing.T) {
	const secret = "PLAINTEXTDEFAULTSECRET1234"
	findings := []finding.Finding{
		{RuleName: "rule", Severity: finding.SeverityMedium, Secret: secret},
	}

	body := postWebhookCapturedBody(t, WebhookSlack, findings, WithAllowInsecure(true))
	if !bytes.Contains(body, []byte(secret)) {
		t.Fatalf("expected full secret when redact not set, got: %s", body)
	}
}

// postWebhookCapturedBody runs PostWebhook against a local HTTP test server and
// returns the raw request body the server received.
func postWebhookCapturedBody(t *testing.T, style WebhookStyle, findings []finding.Finding, opts ...WebhookOption) []byte {
	t.Helper()
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	if err := PostWebhook(srv.URL, style, findings, opts...); err != nil {
		t.Fatalf("PostWebhook failed: %v", err)
	}
	return body
}
