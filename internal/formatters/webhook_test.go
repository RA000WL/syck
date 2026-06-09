package formatters

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

	err := PostWebhook(srv.URL, WebhookJSON, findings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if received["source"] != "syck" {
		t.Fatalf("expected source=syck, got %v", received["source"])
	}
}

func TestPostWebhook_BadURL(t *testing.T) {
	err := PostWebhook("http://localhost:19999/nonexistent", WebhookJSON, nil)
	if err == nil {
		t.Fatal("expected error for bad URL")
	}
}
