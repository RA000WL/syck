package lsp

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/RA000WL/syck/internal/finding"
)

func TestURIToPath(t *testing.T) {
	tests := []struct {
		uri  string
		want string
	}{
		{"file:///home/user/main.go", "/home/user/main.go"},
		{"file:///C:/Users/test/main.go", "C:/Users/test/main.go"},
		{"/home/user/main.go", "/home/user/main.go"},
	}
	for _, tt := range tests {
		got := uriToPath(tt.uri)
		if got != tt.want {
			t.Errorf("uriToPath(%q) = %q, want %q", tt.uri, got, tt.want)
		}
	}
}

func TestFindingToSeverity(t *testing.T) {
	sevs := []finding.Severity{
		finding.SeverityInfo,
		finding.SeverityLow,
		finding.SeverityMedium,
		finding.SeverityHigh,
		finding.SeverityCritical,
	}
	for _, sev := range sevs {
		got := findingToSeverity(sev)
		if got < 1 || got > 4 {
			t.Errorf("findingToSeverity(%v) = %d, want 1-4", sev, got)
		}
	}
}

func TestServerSendMessage(t *testing.T) {
	var buf bytes.Buffer
	s := &Server{
		out:       &buf,
		documents: make(map[string]string),
	}

	err := s.send(Notification{
		JSONRPC: "2.0",
		Method:  "test",
		Params:  json.RawMessage(`{"key":"value"}`),
	})
	if err != nil {
		t.Fatal(err)
	}

	output := buf.String()
	if !strings.Contains(output, "Content-Length:") {
		t.Error("expected Content-Length header")
	}
	if !strings.Contains(output, `"method":"test"`) {
		t.Error("expected method in output")
	}
}

func TestServerSendResponse(t *testing.T) {
	var buf bytes.Buffer
	s := &Server{
		out:       &buf,
		documents: make(map[string]string),
	}

	s.sendResponse(json.RawMessage(`1`), InitializeResult{
		Capabilities: ServerCapabilities{},
	})

	output := buf.String()
	if !strings.Contains(output, `"result"`) {
		t.Error("expected result in response")
	}
}

func TestServerSendError(t *testing.T) {
	var buf bytes.Buffer
	s := &Server{
		out:       &buf,
		documents: make(map[string]string),
	}

	s.sendError(json.RawMessage(`1`), ErrMethodNotFound, "test error")

	output := buf.String()
	if !strings.Contains(output, `"error"`) {
		t.Error("expected error in response")
	}
	if !strings.Contains(output, "test error") {
		t.Error("expected error message")
	}
}
