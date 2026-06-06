package crawler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestJuicyProbe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.env", "/admin":
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(200)
			w.Write([]byte("SECRET=test"))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	cfg := JuicyConfig{
		Client:  srv.Client(),
		BaseURL: srv.URL,
		Paths:   []string{"/.env", "/admin", "/nope"},
	}
	findings := ProbeJuicy(cfg)

	if len(findings) != 2 {
		t.Errorf("expected 2 juicy findings, got %d: %v", len(findings), findings)
	}
}

func TestJuicyProbeRespectsSizeLimit(t *testing.T) {
	big := make([]byte, 2*1024*1024)
	for i := range big {
		big[i] = 'a'
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(200)
		w.Write(big)
	}))
	defer srv.Close()

	cfg := JuicyConfig{
		Client:  srv.Client(),
		BaseURL: srv.URL,
		Paths:   []string{"/.env"},
	}
	findings := ProbeJuicy(cfg)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for oversized file, got %d", len(findings))
	}
}
