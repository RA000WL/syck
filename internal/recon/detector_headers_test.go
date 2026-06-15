package recon

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/RA000WL/syck/internal/finding"
)

func TestDetectOrigin(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"https://example.com/path", "https://example.com"},
		{"https://example.com:8443/path", "https://example.com:8443"},
		{"http://localhost:3000/", "http://localhost:3000"},
		{"https://example.com", "https://example.com"},
	}
	for _, tt := range tests {
		got := detectOrigin(tt.url)
		if got != tt.want {
			t.Errorf("detectOrigin(%q) = %q, want %q", tt.url, got, tt.want)
		}
	}
}

func TestFetchHeaders_HEAD(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	client := srv.Client()
	hdr, cookies, status, err := fetchHeaders(client, srv.URL)
	if err != nil {
		t.Fatalf("fetchHeaders: %v", err)
	}
	if status != 200 {
		t.Fatalf("status = %d, want 200", status)
	}
	if hdr.Get("Content-Security-Policy") != "default-src 'self'" {
		t.Errorf("CSP = %q, want %q", hdr.Get("Content-Security-Policy"), "default-src 'self'")
	}
	if len(cookies) != 0 {
		t.Errorf("cookies = %d, want 0", len(cookies))
	}
}

func TestFetchHeaders_HEADFallbackToGET(t *testing.T) {
	getCalled := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.WriteHeader(405)
			return
		}
		getCalled = true
		w.Header().Set("X-Frame-Options", "DENY")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	client := srv.Client()
	hdr, _, status, err := fetchHeaders(client, srv.URL)
	if err != nil {
		t.Fatalf("fetchHeaders: %v", err)
	}
	if !getCalled {
		t.Error("GET fallback not called after HEAD 405")
	}
	if status != 200 {
		t.Fatalf("status = %d, want 200", status)
	}
	if hdr.Get("X-Frame-Options") != "DENY" {
		t.Errorf("XFO = %q, want DENY", hdr.Get("X-Frame-Options"))
	}
}

func TestFetchHeaders_CookiesParsed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "session=abc123; Path=/; HttpOnly; Secure; SameSite=Strict")
		w.Header().Add("Set-Cookie", "theme=dark; Path=/")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	client := srv.Client()
	_, cookies, _, err := fetchHeaders(client, srv.URL)
	if err != nil {
		t.Fatalf("fetchHeaders: %v", err)
	}
	if len(cookies) != 2 {
		t.Fatalf("cookies = %d, want 2", len(cookies))
	}
	if cookies[0].Name != "session" || cookies[0].Value != "abc123" {
		t.Errorf("cookie[0] = %s=%s, want session=abc123", cookies[0].Name, cookies[0].Value)
	}
	if !cookies[0].Secure {
		t.Error("cookie[0].Secure = false, want true")
	}
}

func TestSecurityHeaderDetector_DeduplicatesByOrigin(t *testing.T) {
	checkCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkCount++
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := NewSecurityHeaderDetector(srv.Client())
	// 3 URLs on same origin — should only check once
	urls := []string{
		srv.URL + "/",
		srv.URL + "/about",
		srv.URL + "/login",
	}
	findings := d.Detect(urls)

	_ = findings // check count matters here
	if checkCount != 1 {
		t.Errorf("checkCount = %d, want 1 (host-level dedup)", checkCount)
	}
}

// Task 2: CSP + HSTS + XFO tests

func TestAnalyzeCSP_Missing(t *testing.T) {
	hdr := http.Header{}
	findings := analyzeCSP(hdr)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Source != "missing-csp" || findings[0].Severity != finding.SeverityHigh {
		t.Errorf("got %s/%v, want missing-csp/HIGH", findings[0].Source, findings[0].Severity)
	}
}

func TestAnalyzeCSP_UnsafeInline(t *testing.T) {
	hdr := http.Header{}
	hdr.Set("Content-Security-Policy", "script-src 'self' 'unsafe-inline'")
	findings := analyzeCSP(hdr)
	for _, f := range findings {
		if f.Source == "weak-csp-unsafe-inline" && f.Severity == finding.SeverityMedium {
			return
		}
	}
	t.Error("expected weak-csp-unsafe-inline MEDIUM finding")
}

func TestAnalyzeCSP_UnsafeEval(t *testing.T) {
	hdr := http.Header{}
	hdr.Set("Content-Security-Policy", "script-src 'self' 'unsafe-eval'")
	findings := analyzeCSP(hdr)
	for _, f := range findings {
		if f.Source == "weak-csp-unsafe-eval" && f.Severity == finding.SeverityMedium {
			return
		}
	}
	t.Error("expected weak-csp-unsafe-eval MEDIUM finding")
}

func TestAnalyzeCSP_Wildcard(t *testing.T) {
	hdr := http.Header{}
	hdr.Set("Content-Security-Policy", "default-src *")
	findings := analyzeCSP(hdr)
	for _, f := range findings {
		if f.Source == "weak-csp-wildcard" && f.Severity == finding.SeverityMedium {
			return
		}
	}
	t.Error("expected weak-csp-wildcard MEDIUM finding")
}

func TestAnalyzeCSP_Good(t *testing.T) {
	hdr := http.Header{}
	hdr.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'")
	findings := analyzeCSP(hdr)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for good CSP, got %d: %v", len(findings), findings)
	}
}

func TestAnalyzeHSTS_Missing(t *testing.T) {
	hdr := http.Header{}
	findings := analyzeHSTS(hdr)
	if len(findings) != 1 || findings[0].Source != "missing-hsts" {
		t.Errorf("expected missing-hsts, got %v", findings)
	}
}

func TestAnalyzeHSTS_Weak(t *testing.T) {
	hdr := http.Header{}
	hdr.Set("Strict-Transport-Security", "max-age=300")
	findings := analyzeHSTS(hdr)
	if len(findings) != 1 || findings[0].Source != "weak-hsts" {
		t.Errorf("expected weak-hsts, got %v", findings)
	}
}

func TestAnalyzeHSTS_Good(t *testing.T) {
	hdr := http.Header{}
	hdr.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	findings := analyzeHSTS(hdr)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for good HSTS, got %d", len(findings))
	}
}

func TestAnalyzeXFO_Missing(t *testing.T) {
	hdr := http.Header{}
	findings := analyzeXFO(hdr)
	if len(findings) != 1 || findings[0].Source != "missing-xfo" {
		t.Errorf("expected missing-xfo, got %v", findings)
	}
}

func TestAnalyzeXFO_WithCSPFrameAncestors(t *testing.T) {
	hdr := http.Header{}
	hdr.Set("Content-Security-Policy", "frame-ancestors 'self'")
	findings := analyzeXFO(hdr)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when CSP has frame-ancestors, got %d", len(findings))
	}
}

func TestAnalyzeXFO_Present(t *testing.T) {
	hdr := http.Header{}
	hdr.Set("X-Frame-Options", "DENY")
	findings := analyzeXFO(hdr)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

// Task 3: CORS tests

func TestAnalyzeCORS_Wildcard(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := NewSecurityHeaderDetector(srv.Client())
	hdr, _, _, _ := fetchHeaders(d.client, srv.URL)
	findings := d.analyzeCORS(hdr, srv.URL)
	for _, f := range findings {
		if f.Source == "cors-wildcard" && f.Severity == finding.SeverityMedium {
			return
		}
	}
	t.Error("expected cors-wildcard MEDIUM")
}

func TestAnalyzeCORS_WildcardCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := NewSecurityHeaderDetector(srv.Client())
	hdr, _, _, _ := fetchHeaders(d.client, srv.URL)
	findings := d.analyzeCORS(hdr, srv.URL)
	for _, f := range findings {
		if f.Source == "cors-wildcard-credentials" && f.Severity == finding.SeverityHigh {
			return
		}
	}
	t.Error("expected cors-wildcard-credentials HIGH")
}

func TestAnalyzeCORS_OriginReflection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		} else {
			// Return a non-wildcard ACAO so analyzeCORS proceeds to reflection test
			w.Header().Set("Access-Control-Allow-Origin", "https://legit.example.com")
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := NewSecurityHeaderDetector(srv.Client())
	hdr, _, _, _ := fetchHeaders(d.client, srv.URL)
	findings := d.analyzeCORS(hdr, srv.URL)
	for _, f := range findings {
		if f.Source == "cors-origin-reflection" && f.Severity == finding.SeverityHigh {
			return
		}
	}
	t.Error("expected cors-origin-reflection HIGH")
}

func TestAnalyzeCORS_SafeOrigin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://example.com")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := NewSecurityHeaderDetector(srv.Client())
	hdr, _, _, _ := fetchHeaders(d.client, srv.URL)
	findings := d.analyzeCORS(hdr, srv.URL)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for safe CORS, got %d: %v", len(findings), findings)
	}
}

// Task 4: XCTO, Referrer-Policy, Permissions-Policy, Cookies, Server Info tests

func TestAnalyzeXCTO_Missing(t *testing.T) {
	hdr := http.Header{}
	findings := analyzeXCTO(hdr)
	if len(findings) != 1 || findings[0].Source != "missing-xcto" {
		t.Errorf("expected missing-xcto, got %v", findings)
	}
}

func TestAnalyzeXCTO_Present(t *testing.T) {
	hdr := http.Header{}
	hdr.Set("X-Content-Type-Options", "nosniff")
	findings := analyzeXCTO(hdr)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestAnalyzeReferrerPolicy_Missing(t *testing.T) {
	hdr := http.Header{}
	findings := analyzeReferrerPolicy(hdr)
	if len(findings) != 1 || findings[0].Source != "missing-referrer-policy" || findings[0].Severity != finding.SeverityInfo {
		t.Errorf("expected missing-referrer-policy INFO, got %v", findings)
	}
}

func TestAnalyzePermissionsPolicy_Missing(t *testing.T) {
	hdr := http.Header{}
	findings := analyzePermissionsPolicy(hdr)
	if len(findings) != 1 || findings[0].Source != "missing-permissions-policy" || findings[0].Severity != finding.SeverityInfo {
		t.Errorf("expected missing-permissions-policy INFO, got %v", findings)
	}
}

func TestAnalyzeCookies_NoSecure(t *testing.T) {
	cookies := []*http.Cookie{{Name: "session", Value: "abc"}}
	findings := analyzeCookies(cookies)
	for _, f := range findings {
		if f.Source == "cookie-no-secure" {
			return
		}
	}
	t.Error("expected cookie-no-secure")
}

func TestAnalyzeCookies_NoHttpOnly(t *testing.T) {
	cookies := []*http.Cookie{{Name: "session", Value: "abc", Secure: true}}
	findings := analyzeCookies(cookies)
	for _, f := range findings {
		if f.Source == "cookie-no-httponly" {
			return
		}
	}
	t.Error("expected cookie-no-httponly")
}

func TestAnalyzeCookies_NoSameSite(t *testing.T) {
	cookies := []*http.Cookie{{Name: "session", Value: "abc", Secure: true, HttpOnly: true}}
	findings := analyzeCookies(cookies)
	for _, f := range findings {
		if f.Source == "cookie-no-samesite" {
			return
		}
	}
	t.Error("expected cookie-no-samesite")
}

func TestAnalyzeCookies_Good(t *testing.T) {
	cookies := []*http.Cookie{{
		Name:     "session",
		Value:    "abc",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}}
	findings := analyzeCookies(cookies)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for good cookie, got %d: %v", len(findings), findings)
	}
}

func TestAnalyzeServerInfo_ServerVersion(t *testing.T) {
	hdr := http.Header{}
	hdr.Set("Server", "Apache/2.4.12")
	findings := analyzeServerInfo(hdr)
	for _, f := range findings {
		if f.Source == "server-version-disclosure" {
			return
		}
	}
	t.Error("expected server-version-disclosure")
}

func TestAnalyzeServerInfo_XPoweredBy(t *testing.T) {
	hdr := http.Header{}
	hdr.Set("X-Powered-By", "PHP/5.6")
	findings := analyzeServerInfo(hdr)
	for _, f := range findings {
		if f.Source == "x-powered-by-disclosure" {
			return
		}
	}
	t.Error("expected x-powered-by-disclosure")
}

func TestAnalyzeServerInfo_NoVersion(t *testing.T) {
	hdr := http.Header{}
	hdr.Set("Server", "nginx")
	findings := analyzeServerInfo(hdr)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for versionless Server header, got %d", len(findings))
	}
}

// Task 5: Security.txt tests

func TestCheckSecurityTxt_Missing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/security.txt" {
			w.WriteHeader(404)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := NewSecurityHeaderDetector(srv.Client())
	origin := detectOrigin(srv.URL)
	findings := d.checkSecurityTxt(srv.Client(), origin)
	if len(findings) != 1 || findings[0].Source != "missing-security-txt" {
		t.Errorf("expected missing-security-txt, got %v", findings)
	}
}

func TestCheckSecurityTxt_Present(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/security.txt" {
			w.WriteHeader(200)
			w.Write([]byte("Contact: mailto:security@example.com"))
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := NewSecurityHeaderDetector(srv.Client())
	origin := detectOrigin(srv.URL)
	findings := d.checkSecurityTxt(srv.Client(), origin)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d: %v", len(findings), findings)
	}
}

// Task 7: Integration test

func TestSecurityHeaderDetector_FullIntegration(t *testing.T) {
	// Server 1: missing everything
	srvBad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srvBad.Close()

	// Server 2: weak CSP + CORS wildcard + cookies + server version
	srvWeak := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src * 'unsafe-inline' 'unsafe-eval'")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Add("Set-Cookie", "session=abc123; Path=/")
		w.Header().Set("Server", "nginx/1.18.0")
		w.WriteHeader(200)
	}))
	defer srvWeak.Close()

	// Server 3: all good headers
	srvGood := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=()")
		w.Header().Set("X-Powered-By", "Express")
		w.WriteHeader(200)
	}))
	defer srvGood.Close()

	d := NewSecurityHeaderDetector(srvBad.Client())
	urls := []string{
		srvBad.URL + "/",
		srvWeak.URL + "/api",
		srvGood.URL + "/secure",
	}

	findings := d.Detect(urls)
	if len(findings) == 0 {
		t.Fatal("expected findings, got none")
	}

	sourceSet := make(map[string]bool)
	for _, f := range findings {
		sourceSet[f.Source] = true
	}

	// Server 1 (bad): missing-csp, missing-xfo, missing-xcto, missing-referrer-policy, missing-permissions-policy
	if !sourceSet["missing-csp"] {
		t.Error("expected missing-csp from bad server")
	}
	if !sourceSet["missing-xfo"] {
		t.Error("expected missing-xfo from bad server")
	}

	// Server 2 (weak): weak-csp-wildcard, weak-csp-unsafe-inline, weak-csp-unsafe-eval, cors-wildcard-credentials, server-version-disclosure
	if !sourceSet["weak-csp-wildcard"] {
		t.Error("expected weak-csp-wildcard from weak server")
	}
	if !sourceSet["weak-csp-unsafe-inline"] {
		t.Error("expected weak-csp-unsafe-inline from weak server")
	}
	if !sourceSet["weak-csp-unsafe-eval"] {
		t.Error("expected weak-csp-unsafe-eval from weak server")
	}
	if !sourceSet["cors-wildcard-credentials"] {
		t.Error("expected cors-wildcard-credentials from weak server")
	}
	if !sourceSet["server-version-disclosure"] {
		t.Error("expected server-version-disclosure from weak server")
	}

	// Server 3 (good): no additional bad findings from this origin
	// (missing-csp and missing-xfo are from server 1, not server 3)
}
