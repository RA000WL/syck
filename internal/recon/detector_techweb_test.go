package recon

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/RA000WL/syck/internal/finding"
)

func TestTechFingerprintWeb_WordPressDetection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8.2.10")
		w.Header().Set("Server", "Apache/2.4.57")
		w.Write([]byte(`<html><meta name="generator" content="WordPress 6.4" /><link href="/wp-content/themes/style.css" /><script src="/wp-includes/js/jquery.min.js"></script></html>`))
	}))
	defer srv.Close()

	d := NewTechFingerprintWeb(srv.Client())
	findings := d.Detect([]string{srv.URL + "/"})

	techs := make(map[string]bool)
	for _, f := range findings {
		techs[f.Source] = true
	}

	if !techs["tech_language_php"] {
		t.Error("expected PHP detection from X-Powered-By")
	}
	if !techs["tech_server_apache"] {
		t.Error("expected Apache detection from Server header")
	}
	if !techs["tech_cms_wordpress"] {
		t.Error("expected WordPress detection from meta generator")
	}
}

func TestTechFingerprintWeb_ExpressDetection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "Express")
		w.Header().Add("Set-Cookie", "connect.sid=s%3Aabc123; Path=/; HttpOnly")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := NewTechFingerprintWeb(srv.Client())
	findings := d.Detect([]string{srv.URL + "/"})

	techs := make(map[string]bool)
	for _, f := range findings {
		techs[f.Source] = true
	}

	if !techs["tech_framework_express"] {
		t.Error("expected Express detection from X-Powered-By")
	}
}

func TestTechFingerprintWeb_NextJsDetection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><script>window.__NEXT_DATA__ = {"props":{"pageProps":{}}}</script></html>`))
	}))
	defer srv.Close()

	d := NewTechFingerprintWeb(srv.Client())
	findings := d.Detect([]string{srv.URL + "/"})

	found := false
	for _, f := range findings {
		if f.Source == "tech_framework_nextjs" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected Next.js detection from __NEXT_DATA__")
	}
}

func TestTechFingerprintWeb_CloudflareDetection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cf-Ray", "7a1b2c3d4e5f-SJC")
		w.Header().Set("Server", "cloudflare")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := NewTechFingerprintWeb(srv.Client())
	findings := d.Detect([]string{srv.URL + "/"})

	techs := make(map[string]bool)
	for _, f := range findings {
		techs[f.Source] = true
	}

	if !techs["tech_infrastructure_cloudflare"] {
		t.Error("expected Cloudflare detection from Cf-Ray + Server")
	}
}

func TestTechFingerprintWeb_KubernetesAPIDetection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Kubernetes-Pf-Flowschema-Uid", "some-uid")
		w.Write([]byte(`{"kind":"Status","apiVersion":"v1","status":"Failure"}`))
	}))
	defer srv.Close()

	d := NewTechFingerprintWeb(srv.Client())
	findings := d.Detect([]string{srv.URL + "/"})

	techs := make(map[string]bool)
	for _, f := range findings {
		techs[f.Source] = true
	}

	if !techs["tech_infrastructure_kubernetes"] {
		t.Error("expected Kubernetes detection from header + body")
	}
}

func TestTechFingerprintWeb_OriginDeduplication(t *testing.T) {
	originHits := make(map[string]int)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits["origin"]++
		w.Header().Set("Server", "nginx/1.24.0")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := NewTechFingerprintWeb(srv.Client())
	urls := []string{
		srv.URL + "/",
		srv.URL + "/about",
		srv.URL + "/login?foo=bar",
	}
	findings := d.Detect(urls)

	if originHits["origin"] == 0 {
		t.Error("expected at least 1 request to the server")
	}

	nginxCount := 0
	for _, f := range findings {
		if f.Source == "tech_server_nginx" {
			nginxCount++
		}
	}
	if nginxCount != 1 {
		t.Errorf("nginx findings = %d, want 1 (origin dedup)", nginxCount)
	}
}

func TestTechFingerprintWeb_ConfidenceBelowThreshold(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Served-By", "cache-sjc")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := NewTechFingerprintWeb(srv.Client())
	findings := d.Detect([]string{srv.URL + "/"})

	for _, f := range findings {
		if f.Source == "tech_infrastructure_fastly" {
			t.Error("Fastly (confidence 50) should be filtered out below threshold 60")
		}
	}
}

func TestTechFingerprintWeb_HEADFallbackToGET(t *testing.T) {
	getCalled := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.WriteHeader(405)
			return
		}
		getCalled = true
		w.Header().Set("X-Powered-By", "PHP/8.1.0")
		w.Write([]byte(`<html><meta name="generator" content="WordPress 6.4" /></html>`))
	}))
	defer srv.Close()

	d := NewTechFingerprintWeb(srv.Client())
	findings := d.Detect([]string{srv.URL + "/"})

	if !getCalled {
		t.Error("GET fallback not called after HEAD 405")
	}

	foundPHP := false
	for _, f := range findings {
		if f.Source == "tech_language_php" {
			foundPHP = true
		}
	}
	if !foundPHP {
		t.Error("expected PHP detection via GET fallback")
	}
}

func TestTechFingerprintWeb_VersionExtraction(t *testing.T) {
	tests := []struct {
		header   string
		value    string
		wantVer  string
		wantTech string
	}{
		{"Server", "nginx/1.24.0", "1.24.0", "nginx"},
		{"Server", "Apache/2.4.57", "2.4.57", "apache"},
		{"Server", "Kestrel", "", "asp_net_core"},
		{"X-Powered-By", "PHP/8.2.10", "8.2.10", "php"},
		{"X-Powered-By", "Express/4.18.2", "4.18.2", "express"},
	}

	for _, tt := range tests {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(tt.header, tt.value)
			w.WriteHeader(200)
		}))

		d := NewTechFingerprintWeb(srv.Client())
		findings := d.Detect([]string{srv.URL + "/"})

		found := false
		for _, f := range findings {
			if strings.Contains(f.Source, tt.wantTech) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("header=%s value=%q: expected %s detection", tt.header, tt.value, tt.wantTech)
		}
		srv.Close()
	}
}

func TestTechFingerprintWeb_MetaGeneratorExtraction(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><meta name="generator" content="WordPress 6.4.2" /></html>`))
	}))
	defer srv.Close()

	d := NewTechFingerprintWeb(srv.Client())
	findings := d.Detect([]string{srv.URL + "/"})

	found := false
	for _, f := range findings {
		if f.Source == "tech_cms_wordpress" {
			found = true
			if f.Confidence < 60 {
				t.Errorf("WordPress confidence = %d, want >= 60", f.Confidence)
			}
		}
	}
	if !found {
		t.Error("expected WordPress detection from meta generator")
	}
}

func TestTechFingerprintWeb_EmptyBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.18.0")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := NewTechFingerprintWeb(srv.Client())
	findings := d.Detect([]string{srv.URL + "/"})

	found := false
	for _, f := range findings {
		if f.Source == "tech_server_nginx" {
			found = true
		}
	}
	if !found {
		t.Error("expected nginx detection from headers even with empty body")
	}
}

func TestTechFingerprintWeb_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()

	d := NewTechFingerprintWeb(srv.Client())
	findings := d.Detect([]string{srv.URL + "/"})

	if len(findings) != 0 {
		t.Errorf("expected 0 findings on server error, got %d", len(findings))
	}
}

func TestTechFingerprintWeb_ShopifyDetection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "shopify_track_uniqueness=1; Path=/")
		w.Write([]byte(`<html><script src="https://cdn.shopify.com/s/files/1/0001/0002/0003/t/1/assets/script.js"></script></html>`))
	}))
	defer srv.Close()

	d := NewTechFingerprintWeb(srv.Client())
	findings := d.Detect([]string{srv.URL + "/"})

	techs := make(map[string]bool)
	for _, f := range findings {
		techs[f.Source] = true
	}

	if !techs["tech_cms_shopify"] {
		t.Error("expected Shopify detection from cookie + CDN")
	}
}

func TestTechFingerprintWeb_jQueryVersionExtraction(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><script src="/js/jquery-3.6.0.min.js"></script></html>`))
	}))
	defer srv.Close()

	d := NewTechFingerprintWeb(srv.Client())
	findings := d.Detect([]string{srv.URL + "/"})

	found := false
	for _, f := range findings {
		if f.Source == "tech_library_jquery" {
			found = true
		}
	}
	if !found {
		t.Error("expected jQuery detection")
	}
}

func TestTechFingerprintWeb_LaravelCSRFToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "laravel_session=abc123; Path=/")
		w.Write([]byte(`<html><form><input type="hidden" name="_token" value="abc123"><meta name="csrf-token" content="abc123"></form></html>`))
	}))
	defer srv.Close()

	d := NewTechFingerprintWeb(srv.Client())
	findings := d.Detect([]string{srv.URL + "/"})

	found := false
	for _, f := range findings {
		if f.Source == "tech_framework_laravel" {
			found = true
		}
	}
	if !found {
		t.Error("expected Laravel detection from csrf-token + laravel_session cookie combined")
	}
}

func TestTechFingerprintWeb_NuxtJsDetection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><script>window.__NUXT__={}</script></html>`))
	}))
	defer srv.Close()

	d := NewTechFingerprintWeb(srv.Client())
	findings := d.Detect([]string{srv.URL + "/"})

	found := false
	for _, f := range findings {
		if f.Source == "tech_framework_nuxtjs" {
			found = true
		}
	}
	if !found {
		t.Error("expected Nuxt.js detection from __NUXT__")
	}
}

func TestTechFingerprintWeb_RemixDetection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><script>window.__remixContext = {};</script></html>`))
	}))
	defer srv.Close()

	d := NewTechFingerprintWeb(srv.Client())
	findings := d.Detect([]string{srv.URL + "/"})

	found := false
	for _, f := range findings {
		if f.Source == "tech_framework_remix" {
			found = true
		}
	}
	if !found {
		t.Error("expected Remix detection from __remixContext")
	}
}

func TestTechFingerprintWeb_ApolloDetection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><script>window.__APOLLO_STATE__ = {};</script></html>`))
	}))
	defer srv.Close()

	d := NewTechFingerprintWeb(srv.Client())
	findings := d.Detect([]string{srv.URL + "/"})

	found := false
	for _, f := range findings {
		if f.Source == "tech_library_apollo" {
			found = true
		}
	}
	if !found {
		t.Error("expected Apollo detection from __APOLLO_STATE__")
	}
}

func TestTechFingerprintWeb_DrupalDetection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><meta name="generator" content="Drupal 10" /><img src="/sites/default/files/logo.png"></html>`))
	}))
	defer srv.Close()

	d := NewTechFingerprintWeb(srv.Client())
	findings := d.Detect([]string{srv.URL + "/"})

	techs := make(map[string]bool)
	for _, f := range findings {
		techs[f.Source] = true
	}

	if !techs["tech_cms_drupal"] {
		t.Error("expected Drupal detection from meta generator + asset path")
	}
}

func TestTechFingerprintWeb_JoomlaDetection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><meta name="generator" content="Joomla! 4.4" /><a href="/administrator/">Admin</a></html>`))
	}))
	defer srv.Close()

	d := NewTechFingerprintWeb(srv.Client())
	findings := d.Detect([]string{srv.URL + "/"})

	found := false
	for _, f := range findings {
		if f.Source == "tech_cms_joomla" {
			found = true
		}
	}
	if !found {
		t.Error("expected Joomla detection")
	}
}

func TestTechFingerprintWeb_SpringBootDetection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Application-Context", "myapp:production:8080")
		w.Write([]byte(`<html><body><h1>Whitelabel Error Page</h1><p>No message available</p></body></html>`))
	}))
	defer srv.Close()

	d := NewTechFingerprintWeb(srv.Client())
	findings := d.Detect([]string{srv.URL + "/"})

	techs := make(map[string]bool)
	for _, f := range findings {
		techs[f.Source] = true
	}

	if !techs["tech_framework_spring_boot"] {
		t.Error("expected Spring Boot detection from header + body")
	}
}

func TestTechFingerprintWeb_FlaskDetection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Werkzeug/2.3.7 Python/3.11.0")
		w.Header().Add("Set-Cookie", "session=eyJhbGciOiJIUzI1NiJ9.sessionvalue; Path=/")
		w.Write([]byte(`<html><body>Werkzeug Debugger</body></html>`))
	}))
	defer srv.Close()

	d := NewTechFingerprintWeb(srv.Client())
	findings := d.Detect([]string{srv.URL + "/"})

	techs := make(map[string]bool)
	for _, f := range findings {
		techs[f.Source] = true
	}

	if !techs["tech_framework_flask"] {
		t.Error("expected Flask detection from Werkzeug + session cookie")
	}
}

func TestTechFingerprintWeb_DjangoDetection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "csrftoken=abc123; Path=/")
		w.Write([]byte(`<html><form><input type="hidden" name="csrfmiddlewaretoken" value="xyz"></form></html>`))
	}))
	defer srv.Close()

	d := NewTechFingerprintWeb(srv.Client())
	results := d.fetchAndAnalyze(srv.URL + "/")

	found := false
	for _, r := range results {
		if r.Technology == "django" {
			found = true
		}
	}
	if !found {
		t.Error("expected Django detection from csrftoken cookie")
	}
}

func TestTechFingerprintWeb_RubyDetection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "Phusion Passenger 6.0.18")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := NewTechFingerprintWeb(srv.Client())
	findings := d.Detect([]string{srv.URL + "/"})

	found := false
	for _, f := range findings {
		if f.Source == "tech_language_ruby" {
			found = true
		}
	}
	if !found {
		t.Error("expected Ruby detection from Phusion Passenger")
	}
}

func TestTechFingerprintWeb_ReactDevTools(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><script>window.__REACT_DEVTOOLS_GLOBAL_HOOK__ = {};</script></html>`))
	}))
	defer srv.Close()

	d := NewTechFingerprintWeb(srv.Client())
	results := d.fetchAndAnalyze(srv.URL + "/")

	found := false
	for _, r := range results {
		if r.Technology == "react" {
			found = true
		}
	}
	if !found {
		t.Error("expected React detection from __REACT_DEVTOOLS_GLOBAL_HOOK__")
	}
}

func TestTechFingerprintWeb_VueDataAttribute(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><div data-v-abc12345>Hello</div></html>`))
	}))
	defer srv.Close()

	d := NewTechFingerprintWeb(srv.Client())
	results := d.fetchAndAnalyze(srv.URL + "/")

	found := false
	for _, r := range results {
		if r.Technology == "vue" {
			found = true
		}
	}
	if !found {
		t.Error("expected Vue detection from data-v-* attribute")
	}
}

func TestTechFingerprintWeb_AngularDetection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><app ng-version="16.2.0">Hello</app></html>`))
	}))
	defer srv.Close()

	d := NewTechFingerprintWeb(srv.Client())
	results := d.fetchAndAnalyze(srv.URL + "/")

	found := false
	for _, r := range results {
		if r.Technology == "angular" {
			found = true
		}
	}
	if !found {
		t.Error("expected Angular detection from ng-version")
	}
}

func TestTechFingerprintWeb_PythonTraceback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><pre>Traceback (most recent call last):
  File "app.py", line 42, in handle
    result = divide(x, y)
ZeroDivisionError: division by zero</pre></html>`))
	}))
	defer srv.Close()

	d := NewTechFingerprintWeb(srv.Client())
	results := d.fetchAndAnalyze(srv.URL + "/")

	found := false
	for _, r := range results {
		if r.Technology == "python" {
			found = true
		}
	}
	if !found {
		t.Error("expected Python detection from traceback")
	}
}

func TestTechFingerprintWeb_GraphQLEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><a href="/graphql">GraphQL Playground</a><a href="/graphiql">GraphiQL</a></html>`))
	}))
	defer srv.Close()

	d := NewTechFingerprintWeb(srv.Client())
	findings := d.Detect([]string{srv.URL + "/"})

	found := false
	for _, f := range findings {
		if f.Source == "tech_exposed_graphql" {
			found = true
		}
	}
	if !found {
		t.Error("expected GraphQL detection from /graphql path")
	}
}

func TestTechFingerprintWeb_ConfidenceAccumulation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8.2.0")
		w.Header().Add("Set-Cookie", "PHPSESSID=abc123; Path=/")
		w.Write([]byte(`<html></html>`))
	}))
	defer srv.Close()

	d := NewTechFingerprintWeb(srv.Client())
	findings := d.Detect([]string{srv.URL + "/"})

	var phpFinding *SurfaceFinding
	for i, f := range findings {
		if f.Source == "tech_language_php" {
			phpFinding = &findings[i]
			break
		}
	}

	if phpFinding == nil {
		t.Fatal("expected PHP finding")
	}

	if phpFinding.Confidence != 99 {
		t.Errorf("PHP confidence = %d, want 99 (capped from 80+50=130)", phpFinding.Confidence)
	}
}

func TestTechFingerprintWeb_ConfidenceCapped99(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8.2.0")
		w.Header().Add("Set-Cookie", "PHPSESSID=abc123; Path=/")
		w.Write([]byte(`<html></html>`))
	}))
	defer srv.Close()

	d := NewTechFingerprintWeb(srv.Client())
	findings := d.Detect([]string{srv.URL + "/"})

	for _, f := range findings {
		if f.Confidence > 99 {
			t.Errorf("confidence = %d, exceeds cap of 99", f.Confidence)
		}
	}
}

func TestTechFingerprintWeb_ASPNetDetection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "ASP.NET_SessionId=abc123; Path=/")
		w.Write([]byte(`<html><form><input type="hidden" name="__RequestVerificationToken" value="xyz789"></form></html>`))
	}))
	defer srv.Close()

	d := NewTechFingerprintWeb(srv.Client())
	findings := d.Detect([]string{srv.URL + "/"})

	techs := make(map[string]bool)
	for _, f := range findings {
		techs[f.Source] = true
	}

	if !techs["tech_framework_asp_net"] {
		t.Error("expected ASP.NET detection from cookie + body token")
	}
}

func TestTechFingerprintWeb_ASPNetCoreApplication(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", ".AspNetCore.Session=CfDJ8abc; Path=/")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := NewTechFingerprintWeb(srv.Client())
	results := d.fetchAndAnalyze(srv.URL + "/")

	found := false
	for _, r := range results {
		if r.Technology == "asp_net_core" {
			found = true
		}
	}
	if !found {
		t.Error("expected ASP.NET Core detection from .AspNetCore.Session cookie")
	}
}

func TestTechFingerprintWeb_RailsSession(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "_rails_session=abc123def; Path=/")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := NewTechFingerprintWeb(srv.Client())
	results := d.fetchAndAnalyze(srv.URL + "/")

	found := false
	for _, r := range results {
		if r.Technology == "rails" {
			found = true
		}
	}
	if !found {
		t.Error("expected Rails detection from _rails_session cookie")
	}
}

func TestTechFingerprintWeb_GzipHandling(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Server", "nginx/1.24.0")
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		gz.Write([]byte(`<html><meta name="generator" content="WordPress 6.4" /></html>`))
		gz.Close()
		w.Write(buf.Bytes())
	}))
	defer srv.Close()

	d := NewTechFingerprintWeb(srv.Client())
	findings := d.Detect([]string{srv.URL + "/"})

	found := false
	for _, f := range findings {
		if f.Source == "tech_server_nginx" || f.Source == "tech_cms_wordpress" {
			found = true
		}
	}
	if !found {
		t.Error("expected detection from gzip-encoded response")
	}
}

func TestTechFingerprintWeb_KubernetesFlowschemaHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Kubernetes-Pf-Flowschema-Uid", "some-uid-value")
		w.WriteHeader(403)
	}))
	defer srv.Close()

	d := NewTechFingerprintWeb(srv.Client())
	findings := d.Detect([]string{srv.URL + "/"})

	found := false
	for _, f := range findings {
		if f.Source == "tech_infrastructure_kubernetes" {
			found = true
			if f.Severity != finding.SeverityHigh {
				t.Errorf("Kubernetes severity = %v, want HIGH", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected Kubernetes detection from Flowschema header")
	}
}

func TestTechFingerprintWeb_GraphQLSchemaString(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":{"__schema":{"queryType":{"name":"Query"}}}}`))
	}))
	defer srv.Close()

	d := NewTechFingerprintWeb(srv.Client())
	findings := d.Detect([]string{srv.URL + "/"})

	found := false
	for _, f := range findings {
		if f.Source == "tech_exposed_graphql" {
			found = true
		}
	}
	if !found {
		t.Error("expected GraphQL detection from __schema")
	}
}

func TestTechFingerprintWeb_AkamaiDetection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Akamai-Origin-Hop", "1")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := NewTechFingerprintWeb(srv.Client())
	findings := d.Detect([]string{srv.URL + "/"})

	found := false
	for _, f := range findings {
		if f.Source == "tech_infrastructure_akamai" {
			found = true
		}
	}
	if !found {
		t.Error("expected Akamai detection from Akamai-Origin-Hop header")
	}
}

func TestTechFingerprintWeb_VarnishDetection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Via", "1.1 varnish-v4")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := NewTechFingerprintWeb(srv.Client())
	results := d.fetchAndAnalyze(srv.URL + "/")

	found := false
	for _, r := range results {
		if r.Technology == "varnish" {
			found = true
		}
	}
	if !found {
		t.Error("expected Varnish detection from Via header")
	}
}

func TestTechFingerprintWeb_CloudHeadersAWS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Amz-Request-Id", "abc123")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := NewTechFingerprintWeb(srv.Client())
	results := d.fetchAndAnalyze(srv.URL + "/")

	found := false
	for _, r := range results {
		if r.Technology == "aws" {
			found = true
		}
	}
	if !found {
		t.Error("expected AWS detection from X-Amz-Request-Id")
	}
}

func TestTechFingerprintWeb_CloudHeadersAzure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Ms-Request-Id", "abc123")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := NewTechFingerprintWeb(srv.Client())
	results := d.fetchAndAnalyze(srv.URL + "/")

	found := false
	for _, r := range results {
		if r.Technology == "azure" {
			found = true
		}
	}
	if !found {
		t.Error("expected Azure detection from X-Ms-Request-Id")
	}
}

func TestTechFingerprintWeb_CloudHeadersGCP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Goog-Generation", "1234567890")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := NewTechFingerprintWeb(srv.Client())
	results := d.fetchAndAnalyze(srv.URL + "/")

	found := false
	for _, r := range results {
		if r.Technology == "gcp" {
			found = true
		}
	}
	if !found {
		t.Error("expected GCP detection from X-Goog-Generation")
	}
}

func TestTechFingerprintWeb_HugoDetection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><meta name="generator" content="Hugo 0.120.0" /></html>`))
	}))
	defer srv.Close()

	d := NewTechFingerprintWeb(srv.Client())
	findings := d.Detect([]string{srv.URL + "/"})

	found := false
	for _, f := range findings {
		if f.Source == "tech_framework_hugo" {
			found = true
		}
	}
	if !found {
		t.Error("expected Hugo detection from meta generator")
	}
}

func TestTechFingerprintWeb_KestrelDetection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Kestrel")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := NewTechFingerprintWeb(srv.Client())
	findings := d.Detect([]string{srv.URL + "/"})

	found := false
	for _, f := range findings {
		if f.Source == "tech_framework_asp_net_core" {
			found = true
		}
	}
	if !found {
		t.Error("expected ASP.NET Core detection from Kestrel server")
	}
}

func TestTechFingerprintWeb_LiteSpeedDetection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "LiteSpeed/1.7.16")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := NewTechFingerprintWeb(srv.Client())
	findings := d.Detect([]string{srv.URL + "/"})

	found := false
	for _, f := range findings {
		if f.Source == "tech_server_litespeed" {
			found = true
		}
	}
	if !found {
		t.Error("expected LiteSpeed detection from Server header")
	}
}

func TestTechFingerprintWeb_CaddyDetection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Caddy")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := NewTechFingerprintWeb(srv.Client())
	findings := d.Detect([]string{srv.URL + "/"})

	found := false
	for _, f := range findings {
		if f.Source == "tech_server_caddy" {
			found = true
		}
	}
	if !found {
		t.Error("expected Caddy detection from Server header")
	}
}

func TestTechFingerprintWeb_GunicornDetection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "gunicorn/21.2.0")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := NewTechFingerprintWeb(srv.Client())
	findings := d.Detect([]string{srv.URL + "/"})

	found := false
	for _, f := range findings {
		if f.Source == "tech_language_python" {
			found = true
		}
	}
	if !found {
		t.Error("expected Python detection from Gunicorn server")
	}
}

func TestTechFingerprintWeb_UvicornDetection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "uvicorn")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := NewTechFingerprintWeb(srv.Client())
	findings := d.Detect([]string{srv.URL + "/"})

	found := false
	for _, f := range findings {
		if f.Source == "tech_framework_fastapi" {
			found = true
		}
	}
	if !found {
		t.Error("expected FastAPI detection from Uvicorn server")
	}
}

func TestTechFingerprintWeb_EmptyURLList(t *testing.T) {
	d := NewTechFingerprintWeb(http.DefaultClient)
	findings := d.Detect([]string{})
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty URL list, got %d", len(findings))
	}
}

func TestTechFingerprintWeb_InvalidURL(t *testing.T) {
	d := NewTechFingerprintWeb(http.DefaultClient)
	findings := d.Detect([]string{"not-a-valid-url"})
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for invalid URL, got %d", len(findings))
	}
}

func TestTechFingerprintWeb_SourceFormat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.24.0")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := NewTechFingerprintWeb(srv.Client())
	findings := d.Detect([]string{srv.URL + "/"})

	for _, f := range findings {
		if !strings.HasPrefix(f.Source, "tech_") {
			t.Errorf("Source %q does not start with 'tech_'", f.Source)
		}
		parts := strings.SplitN(f.Source, "_", 3)
		if len(parts) < 3 {
			t.Errorf("Source %q should have format tech_<category>_<technology>", f.Source)
		}
	}
}

func TestTechFingerprintWeb_FastlyViaHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Served-By", "cache-sjc12345-SJC")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := NewTechFingerprintWeb(srv.Client())
	findings := d.Detect([]string{srv.URL + "/"})

	for _, f := range findings {
		if f.Source == "tech_infrastructure_fastly" {
			t.Error("Fastly (confidence 50) should be filtered below threshold 60")
		}
	}
}

func TestTechFingerprintWeb_JoomlaLowConfidenceFiltered(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><a href="/administrator/">Admin</a></html>`))
	}))
	defer srv.Close()

	d := NewTechFingerprintWeb(srv.Client())
	findings := d.Detect([]string{srv.URL + "/"})

	for _, f := range findings {
		if f.Source == "tech_cms_joomla" {
			t.Error("Joomla /administrator/ only (confidence 40) should be filtered below threshold")
		}
	}
}

func TestTechFingerprintWeb_PerlDetection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "Perl")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := NewTechFingerprintWeb(srv.Client())
	findings := d.Detect([]string{srv.URL + "/"})

	found := false
	for _, f := range findings {
		if f.Source == "tech_language_perl" {
			found = true
		}
	}
	if !found {
		t.Error("expected Perl detection from X-Powered-By")
	}
}

func TestTechFingerprintWeb_UvicornPoweredBy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "uvicorn")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := NewTechFingerprintWeb(srv.Client())
	findings := d.Detect([]string{srv.URL + "/"})

	found := false
	for _, f := range findings {
		if f.Source == "tech_server_uvicorn" {
			found = true
		}
	}
	if !found {
		t.Error("expected Uvicorn detection from X-Powered-By")
	}
}

func TestTechFingerprintWeb_MultipleServers(t *testing.T) {
	wpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8.2")
		w.Header().Set("Server", "Apache/2.4.57")
		fmt.Fprint(w, `<html><head><meta name="generator" content="WordPress 6.4"></head><body></body></html>`)
	}))
	defer wpServer.Close()

	expressServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "Express")
		w.Header().Set("Set-Cookie", "connect.sid=s%3Abigsecret")
		fmt.Fprint(w, `<html><body>Hello</body></html>`)
	}))
	defer expressServer.Close()

	nginxServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.24.0")
		fmt.Fprint(w, `<html><body>Hello</body></html>`)
	}))
	defer nginxServer.Close()

	d := NewTechFingerprintWeb(http.DefaultClient)
	findings := d.Detect([]string{wpServer.URL, expressServer.URL, nginxServer.URL})

	wpFound := false
	for _, f := range findings {
		if strings.Contains(f.Source, "wordpress") {
			wpFound = true
		}
	}
	if !wpFound {
		t.Error("WordPress not detected")
	}

	expressFound := false
	for _, f := range findings {
		if strings.Contains(f.Source, "express") {
			expressFound = true
		}
	}
	if !expressFound {
		t.Error("Express not detected")
	}

	nginxFound := false
	for _, f := range findings {
		if strings.Contains(f.Source, "nginx") {
			nginxFound = true
		}
	}
	if !nginxFound {
		t.Error("Nginx not detected")
	}
}
