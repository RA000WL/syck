package crawler

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/httpclient"
)

var defaultJuicyPaths = []string{
	// Environment files
	"/.env", "/.env.local", "/.env.production", "/.env.development",
	"/.env.staging", "/.env.test", "/.env.backup", "/.env.old",
	"/env.json", "/env.yaml", "/env.yml",

	// Configuration files
	"/config.json", "/config.yaml", "/config.yml", "/config.js",
	"/config.ts", "/config.php", "/config.py", "/config.rb",
	"/settings.json", "/settings.yaml", "/settings.yml",
	"/application.yml", "/application.yaml", "/application.properties",

	// API documentation (high value for recon)
	"/swagger.json", "/swagger.yaml", "/swagger-ui.html",
	"/openapi.json", "/openapi.yaml", "/openapi.yml",
	"/api-docs", "/v3/api-docs", "/v2/api-docs", "/v1/api-docs",
	"/docs", "/api/docs", "/api/swagger",
	"/redoc", "/rapidoc",

	// Spring Boot Actuator endpoints
	"/actuator", "/actuator/env", "/actuator/configprops", "/actuator/beans",
	"/actuator/mappings", "/actuator/health", "/actuator/info",
	"/actuator/metrics", "/actuator/trace", "/actuator/httptrace",
	"/actuator/threaddump", "/actuator/heapdump", "/actuator/loggers",
	"/actuator/conditions", "/actuator/scheduledtasks", "/actuator/caches",
	"/actuator/sessions", "/actuator/shutdown",

	// Monitoring & metrics
	"/metrics", "/prometheus", "/prometheus/metrics",
	"/health", "/healthcheck", "/health/check", "/healthz", "/ready",
	"/info", "/version", "/status",

	// Server info
	"/server-status", "/server-info", "/server-info.php",

	// Cross-domain & security files
	"/crossdomain.xml", "/clientaccesspolicy.xml",
	"/.htaccess", "/.htpasswd",

	// Version control exposure (high severity)
	"/.git/HEAD", "/.git/config", "/.gitignore", "/.gitmodules",
	"/.gitattributes", "/.git/logs/HEAD",
	"/.svn/entries", "/.svn/wc.db",
	"/.hg/store/00manifest.i",

	// robots.txt & sitemaps
	"/robots.txt", "/sitemap.xml", "/sitemap_index.xml",

	// PHP info/test files
	"/phpinfo.php", "/info.php", "/test.php", "/debug.php",
	"/php.php", "/test-info.php", "/test.php",

	// Admin panels
	"/admin", "/administrator", "/admin/login", "/admin/dashboard",
	"/wp-admin", "/wp-login.php", "/wp-config.php.bak",
	"/phpmyadmin", "/pma", "/adminer.php",

	// Debug/trace endpoints
	"/elmah.axd", "/trace.axd", "/debug/vars", "/debug/pprof/",
	"/debug/requests", "/debug/events",

	// .well-known paths (important for recon)
	"/.well-known/security.txt", "/.well-known/openid-configuration",
	"/.well-known/jwks.json", "/.well-known/change-password",
	"/.well-known/host-meta", "/.well-known/apple-app-site-association",

	// Backup / archive discovery
	"/backup", "/backup.sql", "/backup.zip", "/backup.tar.gz",
	"/backup.tar.bz2", "/backup.tgz", "/backup.rar",
	"/db", "/db.sql", "/database.sql", "/dump.sql", "/dump.zip",
	"/data", "/data.sql", "/data.zip", "/data.tar.gz",
	"/exports", "/export.sql", "/export.zip",
	"/uploads", "/uploads.zip", "/uploads.tar.gz",
	"/site.zip", "/source.zip", "/src.zip", "/code.zip",
	"/app.zip", "/www.zip", "/web.zip", "/public.zip",

	// System files
	"/.DS_Store", "/Thumbs.db", "/.env.swp", "/.env.swo",

	// Package manager files
	"/package.json", "/package-lock.json", "/yarn.lock",
	"/composer.json", "/composer.lock",
	"/Gemfile", "/Gemfile.lock",
	"/go.mod", "/go.sum",
	"/requirements.txt", "/Pipfile", "/poetry.lock",
	"/Cargo.toml", "/Cargo.lock",
	"/pom.xml", "/build.gradle",

	// Docker & Kubernetes
	"/Dockerfile", "/docker-compose.yml", "/docker-compose.yaml",
	"/docker-compose.override.yml", "/.dockerignore",
	"/.docker/config.json",

	// CI/CD & DevOps
	"/Jenkinsfile", "/.gitlab-ci.yml", "/.github/workflows/",
	"/.circleci/config.yml", "/.travis.yml", "/bitbucket-pipelines.yml",

	// Terraform & Infrastructure
	"/.terraform", "/.terraform.lock.hcl", "/terraform.tfstate",
	"/terraform.tfstate.backup", "/.terraform.tfstate",
	"/variables.tf", "/main.tf", "/outputs.tf",

	// Secrets & credentials (high severity)
	"/secrets.yml", "/secrets.yaml", "/secrets.json",
	"/credentials", "/credentials.json", "/credentials.yaml",
	"/.htpasswd", "/.netrc", "/.ssh/id_rsa",
	"/service-account.json", "/sa-key.json",

	// Source maps (expose original source code)
	"/js/app.js.map", "/js/main.js.map", "/static/js/*.js.map",
	"/assets/*.js.map", "/dist/*.js.map",

	// Common sensitive paths
	"/server.log", "/app.log", "/error.log", "/access.log",
	"/debug.log", "/application.log",
	"/php_errors.log", "/wp-content/debug.log",

	// GraphQL endpoints
	"/graphql", "/graphiql", "/graphql/console", "/playground",

	// Database admin interfaces
	"/adminer", "/adminer.php", "/dbadmin", "/sql",
}

const maxJuicyBodyBytes = 1 << 20

type JuicyConfig struct {
	Client    *http.Client
	BaseURL   string
	Paths     []string
	UserAgent string
}

type JuicyFinding struct {
	URL         string
	Path        string
	ContentType string
	Body        string
}

func ProbeJuicy(cfg JuicyConfig) []JuicyFinding {
	if cfg.Client == nil {
		cfg.Client = httpclient.NewClient(10*time.Second, "", false)
	}
	base, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return nil
	}
	paths := cfg.Paths
	if len(paths) == 0 {
		paths = defaultJuicyPaths
	}

	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		results []JuicyFinding
		limit   = make(chan struct{}, 5)
	)

	for _, p := range paths {
		target := *base
		target.Path = strings.TrimRight(base.Path, "/") + p
		raw := target.String()

		wg.Add(1)
		limit <- struct{}{}
		go func(rawURL string) {
			defer wg.Done()
			defer func() { <-limit }()

			ua := cfg.UserAgent
			if ua == "" {
				ua = "syck/1.1"
			}

			req, err := http.NewRequest("HEAD", rawURL, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", ua)
			resp, err := cfg.Client.Do(req)
			if err != nil {
				return
			}
			resp.Body.Close()
			if resp.StatusCode != 200 {
				return
			}
			req2, err := http.NewRequest("GET", rawURL, nil)
			if err != nil {
				return
			}
			req2.Header.Set("User-Agent", ua)
			resp2, err := cfg.Client.Do(req2)
			if err != nil {
				return
			}
			defer resp2.Body.Close()
			if resp2.ContentLength > maxJuicyBodyBytes {
				return
			}
			body, _ := io.ReadAll(io.LimitReader(resp2.Body, maxJuicyBodyBytes+1))
			if len(body) > maxJuicyBodyBytes {
				_, _ = io.Copy(io.Discard, resp2.Body)
				return
			}

			getContentType := resp2.Header.Get("Content-Type")
			if getContentType == "" {
				getContentType = "application/octet-stream"
			}

			mu.Lock()
			results = append(results, JuicyFinding{
				URL:         rawURL,
				Path:        p,
				ContentType: getContentType,
				Body:        string(body),
			})
			mu.Unlock()
		}(raw)
	}
	wg.Wait()
	return results
}

func (j JuicyFinding) ToFinding() finding.Finding {
	return finding.Finding{
		File:      j.URL,
		Line:      1,
		Column:    0,
		RuleName:  "juicy_file",
		Severity:  finding.SeverityMedium,
		RiskScore: 0,
		Secret:    fmt.Sprintf("%s [%s]", j.Path, j.ContentType),
		Context:   truncate(j.Body, 200),
		Entropy:   0.0,
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
