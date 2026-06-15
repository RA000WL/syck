package recon

import (
	"compress/gzip"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/RA000WL/syck/internal/finding"
)

type TechEvidence struct {
	Signal string
}

type TechFindResult struct {
	URL        string
	Technology string
	Version    string
	Category   string
	Confidence int
	Evidence   []TechEvidence
	Severity   finding.Severity
}

type TechFingerprintWeb struct {
	client *http.Client
}

func NewTechFingerprintWeb(client *http.Client) *TechFingerprintWeb {
	return &TechFingerprintWeb{client: client}
}

func (d *TechFingerprintWeb) Detect(urls []string) []SurfaceFinding {
	seen := make(map[string]bool)
	var allResults []TechFindResult

	for _, u := range urls {
		origin := detectOrigin(u)
		if origin == "" || seen[origin] {
			continue
		}
		seen[origin] = true

		results := d.fetchAndAnalyze(u)
		allResults = append(allResults, results...)
	}

	return d.buildFindings(allResults)
}

func (d *TechFingerprintWeb) fetchAndAnalyze(rawURL string) []TechFindResult {
	hdr, cookies, status, body := d.fetchAll(rawURL)
	if status >= 500 || status == 0 {
		return nil
	}

	var results []TechFindResult
	results = append(results, analyzeTechHeaders(hdr)...)
	results = append(results, analyzeBody(body)...)
	results = append(results, analyzeTechCookies(cookies)...)
	for i := range results {
		results[i].URL = rawURL
	}
	return results
}

func (d *TechFingerprintWeb) fetchAll(rawURL string) (http.Header, []*http.Cookie, int, string) {
	status, hdr, cookies, body, err := d.doFullRequest("HEAD", rawURL)
	if err == nil && status != 405 && status != 403 && status < 500 {
		getBody := d.fetchBody(rawURL)
		return hdr, cookies, status, getBody
	}

	status, hdr, cookies, body, err = d.doFullRequest("GET", rawURL)
	if err != nil {
		return nil, nil, 0, ""
	}
	return hdr, cookies, status, body
}

func (d *TechFingerprintWeb) fetchBody(rawURL string) string {
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Range", "bytes=0-0")
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Syck/1.0)")

	resp, err := d.client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	var bodyReader io.Reader = resp.Body
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gr, gErr := gzip.NewReader(resp.Body)
		if gErr == nil {
			defer gr.Close()
			bodyReader = gr
		}
	}

	limited := io.LimitReader(bodyReader, 50*1024)
	bodyBytes, _ := io.ReadAll(limited)
	return string(bodyBytes)
}

func (d *TechFingerprintWeb) doFullRequest(method, rawURL string) (int, http.Header, []*http.Cookie, string, error) {
	req, err := http.NewRequest(method, rawURL, nil)
	if err != nil {
		return 0, nil, nil, "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Syck/1.0)")
	if method == http.MethodGet {
		req.Header.Set("Range", "bytes=0-0")
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return 0, nil, nil, "", err
	}
	defer resp.Body.Close()

	var bodyReader io.Reader = resp.Body
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gr, gErr := gzip.NewReader(resp.Body)
		if gErr == nil {
			defer gr.Close()
			bodyReader = gr
		}
	}

	limited := io.LimitReader(bodyReader, 50*1024)
	bodyBytes, _ := io.ReadAll(limited)
	return resp.StatusCode, resp.Header, resp.Cookies(), string(bodyBytes), nil
}

func (d *TechFingerprintWeb) buildFindings(results []TechFindResult) []SurfaceFinding {
	acc := make(map[string]*TechFindResult)

	for _, r := range results {
		key := r.Technology
		if existing, ok := acc[key]; ok {
			existing.Confidence += r.Confidence
			if existing.Confidence > 99 {
				existing.Confidence = 99
			}
			if r.Severity > existing.Severity {
				existing.Severity = r.Severity
			}
			existing.Evidence = append(existing.Evidence, r.Evidence...)
			if existing.Version == "" {
				existing.Version = r.Version
			}
		} else {
			cp := r
			if cp.Confidence > 99 {
				cp.Confidence = 99
			}
			acc[key] = &cp
		}
	}

	var out []SurfaceFinding
	for _, tech := range acc {
		if tech.Confidence < 60 {
			continue
		}
		out = append(out, SurfaceFinding{
			URL:        tech.URL,
			Category:   tech.Category,
			Severity:   tech.Severity,
			Confidence: tech.Confidence,
			Source:     "tech_" + tech.Category + "_" + tech.Technology,
		})
	}
	return out
}

var (
	phpVersionRE     = regexp.MustCompile(`(?i)PHP/(\d+\.\d+(?:\.\d+)?)`)
	expressVersionRE = regexp.MustCompile(`(?i)Express/(\d+\.\d+(?:\.\d+)?)`)
	aspNetVersionRE  = regexp.MustCompile(`(?i)ASP\.NET/(\d+\.\d+(?:\.\d+)?)`)
	nginxVersionRE   = regexp.MustCompile(`(?i)nginx/(\d+\.\d+(?:\.\d+)?)`)
	apacheVersionRE  = regexp.MustCompile(`(?i)Apache/(\d+\.\d+(?:\.\d+)?)`)
	kestrelVersionRE = regexp.MustCompile(`(?i)Kestrel/(\d+\.\d+(?:\.\d+)?)`)
	cloudflareVerRE  = regexp.MustCompile(`(?i)cloudflare/(\d+)`)
	litespeedVerRE   = regexp.MustCompile(`(?i)LiteSpeed/(\d+\.\d+(?:\.\d+)?)`)
	caddyVerRE       = regexp.MustCompile(`(?i)Caddy`)
	jqueryVersionRE  = regexp.MustCompile(`jquery[/-](\d+\.\d+(?:\.\d+)*)\.min\.js`)
	generatorVerRE   = regexp.MustCompile(`(?i)<meta[^>]+name\s*=\s*["']generator["'][^>]+content\s*=\s*["']([^"']+)["']`)
	ngVersionRE      = regexp.MustCompile(`ng-version="([^"]+)"`)
	springBootErrRE  = regexp.MustCompile(`Whitelabel Error Page`)
	graphqlPathRE    = regexp.MustCompile(`(?i)/graphql[\s"'/>]|/graphiql[\s"'/>]`)
	schemaRE         = regexp.MustCompile(`__schema`)
	reactDevToolsRE  = regexp.MustCompile(`__REACT_DEVTOOLS_GLOBAL_HOOK__`)
	vueDataRE        = regexp.MustCompile(`data-v-[a-f0-9]+`)
	angularAppRE     = regexp.MustCompile(`ng-app="[^"]+"`)
	nextDataRE       = regexp.MustCompile(`__NEXT_DATA__`)
	nuxtDataRE       = regexp.MustCompile(`__NUXT__`)
	remixContextRE   = regexp.MustCompile(`__remixContext`)
	apolloStateRE    = regexp.MustCompile(`__APOLLO_STATE__`)
	wpContentRE      = regexp.MustCompile(`wp-content/`)
	wpIncludesRE     = regexp.MustCompile(`wp-includes/`)
	drupalFilesRE    = regexp.MustCompile(`sites/default/files/`)
	shopifyCDNRE     = regexp.MustCompile(`cdn\.shopify\.com`)
	joomlaAdminRE    = regexp.MustCompile(`/administrator/`)
	xmlrpcRE         = regexp.MustCompile(`xmlrpc\.php`)
	csrfTokenRE      = regexp.MustCompile(`(?i)csrf[-_]token`)
	werkzeugRE       = regexp.MustCompile(`(?i)Werkzeug`)
	reqVerifTokenRE  = regexp.MustCompile(`__RequestVerificationToken`)
	k8sStatusRE      = regexp.MustCompile(`"kind"\s*:\s*"Status"`)
)

func analyzeTechHeaders(headers http.Header) []TechFindResult {
	var results []TechFindResult

	if xpb := headers.Get("X-Powered-By"); xpb != "" {
		results = append(results, analyzePoweredBy(xpb)...)
	}

	if server := headers.Get("Server"); server != "" {
		results = append(results, analyzeServerHeader(server)...)
	}

	if ctx := headers.Get("X-Application-Context"); ctx != "" {
		results = append(results, TechFindResult{
			Technology: "spring_boot",
			Category:   "framework",
			Confidence: 80,
			Severity:   finding.SeverityMedium,
			Evidence:   []TechEvidence{{Signal: "X-Application-Context: " + ctx}},
		})
	}

	if headers.Get("X-Kubernetes-Pf-Flowschema-Uid") != "" {
		results = append(results, TechFindResult{
			Technology: "kubernetes",
			Category:   "infrastructure",
			Confidence: 90,
			Severity:   finding.SeverityHigh,
			Evidence:   []TechEvidence{{Signal: "X-Kubernetes-Pf-Flowschema-Uid"}},
		})
	}

	results = append(results, analyzeCloudHeaders(headers)...)
	results = append(results, analyzeCDNHeaders(headers)...)

	return results
}

func analyzePoweredBy(xpb string) []TechFindResult {
	var results []TechFindResult
	xpbLower := strings.ToLower(xpb)

	switch {
	case strings.Contains(xpbLower, "php"):
		ver := extractVersion(phpVersionRE, xpb)
		results = append(results, TechFindResult{
			Technology: "php",
			Version:    ver,
			Category:   "language",
			Confidence: 80,
			Severity:   finding.SeverityLow,
			Evidence:   []TechEvidence{{Signal: "X-Powered-By: " + xpb}},
		})
	case strings.Contains(xpbLower, "express"):
		ver := extractVersion(expressVersionRE, xpb)
		results = append(results, TechFindResult{
			Technology: "express",
			Version:    ver,
			Category:   "framework",
			Confidence: 80,
			Severity:   finding.SeverityMedium,
			Evidence:   []TechEvidence{{Signal: "X-Powered-By: " + xpb}},
		})
	case strings.Contains(xpbLower, "asp.net"):
		ver := extractVersion(aspNetVersionRE, xpb)
		results = append(results, TechFindResult{
			Technology: "asp_net",
			Version:    ver,
			Category:   "framework",
			Confidence: 80,
			Severity:   finding.SeverityMedium,
			Evidence:   []TechEvidence{{Signal: "X-Powered-By: " + xpb}},
		})
	case strings.Contains(xpbLower, "ruby") || strings.Contains(xpbLower, "passenger"):
		results = append(results, TechFindResult{
			Technology: "ruby",
			Category:   "language",
			Confidence: 80,
			Severity:   finding.SeverityLow,
			Evidence:   []TechEvidence{{Signal: "X-Powered-By: " + xpb}},
		})
	case strings.Contains(xpbLower, "perl"):
		results = append(results, TechFindResult{
			Technology: "perl",
			Category:   "language",
			Confidence: 80,
			Severity:   finding.SeverityLow,
			Evidence:   []TechEvidence{{Signal: "X-Powered-By: " + xpb}},
		})
	case strings.Contains(xpbLower, "uvicorn"):
		results = append(results, TechFindResult{
			Technology: "uvicorn",
			Category:   "server",
			Confidence: 80,
			Severity:   finding.SeverityLow,
			Evidence:   []TechEvidence{{Signal: "X-Powered-By: " + xpb}},
		})
	}
	return results
}

func analyzeServerHeader(server string) []TechFindResult {
	var results []TechFindResult
	serverLower := strings.ToLower(server)

	switch {
	case strings.Contains(serverLower, "nginx"):
		ver := extractVersion(nginxVersionRE, server)
		results = append(results, TechFindResult{
			Technology: "nginx",
			Version:    ver,
			Category:   "server",
			Confidence: 60,
			Severity:   finding.SeverityLow,
			Evidence:   []TechEvidence{{Signal: "Server: " + server}},
		})
	case strings.Contains(serverLower, "apache"):
		ver := extractVersion(apacheVersionRE, server)
		results = append(results, TechFindResult{
			Technology: "apache",
			Version:    ver,
			Category:   "server",
			Confidence: 60,
			Severity:   finding.SeverityLow,
			Evidence:   []TechEvidence{{Signal: "Server: " + server}},
		})
	case strings.Contains(serverLower, "cloudflare"):
		ver := extractVersion(cloudflareVerRE, server)
		results = append(results, TechFindResult{
			Technology: "cloudflare",
			Version:    ver,
			Category:   "infrastructure",
			Confidence: 70,
			Severity:   finding.SeverityLow,
			Evidence:   []TechEvidence{{Signal: "Server: " + server}},
		})
	case strings.Contains(serverLower, "kestrel"):
		ver := extractVersion(kestrelVersionRE, server)
		results = append(results, TechFindResult{
			Technology: "asp_net_core",
			Version:    ver,
			Category:   "framework",
			Confidence: 70,
			Severity:   finding.SeverityMedium,
			Evidence:   []TechEvidence{{Signal: "Server: " + server}},
		})
	case strings.Contains(serverLower, "gunicorn"):
		results = append(results, TechFindResult{
			Technology: "python",
			Category:   "language",
			Confidence: 60,
			Severity:   finding.SeverityLow,
			Evidence:   []TechEvidence{{Signal: "Server: " + server}},
		})
	case strings.Contains(serverLower, "uvicorn"):
		results = append(results, TechFindResult{
			Technology: "fastapi",
			Category:   "framework",
			Confidence: 60,
			Severity:   finding.SeverityMedium,
			Evidence:   []TechEvidence{{Signal: "Server: " + server}},
		})
	case strings.Contains(serverLower, "litespeed"):
		ver := extractVersion(litespeedVerRE, server)
		results = append(results, TechFindResult{
			Technology: "litespeed",
			Version:    ver,
			Category:   "server",
			Confidence: 60,
			Severity:   finding.SeverityLow,
			Evidence:   []TechEvidence{{Signal: "Server: " + server}},
		})
	case strings.Contains(serverLower, "caddy"):
		results = append(results, TechFindResult{
			Technology: "caddy",
			Category:   "server",
			Confidence: 60,
			Severity:   finding.SeverityLow,
			Evidence:   []TechEvidence{{Signal: "Server: " + server}},
		})
	}
	return results
}

func analyzeCloudHeaders(headers http.Header) []TechFindResult {
	var results []TechFindResult

	if headers.Get("X-Amz-Request-Id") != "" {
		results = append(results, TechFindResult{
			Technology: "aws",
			Category:   "infrastructure",
			Confidence: 50,
			Severity:   finding.SeverityLow,
			Evidence:   []TechEvidence{{Signal: "X-Amz-Request-Id"}},
		})
	}
	if headers.Get("X-Amz-Cf-Id") != "" || strings.ToLower(headers.Get("X-Cache")) == "cloudfront" {
		results = append(results, TechFindResult{
			Technology: "cloudfront",
			Category:   "infrastructure",
			Confidence: 60,
			Severity:   finding.SeverityLow,
			Evidence:   []TechEvidence{{Signal: "CloudFront header"}},
		})
	}
	if headers.Get("X-Ms-Request-Id") != "" {
		results = append(results, TechFindResult{
			Technology: "azure",
			Category:   "infrastructure",
			Confidence: 50,
			Severity:   finding.SeverityLow,
			Evidence:   []TechEvidence{{Signal: "X-Ms-Request-Id"}},
		})
	}
	if headers.Get("X-Goog-Generation") != "" {
		results = append(results, TechFindResult{
			Technology: "gcp",
			Category:   "infrastructure",
			Confidence: 50,
			Severity:   finding.SeverityLow,
			Evidence:   []TechEvidence{{Signal: "X-Goog-Generation"}},
		})
	}

	return results
}

func analyzeCDNHeaders(headers http.Header) []TechFindResult {
	var results []TechFindResult

	if headers.Get("Cf-Ray") != "" {
		results = append(results, TechFindResult{
			Technology: "cloudflare",
			Category:   "infrastructure",
			Confidence: 60,
			Severity:   finding.SeverityLow,
			Evidence:   []TechEvidence{{Signal: "Cf-Ray"}},
		})
	}
	if headers.Get("Akamai-Origin-Hop") != "" {
		results = append(results, TechFindResult{
			Technology: "akamai",
			Category:   "infrastructure",
			Confidence: 60,
			Severity:   finding.SeverityLow,
			Evidence:   []TechEvidence{{Signal: "Akamai-Origin-Hop"}},
		})
	}
	if xsh := headers.Get("X-Served-By"); xsh != "" {
		results = append(results, TechFindResult{
			Technology: "fastly",
			Category:   "infrastructure",
			Confidence: 50,
			Severity:   finding.SeverityLow,
			Evidence:   []TechEvidence{{Signal: "X-Served-By: " + xsh}},
		})
	}
	if via := headers.Get("Via"); strings.Contains(strings.ToLower(via), "varnish") {
		results = append(results, TechFindResult{
			Technology: "varnish",
			Category:   "infrastructure",
			Confidence: 50,
			Severity:   finding.SeverityLow,
			Evidence:   []TechEvidence{{Signal: "Via: " + via}},
		})
	}

	return results
}

func analyzeBody(body string) []TechFindResult {
	var results []TechFindResult

	if m := generatorVerRE.FindStringSubmatch(body); len(m) > 1 {
		gen := strings.TrimSpace(m[1])
		genLower := strings.ToLower(gen)
		switch {
		case strings.Contains(genLower, "wordpress"):
			ver := extractVersionString(gen, `(?i)WordPress\s+(\d+\.\d+(?:\.\d+)?)`)
			results = append(results, TechFindResult{
				Technology: "wordpress",
				Version:    ver,
				Category:   "cms",
				Confidence: 80,
				Severity:   finding.SeverityHigh,
				Evidence:   []TechEvidence{{Signal: "meta generator: " + gen}},
			})
		case strings.Contains(genLower, "drupal"):
			results = append(results, TechFindResult{
				Technology: "drupal",
				Category:   "cms",
				Confidence: 80,
				Severity:   finding.SeverityHigh,
				Evidence:   []TechEvidence{{Signal: "meta generator: " + gen}},
			})
		case strings.Contains(genLower, "joomla"):
			results = append(results, TechFindResult{
				Technology: "joomla",
				Category:   "cms",
				Confidence: 80,
				Severity:   finding.SeverityHigh,
				Evidence:   []TechEvidence{{Signal: "meta generator: " + gen}},
			})
		case strings.Contains(genLower, "hugo"):
			results = append(results, TechFindResult{
				Technology: "hugo",
				Category:   "framework",
				Confidence: 80,
				Severity:   finding.SeverityMedium,
				Evidence:   []TechEvidence{{Signal: "meta generator: " + gen}},
			})
		case strings.Contains(genLower, "jekyll"):
			results = append(results, TechFindResult{
				Technology: "jekyll",
				Category:   "framework",
				Confidence: 80,
				Severity:   finding.SeverityMedium,
				Evidence:   []TechEvidence{{Signal: "meta generator: " + gen}},
			})
		case strings.Contains(genLower, "next.js") || strings.Contains(genLower, "nextjs"):
			results = append(results, TechFindResult{
				Technology: "nextjs",
				Category:   "framework",
				Confidence: 80,
				Severity:   finding.SeverityMedium,
				Evidence:   []TechEvidence{{Signal: "meta generator: " + gen}},
			})
		case strings.Contains(genLower, "nuxt"):
			results = append(results, TechFindResult{
				Technology: "nuxtjs",
				Category:   "framework",
				Confidence: 80,
				Severity:   finding.SeverityMedium,
				Evidence:   []TechEvidence{{Signal: "meta generator: " + gen}},
			})
		}
	}

	if nextDataRE.MatchString(body) {
		results = append(results, TechFindResult{
			Technology: "nextjs",
			Category:   "framework",
			Confidence: 80,
			Severity:   finding.SeverityMedium,
			Evidence:   []TechEvidence{{Signal: "__NEXT_DATA__"}},
		})
	}
	if nuxtDataRE.MatchString(body) {
		results = append(results, TechFindResult{
			Technology: "nuxtjs",
			Category:   "framework",
			Confidence: 80,
			Severity:   finding.SeverityMedium,
			Evidence:   []TechEvidence{{Signal: "__NUXT__"}},
		})
	}
	if remixContextRE.MatchString(body) {
		results = append(results, TechFindResult{
			Technology: "remix",
			Category:   "framework",
			Confidence: 80,
			Severity:   finding.SeverityMedium,
			Evidence:   []TechEvidence{{Signal: "__remixContext"}},
		})
	}
	if apolloStateRE.MatchString(body) {
		results = append(results, TechFindResult{
			Technology: "apollo",
			Category:   "library",
			Confidence: 70,
			Severity:   finding.SeverityLow,
			Evidence:   []TechEvidence{{Signal: "__APOLLO_STATE__"}},
		})
	}

	if wpContentRE.MatchString(body) || wpIncludesRE.MatchString(body) {
		results = append(results, TechFindResult{
			Technology: "wordpress",
			Category:   "cms",
			Confidence: 60,
			Severity:   finding.SeverityHigh,
			Evidence:   []TechEvidence{{Signal: "wp-content/wp-includes asset"}},
		})
	}
	if drupalFilesRE.MatchString(body) {
		results = append(results, TechFindResult{
			Technology: "drupal",
			Category:   "cms",
			Confidence: 60,
			Severity:   finding.SeverityHigh,
			Evidence:   []TechEvidence{{Signal: "sites/default/files/"}},
		})
	}
	if shopifyCDNRE.MatchString(body) {
		results = append(results, TechFindResult{
			Technology: "shopify",
			Category:   "cms",
			Confidence: 70,
			Severity:   finding.SeverityHigh,
			Evidence:   []TechEvidence{{Signal: "cdn.shopify.com"}},
		})
	}
	if joomlaAdminRE.MatchString(body) {
		results = append(results, TechFindResult{
			Technology: "joomla",
			Category:   "cms",
			Confidence: 40,
			Severity:   finding.SeverityHigh,
			Evidence:   []TechEvidence{{Signal: "/administrator/"}},
		})
	}
	if xmlrpcRE.MatchString(body) {
		results = append(results, TechFindResult{
			Technology: "wordpress",
			Category:   "cms",
			Confidence: 70,
			Severity:   finding.SeverityHigh,
			Evidence:   []TechEvidence{{Signal: "xmlrpc.php"}},
		})
	}

	if springBootErrRE.MatchString(body) {
		results = append(results, TechFindResult{
			Technology: "spring_boot",
			Category:   "framework",
			Confidence: 80,
			Severity:   finding.SeverityMedium,
			Evidence:   []TechEvidence{{Signal: "Whitelabel Error Page"}},
		})
	}
	if graphqlPathRE.MatchString(body) {
		results = append(results, TechFindResult{
			Technology: "graphql",
			Category:   "exposed",
			Confidence: 60,
			Severity:   finding.SeverityHigh,
			Evidence:   []TechEvidence{{Signal: "/graphql path"}},
		})
	}
	if schemaRE.MatchString(body) {
		results = append(results, TechFindResult{
			Technology: "graphql",
			Category:   "exposed",
			Confidence: 70,
			Severity:   finding.SeverityHigh,
			Evidence:   []TechEvidence{{Signal: "__schema"}},
		})
	}
	if csrfTokenRE.MatchString(body) {
		results = append(results, TechFindResult{
			Technology: "laravel",
			Category:   "framework",
			Confidence: 40,
			Severity:   finding.SeverityMedium,
			Evidence:   []TechEvidence{{Signal: "csrf-token"}},
		})
	}
	if werkzeugRE.MatchString(body) {
		results = append(results, TechFindResult{
			Technology: "flask",
			Category:   "framework",
			Confidence: 70,
			Severity:   finding.SeverityMedium,
			Evidence:   []TechEvidence{{Signal: "Werkzeug"}},
		})
	}
	if strings.Contains(body, "Traceback (most recent call last)") && strings.Contains(body, "File \"") {
		results = append(results, TechFindResult{
			Technology: "python",
			Category:   "language",
			Confidence: 50,
			Severity:   finding.SeverityLow,
			Evidence:   []TechEvidence{{Signal: "Python traceback"}},
		})
	}
	if reqVerifTokenRE.MatchString(body) {
		results = append(results, TechFindResult{
			Technology: "asp_net",
			Category:   "framework",
			Confidence: 70,
			Severity:   finding.SeverityMedium,
			Evidence:   []TechEvidence{{Signal: "__RequestVerificationToken"}},
		})
	}
	if k8sStatusRE.MatchString(body) {
		results = append(results, TechFindResult{
			Technology: "kubernetes",
			Category:   "infrastructure",
			Confidence: 70,
			Severity:   finding.SeverityHigh,
			Evidence:   []TechEvidence{{Signal: `"kind":"Status"`}},
		})
	}

	if m := jqueryVersionRE.FindStringSubmatch(body); len(m) > 1 {
		results = append(results, TechFindResult{
			Technology: "jquery",
			Version:    m[1],
			Category:   "library",
			Confidence: 60,
			Severity:   finding.SeverityLow,
			Evidence:   []TechEvidence{{Signal: "jQuery " + m[1] + " detected"}},
		})
	}

	if reactDevToolsRE.MatchString(body) {
		results = append(results, TechFindResult{
			Technology: "react",
			Category:   "library",
			Confidence: 50,
			Severity:   finding.SeverityLow,
			Evidence:   []TechEvidence{{Signal: "__REACT_DEVTOOLS_GLOBAL_HOOK__"}},
		})
	}
	if vueDataRE.MatchString(body) {
		results = append(results, TechFindResult{
			Technology: "vue",
			Category:   "library",
			Confidence: 40,
			Severity:   finding.SeverityLow,
			Evidence:   []TechEvidence{{Signal: "data-v-* attribute"}},
		})
	}
	if ngVersionRE.MatchString(body) || angularAppRE.MatchString(body) {
		results = append(results, TechFindResult{
			Technology: "angular",
			Category:   "library",
			Confidence: 50,
			Severity:   finding.SeverityLow,
			Evidence:   []TechEvidence{{Signal: "ng-version/ng-app"}},
		})
	}

	return results
}

func analyzeTechCookies(cookies []*http.Cookie) []TechFindResult {
	var results []TechFindResult

	for _, c := range cookies {
		name := strings.ToLower(c.Name)
		switch {
		case name == "phpsessid":
			results = append(results, TechFindResult{
				Technology: "php",
				Category:   "language",
				Confidence: 50,
				Severity:   finding.SeverityLow,
				Evidence:   []TechEvidence{{Signal: "PHPSESSID cookie"}},
			})
		case name == "jsessionid":
			results = append(results, TechFindResult{
				Technology: "java",
				Category:   "language",
				Confidence: 50,
				Severity:   finding.SeverityLow,
				Evidence:   []TechEvidence{{Signal: "JSESSIONID cookie"}},
			})
		case name == "connect.sid":
			results = append(results, TechFindResult{
				Technology: "express",
				Category:   "framework",
				Confidence: 50,
				Severity:   finding.SeverityMedium,
				Evidence:   []TechEvidence{{Signal: "connect.sid cookie"}},
			})
		case name == "csrftoken":
			results = append(results, TechFindResult{
				Technology: "django",
				Category:   "framework",
				Confidence: 50,
				Severity:   finding.SeverityMedium,
				Evidence:   []TechEvidence{{Signal: "csrftoken cookie"}},
			})
		case name == "laravel_session":
			results = append(results, TechFindResult{
				Technology: "laravel",
				Category:   "framework",
				Confidence: 50,
				Severity:   finding.SeverityMedium,
				Evidence:   []TechEvidence{{Signal: "laravel_session cookie"}},
			})
		case name == "asp.net_sessionid":
			results = append(results, TechFindResult{
				Technology: "asp_net",
				Category:   "framework",
				Confidence: 50,
				Severity:   finding.SeverityMedium,
				Evidence:   []TechEvidence{{Signal: "ASP.NET_SessionId cookie"}},
			})
		case name == ".aspnetcore.session":
			results = append(results, TechFindResult{
				Technology: "asp_net_core",
				Category:   "framework",
				Confidence: 50,
				Severity:   finding.SeverityMedium,
				Evidence:   []TechEvidence{{Signal: ".AspNetCore.Session cookie"}},
			})
		case strings.HasPrefix(name, "shopify_"):
			results = append(results, TechFindResult{
				Technology: "shopify",
				Category:   "cms",
				Confidence: 50,
				Severity:   finding.SeverityHigh,
				Evidence:   []TechEvidence{{Signal: "shopify_* cookie: " + c.Name}},
			})
		case name == "_rails_session":
			results = append(results, TechFindResult{
				Technology: "rails",
				Category:   "framework",
				Confidence: 50,
				Severity:   finding.SeverityMedium,
				Evidence:   []TechEvidence{{Signal: "_rails_session cookie"}},
			})
		case name == "session" && c.Value != "":
			results = append(results, TechFindResult{
				Technology: "flask",
				Category:   "framework",
				Confidence: 40,
				Severity:   finding.SeverityMedium,
				Evidence:   []TechEvidence{{Signal: "session cookie (Flask)"}},
			})
		}
	}

	return results
}

func extractVersion(re *regexp.Regexp, text string) string {
	if m := re.FindStringSubmatch(text); len(m) > 1 {
		return m[1]
	}
	return ""
}

func extractVersionString(text, pattern string) string {
	re := regexp.MustCompile(pattern)
	if m := re.FindStringSubmatch(text); len(m) > 1 {
		return m[1]
	}
	return ""
}
