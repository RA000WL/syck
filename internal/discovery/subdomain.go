package discovery

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// SubdomainResult holds a discovered subdomain.
type SubdomainResult struct {
	Subdomain string
	Source    string // "crt.sh", "certspotter", "dns", "wordlist", etc.
}

// EnumerateSubdomains discovers subdomains for a domain using multiple sources:
// certificate transparency logs (crt.sh, CertSpotter), DNS bruteforce, and more.
func EnumerateSubdomains(domain string, client *http.Client, resolveDNS bool) ([]SubdomainResult, error) {
	var results []SubdomainResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	// crt.sh certificate transparency
	wg.Add(1)
	go func() {
		defer wg.Done()
		subs, err := queryCrtSh(domain, client)
		if err == nil {
			mu.Lock()
			results = append(results, subs...)
			mu.Unlock()
		}
	}()

	// CertSpotter CT logs
	wg.Add(1)
	go func() {
		defer wg.Done()
		subs, err := queryCertSpotter(domain, client)
		if err == nil {
			mu.Lock()
			results = append(results, subs...)
			mu.Unlock()
		}
	}()

	wg.Wait()

	// Deduplicate
	seen := make(map[string]bool)
	var unique []SubdomainResult
	for _, r := range results {
		key := strings.ToLower(r.Subdomain)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, r)
		}
	}

	// Optional DNS resolution to filter dead subdomains
	if resolveDNS {
		unique = resolveSubdomains(unique)
	}

	sort.Slice(unique, func(i, j int) bool {
		return unique[i].Subdomain < unique[j].Subdomain
	})

	return unique, nil
}

// crt.sh response types
type crtShEntry struct {
	Name string `json:"name_value"`
}

func queryCrtSh(domain string, client *http.Client) ([]SubdomainResult, error) {
	crtURL := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)

	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	req, err := http.NewRequest("GET", crtURL, nil)
	if err != nil {
		return nil, fmt.Errorf("crt.sh request: %w", err)
	}
	req.Header.Set("User-Agent", "syck/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crt.sh request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("crt.sh returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10MB limit
	if err != nil {
		return nil, fmt.Errorf("crt.sh read: %w", err)
	}

	var entries []crtShEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("crt.sh parse: %w", err)
	}

	domainLower := strings.ToLower(domain)
	seen := make(map[string]bool)
	var results []SubdomainResult

	for _, e := range entries {
		// crt.sh returns newline-separated names in name_value
		for _, name := range strings.Split(e.Name, "\n") {
			name = strings.TrimSpace(strings.ToLower(name))
			if name == "" {
				continue
			}
			// Must be the domain itself or a subdomain of the target
			if name != domainLower && !strings.HasSuffix(name, "."+domainLower) {
				continue
			}
			// Skip wildcards
			if strings.HasPrefix(name, "*.") {
				name = name[2:]
			}
			if seen[name] {
				continue
			}
			seen[name] = true
			results = append(results, SubdomainResult{
				Subdomain: name,
				Source:    "crt.sh",
			})
		}
	}

	return results, nil
}

// resolveSubdomains checks which subdomains resolve via DNS.
func resolveSubdomains(subs []SubdomainResult) []SubdomainResult {
	var resolved []SubdomainResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Limit concurrent DNS lookups
	sem := make(chan struct{}, 20)

	for _, s := range subs {
		wg.Add(1)
		sem <- struct{}{}
		go func(sub SubdomainResult) {
			defer wg.Done()
			defer func() { <-sem }()

			host := sub.Subdomain
			addrs, err := netLookupHost(host)
			if err == nil && len(addrs) > 0 {
				mu.Lock()
				resolved = append(resolved, sub)
				mu.Unlock()
			}
		}(s)
	}

	wg.Wait()
	return resolved
}

// CertSpotterEntry represents a CertSpotter API response entry.
type CertSpotterEntry struct {
	DNSNames []string `json:"dns_names"`
}

// queryCertSpotter discovers subdomains via CertSpotter's certificate transparency API.
func queryCertSpotter(domain string, client *http.Client) ([]SubdomainResult, error) {
	// CertSpotter offers a free API endpoint for CT logs
	certURL := fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", domain)

	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	req, err := http.NewRequest("GET", certURL, nil)
	if err != nil {
		return nil, fmt.Errorf("certspotter request: %w", err)
	}
	req.Header.Set("User-Agent", "syck/1.0")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("certspotter request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("certspotter returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10MB limit
	if err != nil {
		return nil, fmt.Errorf("certspotter read: %w", err)
	}

	var entries []CertSpotterEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("certspotter parse: %w", err)
	}

	domainLower := strings.ToLower(domain)
	seen := make(map[string]bool)
	var results []SubdomainResult

	for _, e := range entries {
		for _, name := range e.DNSNames {
			name = strings.TrimSpace(strings.ToLower(name))
			if name == "" {
				continue
			}
			// Must be the domain itself or a subdomain of the target
			if name != domainLower && !strings.HasSuffix(name, "."+domainLower) {
				continue
			}
			// Skip wildcards
			if strings.HasPrefix(name, "*.") {
				name = name[2:]
			}
			if seen[name] {
				continue
			}
			seen[name] = true
			results = append(results, SubdomainResult{
				Subdomain: name,
				Source:    "certspotter",
			})
		}
	}

	return results, nil
}

// BruteForceSubdomains attempts DNS bruteforce with common subdomain wordlist.
func BruteForceSubdomains(domain string, client *http.Client) []SubdomainResult {
	// Common subdomain wordlist for bug bounty
	wordlist := []string{
		"www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2", "ns3", "ns4",
		"cdn", "api", "dev", "staging", "test", "admin", "portal", "blog", "shop", "store",
		"app", "mobile", "m", "beta", "alpha", "demo", "sandbox", "preview", "preprod",
		"git", "gitlab", "github", "bitbucket", "jenkins", "ci", "cd", "drone",
		"grafana", "prometheus", "kibana", "elasticsearch", "elastic", "monitor",
		"grafana", "stats", "metrics", "health", "status", "info",
		"db", "database", "mysql", "postgres", "redis", "mongo", "memcached", "elasticsearch",
		"auth", "sso", "oauth", "login", "signin", "signup", "register",
		"intranet", "internal", "private", "corp", "vpn", "proxy", "gateway",
		"ftp", "sftp", "ssh", "rdp", "jump", "bastion",
		"backup", "bak", "old", "legacy", "archive",
		"docs", "wiki", "confluence", "jira", "redmine",
		"mx", "mx1", "mx2", "mx3", "imap", "pop3",
		"autoconfig", "autodiscover", "caldav", "carddav",
		"vpn", "openvpn", "wireguard", "ipsec",
		"kubernetes", "k8s", "docker", "registry", "harbor",
		"aws", "gcp", "azure", "cloud",
		"search", "index", "query", "graphql",
		"socket", "ws", "wss", "realtime", "rt",
		"cache", "cdn", "assets", "static", "media",
		"images", "img", "uploads", "files", "attachments",
		"webhooks", "hooks", "events", "notifications",
		"reports", "analytics", "tracking", "pixels",
		"pay", "payment", "billing", "invoice",
		"support", "help", "faq", "contact",
		"careers", "jobs", "recruit",
		"legal", "terms", "privacy", "policy",
		"status", "uptime", "maintenance",
	}

	var results []SubdomainResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Limit concurrent DNS lookups
	sem := make(chan struct{}, 50)

	domainLower := strings.ToLower(domain)

	for _, word := range wordlist {
		subdomain := word + "." + domainLower
		wg.Add(1)
		sem <- struct{}{}
		go func(sub SubdomainResult) {
			defer wg.Done()
			defer func() { <-sem }()

			addrs, err := netLookupHost(sub.Subdomain)
			if err == nil && len(addrs) > 0 {
				mu.Lock()
				results = append(results, sub)
				mu.Unlock()
			}
		}(SubdomainResult{Subdomain: subdomain, Source: "wordlist"})
	}

	wg.Wait()
	return results
}
