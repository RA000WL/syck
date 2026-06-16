package discovery

import (
	"net/http"
	"strings"
	"sync"
	"time"
)

// HostResult holds the result of a live host check.
type HostResult struct {
	Host      string
	Alive     bool
	StatusCode int
	IP        string
}

// CheckLiveHosts performs HTTP HEAD requests to determine which hosts are alive.
func CheckLiveHosts(hosts []string, client *http.Client, timeout time.Duration) []HostResult {
	if client == nil {
		client = &http.Client{
			Timeout:     timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
		}
	}

	var results []HostResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Limit concurrent checks
	sem := make(chan struct{}, 20)

	for _, host := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(h string) {
			defer wg.Done()
			defer func() { <-sem }()

			result := checkHost(client, h)
			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}(host)
	}

	wg.Wait()
	return results
}

func checkHost(client *http.Client, host string) HostResult {
	result := HostResult{Host: host}

	// Try HTTPS first, then HTTP
	for _, scheme := range []string{"https", "http"} {
		url := scheme + "://" + host
		resp, err := client.Head(url)
		if err != nil {
			continue
		}
		resp.Body.Close()
		result.Alive = true
		result.StatusCode = resp.StatusCode
		break
	}

	return result
}

// FilterAliveHosts returns only hosts that responded to the live check.
func FilterAliveHosts(results []HostResult) []string {
	var alive []string
	for _, r := range results {
		if r.Alive {
			alive = append(alive, r.Host)
		}
	}
	return alive
}

// HostsFromSubdomains extracts unique hostnames from subdomain results.
func HostsFromSubdomains(subs []SubdomainResult) []string {
	seen := make(map[string]bool)
	var hosts []string
	for _, s := range subs {
		h := strings.ToLower(s.Subdomain)
		if !seen[h] {
			seen[h] = true
			hosts = append(hosts, h)
		}
	}
	return hosts
}
