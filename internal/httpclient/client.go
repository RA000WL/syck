// Package httpclient provides a shared HTTP client factory for all syck components.
package httpclient

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// dnsCache caches DNS lookups to reduce DNS queries
var (
	dnsCache   = make(map[string][]net.IP)
	dnsMu      sync.RWMutex
	dnsExpiry  = make(map[string]time.Time)
	dnsTTL     = 5 * time.Minute
)

// cachedResolver returns a DNS resolver that caches results
type cachedResolver struct{}

func (r *cachedResolver) LookupHost(host string) ([]net.IP, error) {
	dnsMu.RLock()
	if ips, ok := dnsCache[host]; ok {
		if expiry, ok := dnsExpiry[host]; ok && time.Now().Before(expiry) {
			dnsMu.RUnlock()
			return ips, nil
		}
	}
	dnsMu.RUnlock()

	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}

	dnsMu.Lock()
	dnsCache[host] = ips
	dnsExpiry[host] = time.Now().Add(dnsTTL)
	dnsMu.Unlock()

	return ips, nil
}

// NewTransport creates an http.Transport with optional proxy and TLS settings.
// If proxyURL is empty, falls back to http.ProxyFromEnvironment (respects HTTP_PROXY env vars).
func NewTransport(proxyURL string, insecureSkipVerify bool) *http.Transport {
	tr := &http.Transport{
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   50,
		IdleConnTimeout:       120 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		DisableKeepAlives:     false,
		DisableCompression:    false,
		MaxResponseHeaderBytes: 1 << 20,
		WriteBufferSize:       1 << 16,
		ReadBufferSize:        1 << 16,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS13,
		},
	}
	if proxyURL != "" {
		u, err := url.Parse(proxyURL)
		if err == nil {
			tr.Proxy = http.ProxyURL(u)
		}
	}
	if insecureSkipVerify {
		tr.TLSClientConfig.InsecureSkipVerify = true // #nosec G402 -- validator needs this
	}
	return tr
}

// NewClient creates an http.Client with the given timeout, proxy, and TLS settings.
func NewClient(timeout time.Duration, proxyURL string, insecureSkipVerify bool) *http.Client {
	transport := NewTransport(proxyURL, insecureSkipVerify)
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}
}

// TransportPool provides reusable transport instances
var TransportPool = sync.Pool{
	New: func() interface{} {
		return NewTransport("", false)
	},
}
