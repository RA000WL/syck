// Package httpclient provides a shared HTTP client factory for all syck components.
package httpclient

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// NewTransport creates an http.Transport with optional proxy and TLS settings.
// If proxyURL is empty, falls back to http.ProxyFromEnvironment (respects HTTP_PROXY env vars).
func NewTransport(proxyURL string, insecureSkipVerify bool) *http.Transport {
	tr := &http.Transport{
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
	}
	if proxyURL != "" {
		u, err := url.Parse(proxyURL)
		if err == nil {
			tr.Proxy = http.ProxyURL(u)
		}
	}
	if insecureSkipVerify {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- validator needs this
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
