package validator

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"
)

var (
	httpClient = &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	defaultRateLimiter = NewRateLimiter(5.0)
)

func httpDo(req *http.Request) (*http.Response, error) {
	host := req.URL.Host
	if !defaultRateLimiter.Allow(host) {
		return nil, fmt.Errorf("rate limited: %s", host)
	}
	return httpClient.Do(req)
}
