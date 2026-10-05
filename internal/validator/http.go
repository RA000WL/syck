package validator

import (
	"fmt"
	"net/http"
	"time"

	"github.com/RA000WL/syck/internal/httpclient"
)

var (
	httpClient         *http.Client
	defaultRateLimiter = NewRateLimiter(5.0)
)

// InitValidatorClient sets the validator's HTTP client with proxy support.
// TLS certificate verification is always enabled.
func InitValidatorClient(proxyURL string) {
	httpClient = httpclient.NewValidatorClient(5*time.Second, proxyURL)
}

func init() {
	httpClient = httpclient.NewValidatorClient(5*time.Second, "")
}

func httpDo(req *http.Request) (*http.Response, error) {
	host := req.URL.Host
	if !defaultRateLimiter.Allow(host) {
		return nil, fmt.Errorf("rate limited: %s", host)
	}
	return httpClient.Do(req)
}
