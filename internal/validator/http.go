package validator

import (
	"crypto/tls"
	"net/http"
	"time"
)

var httpClient = &http.Client{
	Timeout: 5 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

func httpDo(req *http.Request) (*http.Response, error) {
	return httpClient.Do(req)
}
