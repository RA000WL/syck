package netguard

import "testing"

func TestAllowFetchDenyTable(t *testing.T) {
	deny := []string{"http://10.0.0.1/", "http://172.16.5.4:8080/x", "http://192.168.1.1/admin", "http://169.254.169.254/latest/meta-data/", "http://metadata.google.internal/"}
	for _, u := range deny {
		if AllowFetch(u) {
			t.Fatalf("should deny %s", u)
		}
	}
	allow := []string{"https://example.com/", "https://8.8.8.8/"}
	for _, u := range allow {
		if !AllowFetch(u) {
			t.Fatalf("should allow %s", u)
		}
	}
}
