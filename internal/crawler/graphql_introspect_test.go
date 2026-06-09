package crawler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestProbeGraphQLIntrospection_Enabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"data": map[string]interface{}{
				"__schema": map[string]interface{}{
					"types": []map[string]interface{}{
						{"name": "User", "fields": []map[string]interface{}{{"name": "id"}}},
					},
					"queryType":    map[string]interface{}{"name": "Query"},
					"mutationType": nil,
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	result, err := ProbeGraphQLIntrospection(client, srv.URL, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Types) != 1 || result.Types[0] != "User" {
		t.Fatalf("expected [User], got %v", result.Types)
	}
}

func TestProbeGraphQLIntrospection_Disabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		w.Write([]byte(`{"errors":[{"message":"introspection disabled"}]}`))
	}))
	defer srv.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	_, err := ProbeGraphQLIntrospection(client, srv.URL, 5*time.Second)
	if err == nil {
		t.Fatal("expected error for disabled introspection")
	}
}
