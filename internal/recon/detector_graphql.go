package recon

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/RA000WL/syck/internal/finding"
)

var graphqlRE = regexp.MustCompile(`(?i)(/graphql(\b|/|$)|/gql(\b|/|$))`)

type GraphQLDetector struct {
	client *http.Client
}

func NewGraphQLDetector(client *http.Client) *GraphQLDetector {
	return &GraphQLDetector{client: client}
}

func (d *GraphQLDetector) Detect(urls []string) []SurfaceFinding {
	var out []SurfaceFinding

	for _, u := range urls {
		if !graphqlRE.MatchString(u) {
			continue
		}

		// Basic URL pattern match
		out = append(out, SurfaceFinding{
			URL:      u,
			Category: "graphql",
			Severity: finding.SeverityHigh,
		})

		// Deep schema analysis if client available
		if d.client != nil {
			schemaFindings := d.analyzeSchema(u)
			out = append(out, schemaFindings...)
		}
	}

	return out
}

// deepIntrospectionQuery discovers mutation input types, their fields,
// and all type fields — not just root query/mutation types.
const deepIntrospectionQuery = `{"query":"query { __schema { types { name kind fields { name type { name kind ofType { name } } } inputFields { name type { name kind ofType { name } } } } queryType { name } mutationType { name } subscriptionType { name } } }"}`

type deepSchemaResult struct {
	Data struct {
		Schema struct {
			Types []struct {
				Name       string `json:"name"`
				Kind       string `json:"kind"`
				Fields     []struct {
					Name string `json:"name"`
					Type struct {
						Name string `json:"name"`
						Kind string `json:"kind"`
					} `json:"type"`
				} `json:"fields"`
				InputFields []struct {
					Name string `json:"name"`
					Type struct {
						Name string `json:"name"`
						Kind string `json:"kind"`
					} `json:"type"`
				} `json:"inputFields"`
			} `json:"types"`
			QueryType       *struct{ Name string } `json:"queryType"`
			MutationType    *struct{ Name string } `json:"mutationType"`
			SubscriptionType *struct{ Name string } `json:"subscriptionType"`
		} `json:"__schema"`
	} `json:"data"`
}

func (d *GraphQLDetector) analyzeSchema(endpointURL string) []SurfaceFinding {
	var out []SurfaceFinding

	if d.client == nil {
		return nil
	}

	req, err := http.NewRequest("POST", endpointURL, bytes.NewBufferString(deepIntrospectionQuery))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "syck/1.0")

	resp, err := d.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 500*1024))
	if err != nil {
		return nil
	}

	var result deepSchemaResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil
	}

	schema := result.Data.Schema
	if schema.QueryType == nil && schema.MutationType == nil {
		return nil
	}

	// Discover mutation input types and their fields
	for _, t := range schema.Types {
		if t.Kind == "INPUT_OBJECT" && len(t.InputFields) > 0 {
			for _, field := range t.InputFields {
				// Fields that look like they accept secrets
				if isSecretFieldName(field.Name) {
					out = append(out, SurfaceFinding{
						URL:      endpointURL,
						Category: "graphql_mutation_input",
						Severity: finding.SeverityHigh,
						Source:   fmt.Sprintf("graphql_input_%s", t.Name),
					})
				}
			}
		}
	}

	// Discover all fields on root types
	if schema.QueryType != nil {
		for _, t := range schema.Types {
			if t.Name == schema.QueryType.Name {
				for _, field := range t.Fields {
					if isSensitiveFieldName(field.Name) {
						out = append(out, SurfaceFinding{
							URL:      endpointURL,
							Category: "graphql_sensitive_query",
							Severity: finding.SeverityHigh,
							Source:   fmt.Sprintf("graphql_query_%s", field.Name),
						})
					}
				}
			}
		}
	}

	if schema.MutationType != nil {
		for _, t := range schema.Types {
			if t.Name == schema.MutationType.Name {
				for _, field := range t.Fields {
					if isSensitiveFieldName(field.Name) {
						out = append(out, SurfaceFinding{
							URL:      endpointURL,
							Category: "graphql_sensitive_mutation",
							Severity: finding.SeverityHigh,
							Source:   fmt.Sprintf("graphql_mutation_%s", field.Name),
						})
					}
				}
			}
		}
	}

	return out
}

func isSecretFieldName(name string) bool {
	secretFields := []string{
		"password", "secret", "token", "apiKey", "api_key",
		"privateKey", "private_key", "credential", "auth",
		"accessToken", "access_token", "refreshToken", "refresh_token",
		"secretKey", "secret_key", "encryptionKey", "encryption_key",
	}
	nameLower := strings.ToLower(name)
	for _, s := range secretFields {
		if strings.Contains(nameLower, strings.ToLower(s)) {
			return true
		}
	}
	return false
}

func isSensitiveFieldName(name string) bool {
	sensitiveFields := []string{
		"users", "user", "accounts", "account", "admin", "admins",
		"secrets", "credentials", "tokens", "apiKeys", "api_keys",
		"passwords", "keys", "privateKeys", "private_keys",
		"emails", "email", "phone", "phones",
		"billing", "payments", "transactions",
		"config", "settings", "environment",
	}
	nameLower := strings.ToLower(name)
	for _, s := range sensitiveFields {
		if strings.Contains(nameLower, strings.ToLower(s)) {
			return true
		}
	}
	return false
}
