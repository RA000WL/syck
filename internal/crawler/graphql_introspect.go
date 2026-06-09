package crawler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type GraphQLIntrospectResult struct {
	URL       string
	Schema    string
	Types     []string
	Mutations []string
	Queries   []string
}

const introspectionQuery = `{"query":"query { __schema { types { name fields { name } } queryType { name } mutationType { name } } }"}`

func ProbeGraphQLIntrospection(client *http.Client, endpointURL string, timeout time.Duration) (*GraphQLIntrospectResult, error) {
	req, err := http.NewRequest("POST", endpointURL, bytes.NewBufferString(introspectionQuery))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 100*1024))
	var result struct {
		Data_ struct {
			Schema_ struct {
				Types        []map[string]interface{} `json:"types"`
				QueryType    *map[string]interface{}  `json:"queryType"`
				MutationType *map[string]interface{}  `json:"mutationType"`
			} `json:"__schema"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse introspection: %w", err)
	}

	if result.Data_.Schema_.QueryType == nil && result.Data_.Schema_.MutationType == nil {
		return nil, fmt.Errorf("introspection disabled or empty schema")
	}

	parsed := &GraphQLIntrospectResult{URL: endpointURL}

	for _, t := range result.Data_.Schema_.Types {
		name, _ := t["name"].(string)
		if name == "" || strings.HasPrefix(name, "__") {
			continue
		}
		parsed.Types = append(parsed.Types, name)
	}

	if qt := result.Data_.Schema_.QueryType; qt != nil {
		if name, ok := (*qt)["name"].(string); ok {
			parsed.Queries = append(parsed.Queries, name)
		}
	}
	if mt := result.Data_.Schema_.MutationType; mt != nil {
		if name, ok := (*mt)["name"].(string); ok {
			parsed.Mutations = append(parsed.Mutations, name)
		}
	}

	schemaBytes, _ := json.Marshal(result.Data_.Schema_)
	if len(schemaBytes) > 1000 {
		schemaBytes = schemaBytes[:1000]
	}
	parsed.Schema = string(schemaBytes)

	return parsed, nil
}
