package crawler

import (
	"strings"
	"testing"
)

const testOpenAPIJSON = `{
	"openapi": "3.0.0",
	"info": {"title": "Test API", "version": "1.0"},
	"paths": {
		"/users": {"get": {}, "post": {}},
		"/users/{id}": {"get": {}, "delete": {}}
	}
}`

const testSwaggerYAML = `
swagger: "2.0"
info:
  title: Swagger Petstore
  version: "1.0"
basePath: /api/v1
paths:
  /pets:
    get:
    post:
  /pets/{petId}:
    delete:
`

func TestParseOpenAPI_JSON(t *testing.T) {
	spec, err := ParseOpenAPI(testOpenAPIJSON)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(spec.Paths) != 2 {
		t.Fatalf("expected 2 paths, got %d", len(spec.Paths))
	}
	urls := spec.ExtractEndpointURLs("https://api.example.com")
	if len(urls) < 2 {
		t.Fatalf("expected at least 2 URLs, got %d: %v", len(urls), urls)
	}
}

func TestParseOpenAPI_YAML(t *testing.T) {
	spec, err := ParseOpenAPI(testSwaggerYAML)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(spec.Paths) != 2 {
		t.Fatalf("expected 2 paths, got %d", len(spec.Paths))
	}
	urls := spec.ExtractEndpointURLs("https://petstore.swagger.io")
	found := false
	for _, u := range urls {
		if strings.Contains(u, "/api/v1/pets") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected /api/v1/pets in URLs, got %v", urls)
	}
}

func TestParseOpenAPI_Invalid(t *testing.T) {
	_, err := ParseOpenAPI("not json or yaml")
	if err == nil {
		t.Fatal("expected error for invalid content")
	}
}
