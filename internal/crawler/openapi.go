package crawler

import (
	"encoding/json"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

type OpenAPISpec struct {
	Paths    map[string]map[string]interface{} `json:"paths" yaml:"paths"`
	BasePath string                            `json:"basePath" yaml:"basePath"`
	Servers  []struct {
		URL string `json:"url" yaml:"url"`
	} `json:"servers" yaml:"servers"`
	Info struct {
		Title   string `json:"title" yaml:"title"`
		Version string `json:"version" yaml:"version"`
	} `json:"info" yaml:"info"`
}

func ParseOpenAPI(content string) (*OpenAPISpec, error) {
	var spec OpenAPISpec

	if err := json.Unmarshal([]byte(content), &spec); err == nil {
		if len(spec.Paths) > 0 {
			return &spec, nil
		}
	}

	if err := yaml.Unmarshal([]byte(content), &spec); err != nil {
		return nil, fmt.Errorf("parse swagger: not valid JSON or YAML")
	}
	if len(spec.Paths) == 0 {
		return nil, fmt.Errorf("no paths found in spec")
	}
	return &spec, nil
}

func (s *OpenAPISpec) ExtractEndpointURLs(baseURL string) []string {
	var urls []string
	base := strings.TrimRight(baseURL, "/")

	if s.BasePath != "" {
		base += "/" + strings.Trim(s.BasePath, "/")
	}

	for path, methods := range s.Paths {
		fullPath := base + "/" + strings.TrimLeft(path, "/")
		for method := range methods {
			upper := strings.ToUpper(method)
			switch upper {
			case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS":
				urls = append(urls, fmt.Sprintf("%s [%s]", fullPath, upper))
			}
		}
	}

	if len(urls) == 0 {
		for path := range s.Paths {
			fullPath := base + "/" + strings.TrimLeft(path, "/")
			urls = append(urls, fullPath)
		}
	}

	return urls
}
