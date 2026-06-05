package sourcemap

import (
	"encoding/json"
	"fmt"
)

type SourceMapRef struct {
	Kind   string // "file", "url", "inline"
	Target string // file path, URL, or data: URI
	File   string // source JS file
	Line   int
}

type SourceMap struct {
	Version        int      `json:"version"`
	Sources        []string `json:"sources"`
	SourcesContent []string `json:"sourcesContent"`
	Mappings       string   `json:"mappings"`
}

func ParseSourceMap(data []byte) (*SourceMap, error) {
	var sm SourceMap
	if err := json.Unmarshal(data, &sm); err != nil {
		return nil, err
	}
	if sm.Version != 3 {
		return nil, fmt.Errorf("unsupported source map version: %d", sm.Version)
	}
	return &sm, nil
}

func ReconstructSource(sm *SourceMap) map[string]string {
	out := make(map[string]string)
	for i, src := range sm.Sources {
		if i < len(sm.SourcesContent) {
			out[src] = sm.SourcesContent[i]
		}
	}
	return out
}
