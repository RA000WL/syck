package sourcemap

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var sourceMapURLRE = regexp.MustCompile(`//# sourceMappingURL=(.+)`)

type Analyzer struct {
	client  *http.Client
	enabled bool
}

func NewAnalyzer(enabled bool) *Analyzer {
	return &Analyzer{
		client:  &http.Client{Timeout: 10 * time.Second},
		enabled: enabled,
	}
}

func DetectRefs(content string, file string) []SourceMapRef {
	var refs []SourceMapRef
	lines := strings.Split(content, "\n")
	for lineno, line := range lines {
		m := sourceMapURLRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		target := strings.TrimSpace(m[1])

		if strings.HasPrefix(target, "data:") {
			refs = append(refs, SourceMapRef{
				Kind:   "inline",
				Target: target,
				File:   file,
				Line:   lineno + 1,
			})
			continue
		}

		kind := "url"
		if !strings.HasPrefix(target, "http") {
			kind = "file"
			if lastSlash := strings.LastIndex(file, "/"); lastSlash >= 0 {
				target = file[:lastSlash+1] + target
			}
		}
		refs = append(refs, SourceMapRef{
			Kind:   kind,
			Target: target,
			File:   file,
			Line:   lineno + 1,
		})
	}
	return refs
}

func FetchMap(ref SourceMapRef) (*SourceMap, error) {
	var data []byte

	switch ref.Kind {
	case "inline":
		comma := strings.Index(ref.Target, ",")
		if comma < 0 {
			return nil, fmt.Errorf("invalid inline data URI")
		}
		encoded := ref.Target[comma+1:]
		var err error
		data, err = base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("inline base64 decode: %w", err)
		}

	case "file", "url":
		var body []byte
		if ref.Kind == "file" {
			body = readFileOrFetch(ref.Target)
		} else {
			body = fetchURL(ref.Target)
		}
		if body == nil {
			return nil, fmt.Errorf("failed to read source map: %s", ref.Target)
		}
		data = body
	}

	if len(data) >= 2 && data[0] == 0x1F && data[1] == 0x8B {
		gr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("gzip read: %w", err)
		}
		defer gr.Close()
		data, err = io.ReadAll(gr)
		if err != nil {
			return nil, fmt.Errorf("gzip decompress: %w", err)
		}
	}

	return ParseSourceMap(data)
}

func readFileOrFetch(path string) []byte {
	return nil
}

func fetchURL(u string) []byte {
	return nil
}

func ExtractSignals(content string) []Signal {
	var signals []Signal
	lines := strings.Split(content, "\n")
	for lineno, line := range lines {
		if strings.Contains(line, "process.env.") || strings.Contains(line, "import.meta.env.") {
			signals = append(signals, Signal{
				Type: "env_ref",
				Line: lineno + 1,
				Text: strings.TrimSpace(line),
			})
		}
		if matched, _ := regexp.MatchString(`(?i)\b(TODO|FIXME|HACK|XXX)\b`, line); matched {
			signals = append(signals, Signal{
				Type: "comment_todo",
				Line: lineno + 1,
				Text: strings.TrimSpace(line),
			})
		}
		if matched, _ := regexp.MatchString(`(?i)/(debug|admin|_debug|_admin|internal)(\b|/|$)`, line); matched {
			signals = append(signals, Signal{
				Type: "debug_endpoint",
				Line: lineno + 1,
				Text: strings.TrimSpace(line),
			})
		}
	}
	return signals
}

type Signal struct {
	Type string
	Line int
	Text string
}
