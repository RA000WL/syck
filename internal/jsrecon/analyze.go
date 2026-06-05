package jsrecon

import (
	"encoding/base64"
	"regexp"
	"strings"
)

var (
	fetchRE        = regexp.MustCompile(`fetch\s*\(\s*(['"` + "`" + `])(https?://[^'"` + "`" + `]+)['"` + "`" + `]`)
	axiosRE        = regexp.MustCompile(`axios\.(get|post|put|delete|patch|head|options)\s*\(\s*(['"` + "`" + `])(https?://[^'"` + "`" + `]+)['"` + "`" + `]`)
	xhrOpenRE      = regexp.MustCompile(`\.open\s*\(\s*(['"` + "`" + `])(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)['"` + "`" + `]\s*,\s*(['"` + "`" + `])([^'"` + "`" + `]+)['"` + "`" + `]`)
	apolloClientRE = regexp.MustCompile(`(?:uri|endpoint|url)\s*[:=]\s*(['"` + "`" + `])(https?://[^'"` + "`" + `]*(?:graphql|gql)[^'"` + "`" + `]*)['"` + "`" + `]`)
	authHeaderRE   = regexp.MustCompile(`['"` + "`" + `]Authorization['"` + "`" + `]\s*[:=]\s*(['"` + "`" + `])(Bearer\s+(\S+)|Basic\s+(\S+)|(\S+))['"` + "`" + `]`)
	methodRE       = regexp.MustCompile(`method\s*:\s*(['"` + "`" + `])(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)['"` + "`" + `]`)
	headerBlockRE  = regexp.MustCompile(`headers\s*:\s*\{([^}]+)\}`)
	headerPairRE   = regexp.MustCompile(`(['"` + "`" + `])([^'"` + "`" + `]+)['"` + "`" + `]\s*:\s*(['"` + "`" + `])([^'"` + "`" + `]+)['"` + "`" + `]`)
	hostRE         = regexp.MustCompile(`https?://([^/]+)`)
)

func Analyze(content string, file string) []JSRequest {
	var results []JSRequest
	lines := strings.Split(content, "\n")

	for lineno, line := range lines {
		for _, m := range fetchRE.FindAllStringSubmatch(line, -1) {
			req := JSRequest{
				Endpoint:   m[2],
				Method:     "GET",
				SourceFile: file,
				SourceLine: lineno + 1,
			}
			extractFetchOptions(line, &req)
			extractAuthFromLine(line, &req)
			extractDomains(&req)
			results = append(results, req)
		}

		for _, m := range axiosRE.FindAllStringSubmatch(line, -1) {
			req := JSRequest{
				Endpoint:   m[3],
				Method:     strings.ToUpper(m[1]),
				SourceFile: file,
				SourceLine: lineno + 1,
			}
			extractAuthFromLine(line, &req)
			extractDomains(&req)
			results = append(results, req)
		}

		for _, m := range xhrOpenRE.FindAllStringSubmatch(line, -1) {
			req := JSRequest{
				Endpoint:   m[4],
				Method:     strings.ToUpper(m[2]),
				SourceFile: file,
				SourceLine: lineno + 1,
			}
			extractAuthFromLine(line, &req)
			extractDomains(&req)
			results = append(results, req)
		}

		for _, m := range apolloClientRE.FindAllStringSubmatch(line, -1) {
			req := JSRequest{
				Endpoint:   m[2],
				Method:     "POST",
				SourceFile: file,
				SourceLine: lineno + 1,
				Headers:    map[string]string{"Content-Type": "application/json"},
			}
			extractDomains(&req)
			results = append(results, req)
		}

		if authHeaderRE.MatchString(line) && !hasRequestOnLine(line) {
			req := JSRequest{
				SourceFile: file,
				SourceLine: lineno + 1,
			}
			extractAuthFromLine(line, &req)
			if len(req.APIKeys) > 0 {
				results = append(results, req)
			}
		}
	}

	return dedupRequests(results)
}

func hasRequestOnLine(line string) bool {
	return fetchRE.MatchString(line) || axiosRE.MatchString(line) || xhrOpenRE.MatchString(line) || apolloClientRE.MatchString(line)
}

func extractFetchOptions(line string, req *JSRequest) {
	if strings.Contains(line, "method") {
		if m := methodRE.FindStringSubmatch(line); len(m) > 0 {
			req.Method = strings.ToUpper(m[2])
		}
	}
	if req.Headers == nil {
		req.Headers = make(map[string]string)
	}
	if hm := headerBlockRE.FindStringSubmatch(line); len(hm) > 0 {
		for _, p := range headerPairRE.FindAllStringSubmatch(hm[1], -1) {
			req.Headers[p[2]] = p[4]
		}
	}
}

func extractAuthFromLine(line string, req *JSRequest) {
	for _, m := range authHeaderRE.FindAllStringSubmatch(line, -1) {
		if req.Headers == nil {
			req.Headers = make(map[string]string)
		}
		req.Headers["Authorization"] = m[2]
		if m[3] != "" {
			req.APIKeys = append(req.APIKeys, m[3])
		} else if m[4] != "" {
			raw, err := base64.StdEncoding.DecodeString(m[4])
			if err == nil {
				req.APIKeys = append(req.APIKeys, string(raw))
			}
		}
	}
}

func extractDomains(req *JSRequest) {
	if m := hostRE.FindStringSubmatch(req.Endpoint); len(m) > 0 {
		req.Domains = []string{strings.ToLower(m[1])}
	}
}

func dedupRequests(reqs []JSRequest) []JSRequest {
	seen := make(map[string]bool)
	var out []JSRequest
	for _, r := range reqs {
		key := r.Endpoint + "|" + r.Method
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, r)
	}
	return out
}
