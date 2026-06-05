# Module 06 — JS Analyzer

> Extract structured records from JavaScript bundles: endpoints, methods, headers, domains, and embedded API keys.

## Status

- **Tier:** P1
- **Phase:** V1.2
- **Action:** extend
- **Owner:** unclaimed
- **Source package:** `internal/jsrecon/`

## Goal

Extend the existing `jsrecon` package (currently `reconstruct.go`, 225 lines) so that, in addition to reconstructing concatenated strings, the analyzer emits structured records describing how the script talks to the network: the URL, the HTTP method, the headers (with the `Authorization` value parsed out), the domains referenced, and any API keys embedded in those calls.

## Tasks

- [ ] Define `JSRequest` struct: `Endpoint string`, `Method string`, `Headers map[string]string`, `Domains []string`, `APIKeys []string`, `SourceFile string`, `SourceLine int`.
- [ ] Detect `fetch(url, { method, headers, body })` calls and emit one `JSRequest` per call.
- [ ] Detect `axios.{get,post,put,delete,patch}(url, config)` and emit one `JSRequest` per call.
- [ ] Detect `new XMLHttpRequest()` followed by `.open(method, url)` and `.setRequestHeader(name, value)`.
- [ ] Detect Apollo Client: `ApolloClient` instantiation, `gql\`...\`` template tags, `apolloLink` HTTP link construction.
- [ ] Detect GraphQL endpoint strings: URLs ending in `/graphql` or `/gql`, or containing `query`/`mutation` keyword in headers.
- [ ] Parse `Authorization` headers: extract the bearer token, basic-auth credentials, or custom scheme. Emit the token as an `APIKey` and (when the host matches a rule from M1) as a finding.
- [ ] Reuse the existing `reconstruct.go` logic for concat/join/template reconstruction — feed reconstructed strings into the new detectors.
- [ ] Expose `Analyze(content string, file string) []JSRequest` as the public entry point.
- [ ] Unit tests: a bundle fixture with `fetch`/`axios`/XHR/Apollo/GraphQL produces the expected `JSRequest` records.

## Exit Criteria

- [ ] `go test ./internal/jsrecon/...` passes.
- [ ] A fixture bundle with a `fetch('https://api.example.com/v1/users', { headers: { Authorization: 'Bearer abc...' } })` produces one `JSRequest` with `Endpoint`, `Method: "GET"`, `Headers["Authorization"]`, and `APIKeys: ["abc..."]`.
- [ ] A fixture bundle with `new XMLHttpRequest()` + `.open('POST', url)` + `.setRequestHeader('X-API-Key', '...')` produces one `JSRequest` with the expected method, endpoint, and `APIKey`.
- [ ] Apollo and GraphQL patterns are detected on a fixture bundle.
- [ ] The existing concat/join/template reconstruction tests still pass (no regression).
- [ ] `JSRequest.APIKeys` are not emitted as findings directly — they are picked up by the regular rule engine via M11 wiring.

## Dependencies

- Depends on: M1 (rule patterns are used to recognize API keys in headers), M2 (JWT entropy used to detect token-shaped strings in headers)
- Depended on by: M7 (source map analyzer feeds reconstructed source through `Analyze`), M11 (scanner pipeline calls `Analyze` on `.js` content)

## Notes for implementer

- `reconstruct.go` stays. The new file is `analyze.go` or `requests.go`.
- Use simple regex detectors. AST parsing of JS in Go is overkill for the V1 surface; the existing reconstruct-based approach is good enough.
- `Authorization` header parsing: support `Bearer <token>`, `Basic <base64>`, and custom schemes. Anything else, capture the raw value.
- `Domains` is the set of unique hostnames across all requests. Dedupe by lowercased hostname.
- Watch for false positives: `fetch('/api/users')` is a relative URL — emit it as `Endpoint: "/api/users"` and let M8 (frontend recon) flag the relative path. Do not invent a domain.
