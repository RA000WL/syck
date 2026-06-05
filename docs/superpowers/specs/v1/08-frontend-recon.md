# Module 08 — Frontend Recon

> Detect frontend attack surface: graphql, swagger, openapi, admin, debug, metrics, internal, staging, uat endpoints. Detect cloud storage URLs.

## Status

- **Tier:** P1
- **Phase:** V1.2
- **Action:** new
- **Owner:** unclaimed
- **New package:** `internal/recon/`

## Goal

When scanning a JS bundle, a config file, or a URL, identify endpoints and URLs that are not necessarily secrets but are indicators of attack surface. The recon engine emits findings of type `attack_surface` (not `secret`) with confidence and category metadata.

## Tasks

- [ ] Create `internal/recon/recon.go` with the public `Detector` interface and a `Registry`.
- [ ] Define `SurfaceFinding` struct: `URL string`, `Category string` (one of `graphql`, `swagger`, `openapi`, `admin`, `debug`, `metrics`, `internal`, `staging`, `uat`, `storage`), `Severity finding.Severity`, `Confidence confidence.Confidence` (the type defined in M9), `Source string` (the file or URL where it was found), `Line int`.
- [ ] Add category detectors:
  - `graphql`: URLs matching `(?i)/graphql(\b|/|$)`, `/gql(\b|/|$)`, `?query=`, or `ApolloClient` instantiations.
  - `swagger` / `openapi`: URLs matching `(?i)/swagger\.(json|yaml|yml)`, `/api-docs`, `/openapi\.(json|yaml|yml)`.
  - `admin`: URLs matching `(?i)/(admin|administrator|manage|management|panel|console)(\b|/|$)`.
  - `debug`: URLs matching `(?i)/(debug|trace|diag|diagnostic|healthz|readyz|livez)(\b|/|$)`.
  - `metrics`: URLs matching `(?i)/(metrics|prometheus|statsd|actuator)(\b|/|$)`.
  - `internal`: URLs matching `(?i)/(internal|private|intranet|corp)(\b|/|$)` or hostnames containing `internal.`, `corp.`, `.local`.
  - `staging` / `uat`: URLs matching `(?i)/(staging|stg|uat|sit|preprod|dev|test)(\b|[-.]|$)` or hostnames containing those substrings.
  - `storage`: hostnames matching `([a-z0-9.-]+\.)?(s3\.amazonaws\.com|s3\.[a-z0-9-]+\.amazonaws\.com|blob\.core\.windows\.net|storage\.googleapis\.com|storage\.cloud\.google\.com)` or path patterns like `/(s3|bucket|blob|storage)/`.
- [ ] Each detector returns `[]SurfaceFinding`. The registry runs all detectors against the input.
- [ ] Wire recon findings into the scanner pipeline (M11) as a new stage. Findings flow to the formatters (M12) with `Type: "attack_surface"`.
- [ ] Unit tests: a fixture with each category produces the expected `SurfaceFinding`; clean URLs produce no findings.

## Exit Criteria

- [ ] `go test ./internal/recon/...` passes.
- [ ] A fixture URL `https://example.com/admin/users` produces one `SurfaceFinding` with `Category: "admin"`.
- [ ] A fixture URL `https://mybucket.s3.amazonaws.com/` produces one `SurfaceFinding` with `Category: "storage"`.
- [ ] All 9 category detectors are implemented and have at least one positive and one negative test case.
- [ ] Recon findings appear in JSON and SARIF output with a distinct `type` field.
- [ ] No regression: existing `internal/endpoints/` tests still pass.

## Dependencies

- Depends on: M6 (JS analyzer produces the URL list the recon engine scans), M9 (confidence scoring applies to recon findings)
- Depended on by: M11 (scanner pipeline includes the Recon Engine stage), M12 (formatters render the recon type)

## Notes for implementer

- `internal/endpoints/extract.go` (87 lines) extracts API/GraphQL/WebSocket URLs. Recon reuses the same URL list and adds categorization. Do not duplicate the URL extraction.
- The `internal` and `staging`/`uat` detectors are noisy by design — they catch the "I accidentally deployed dev config to prod" case. Tag these with `Confidence: LOW` and let `--severity` filtering hide them by default.
- The `storage` detector is the highest-value one for bug bounty: exposed S3 buckets are a frequent finding.
- Severity mapping: `graphql`, `admin`, `storage` → `HIGH`; `swagger`/`openapi`, `debug`, `metrics` → `MEDIUM`; `internal`, `staging`, `uat` → `LOW`.
- Findings should redact any query parameters in the URL to avoid leaking tokens in the output.
