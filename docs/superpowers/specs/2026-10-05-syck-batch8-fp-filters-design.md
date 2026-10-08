# SYCK Batch 8 — FP Filters on the Lagging Paths — Design Spec

Date: 2026-10-08
Status: grounded; three paths, suppression direction

## 1. Intent

Three rule-matching paths apply the entropy floor (Batch 5) but skip the false-positive and context filters that the plain-file path applies. Adopting them removes false positives — findings go **down**.

| Path | Has floor | Missing |
|---|---|---|
| `internal/jsrecon/reconstruct.go` | yes (`:415`) | `IsFalsePositiveSecret`, `IsFalsePositiveToken`, `IsFalsePositiveEmail`, `RequiresContext` |
| `internal/json_scanner/scanner.go` | yes (`:111`) | same four |
| `internal/decoder/pipeline.go` | yes (`:168`) | `IsFalsePositiveSecret`, `RequiresContext` (has Token/Email at 171/174) |

The plain-file reference (`internal/scanner/helpers.go:529-564`):

```go
if rule.RequiresContext && !lineHasContextKeyword(line, rule.ContextKeywords) { continue }
// ... secret extraction, skipSecrets, severity, entropy floor ...
if entropy.IsFalsePositiveSecret(secret) { continue }
if entropy.IsFalsePositiveToken(secret) { continue }
if entropy.IsFalsePositiveEmail(secret) { continue }
```

## 2. What is NOT in this batch

**`internal/scanner/multiline.go` is Batch 9.** It applies no entropy floor at all, no FP filters, and no `RequiresContext` — and it runs on the live path (`--multiline` defaults true, LSP forces it on). That is a floor-plus-filters change on a default-on path, a different shape with a wider blast radius. Doing it here would mean one review covering two different change shapes.

## 3. The `RequiresContext` subtlety

`helpers.go:529` checks `lineHasContextKeyword(line, rule.ContextKeywords)` — the **source line**. Each lagging path must check the analogous text:

- jsrecon: the reconstructed string (or the finding's context — decide during implementation, record it)
- json_scanner: the JSON key path / value context
- decoder/pipeline: the decoded chunk

`env_generic_secret` sets `requires_context: true`, so on these paths that guard is currently inert — adopting it will suppress exactly the low-context matches. That is the point, but it must be characterized, not assumed.

## 4. Behavior change, stated precisely

For each path, findings currently reported that match an FP heuristic or lack a required context keyword will disappear. Direction is strictly suppression — these filters can only remove, never add. `CHANGELOG.md` must frame it as false-positive reduction with the measured counts.

## 5. Testing

Characterize before changing, per path: drive each with inputs that currently produce findings the filters would remove (a known FP-token string, a context-less `env_generic_secret` match), plus controls that must survive. Assert current behavior first (reported), then the suppression.

## 6. Risks

- **Context-keyword checking needs comparable text.** If a path has no natural "line" (decoded chunks, JSON values), the `RequiresContext` check may need the finding context rather than source text. Whatever is chosen must be documented, because it defines what "has context" means on that path.
- **`decoder/pipeline.go` already applies Token/Email.** Do not double-apply; add only what is missing.
- **Do not touch `multiline.go`, `url_secrets.go`, or the key-name heuristic branch.** Out of scope, each for a recorded reason.
- Parity will not catch this unless fixtures contain FP-shaped matches — do not cite it.