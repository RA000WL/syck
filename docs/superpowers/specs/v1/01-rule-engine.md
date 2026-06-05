# Module 01 — Rule Engine

> YAML-driven detection engine. Compiled regex cache, validation, duplicate detection, rule versioning.

## Status

- **Tier:** P0
- **Phase:** V1.0
- **Action:** extend
- **Owner:** unclaimed
- **Source package:** `internal/rules/`

## Goal

Extend the existing Rule struct to carry the V1 schema (entropy gate, context keywords, requires_context, verify flag, version) without breaking the current 130+ built-in rules. Add `RuleLoader`, `RuleValidator`, and `RuleCompiler` types so contributors have explicit, testable units for each stage of the rule pipeline.

## Tasks

- [ ] Extend `Rule` struct with: `EntropyThreshold float64`, `ContextKeywords []string`, `RequiresContext bool`, `Verify bool`, `Version string`. All fields YAML-optional.
- [ ] Add `RuleLoader` (LoadFromFile, LoadFromDir) that returns `*RuleSet` and a `LoadError` per-file.
- [ ] Add `RuleValidator` that checks: non-empty name, valid severity, compilable pattern, unique name within a set.
- [ ] Add `RuleCompiler` with a regex compile cache keyed by pattern string. Reject patterns that do not compile.
- [ ] Add duplicate-rule detection across the entire set (case-insensitive name match).
- [ ] Add a `Version` constant on the package (`RuleSchemaVersion = "1"`) and refuse to load rules whose `version` is greater.
- [ ] Keep all current rules loading as-is. Existing 130+ rules must pass the new validator.
- [ ] Unit tests: validation rejects bad rules, loader handles missing files, compiler cache hits on second call.

## Exit Criteria

- [ ] `go test ./internal/rules/...` passes.
- [ ] Loading `internal/rules/builtin.yaml` succeeds with no errors.
- [ ] A rule with `entropy_threshold: 4.5`, `context_keywords: [github]`, `requires_context: true` is loaded, compiled, and surfaced through the existing `RuleSet.MatchAll` API.
- [ ] Two rules with the same name in the same set produce a load error with a file:line hint.
- [ ] A rule with an invalid regex produces a load error with the pattern in the message.
- [ ] No change to the public API consumed by `internal/scanner/scanner.go`.

## Dependencies

- Depends on: nothing (this is the foundation)
- Depended on by: M2 (entropy threshold consumed by entropy engine), M5 (correlation uses verify flag), M9 (confidence uses regex match signal), M10 (rule testing consumes the validator)

## Notes for implementer

- The struct lives in `internal/rules/rule.go`. The validator, compiler, and loader should be sibling files (`validate.go`, `compile.go`, `load.go`).
- The existing `Load` function in `load.go` (35 lines) becomes a thin wrapper around `RuleLoader.LoadFromFile`.
- Do not break `Rule.Compiled()` or `Rule.MatchAll` — `internal/scanner/scanner.go` and `internal/decoder/pipeline.go` both call them.
