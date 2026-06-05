# Module 10 — Rule Quality Testing

> Precision, recall, FP-rate, coverage harness. Reject rules with FP-rate > 0.5% on the negative corpus.

## Status

- **Tier:** P1
- **Phase:** V1.3
- **Action:** new
- **Owner:** unclaimed
- **New package:** `internal/ruletest/`

## Goal

A new rule added to `builtin.yaml` can quietly degrade precision if it is too broad. The rule quality testing framework runs every rule against a positive corpus (real token examples) and a negative corpus (large sample of JS, JSON, HTML files), and rejects rules that produce too many false positives.

## Tasks

- [ ] Create `internal/ruletest/ruletest.go` with the public `Harness` type.
- [ ] Define positive corpus: `internal/ruletest/testdata/positive/` — one text file per rule, each containing 50+ real token examples that must match.
- [ ] Define negative corpus: `internal/ruletest/testdata/negative/` — 100k JS, 100k JSON, 100k HTML files. Source from public datasets (npm registry, GitHub API, Common Crawl). Use `go:generate` to fetch and snapshot the corpora.
- [ ] `Harness.Run(rule rules.Rule) Report` — runs the rule against both corpora, returns precision, recall, FP-rate, coverage.
- [ ] FP-rate gate: any rule with `FP-rate > 0.5%` on the negative corpus is reported as `REJECTED`.
- [ ] Coverage gate: any rule with `recall < 95%` on the positive corpus is reported as `REJECTED`.
- [ ] Add a `cmd/ruletest/main.go` subcommand: `./syck ruletest` runs the harness against all built-in rules and prints a summary table. CI runs this and fails on any `REJECTED` rule.
- [ ] Add a CI workflow (`.github/workflows/ruletest.yml`) that runs `./syck ruletest` on every PR and on every push to main.
- [ ] Unit tests: a synthetic rule that always matches produces a known FP-rate; the gate triggers at 0.5%.

## Exit Criteria

- [ ] `go test ./internal/ruletest/...` passes.
- [ ] `./syck ruletest` runs against all built-in rules and prints a per-rule report.
- [ ] CI workflow runs on every PR and fails when any rule is `REJECTED`.
- [ ] A rule with `pattern: '.*'` (always matches) is `REJECTED` with FP-rate near 100%.
- [ ] A rule with `pattern: '\\bghp_[a-zA-Z0-9]{36}\\b'` passes the gate (GitHub PATs are well-formed and rare in real code).
- [ ] No regression: the existing 130+ rules pass the harness with no `REJECTED` result.

## Dependencies

- Depends on: M1 (rule schema is the input), M9 (uses the scorer indirectly via the existing pipeline)
- Depended on by: nothing — this is a leaf in the dependency graph

## Notes for implementer

- The negative corpus is large. Do not commit 300k files to git. Use `git lfs` or download on first run and cache. Document the download size in `testdata/README.md`.
- The positive corpus is smaller and can be committed. Start with 50 examples per rule for the 130 built-in rules = ~6,500 lines. Manageable.
- The harness must be fast. Parallelize the negative corpus scan with the existing `sync.WaitGroup` worker pattern from `internal/scanner/scanner.go:82`.
- A `REJECTED` rule does not get auto-removed from `builtin.yaml`. The CI failure forces a human to either tighten the pattern or add a `context_keywords` constraint (M1).
- The V1 spec asks for 10,000 real token examples. Start with 50 per rule × 130 rules = 6,500. Expand to 10,000+ as contributors add more examples. Track corpus size in the harness output.
- Recorded fixtures for HTTP-dependent rules (none in the current 130+ built-ins) are out of scope for V1.
