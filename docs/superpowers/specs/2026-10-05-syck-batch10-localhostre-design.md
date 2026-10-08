# SYCK Batch 10 — jsanalysis localhostRE — Design Spec

Date: 2026-10-08
Status: grounded; single regex, two coupled fixes

## 1. Intent

`internal/jsanalysis/analyze.go`'s `localhostRE` under-matches. It is:

```
(?:localhost|127\.0\.0\.1|0\.0\.0\.0):\d+
```

Three case-sensitive spellings, `127.0.0.1` only (not `127/8`), no `::1`, and a mandatory `:port`. A JS config value containing `LOCALHOST:8080`, `127.0.0.2:8080`, or `[::1]:8080` yields no finding, even though `internal/internalurl.IsLoopback` accepts all three and `internal/recon`'s `classifyInternal` already reports them for URLs.

## 2. Why this is not a one-line swap

The regex is **unanchored**, so it emits a *subspan*: `http://my-localhost:8080/` produces the finding `localhost:8080`. `IsLoopback` parses a host and answers false for `my-localhost:8080` — the span the current code emits was never a host. Batch 5 declined to delegate for exactly this reason and recorded it in `ARCHITECTURE.md` §15 item 3.

**The vocabulary and the anchoring must be fixed in the same edit.** Widening the token list while leaving the regex unanchored would:
- trade under-matches for *wrong* findings (subspans of longer hostnames keep being emitted), and
- still not emit whole hosts, which is the precondition for any future delegation.

## 3. What changes

Fix the extractor so it emits whole hosts and recognizes the loopback set:

- anchor the match at a token boundary (`\b` or an explicit delimiter class), so `my-localhost:8080` is not carved into `localhost:8080`
- accept the loopback vocabulary: `localhost` (any case), `127.0.0.0/8`, `::1`, `0.0.0.0`
- keep the `:port` requirement, which is what makes it a service-address finding rather than a bare hostname
- keep emitting what it emits today for inputs it already handles correctly, so existing findings are unchanged

## 4. Direction

Findings go **up** for the three under-matched classes, and the subspan carve-ups change *which* string is reported for a fourth class. State both explicitly.

## 5. Testing

Characterize first, per the standing rule. Drive `Analyze` (or whichever entry point owns the regex) with:

| Input | Current behaviour | Expected after |
|---|---|---|
| `http://my-localhost:8080/` | reports `localhost:8080` | must change — see §4 |
| `var db = "LOCALHOST:8080"` | nothing | reports it |
| `var db = "127.0.0.2:8080"` | nothing | reports it |
| `var db = "[::1]:8080"` | nothing | reports it |
| `var db = "localhost:8080"` | reports | **unchanged** |
| `var db = "example.com:8080"` | nothing | **unchanged** (still nothing) |

Pin current behaviour first, then the change.

## 6. Risks

- **Anchoring changes what the existing findings *contain*.** `http://my-localhost:8080/` currently yields `localhost:8080`; anchored, it should yield the whole host. That is a visible change to a field users may be keying on — record it.
- **`Batch 5`'s tripwire comment says delegation becomes viable once the extractor emits whole hosts.** After this batch that comment's trigger condition is closer to true; update the comment so it does not overstate readiness. Do **not** delegate in this batch — that is a separate decision with its own blast radius.
- `internal/recon`'s `classifyInternal` must not be touched — it already reports these forms via `internalurl`.
- Parity will not catch this unless a fixture happens to contain one of these shapes. Do not cite it.
