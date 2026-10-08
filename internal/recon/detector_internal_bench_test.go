package recon

import "testing"

// Benchmarks for classifyInternal, added by the Batch 4c final whole-branch
// review to MEASURE the delegation's cost. Measured on this branch (median of
// 6 at -benchtime 2000x): the delegation is FASTER in time but allocates. On a
// 16-URL mixed corpus, 53.7k ns/op and 57 allocs/op versus 79.5k ns/op and
// 0 allocs/op for the old regex chain; on the all-public worst case (every
// branch evaluated), 40.7k ns/op and 48 allocs/op versus 60.1k ns/op and
// 0 allocs/op.
//
// The concern that motivated adding this (hostOf calls url.Parse up to three
// times per URL) does not show up as time on this corpus — url.Parse is cheaper
// than the alternations it replaced — but it is real as garbage. Nothing was
// optimized in response; these numbers are a baseline for a future change to be
// measured against, not a claim that the delegation is free.
//
// classifyInternalOld (the ten regexes, preserved in
// detector_internal_delta_test.go) is the pre-4c implementation, so the two are
// directly comparable.
//
// benchPublic is a corpus of URLs that match no branch at all: the case where
// classifyInternal evaluates every branch and returns "", and therefore pays for
// every predicate.
var benchPublic = []string{
	"https://example.com/",
	"https://example.com/api/users/123",
	"https://cdn.example.com/assets/app.4f2a1b.js",
	"https://example.com/blog/2026/10/hello-world?ref=hn",
	"https://api.example.com/v2/graphql",
	"https://example.com/static/css/site.css",
	"https://www.example.org/docs/guide#section-3",
	"https://example.com/search?q=golang+tutorial&page=2",
}

func benchCorpus() []string {
	internal := []string{
		"http://10.0.0.5/admin/settings",
		"http://internal.corp.example.com/api",
		"http://localhost:8080/debug/pprof",
		"http://127.0.0.1:5432/",
		"http://10.0.0.1:6379/",
		"http://dev.staging.example.com/",
		"http://svc.cluster.local:3306/",
		"http://metadata.google.internal/computeMetadata/v1/",
	}
	out := make([]string, 0, len(benchPublic)+len(internal))
	out = append(out, benchPublic...)
	out = append(out, internal...)
	return out
}

func BenchmarkClassifyInternalNew(b *testing.B) {
	benchClassify(b, classifyInternal)
}

func BenchmarkClassifyInternalOld(b *testing.B) {
	benchClassify(b, classifyInternalOld)
}

// BenchmarkClassifyInternalPublic isolates the worst case for the delegation: a
// URL that matches NO branch. internalurl's three parsed predicates each call
// hostOf → url.Parse, so a total miss pays for three parses where the old
// regex chain paid for several cheap MatchString calls and allocated nothing.
func BenchmarkClassifyInternalPublicNew(b *testing.B) {
	benchClassify(b, classifyInternal, benchPublic...)
}

func BenchmarkClassifyInternalPublicOld(b *testing.B) {
	benchClassify(b, classifyInternalOld, benchPublic...)
}

func benchClassify(b *testing.B, fn func(string) string, corpus ...string) {
	if len(corpus) == 0 {
		corpus = benchCorpus()
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, u := range corpus {
			fn(u)
		}
	}
}
