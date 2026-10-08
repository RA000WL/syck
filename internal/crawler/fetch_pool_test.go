package crawler

import (
	"net/http"
	"net/http/httptest"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// fetchBenchBody is a realistic crawled page: a few KB of HTML with a charset
// declaration, ordinary markup and no high bytes, so DetectEncoding resolves
// from the header and the body is copied once on the way out to a string.
func fetchBenchBody() []byte {
	var b strings.Builder
	b.WriteString(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>bench</title></head><body>` + "\n")
	for i := 0; i < 40; i++ {
		b.WriteString("<p>Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor.</p>\n")
	}
	b.WriteString("</body></html>\n")
	return []byte(b.String())
}

// BenchmarkFetchURL is the gate ARCHITECTURE.md §15 item 5 puts on pooling
// fetchURL's read buffer: measure allocs/op and B/op before changing anything,
// and again after, and keep the pooling only if the numbers improve.
//
// Every op is one full fetch over a keep-alive connection, so the numbers
// include the HTTP round trip — that is deliberate. The buffer being pooled is
// a fraction of what fetchURL allocates, and the benchmark has to show the
// fraction is worth having rather than hiding it behind a micro-benchmark of
// the read alone.
func BenchmarkFetchURL(b *testing.B) {
	body := fetchBenchBody()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	client := srv.Client()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got, ct, err := fetchURL(client, srv.URL, "bench-agent")
		if err != nil {
			b.Fatalf("fetchURL: %v", err)
		}
		if len(got) != len(body) {
			b.Fatalf("body length = %d, want %d", len(got), len(body))
		}
		if ct == "" {
			b.Fatal("content type is empty")
		}
	}
}

// Three bodies, each long enough to cover the previous one in the buffer, so an
// early Put shows up as changed content in a result that was already returned.
// Built with strings.Repeat because a const cannot call it.
var (
	aliasBodyA = "head-AAAA" + strings.Repeat("A", 4096)
	aliasBodyB = "head-BBBB" + strings.Repeat("B", 4096)
	aliasBodyC = "head-CCCC" + strings.Repeat("C", 4096)
)

// TestFetchURLNoBufferAliasing is the guard for the only bug a pooled
// fetchURL can introduce that no other test and not reliably the race detector
// would catch: the buffer going back into the pool before the string copy.
//
// It fetches once, then fetches again through the same client and checks the
// first result is still the body it was handed. If a Put ever lands before
// string(utf8Body), the second fetch reuses the same buffer underneath the
// first result and this fails.
//
// GOMAXPROCS is pinned because sync.Pool hands a Put'd buffer back to the Put'er
// only while the goroutine stays on the owning P. With a single P the reuse —
// and therefore this test — is deterministic rather than timing-dependent.
func TestFetchURLNoBufferAliasing(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))

	bodies := []string{aliasBodyA, aliasBodyB, aliasBodyC, aliasBodyA}
	var n int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		body := bodies[n%len(bodies)]
		n++
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	client := srv.Client()

	first, _, err := fetchURL(client, srv.URL, "alias-agent")
	if err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	if first != aliasBodyA {
		t.Fatalf("first fetch body = %d bytes, want %d", len(first), len(aliasBodyA))
	}

	// Fetch enough times that the buffer is certainly handed back out, and
	// check the first result after every one.
	for i := 0; i < len(bodies); i++ {
		want := bodies[(i+1)%len(bodies)]
		got, _, err := fetchURL(client, srv.URL, "alias-agent")
		if err != nil {
			t.Fatalf("fetch %d: %v", i+2, err)
		}
		if got != want {
			t.Fatalf("fetch %d returned %d bytes of the wrong body", i+2, len(got))
		}
		if first != aliasBodyA {
			t.Fatalf("first result changed after %d more fetches: "+
				"fetchURL returned a string aliasing a reused buffer "+
				"(want %d bytes of %q, got %d bytes of %q)",
				i+1, len(aliasBodyA), aliasBodyA[:16], len(first), first[:16])
		}
	}
}
