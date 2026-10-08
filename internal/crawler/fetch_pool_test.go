package crawler

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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

// TestFetchURLConcurrentFetchesDoNotShareScratch is the test that actually
// catches a premature Put. The crawler calls fetchURL from one goroutine per
// URL against a shared client, so the buffer being Put back while the fetcher is
// still converting it means one goroutine reads bytes another is rewriting. The
// sequential case cannot see that — a string copy happens either way — but here
// a stolen buffer shows up as a result that belongs to a different worker.
func TestFetchURLConcurrentFetchesDoNotShareScratch(t *testing.T) {
	const (
		workers = 8
		rounds  = 40
		bodyLen = 8192
	)

	bodies := make([]string, workers)
	for i := range bodies {
		bodies[i] = fmt.Sprintf("worker-%02d-", i) + strings.Repeat(string(rune('A'+i)), bodyLen)
	}

	var reqs atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.Atoi(r.URL.Query().Get("id"))
		if err != nil || id < 0 || id >= workers {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		reqs.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(bodies[id]))
	}))
	defer srv.Close()
	client := srv.Client()

	var wg sync.WaitGroup
	var bad atomic.Int64
	var firstBad atomic.Value
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			url := srv.URL + "?id=" + strconv.Itoa(id)
			for i := 0; i < rounds; i++ {
				got, _, err := fetchURL(client, url, "concurrent-agent")
				if err != nil {
					bad.Add(1)
					firstBad.CompareAndSwap(nil, fmt.Sprintf("worker %d round %d: %v", id, i, err))
					return
				}
				if got != bodies[id] {
					bad.Add(1)
					firstBad.CompareAndSwap(nil,
						fmt.Sprintf("worker %d round %d: got %d bytes starting %q, want %d bytes of worker %d",
							id, i, len(got), prefixForLog(got), len(bodies[id]), id))
					return
				}
			}
		}(w)
	}
	wg.Wait()

	if n := bad.Load(); n > 0 {
		msg, _ := firstBad.Load().(string)
		t.Fatalf("%d of %d workers saw a body that was not theirs (pooled scratch shared between fetches); first: %s",
			n, workers*rounds, msg)
	}
	if n := reqs.Load(); n != workers*rounds {
		t.Fatalf("expected %d fetches, server saw %d", workers*rounds, n)
	}
}

func prefixForLog(s string) string {
	if len(s) > 24 {
		return s[:24]
	}
	return s
}

// Three bodies, each long enough to cover the previous one's bytes in a reused
// buffer and each different, so a result that does alias pooled bytes is visible
// immediately. Built with strings.Repeat because a const cannot call it.
var (
	aliasBodyA = "head-AAAA" + strings.Repeat("A", 4096)
	aliasBodyB = "head-BBBB" + strings.Repeat("B", 4096)
	aliasBodyC = "head-CCCC" + strings.Repeat("C", 4096)
)

// TestFetchURLNoBufferAliasing is the guard against the copy boundary being
// broken. It fetches once, then fetches again through the same client and
// checks the first result is still the body it was handed.
//
// GOMAXPROCS is pinned because sync.Pool hands a Put'd buffer back to the Put'er
// only while the goroutine stays on the owning P. With a single P the reuse — and
// therefore this test — is deterministic rather than timing-dependent.
//
// What this guards: fetchURL returning a string that still aliases pooled bytes.
// A string built with string(b) never aliases, so this is a net for a future
// refactor that returns the bytes instead ([]byte, or unsafe.String). It is NOT
// the test that catches a premature Put: a Put that lands before the copy is
// invisible to a single goroutine, because the copy happens regardless. That
// hazard is TestFetchURLConcurrentFetchesDoNotShareScratch, above.
func TestFetchURLNoBufferAliasing(t *testing.T) {
	prev := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(prev)

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

// TestFetchBufPoolRetentionCap checks the drop direction only: a buffer that
// outgrew maxPooledFetchBufBytes must not come back out of the pool, because one
// 10MB entry would pin the pool for the rest of the crawl.
//
// The positive direction — a buffer at the cap is still recycled — is
// deliberately NOT asserted here. Two things outside this test's control can
// empty sync.Pool between a Put and a Get: the GC clears it every cycle, and the
// race build of sync.Pool randomly drops one Put in four (see the
// "Randomly drop x on floor" branch in sync/pool.go). Either one makes a
// retained buffer look absent, so that assertion would be a flake rather than a
// guard. That recycling works at all is what BenchmarkFetchURL measures.
//
// GOMAXPROCS is pinned so the goroutine stays on the P it Put into, which leaves
// only those two effects in play.
func TestFetchBufPoolRetentionCap(t *testing.T) {
	prev := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(prev)

	// poolPutThenGet empties this P's private slot first, because whatever an
	// earlier test left there is what Get would otherwise hand back, then puts
	// buf and returns the next Get.
	poolPutThenGet := func(buf []byte) []byte {
		_ = getFetchBuf()
		p := &buf
		putFetchBuf(p)
		return *getFetchBuf()
	}

	for i := 0; i < 8; i++ {
		if got := poolPutThenGet(make([]byte, maxPooledFetchBufBytes+1)); cap(got) > maxPooledFetchBufBytes {
			t.Fatalf("pool retained an oversized buffer: cap = %d, retention cap = %d",
				cap(got), maxPooledFetchBufBytes)
		}
	}
}

// TestFetchURLOversizeBodyDoesNotPinPool is the end-to-end half of the
// retention cap: an 11MB body must still be truncated to maxBodyBytes (the
// existing behavioural expectation) AND must not be left sitting in the pool.
func TestFetchURLOversizeBodyDoesNotPinPool(t *testing.T) {
	prev := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(prev)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		chunk := make([]byte, 64*1024)
		for i := range chunk {
			chunk[i] = 'a'
		}
		for i := 0; i < (11*1024*1024)/(64*1024); i++ {
			_, _ = w.Write(chunk)
		}
	}))
	defer srv.Close()

	body, _, err := fetchURL(srv.Client(), srv.URL, "oversize-agent")
	if err != nil {
		t.Fatalf("fetchURL: %v", err)
	}
	if len(body) != maxBodyBytes {
		t.Fatalf("oversize body was not truncated: len = %d, want %d", len(body), maxBodyBytes)
	}

	for i := 0; i < 3; i++ {
		got := getFetchBuf()
		if cap(*got) > maxPooledFetchBufBytes {
			t.Fatalf("oversize fetch left an oversized buffer in the pool: cap = %d, retention cap = %d",
				cap(*got), maxPooledFetchBufBytes)
		}
		putFetchBuf(got)
	}
}

// scriptReader is a reader that hands out at most perRead bytes per Read, can
// return data together with a non-EOF error, and reports EOF when drained.
type scriptReader struct {
	data    []byte
	fail    error
	perRead int
}

func (r *scriptReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		if r.fail != nil {
			return 0, r.fail
		}
		return 0, io.EOF
	}
	n := len(r.data)
	if r.perRead > 0 && n > r.perRead {
		n = r.perRead
	}
	if n > len(p) {
		n = len(p)
	}
	copy(p, r.data[:n])
	r.data = r.data[n:]
	if len(r.data) == 0 && r.fail != nil {
		return n, r.fail
	}
	return n, nil
}

// TestReadAllIntoMatchesIOReadAll is the correctness half of the pooling work.
// readAllInto replaces io.ReadAll(io.LimitReader(r, limit+1)) inside fetchURL,
// so the two have to agree byte for byte, including on the truncation boundary
// and on a reader that fails mid-body.
func TestReadAllIntoMatchesIOReadAll(t *testing.T) {
	cases := []struct {
		name    string
		data    string
		limit   int
		fail    error
		perRead int
	}{
		{name: "empty body", data: "", limit: 1024},
		{name: "one byte per read", data: "hello world", limit: 1024, perRead: 1},
		{name: "exactly the limit", data: strings.Repeat("x", 64), limit: 64},
		{name: "limit plus one", data: strings.Repeat("x", 65), limit: 64},
		{name: "far past the limit", data: strings.Repeat("x", 5000), limit: 64},
		{name: "error after partial data", data: "abc", limit: 1024, fail: errors.New("boom")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want, wantErr := io.ReadAll(io.LimitReader(
				&scriptReader{data: []byte(tc.data), fail: tc.fail, perRead: tc.perRead}, int64(tc.limit)+1))

			bufp := getFetchBuf()
			err := readAllInto(bufp,
				&scriptReader{data: []byte(tc.data), fail: tc.fail, perRead: tc.perRead}, tc.limit)
			got := *bufp
			putFetchBuf(bufp)

			if (err == nil) != (wantErr == nil) {
				t.Fatalf("error mismatch: readAllInto err = %v, io.ReadAll err = %v", err, wantErr)
			}
			if string(got) != string(want) {
				t.Fatalf("bytes mismatch: readAllInto returned %d bytes %q, io.ReadAll returned %d bytes %q",
					len(got), truncateForLog(got), len(want), truncateForLog(want))
			}
		})
	}
}

func truncateForLog(b []byte) string {
	if len(b) > 32 {
		return string(b[:32]) + "..."
	}
	return string(b)
}
