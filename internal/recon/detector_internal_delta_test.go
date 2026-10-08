package recon

// The delta ledger for Batch 4c Task 4: which inputs the delegation to
// internal/internalurl changed the answer for, and proof that nothing else in a
// generated vocabulary changed.
//
// The ten deleted regexes are reproduced here verbatim so a reader can re-derive
// the "was" side of every claim instead of trusting it. They are NOT a second
// implementation to maintain: classifyInternalOld exists only for these two
// tests. If a future change alters a branch, this file will fail and that
// failure means "update the CHANGELOG delta table", not "revert the code".
//
// Vocabulary covered by the sweep (this is the scope of the claim, not the input
// space — see the Limitations note in CHANGELOG.md):
//
//   - every token the old text regexes could match: the RFC 1918 ranges and
//     their boundaries, the loopback tokens (name, 127/8, 0.0.0.0, ::1, ::,
//     v4-mapped), the metadata address and hostname, plus public controls
//   - each of those in every position a URL can place text: authority, path,
//     query, fragment, and a scheme-lookalike inside a path or query
//   - five scheme forms: absent, http://, https://, protocol-relative, uppercase
//   - a second axis of internal-path / internal-host / container / port
//     vocabulary, which must reproduce its predecessor exactly
//
// What the sweep asserts, in order of importance:
//
//  1. If any branch's old-regex match differs from its new predicate's match,
//     the flip must be one of the four declared mechanisms below. Anything else
//     means internalurl drifted from the regex it replaced.
//  2. If NO branch flipped, oldClassify and classifyInternal must agree
//     exactly. This catches a change to the chain itself — a reordered or
//     edited branch — independently of the branch-by-branch comparison.
//  3. Each declared mechanism must be exercised by the sweep at least once, so
//     trimming the token list cannot silently drop coverage. This is the check
//     that would have caught the blind spot in the first version of the
//     corpus, whose generator always paired a path-position loopback token with
//     a loopback HOST and so never produced a "localhost -> *" transition.

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/RA000WL/syck/internal/internalurl"
)

// The ten regexes deleted from detector_internal.go by this task, verbatim.
var (
	oldInternalRE     = regexp.MustCompile(`(?i)/(internal|private|intranet|corp)(\b|/|$)`)
	oldInternalHostRE = regexp.MustCompile(`(?i)(internal\.|corp\.|\.local)`)
	oldPrivateIP10RE  = regexp.MustCompile(`\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	oldPrivateIP172RE = regexp.MustCompile(`\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b`)
	oldPrivateIP192RE = regexp.MustCompile(`\b192\.168\.\d{1,3}\.\d{1,3}\b`)
	oldLocalhostRE    = regexp.MustCompile(`\b(?:localhost|127\.0\.0\.\d+|0\.0\.0\.0)\b`)
	oldCloudMetaRE    = regexp.MustCompile(`\b169\.254\.169\.254\b`)
	oldK8sRE          = regexp.MustCompile(`(?i)(?:[a-z0-9-]+\.){1,3}(?:svc|cluster|local|internal)\b`)
	oldDockerRE       = regexp.MustCompile(`(?i)(?:docker|container)[_.]?(?:host|name|id|service)\b`)
	oldInternalPathRE = regexp.MustCompile(`(?i)/(?:debug|trace|admin|internal|private|staging|dev|test|sandbox|legacy|hidden)(?:/|$)`)
	oldSensitivePort  = regexp.MustCompile(`:(?:3306|5432|6379|27017|9200|9300|11211|5984|8500|8600|8200)\b`)
)

// classifyInternalOld is classifyInternal as it stood before Batch 4c Task 4:
// the same if-chain, in the same order, over the regexes above.
func classifyInternalOld(url string) string {
	if oldInternalRE.MatchString(url) || oldInternalPathRE.MatchString(url) {
		return "internal"
	}
	if oldInternalHostRE.MatchString(url) || oldK8sRE.MatchString(url) {
		return "internal_host"
	}
	if oldPrivateIP10RE.MatchString(url) || oldPrivateIP172RE.MatchString(url) || oldPrivateIP192RE.MatchString(url) {
		return "private_ip"
	}
	if oldLocalhostRE.MatchString(url) {
		return "localhost"
	}
	if oldCloudMetaRE.MatchString(url) {
		return "cloud_metadata"
	}
	if oldDockerRE.MatchString(url) {
		return "container_service"
	}
	if oldSensitivePort.MatchString(url) {
		return "sensitive_port"
	}
	return ""
}

// branchPair pairs one branch's pre-Task-4 regex test with its post-Task-4
// predicate, so a difference can be attributed to a specific branch.
type branchPair struct {
	name string
	old  func(string) bool
	new  func(string) bool
}

func deltaBranches() []branchPair {
	return []branchPair{
		{"internal",
			func(u string) bool { return oldInternalRE.MatchString(u) || oldInternalPathRE.MatchString(u) },
			internalurl.IsInternalPath},
		{"internal_host",
			func(u string) bool { return oldInternalHostRE.MatchString(u) || oldK8sRE.MatchString(u) },
			internalurl.IsInternalHost},
		{"private_ip",
			func(u string) bool {
				return oldPrivateIP10RE.MatchString(u) || oldPrivateIP172RE.MatchString(u) ||
					oldPrivateIP192RE.MatchString(u)
			},
			internalurl.IsPrivateHost},
		{"localhost", oldLocalhostRE.MatchString, internalurl.IsLoopback},
		{"cloud_metadata", oldCloudMetaRE.MatchString, internalurl.IsCloudMetadata},
		{"container_service", oldDockerRE.MatchString, dockerServiceRE.MatchString},
		{"sensitive_port", oldSensitivePort.MatchString, internalurl.IsSensitivePort},
	}
}

// TestClassifyInternalDeltaLedger pins the declared delta classes one row at a
// time. Each row's "was" column is not copied from the CHANGELOG — it is
// recomputed from the old regexes at run time and compared against the
// documented value, so the table cannot drift away from the code it describes.
//
// Three of the seven classes REMOVE a finding. Two of those three are Low
// severity (localhost) and one is High (cloud_metadata); the private_ip class
// removes a Medium one. The four widenings only ever add Low-severity
// findings.
func TestClassifyInternalDeltaLedger(t *testing.T) {
	tests := []struct {
		name   string
		url    string
		was    string // documented pre-Task-4 category, itself verified below
		now    string // post-Task-4 category
		dir    string
		reason string
	}{
		// --- widenings: loopback spelled more ways than the old regex ---
		{"widen-localhost-name-case-insensitive", "http://LOCALHOST/api", "", "localhost", "widening (adds Low)",
			"oldLocalhostRE carried no (?i) flag, so an uppercase host matched nothing"},
		{"widen-loopback-outside-127-0-0-x", "http://127.1.2.3/x", "", "localhost", "widening (adds Low)",
			"oldLocalhostRE hardcoded 127\\.0\\.0\\.\\d+; ip.IsLoopback() covers all of 127/8"},
		{"widen-ipv6-loopback", "http://[::1]/x", "", "localhost", "widening (adds Low)",
			"oldLocalhostRE had no IPv6 literal; ip.IsLoopback() covers ::1"},
		{"widen-ipv6-unspecified", "http://[::]/x", "", "localhost", "widening (adds Low)",
			"the old regex matched 0.0.0.0 only; ip.IsUnspecified() also covers ::"},

		// --- narrowings: text-matched tokens that are not the host ---
		{"narrow-private-ip-in-path", "http://foo.com/10.0.0.1/x", "private_ip", "", "narrowing (removes Medium)",
			"oldPrivateIP10RE text-matched the private IP in the PATH; IsPrivateHost parses the host foo.com"},
		{"narrow-metadata-ip-in-path", "http://foo.com/169.254.169.254/x", "cloud_metadata", "", "narrowing (removes High)",
			"oldCloudMetaRE text-matched the metadata IP in the PATH; IsCloudMetadata compares the host"},
		{"narrow-loopback-token-in-path", "http://example.com/localhost", "localhost", "", "narrowing (removes Low)",
			"oldLocalhostRE text-matched the name in the PATH; IsLoopback parses the host example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyInternalOld(tt.url); got != tt.was {
				t.Errorf("classifyInternalOld(%q) = %q, but the ledger documents %q — "+
					"the CHANGELOG delta table is stale", tt.url, got, tt.was)
			}
			if got := classifyInternal(tt.url); got != tt.now {
				t.Errorf("classifyInternal(%q)\n  got  %q\n  want %q (%s)",
					tt.url, got, tt.now, tt.dir)
			}
			t.Logf("%s: %q -> %q — %s", tt.dir, tt.was, tt.now, tt.reason)
		})
	}
}

// TestClassifyInternalAdditionalDeltaInstances pins the narrower instances of
// the same four mechanisms that TestClassifyInternalDeltaLedger does not name,
// so "seven classes" is not mistaken for "seven affected inputs".
//
// These are the two positions the ledger's rows do not cover. A hostname that
// EMBEDS an IP literal is an authority component, not a path, yet the old text
// regexes matched the literal inside it — so the narrowing applies to a host.
// All three REMOVE a finding, and the first is a real SSRF-shaped name
// (127.0.0.1.nip.io resolves to loopback), so it is called out here rather than
// left to the sweep.
func TestClassifyInternalAdditionalDeltaInstances(t *testing.T) {
	tests := []struct {
		name string
		url  string
		was  string
		note string
	}{
		{"loopback-literal-inside-hostname", "http://127.0.0.1.nip.io/", "localhost",
			"REMOVES a finding on a name that really does resolve to loopback. The " +
				"host is not an IP literal, so IsLoopback is false. Accepted: " +
				"internalurl deliberately resolves nothing, and netguard gates the " +
				"actual fetch."},
		{"private-literal-inside-hostname", "http://10.0.0.1.example.com/", "private_ip",
			"REMOVES a Medium finding: the host is a name, not an RFC 1918 address"},
		{"localhost-name-inside-hostname", "http://localhost.example.com/", "localhost",
			"REMOVES a Low finding; internalurl does not substring-match the name"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyInternalOld(tt.url); got != tt.was {
				t.Errorf("classifyInternalOld(%q) = %q, ledger says %q", tt.url, got, tt.was)
			}
			if got := classifyInternal(tt.url); got != "" {
				t.Errorf("classifyInternal(%q) = %q, want %q", tt.url, got, "")
			}
			t.Logf("%q: %q -> \"\" — %s", tt.url, tt.was, tt.note)
		})
	}
	// The same three mechanisms also fire in the query and fragment, which are
	// asserted through the sweep below. One representative each, so a future
	// change to hostOf cannot reintroduce a query- or fragment-borne host.
	for _, u := range []string{
		"http://example.com/?next=http://10.0.0.1/",
		"http://example.com/?next=http://169.254.169.254/",
		"http://example.com/?next=http://127.0.0.1/",
	} {
		if got := classifyInternal(u); got != "" {
			t.Errorf("classifyInternal(%q) = %q, want %q (an absolute URL in a query "+
				"is not the host)", u, got, "")
		}
	}
}

// deltaVocab returns the token vocabulary the sweep is built from: every token
// the deleted text regexes could match, plus the public and internal-host
// controls that must NOT flip.
func deltaVocab() []string {
	return []string{
		// RFC 1918, and the addresses just outside each range.
		"10.0.0.1", "10.255.255.255", "9.255.255.255", "11.0.0.0",
		"172.16.0.1", "172.31.255.255", "172.15.255.255", "172.32.0.1",
		"192.168.0.1", "192.168.255.255", "192.167.255.255", "192.169.0.1",
		// The loopback tokens the old regex spelled out...
		"localhost", "LOCALHOST", "LocalHost", "localhost.",
		"127.0.0.1", "127.0.0.5", "127.0.0.0", "127.0.0.255", "127.0.0.200",
		"0.0.0.0", "0.0.0.1", "0.0.1.0",
		// ...and the neighbours and spellings it did not.
		"127.1.2.3", "127.255.255.255", "126.255.255.255", "128.0.0.0",
		"[::1]", "::1", "[::]", "::", "[::ffff:127.0.0.1]", "[::ffff:10.0.0.1]",
		"[::2]", "[2001:db8::1]", "[fe80::1]", "127.1",
		// A hostname that embeds a literal: authority position, but the old
		// regexes matched the literal inside it.
		"127.0.0.1.nip.io", "10.0.0.1.example.com", "localhost.example.com",
		// Metadata address and hostname, with the two attacks netguard pins.
		"169.254.169.254", "169.254.1.1", "169.253.0.1", "169.255.0.1",
		"metadata.google.internal", "METADATA.GOOGLE.INTERNAL",
		"metadata.google.internal.", "xmetadata.google.internal",
		"metadata.google.internal.evil.com",
		// Public controls.
		"example.com", "foo.com", "8.8.8.8", "1.2.3.4", "public.site.org",
		"127.0.0.1.example.com",
		// internal_host vocabulary, which must not flip.
		"foo.internal", "api.corp.example.com", "db.local", "a.b.svc",
		"svc.cluster", "a.b.c.internal", "corp.",
		// container_service and sensitive_port vocabulary, which must not flip.
		"docker_host", "dockerhost", "container.name", "container-id",
	}
}

// deltaPositions returns every way a URL can place one of those tokens.
func deltaPositions() []string {
	return []string{
		"",               // the authority itself
		"/tok",           // path
		"/tok/",          // path, terminated
		"/x/tok",         // path, not the first segment
		"?tok=1",         // query
		"/x?u=tok",       // query on a URL that has a path
		"#tok",           // fragment
		"/x#tok",         // fragment on a URL that has a path
		"/a://b",         // a "://" inside a path must not look like a scheme
		"?u=http://tok/", // an absolute URL inside a query
		"/tok.json",      // token followed by a non-boundary character
		"/tok:5432",      // token alongside a sensitive port
	}
}

func deltaSweep() []string {
	schemes := []string{"", "http://", "https://", "//", "HTTP://"}
	var out []string
	for _, s := range schemes {
		for _, tok := range deltaVocab() {
			for _, pos := range deltaPositions() {
				if u := s + tok + pos; len(u) < 240 {
					out = append(out, u)
				}
			}
		}
	}
	// Second axis: the internal-path / host / port vocabulary, which the
	// shared predicates claim to reproduce exactly, against every public host
	// and a sensitive, near-miss and ordinary port.
	pathVocab := []string{
		"/admin", "/debug", "/trace", "/staging", "/dev", "/test", "/sandbox",
		"/legacy", "/hidden", "/internal", "/private", "/intranet", "/corp",
		"/internal-api", "/admin?x=1", "/sandbox.json", "/administrator",
		"/testing", "/x.internal/y", "/a.b.svc/x", "/x.local",
		"/docker_host/", "/10.0.0.1/x", "/169.254.169.254/x", "/localhost",
		"/127.0.0.5", "/0.0.0.0", "/[::1]/x", "/localhost:3000",
	}
	for _, s := range schemes {
		for _, h := range []string{"example.com", "foo.com", "host", ""} {
			for _, p := range pathVocab {
				for _, port := range []string{"", ":5432", ":33060", ":8080"} {
					out = append(out, s+h+port+p)
				}
			}
		}
	}
	// Third axis, and the one the first two both miss: an interesting HOST with
	// an interesting PATH. Without it the sweep never builds
	// "http://10.0.0.1/x.internal/y", where IsPrivateHost and IsInternalHost are
	// both true and only the branch order decides the category — so the
	// "no undeclared chain change" assertion above would pass even with two
	// branches transposed. This is the same shape of gap that let a whole
	// delta class go unnoticed the first time: the blind spot always sits where
	// two vocabularies meet, never inside either one.
	for _, s := range schemes {
		for _, h := range deltaVocab() {
			for _, p := range pathVocab {
				if u := s + h + p; len(u) < 240 {
					out = append(out, u)
				}
			}
		}
	}
	return out
}

// TestClassifyInternalNoUndeclaredDelta is the exhaustive check behind the
// claim "no transition outside these four mechanisms".
//
// A "flip" is a branch whose old regex and new predicate disagree about one
// input. There are exactly four declared flips, each with one cause: a
// host-parsed predicate replacing a raw-text regex. Everything else — the
// internal-path union, the internal-host union, the container regex, the port
// list — must reproduce its predecessor exactly, and this test proves that over
// the vocabulary in deltaVocab rather than asserting it in prose.
func TestClassifyInternalNoUndeclaredDelta(t *testing.T) {
	// branch:mechanism -> what it means. Nothing else may appear.
	allowed := map[string]string{
		"localhost:up":        "IsLoopback accepts more spellings than oldLocalhostRE (name case, 127/8, ::1, ::)",
		"localhost:down":      "oldLocalhostRE text-matched a loopback token outside the authority",
		"private_ip:down":     "oldPrivateIP*RE text-matched an RFC 1918 address outside the authority",
		"cloud_metadata:down": "oldCloudMetaRE text-matched the metadata address outside the authority",
		"cloud_metadata:up":   "IsCloudMetadata also matches the GCP metadata HOSTNAME, which the old regex did not",
	}

	branches := deltaBranches()
	inputs := deltaSweep()
	sets := map[string]int{}        // flip-set -> how many inputs
	examples := map[string]string{} // flip-set -> one input
	mechs := map[string]int{}       // single mechanism -> how many inputs
	categoryChanges := 0

	for _, in := range inputs {
		var flips []string
		for _, b := range branches {
			ob, nb := b.old(in), b.new(in)
			if ob == nb {
				continue
			}
			dir := "down"
			if !ob {
				dir = "up"
			}
			f := b.name + ":" + dir
			flips = append(flips, f)
			mechs[f]++
			if _, ok := allowed[f]; !ok {
				t.Errorf("UNDECLARED DELTA: %q flips %s, which is not one of the "+
					"declared mechanisms — add it to the CHANGELOG table and the "+
					"allowlist, or fix the mapping", in, f)
			}
		}
		if len(flips) == 0 {
			// No branch disagrees, so the chain must return the same category.
			// This is what catches an edit to the chain itself — a reordered
			// branch, a changed return literal — without any predicate
			// involvement at all.
			if o, n := classifyInternalOld(in), classifyInternal(in); o != n {
				t.Errorf("UNDECLARED CHAIN CHANGE with no predicate flip: %q %q -> %q", in, o, n)
			}
			continue
		}
		sort.Strings(flips)
		key := fmt.Sprint(flips)
		sets[key]++
		if _, ok := examples[key]; !ok {
			examples[key] = in
		}
		if classifyInternalOld(in) != classifyInternal(in) {
			categoryChanges++
		}
	}

	// Every declared mechanism must still be reachable, or the sweep has lost
	// the coverage that makes the allowlist meaningful. This is the check that
	// would have caught the blind spot in the first version of the corpus,
	// whose generator always paired a path-position loopback token with a
	// loopback HOST and so never produced a "localhost -> *" transition.
	for _, m := range sortedKeys(allowed) {
		if mechs[m] == 0 {
			t.Errorf("declared mechanism %s is exercised by NO input in the sweep; "+
				"the sweep's vocabulary has drifted away from the delta set", m)
		}
	}

	t.Logf("sweep=%d inputs, %d change category, %d distinct flip-sets, "+
		"%d inputs flip a single mechanism",
		len(inputs), categoryChanges, len(sets), countSingles(sets))
	keys := make([]string, 0, len(sets))
	for k := range sets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		t.Logf("  %6d  %-32s e.g. %s", sets[k], k, examples[k])
	}
	t.Logf("declared mechanisms (inputs each):")
	for _, m := range sortedKeys(allowed) {
		t.Logf("  %6d  %-22s %s", mechs[m], m, allowed[m])
	}
}

func countSingles(sets map[string]int) int {
	n := 0
	for k, c := range sets {
		if !strings.Contains(k, " ") {
			n += c
		}
	}
	return n
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
