package recon

import (
	"testing"

	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/internalurl"
)

func TestInternalDetectorPositive(t *testing.T) {
	d := InternalDetector{}
	got := d.Detect([]string{"https://internal.example.com/secret"})
	if len(got) == 0 || got[0].Category != "internal" {
		t.Fatal("expected internal finding")
	}
}

func TestInternalDetectorNegative(t *testing.T) {
	d := InternalDetector{}
	got := d.Detect([]string{"https://example.com/public"})
	if len(got) != 0 {
		t.Errorf("expected 0, got %d", len(got))
	}
}

// TestClassifyInternalCharacterization pins the exact category string
// classifyInternal returns for representative inputs.
//
// classifyInternal delegates to internal/internalurl and applies an ordered
// if-chain, so the first branch that matches the URL wins. That ordering is
// itself part of the pinned behavior: the PRECEDENCE block at the end exists
// because reordering the chain would change output while every
// per-category row here still passed.
//
// Provenance. The non-DELTA expectations below were derived by reading the
// regexes this function used before Batch 4c Task 4 — not by observing its
// output — and Task 4 verified them against those regexes directly, via the
// sweep in detector_internal_delta_test.go. That sweep ships the ten deleted
// regexes and compares each branch's old regex against its new predicate over a
// generated cross-product of the old token vocabulary, asserting that the only
// disagreements are the five declared mechanisms.
//
// Not every literal below appears in that sweep's input set — rows like
// "h:33060", "internal.corp:5432" and "a.b.svc:3306" use hosts and ports the
// sweep's vocabulary does not build, and they are asserted here alone. So this
// file is not wholly a subset of the sweep's coverage; it adds host/port and
// precedence cases the sweep does not construct. What the sweep contributes is
// the general claim: across the whole vocabulary, no branch disagrees with its
// predecessor except where a delta is declared.
//
// Rows marked DELTA are the seven intentional behavior changes Task 4 made;
// each note says what changed and why. Rows marked HOSTFIX are the internalurl
// hostOf scheme-boundary fix, which Task 4 also made — they state the corrected
// value. Those prefixes are the only rows that were allowed to move.
func TestClassifyInternalCharacterization(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
		note string
	}{
		// --- internal ---------------------------------------------------
		// internalurl.IsInternalPath is the per-token union of the two regexes
		// this branch used to run: four tokens with a \b|/|$ tail (internal,
		// private, intranet, corp) and nine with the stricter (?:/|$) tail
		// (debug, trace, admin, staging, dev, test, sandbox, legacy, hidden).
		// "internal" here is the scheme's second slash followed by the host,
		// and \b holds between "l" and ".".
		{"internal-host-label", "http://internal.corp/api", "internal",
			"IsInternalPath via the 'internal' token + the \\b tail"},
		// "intranet" is one of the four \b-tail tokens and NOT one of the nine
		// (?:/|$) tokens, so this row pins that the union keeps two tails
		// rather than collapsing onto one.
		{"internal-intranet-regex-only", "http://x.com/intranet", "internal",
			"IsInternalPath: 'intranet' is a \\b-tail token, not one of the nine (?:/|$) tokens"},

		// "admin"/"debug" are (?:/|$)-tail tokens, so they need the path to end
		// after the token — which is why neither of these has a \b in its name.
		{"internal-admin", "http://x.com/admin", "internal",
			"IsInternalPath via the 'admin' token + the (?:/|$) tail"},
		{"internal-debug", "http://x.com/debug", "internal",
			"IsInternalPath via the 'debug' token + the (?:/|$) tail"},

		// --- internal_host ---------------------------------------------
		// internalurl.IsInternalHost is the union of internalHostRE
		// (internal\.|corp\.|\.local) and k8sServiceRE
		// ((?:[a-z0-9-]+\.){1,3}(?:svc|cluster|local|internal)\b). Raw-text,
		// so the path-position rows further down stay true.
		{"internal-host-internal-dot", "http://foo.internal/", "internal_host",
			"IsInternalHost via the 'internal.' rule"},
		// "a.b." is two labels, then "svc" with \b before "/". The internal.
		// rule does not match this string at all.
		{"internal-host-k8s-svc", "http://a.b.svc/x", "internal_host",
			"IsInternalHost via the k8s rule alone — the 'internal.' rule has no svc token"},
		// THE TRAP ROW. "metadata." + "google." is two labels, then "internal"
		// with \b before "/", so the k8s rule matches and internal_host is
		// returned. internal_host is tested BEFORE cloud_metadata in the
		// if-chain, so the metadata hostname NEVER reaches the metadata branch
		// even though internalurl.IsCloudMetadata does match it. This is
		// internal_host, not cloud_metadata and not "".
		{"gcp-metadata-hostname", "http://metadata.google.internal/", "internal_host",
			"PRECEDENCE: the k8s rule matches (metadata.google.internal) and " +
				"internal_host precedes cloud_metadata, so the cloud_metadata " +
				"branch is unreachable for this input — IsCloudMetadata does " +
				"return true for it, but the chain never asks."},

		// --- private_ip -----------------------------------------------
		// internalurl.IsPrivateHost parses the host and delegates to
		// netguard.IsPrivateIP, so the CIDR list is owned in one place.
		{"private-10", "http://10.0.0.1/x", "private_ip", "IsPrivateHost via netguard 10/8"},
		// 172.16/12 spans 172.16.0.0 through 172.31.255.255; this row is the
		// lower bound.
		{"private-172-16", "http://172.16.0.1/x", "private_ip",
			"IsPrivateHost via netguard 172.16/12, lower bound"},
		{"private-192-168", "http://192.168.0.1/x", "private_ip", "IsPrivateHost via netguard 192.168/16"},
		// 172.32 is outside 172.16/12, so the CIDR check fails and the input
		// falls through every remaining branch to "".
		{"outside-172-16-12", "http://172.32.0.1/x", "",
			"negative: 172.32 is outside 172.16/12"},

		// --- localhost -------------------------------------------------
		// internalurl.IsLoopback parses the host and accepts the name
		// "localhost" plus anything ip.IsLoopback() or ip.IsUnspecified()
		// covers (all of 127/8, ::1, 0.0.0.0, ::).
		{"localhost-name", "http://localhost:3000/", "localhost",
			"IsLoopback via the literal name; :3000 is not a sensitive port"},
		{"localhost-127-0-0-5", "http://127.0.0.5/", "localhost",
			"IsLoopback via ip.IsLoopback() on 127.0.0.5"},

		// --- cloud_metadata --------------------------------------------
		// internalurl.IsCloudMetadata compares the parsed host for equality
		// against 169.254.169.254 (net.IP.Equal) or netguard.IsMetadataHost.
		// No earlier branch matches this input: no internal path token, no
		// internal./corp./.local label, no k8s suffix, and 169.254.169.254 is
		// link-local rather than RFC 1918.
		{"metadata-ip", "http://169.254.169.254/", "cloud_metadata",
			"IsCloudMetadata via \\b169\\.254\\.169\\.254\\b host equality"},

		// --- container_service -----------------------------------------
		// The one branch still using a local regex: the
		// docker|container + host|name|id|service vocabulary appears nowhere
		// else in the codebase, so it has no shared predicate to move to.
		// "docker" + "_" + "host" + \b before "/".
		{"docker-host", "http://docker_host/", "container_service",
			"dockerServiceRE (local, not in internalurl)"},

		// --- sensitive_port ---------------------------------------------
		// internalurl.IsSensitivePort keeps the \b terminator.
		{"sensitive-port-5432", "http://h:5432/", "sensitive_port",
			"IsSensitivePort"},
		// ":33060" — the alternation matches ":3306" but \b cannot hold
		// between "6" and "0", both word characters, so the branch fails.
		{"port-33060-not-3306", "http://h:33060/", "",
			"negative: \\b terminator keeps :33060 from matching :3306"},

		// --- plain public URL -------------------------------------------
		{"public-url", "https://example.com/api/users", "",
			"negative: matches no branch"},

		// --- THE SEVEN TASK 4 DELTAS ------------------------------------
		// Four widenings (the first four rows) and three narrowings (the last
		// three). Each note records what changed and why. The delta ledger in
		// detector_internal_delta_test.go re-derives all seven against the old
		// regexes and sweeps for any transition outside this set, so these rows
		// are the canonical list rather than a sample. Any OTHER row in this
		// table moving is a regression, not a delta.

		// --- narrowings: a raw-text match that is not the host. All three
		// share one cause — a host-parsed predicate replacing a text-matching
		// regex, which is what lets the CIDR lists live in netguard alone.

		// privateIP10RE used to text-match the "10.0.0.1" in the PATH. The host
		// is foo.com, a public name, and a private IP in a path is a different
		// signal from a private-IP host. internalurl.IsPrivateHost is
		// host-scoped (net.ParseIP(hostOf(raw))), so the raw-text match is gone
		// and the input is no longer a finding. REMOVES A MEDIUM FINDING.
		{"DELTA-private-ip-in-path", "http://foo.com/10.0.0.1/x", "",
			"CHANGED private_ip -> \"\": privateIP10RE matched the private IP in " +
				"the PATH; IsPrivateHost parses the host (foo.com) instead. The " +
				"narrowing is deliberate so the RFC 1918 CIDR list stays owned by " +
				"netguard instead of being copied into a second regex here."},
		// Same story one branch later: cloudMetadataRE text-matched the
		// metadata IP in the path, and nothing earlier in the chain fired.
		// IsCloudMetadata compares the host, so this is no longer a finding.
		// This row is the whole text-vs-host split in one input, and it is the
		// one that drops a HIGH-severity finding.
		{"DELTA-metadata-ip-in-path", "http://foo.com/169.254.169.254/x", "",
			"CHANGED cloud_metadata -> \"\": cloudMetadataRE matched the metadata " +
				"IP in the PATH; IsCloudMetadata compares the host (foo.com) for " +
				"equality. Same deliberate narrowing as the row above, and the " +
				"largest severity cost in this task: a High finding disappears."},
		// THE THIRD NARROWING, and the one most easily missed. localhostRE was
		// raw text too, so it matched the loopback NAME anywhere in the URL —
		// not just as a private or metadata IP in a path. Here the host is the
		// public name example.com and "localhost" sits in the path, so the
		// input was reported as a Low loopback finding and no longer is.
		// It is the same text-vs-host split as the two rows above; only the
		// token differs.
		{"DELTA-loopback-token-in-path", "http://example.com/localhost", "",
			"CHANGED localhost -> \"\": localhostRE matched the NAME in the PATH; " +
				"IsLoopback parses the host (example.com), which is a public name. " +
				"REMOVES A LOW FINDING. Same deliberate text-vs-host split — see " +
				"the note on DELTA-private-ip-in-path."},

		// --- widenings: loopback spelled more ways than the old regex did.
		// All four only ever ADD a Low-severity finding; none can hide one.

		// localhostRE had no IPv6 rule, so "[::1]" matched nothing and the
		// input reported no finding at all. IsLoopback uses ip.IsLoopback(),
		// which accepts ::1.
		{"DELTA-ipv6-loopback", "http://[::1]/x", "localhost",
			"CHANGED \"\" -> \"localhost\": localhostRE spelled out only " +
				"localhost|127\\.0\\.0\\.\\d+|0\\.0\\.0\\.0, with no IPv6 literal. " +
				"ip.IsLoopback() covers ::1, so this is an under-match fixed."},
		// "[::]" is the IPv6 unspecified address, the v6 counterpart of the
		// 0.0.0.0 the old regex DID spell out. ip.IsUnspecified() covers it.
		{"DELTA-ipv6-unspecified", "http://[::]/x", "localhost",
			"CHANGED \"\" -> \"localhost\": the old regex listed 0\\.0\\.0\\.0 only, " +
				"with no IPv6 form; IsLoopback accepts ip.IsUnspecified(), which " +
				"covers both 0.0.0.0 and ::. The v6 half was an under-match."},
		// Same over-restriction in reverse: 127.1.2.3 is a valid loopback
		// address, but the old regex hardcoded the "0.0." middle octets.
		// ip.IsLoopback() covers all of 127/8.
		{"DELTA-loopback-non-0-0-octets", "http://127.1.2.3/x", "localhost",
			"CHANGED \"\" -> \"localhost\": localhostRE required the literal " +
				"\"127.0.0.\", but 127/8 is loopback per ip.IsLoopback()."},
		// internalurl.hostOf lowercases the host, so IsLoopback's literal-name
		// check accepts "LOCALHOST". The old localhostRE was case-SENSITIVE
		// (it carried no (?i) flag), so an uppercase host was silently missed.
		// A URI host component is case-insensitive per RFC 3986 3.2.2 (RFC 4343
		// 2 for host names), so this is a fix that only ADDS a Low finding.
		{"DELTA-localhost-name-case-insensitive", "http://LOCALHOST/api", "localhost",
			"CHANGED \"\" -> \"localhost\": localhostRE had no (?i) flag and " +
				"missed an uppercase host; hostOf lowercases, so IsLoopback " +
				"matches. A widening, not a loss."},

		// --- hostOf SCHEME-BOUNDARY FIX (internal/internalurl) ----------
		// hostOf used to strip a scheme by taking the first "://" ANYWHERE in
		// the string, so a scheme-less URL whose QUERY carries an absolute URL
		// had its host extracted from inside the query. That is a bug in
		// internalurl, not a consequence of this mapping — the old
		// text-matching localhostRE was immune because it never parsed
		// anything. It is FIXED here, so these rows state the correct value
		// rather than pinning the defect.

		// Before the fix hostOf returned "169.254.169.254" for this input, and
		// the URL was reported as a High cloud_metadata surface instead of the
		// Low localhost one: a false escalation, driven by attacker-supplied
		// query text.
		{"HOSTFIX-scheme-in-query-is-not-a-scheme", "localhost?u=http://169.254.169.254/", "localhost",
			"hostOf only strips a \"://\" that appears before the first /, ?, " +
				"or #, so the host stays \"localhost\". Was cloud_metadata (High) " +
				"before the fix."},

		// The observable direction of the same fix: pre-fix hostOf returned
		// "b" here, so the loopback host was missed entirely.
		{"HOSTFIX-scheme-in-path-keeps-loopback-host", "localhost/a://b", "localhost",
			"the \"://\" is inside the path, so the host is \"localhost\", not \"b\""},

		// The negative half of the same boundary: a public host is still
		// public when a scheme-looking string follows it in the path. Before the
		// fix hostOf returned "b" here too; both readings are non-internal, so
		// this row is pinned to stop a future hostOf change from inventing a
		// host out of the path.
		{"HOSTFIX-scheme-in-path-keeps-public-host", "example.com/a://b", "",
			"negative: the \"://\" belongs to the path, so the host is " +
				"\"example.com\" and nothing classifies"},

		// --- PRECEDENCE --------------------------------------------------
		// classifyInternal is an ordered if-chain, so when an input matches two
		// branches the EARLIER branch wins. These rows exist because a reorder
		// would change output while every per-category row above still passed.
		// Each one names the two competing branches.

		// "/internal" and ":5432" both match; internal is tested first.
		{"precedence-internal-over-sensitive-port", "http://internal.corp:5432/", "internal",
			"PRECEDENCE: matches internal and sensitive_port; internal is " +
				"tested first and wins."},
		// private host and ":5432" both match; private_ip precedes
		// sensitive_port.
		{"precedence-private-ip-over-sensitive-port", "http://10.0.0.1:5432/", "private_ip",
			"PRECEDENCE: matches private_ip and sensitive_port; private_ip is " +
				"tested first and wins."},
		// ".svc" and ":3306" both match; internal_host precedes both
		// private_ip and sensitive_port.
		{"precedence-internal-host-over-sensitive-port", "http://a.b.svc:3306/", "internal_host",
			"PRECEDENCE: matches internal_host and sensitive_port; " +
				"internal_host is tested first and wins."},
		// "docker_host" and ":6379" both match; container_service is
		// immediately before sensitive_port.
		{"precedence-container-service-over-sensitive-port", "http://docker_host:6379/", "container_service",
			"PRECEDENCE: matches container_service and sensitive_port; " +
				"container_service is tested first and wins."},
		// "127.0.0.5" and "/admin" both match; internal is tested before
		// localhost, so internal wins — the OPPOSITE of the natural "loopback
		// host is the more specific thing" intuition, which is exactly why it
		// needs pinning.
		{"precedence-internal-over-localhost", "http://127.0.0.5/admin", "internal",
			"PRECEDENCE: matches internal and localhost; internal is tested " +
				"first and wins."},
		// "169.254.169.254" and "docker_host" both match; cloud_metadata is
		// tested before container_service, so the SSRF-target category wins
		// even though the docker token appears later in the string.
		{"precedence-metadata-over-container-service", "http://169.254.169.254/docker_host/", "cloud_metadata",
			"PRECEDENCE: matches cloud_metadata and container_service; " +
				"cloud_metadata is tested first and wins."},
		// Both are host matches, and localhost is immediately before
		// cloud_metadata. This row guards the one adjacent pair the rows above
		// leave unpinned: the loopback host wins over a metadata IP sitting in
		// its path. (The metadata-IP-in-path text match is gone as of the DELTA
		// rows above; this input now matches only via its HOST, so it stays
		// "localhost" before and after Task 4.)
		{"precedence-localhost-over-metadata", "http://localhost/169.254.169.254", "localhost",
			"PRECEDENCE: the host is loopback and 169.254.169.254 is in the path; " +
				"localhost is tested before cloud_metadata and wins."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyInternal(tt.url); got != tt.want {
				t.Errorf("classifyInternal(%q)\n  got  %q\n  want %q", tt.url, got, tt.want)
			}
			if tt.note != "" {
				t.Logf("note: %s", tt.note)
			}
		})
	}
}

// TestClassifyInternalBranchPrecedence is the executable form of "the branch
// order is a precedence chain".
//
// Every row names an input where TWO OR MORE branch predicates are true at
// once, so the reported category is decided by the chain's order rather than by
// any single predicate. The test asserts both halves: that the earlier branch
// wins, and — via losers — that the competing predicates really do match this
// input. The second assertion is what the output-only category table cannot
// check: if a branch's predicate stopped overlapping the input, these rows
// would fail as test bugs even though the category table still passed.
//
// Coverage is deliberately spread over the whole chain, including the adjacent
// pairs the PRECEDENCE block of the category table leaves unpinned. Swapping
// the internal_host and private_ip branches, for example, changes no row of the
// category table — every one of its internal_host inputs has a public host and
// every private_ip input has a public name — but it flips the two rows below.
func TestClassifyInternalBranchPrecedence(t *testing.T) {
	branchPreds := []struct {
		name string
		pred func(string) bool
	}{
		{"internal", internalurl.IsInternalPath},
		{"internal_host", internalurl.IsInternalHost},
		{"private_ip", internalurl.IsPrivateHost},
		{"localhost", internalurl.IsLoopback},
		{"cloud_metadata", internalurl.IsCloudMetadata},
		{"container_service", dockerServiceRE.MatchString},
		{"sensitive_port", internalurl.IsSensitivePort},
	}
	predOf := func(name string) func(string) bool {
		for _, b := range branchPreds {
			if b.name == name {
				return b.pred
			}
		}
		return func(string) bool { return false }
	}

	tests := []struct {
		name   string
		url    string
		winner string   // the branch the chain must report
		losers []string // branches that also match, but come later in the chain
	}{
		{"internal-over-internal-host", "http://foo.internal/admin", "internal",
			[]string{"internal_host"}},
		{"internal-over-private-ip", "http://10.0.0.1/admin", "internal",
			[]string{"private_ip"}},
		{"internal-over-metadata", "http://169.254.169.254/admin", "internal",
			[]string{"cloud_metadata"}},
		{"internal-over-container-service", "http://docker_host/admin", "internal",
			[]string{"container_service"}},
		// The pair the category table cannot pin: its internal_host rows all
		// have a public host and its private_ip rows all have a public name, so
		// for it neither predicate is ever the sole decider.
		{"internal-host-over-private-ip", "http://10.0.0.1/x.internal/y", "internal_host",
			[]string{"private_ip"}},
		{"internal-host-over-localhost", "http://localhost/x.internal", "internal_host",
			[]string{"localhost"}},
		// The trap in a second costume: the metadata IP is the HOST here and
		// the internal-looking label is only in the path, yet internal_host
		// still wins, because it precedes cloud_metadata in the chain. So the
		// reported category is "internal_host", not "cloud_metadata" — the
		// same shadowing the gcp-metadata-hostname row shows via a hostname.
		{"internal-host-over-metadata", "http://169.254.169.254/x.internal/y", "internal_host",
			[]string{"cloud_metadata"}},
		{"localhost-over-container-service", "http://localhost/docker_host", "localhost",
			[]string{"container_service"}},
		// Three-way overlaps: loopback and metadata against both the container
		// vocabulary and the port list, which sit after them in the chain.
		{"localhost-over-container-service-and-sensitive-port",
			"http://127.0.0.5/docker_host:6379", "localhost",
			[]string{"container_service", "sensitive_port"}},
		{"metadata-over-container-service-and-sensitive-port",
			"http://169.254.169.254/docker_host:6379", "cloud_metadata",
			[]string{"container_service", "sensitive_port"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyInternal(tt.url); got != tt.winner {
				t.Errorf("classifyInternal(%q)\n  got  %q\n  want %q (the branch "+
					"order may have changed)", tt.url, got, tt.winner)
			}
			// Guard the row itself: a "loser" that does not actually match
			// would leave this row asserting nothing about precedence.
			for _, loser := range tt.losers {
				if !predOf(loser)(tt.url) {
					t.Errorf("test bug: %s does not match %q, so this row proves "+
						"nothing about precedence; pick an input both branches claim",
						loser, tt.url)
				}
			}
		})
	}
}

// TestInternalDetectorSeverityMapping pins the category -> severity mapping
// that (InternalDetector).Detect applies. This is user-visible output: the
// severity lands in the recon report, and Task 4 changed the category strings
// feeding it, so the mapping needs its own coverage — a typo in the branch
// silently drops a High finding to Low and every category test still passes.
func TestInternalDetectorSeverityMapping(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want finding.Severity
	}{
		// cloud_metadata is the only High: it is an SSRF target.
		{"cloud-metadata-high", "http://169.254.169.254/", finding.SeverityHigh},
		// private_ip is Medium: possible SSRF or misconfiguration.
		{"private-ip-medium", "http://10.0.0.1/x", finding.SeverityMedium},
		// Everything else is Low.
		{"internal-low", "http://x.com/admin", finding.SeverityLow},
		{"internal-host-low", "http://foo.internal/", finding.SeverityLow},
		{"localhost-low", "http://127.0.0.5/", finding.SeverityLow},
		{"container-service-low", "http://docker_host/", finding.SeverityLow},
		{"sensitive-port-low", "http://h:5432/", finding.SeverityLow},
		// The two loopback rows the DELTA rows above newly classify must also
		// land on Low, not on an unset zero value.
		{"ipv6-loopback-low", "http://[::1]/x", finding.SeverityLow},
		{"loopback-127-1-2-3-low", "http://127.1.2.3/x", finding.SeverityLow},
	}

	d := InternalDetector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := d.Detect([]string{tt.url})
			if len(got) != 1 {
				t.Fatalf("Detect(%q) returned %d findings, want 1", tt.url, len(got))
			}
			if got[0].Severity != tt.want {
				t.Errorf("Detect(%q).Severity = %v, want %v", tt.url, got[0].Severity, tt.want)
			}
		})
	}
}

// TestInternalDetectorSkipsUnclassified confirms Detect emits nothing for an
// input classifyInternal rejects. Without this, a future change could turn ""
// into a Low-severity finding for every public URL in the corpus.
func TestInternalDetectorSkipsUnclassified(t *testing.T) {
	d := InternalDetector{}
	got := d.Detect([]string{"https://example.com/api/users"})
	if len(got) != 0 {
		t.Errorf("Detect on an unclassified URL returned %d findings, want 0", len(got))
	}
}

// TestInternalDetectorCategoryAndSeverityTogether asserts the finding carries
// the URL it was given, unchanged, and the category classifyInternal produced.
// Detect must not rewrite or normalize the URL — recon reports it verbatim to
// the user.
func TestInternalDetectorCategoryAndSeverityTogether(t *testing.T) {
	d := InternalDetector{}
	const raw = "http://169.254.169.254/latest/meta-data/"
	got := d.Detect([]string{raw})
	if len(got) != 1 {
		t.Fatalf("Detect returned %d findings, want 1", len(got))
	}
	if got[0].URL != raw {
		t.Errorf("URL = %q, want %q (must be verbatim)", got[0].URL, raw)
	}
	if got[0].Category != "cloud_metadata" {
		t.Errorf("Category = %q, want %q", got[0].Category, "cloud_metadata")
	}
	if got[0].Severity != finding.SeverityHigh {
		t.Errorf("Severity = %v, want %v", got[0].Severity, finding.SeverityHigh)
	}
}
