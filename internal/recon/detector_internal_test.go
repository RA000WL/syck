package recon

import (
	"testing"

	"github.com/RA000WL/syck/internal/finding"
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
// classifyInternal returns for representative inputs, as of the commit before
// Batch 4c Task 4 rewrites its body to delegate to internal/internalurl.
//
// Every expectation below was derived by reading the regexes in
// detector_internal.go, not by observing the function's output. The function is
// an ordered if-chain, so the first branch whose regexes match the RAW STRING
// wins; that ordering is itself part of the pinned behavior (see the
// precedence block at the end).
//
// The four rows marked "TASK 4 DELTA" carry the value the function returns
// TODAY. Task 4 is expected to change exactly those four and nothing else; if
// a rewrite moves any other row, it is a regression, not a delta.
func TestClassifyInternalCharacterization(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
		note string
	}{
		// --- internal: internalRE only -------------------------------
		// internalRE = `(?i)/(internal|private|intranet|corp)(\b|/|$)`.
		// The "/internal" here is the scheme's second slash followed by the
		// host, and \b holds between "l" and ".".
		{"internal-host-label", "http://internal.corp/api", "internal",
			"internalRE alone: /internal\b"},
		// "intranet" is in internalRE but NOT in internalPathRE, so this
		// row proves the branch is a union and not just internalPathRE.
		{"internal-intranet-regex-only", "http://x.com/intranet", "internal",
			"internalRE only — internalPathRE has no 'intranet' token"},

		// --- internal: internalPathRE only ----------------------------
		// internalPathRE = `(?i)/(?:debug|trace|admin|internal|private|
		// staging|dev|test|sandbox|legacy|hidden)(?:/|$)`. The stricter
		// (?:/|$) tail is why these need the path to end after the token.
		{"internal-admin", "http://x.com/admin", "internal",
			"internalPathRE only — internalRE has no 'admin' token"},
		{"internal-debug", "http://x.com/debug", "internal",
			"internalPathRE only — internalRE has no 'debug' token"},

		// --- internal_host ---------------------------------------------
		// internalHostRE = `(?i)(internal\.|corp\.|\.local)`.
		{"internal-host-internal-dot", "http://foo.internal/", "internal_host",
			"internalHostRE via 'internal.'"},
		// k8sServiceRE = `(?i)(?:[a-z0-9-]+\.){1,3}(?:svc|cluster|local|
		// internal)\b`. "a.b." is two labels, then "svc" with \b before "/".
		// internalHostRE does not match this string at all.
		{"internal-host-k8s-svc", "http://a.b.svc/x", "internal_host",
			"k8sServiceRE only — internalHostRE has no svc rule"},
		// THE TRAP ROW. "metadata." + "google." is two labels, then
		// "internal" with \b before "/", so k8sServiceRE matches and
		// internal_host is returned. internal_host is tested BEFORE
		// cloud_metadata in the if-chain, so the metadata hostname NEVER
		// reaches the metadata branch. This is internal_host, not
		// cloud_metadata and not "" — and Task 4 does not change it.
		{"gcp-metadata-hostname", "http://metadata.google.internal/", "internal_host",
			"PRECEDENCE: k8sServiceRE matches (metadata.google.internal) and " +
				"internal_host precedes cloud_metadata, so the metadata branch " +
				"is unreachable for this input. Unchanged by Task 4."},

		// --- private_ip -----------------------------------------------
		// privateIP10RE = `\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`.
		{"private-10", "http://10.0.0.1/x", "private_ip", "privateIP10RE"},
		// privateIP172RE = `\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b`.
		{"private-172-16", "http://172.16.0.1/x", "private_ip",
			"privateIP172RE lower bound of 172.16/12 (1[6-9])"},
		{"private-192-168", "http://192.168.0.1/x", "private_ip", "privateIP192RE"},
		// 172.32: the second octet 32 matches none of 1[6-9], 2\d (20-29)
		// or 3[01] (30-31), so the whole regex fails. Falls through every
		// remaining branch to "".
		{"outside-172-16-12", "http://172.32.0.1/x", "",
			"negative: 172.32 is outside 172.16/12"},

		// --- localhost -------------------------------------------------
		// localhostRE = `\b(?:localhost|127\.0\.0\.\d+|0\.0\.0\.0)\b`.
		{"localhost-name", "http://localhost:3000/", "localhost",
			"localhostRE via the literal name; :3000 is not a sensitive port"},
		{"localhost-127-0-0-5", "http://127.0.0.5/", "localhost",
			"localhostRE via 127\\.0\\.0\\.\\d+"},

		// --- cloud_metadata --------------------------------------------
		// cloudMetadataRE = `\b169\.254\.169\.254\b`. No earlier branch
		// matches: not an internal token, no "internal."/"corp."/".local"
		// label, no k8s suffix, and 169.254 is not RFC 1918.
		{"metadata-ip", "http://169.254.169.254/", "cloud_metadata",
			"cloudMetadataRE via \\\\b169\\\\.254\\\\.169\\\\.254\\\\b"},

		// --- container_service -----------------------------------------
		// dockerServiceRE = `(?i)(?:docker|container)[_.]?(?:host|name|id|
		// service)\b`. "docker" + "_" + "host" + \b before "/".
		{"docker-host", "http://docker_host/", "container_service",
			"dockerServiceRE"},

		// --- sensitive_port ---------------------------------------------
		// sensitivePortRE = `:(?:3306|5432|...|8200)\b`.
		{"sensitive-port-5432", "http://h:5432/", "sensitive_port",
			"sensitivePortRE"},
		// ":33060" — the alternation matches ":3306" but \b cannot hold
		// between "6" and "0", both word characters, so the branch fails.
		{"port-33060-not-3306", "http://h:33060/", "",
			"negative: \\b terminator keeps :33060 from matching :3306"},

		// --- plain public URL -------------------------------------------
		{"public-url", "https://example.com/api/users", "",
			"negative: matches no branch"},

		// --- TASK 4 DELTAS: values below are what the code returns TODAY -
		//
		// Each row is here so Task 4's rewrite can be proven to move exactly
		// these and nothing else. The four inputs are ones the current regex
		// text-matches anywhere in the string, so a host-scoped predicate
		// (which reads only the host) will stop matching them.

		// privateIP10RE text-matches the "10.0.0.1" in the PATH. The host is
		// foo.com, a public name. TASK 4 DELTA: internalurl.IsPrivateHost is
		// host-scoped (net.ParseIP(hostOf(raw))), so this becomes "".
		{"DELTA-private-ip-in-path", "http://foo.com/10.0.0.1/x", "private_ip",
			"TASK 4 DELTA -> \"\": privateIP10RE matches the private IP in the " +
				"PATH; internalurl.IsPrivateHost parses the host (foo.com) instead."},
		// Same story one branch later: cloudMetadataRE text-matches the
		// metadata IP in the path, and nothing earlier in the chain fires.
		// TASK 4 DELTA: internalurl.IsCloudMetadata is host-scoped, so this
		// becomes "". This row is the text-vs-host split in one input.
		{"DELTA-metadata-ip-in-path", "http://foo.com/169.254.169.254/x", "cloud_metadata",
			"TASK 4 DELTA -> \"\": cloudMetadataRE matches the metadata IP in " +
				"the PATH; internalurl.IsCloudMetadata compares the host (foo.com) for equality."},
		// localhostRE has no rule for IPv6, so "[::1]" matches nothing.
		// TASK 4 DELTA: internalurl.IsLoopback uses ip.IsLoopback(), which
		// accepts ::1, so this becomes "localhost".
		{"DELTA-ipv6-loopback", "http://[::1]/x", "",
			"TASK 4 DELTA -> \"localhost\": localhostRE only spells out " +
				"localhost|127\\\\.0\\\\.0\\\\.\\\\d+|0\\\\.0\\\\.0\\\\.0, no IPv6 literal."},
		// Same over-match in reverse: "127.1.2.3" is a valid loopback address
		// but the regex hardcodes the "0.0." middle octets.
		// TASK 4 DELTA: internalurl.IsLoopback parses the IP and ip.IsLoopback()
		// covers all of 127/8, so this becomes "localhost".
		{"DELTA-loopback-non-0-0-octets", "http://127.1.2.3/x", "",
			"TASK 4 DELTA -> \"localhost\": localhostRE requires the literal " +
				"\"127.0.0.\", but 127/8 is loopback per ip.IsLoopback()."},

		// --- PRECEDENCE --------------------------------------------------
		// classifyInternal is an ordered if-chain, so when an input matches
		// two branches the EARLIER branch wins. Without these rows a Task 4
		// refactor could reorder the chain and silently change which of two
		// equally true categories is reported.

		// internalRE matches "/internal" AND sensitivePortRE matches ":5432".
		// The internal branch is first in the chain, so it wins.
		{"precedence-internal-over-sensitive-port", "http://internal.corp:5432/", "internal",
			"PRECEDENCE: matches internal (internalRE) and sensitive_port " +
				"(sensitivePortRE); internal is tested first and wins."},
		// privateIP10RE matches "10.0.0.1" AND sensitivePortRE matches ":5432".
		// private_ip is tested before localhost and before sensitive_port.
		{"precedence-private-ip-over-sensitive-port", "http://10.0.0.1:5432/", "private_ip",
			"PRECEDENCE: matches private_ip and sensitive_port; private_ip is " +
				"tested first and wins."},
		// k8sServiceRE matches ".svc" AND sensitivePortRE matches ":3306".
		// internal_host is tested before both private_ip and sensitive_port.
		{"precedence-internal-host-over-sensitive-port", "http://a.b.svc:3306/", "internal_host",
			"PRECEDENCE: matches internal_host and sensitive_port; " +
				"internal_host is tested first and wins."},
		// dockerServiceRE matches "docker_host" AND sensitivePortRE matches
		// ":6379". container_service is immediately before sensitive_port.
		{"precedence-container-service-over-sensitive-port", "http://docker_host:6379/", "container_service",
			"PRECEDENCE: matches container_service and sensitive_port; " +
				"container_service is tested first and wins."},
		// localhostRE matches "127.0.0.5" AND internalPathRE matches "/admin".
		// The internal branch is tested before localhost, so internal wins —
		// note this is the OPPOSITE of the natural "loopback host is the more
		// specific thing" intuition, which is exactly why it needs pinning.
		{"precedence-internal-over-localhost", "http://127.0.0.5/admin", "internal",
			"PRECEDENCE: matches internal (internalPathRE) and localhost " +
				"(localhostRE); internal is tested first and wins."},
		// cloudMetadataRE matches "169.254.169.254" AND dockerServiceRE
		// matches "docker_host" in the same path. cloud_metadata is tested
		// before container_service, so the SSRF-target category wins even
		// though the docker token appears later in the string.
		{"precedence-metadata-over-container-service", "http://169.254.169.254/docker_host/", "cloud_metadata",
			"PRECEDENCE: matches cloud_metadata and container_service; " +
				"cloud_metadata is tested first and wins."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyInternal(tt.url); got != tt.want {
				t.Errorf("classifyInternal(%q)\n  got  %q\n  want %q", tt.url, got, tt.want)
				if tt.note != "" {
					t.Logf("note: %s", tt.note)
				}
			}
		})
	}
}

// TestClassifyInternalBranchCoverage guards against the table silently
// ceasing to exercise a branch: each row below must be the FIRST branch in the
// chain that matches its input. If a future edit inserts a branch ahead of one
// of these, this test reports the change even if the category table above is
// not updated in the same commit.
func TestClassifyInternalBranchCoverage(t *testing.T) {
	// Branch order in the if-chain, as the winning branch for a canonical
	// input of that branch.
	type branch struct {
		name  string
		input string
		want  string
	}
	branches := []branch{
		{"internal", "http://x.com/admin", "internal"},
		{"internal_host", "http://foo.internal/", "internal_host"},
		{"private_ip", "http://10.0.0.1/x", "private_ip"},
		{"localhost", "http://127.0.0.5/", "localhost"},
		{"cloud_metadata", "http://169.254.169.254/", "cloud_metadata"},
		{"container_service", "http://docker_host/", "container_service"},
		{"sensitive_port", "http://h:5432/", "sensitive_port"},
		{"none", "https://example.com/api/users", ""},
	}
	for _, b := range branches {
		t.Run(b.name, func(t *testing.T) {
			if got := classifyInternal(b.input); got != b.want {
				t.Errorf("branch %s: classifyInternal(%q) = %q, want %q — the "+
					"if-chain order may have changed", b.name, b.input, got, b.want)
			}
		})
	}
}

// TestInternalDetectorSeverityMapping pins the category -> severity mapping
// that (InternalDetector).Detect applies. This is user-visible output: the
// severity lands in the recon report, and Task 4 changes the category strings
// feeding it, so the mapping needs its own coverage.
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
