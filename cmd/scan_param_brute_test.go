package cmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/parambrute"
)

// paramBruteServer serves a baseline response that two wordlist parameters
// change. "size_change" pads the response past the 10% size threshold without
// echoing the probe value, and "reflect" echoes it, so one finding is
// interesting-but-unreflected and the other is interesting-and-reflected.
func paramBruteServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("size_change") {
		case "test123":
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, strings.Repeat("X", 500))
			return
		}
		if r.URL.Query().Get("reflect") == "test123" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "value is: test123")
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "baseline body")
	}))
	t.Cleanup(srv.Close)
	return srv
}

func paramBruteCfg(srv *httptest.Server) parambrute.Config {
	return parambrute.Config{
		Client:      srv.Client(),
		Concurrency: 1,
		Wordlist:    []string{"size_change", "reflect"},
		RateLimit:   0,
	}
}

// The severity mapping lives here, not in internal/parambrute: BruteForce
// returns []ParamFinding, which has no severity field. The table also pins which
// of those severities BruteForce can actually reach — testParameter returns nil
// for a parameter that is neither interesting nor reflected
// (internal/parambrute/parambrute.go:333), so on the scan path every
// hidden_parameter finding is HIGH and the MEDIUM row is reachable only through
// this function.
func TestHiddenParameterFindingSeverity(t *testing.T) {
	tests := []struct {
		name        string
		reflected   bool
		interesting bool
		want        finding.Severity
		reachable   bool
	}{
		{"reflected only", true, false, finding.SeverityMedium, false},
		{"interesting only", false, true, finding.SeverityHigh, true},
		{"both", true, true, finding.SeverityHigh, true},
		{"neither", false, false, finding.SeverityInfo, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hiddenParameterFinding("http://example.invalid/", parambrute.ParamFinding{
				Parameter:   "debug",
				Reflected:   tt.reflected,
				Interesting: tt.interesting,
				Reason:      "a reason",
			})
			if got.Severity != tt.want {
				t.Errorf("Severity = %v, want %v", got.Severity, tt.want)
			}
			if got.RuleName != "hidden_parameter" {
				t.Errorf("RuleName = %q, want hidden_parameter", got.RuleName)
			}
			if got.Secret != "debug" {
				t.Errorf("Secret = %q, want debug (the parameter name)", got.Secret)
			}
			if got.Context != "a reason" {
				t.Errorf("Context = %q, want the ParamFinding reason", got.Context)
			}
			if got.File != "http://example.invalid/" {
				t.Errorf("File = %q, want the scanned URL", got.File)
			}
		})
	}
}

// Characterization at the default floor: both interesting parameters come back
// as HIGH-severity hidden_parameter rows. This is the pre-fix behaviour of the
// append, which consulted no severity floor at all.
func TestAppendParamBruteFindingsAppendsAtDefaultFloor(t *testing.T) {
	srv := paramBruteServer(t)
	base := []finding.Finding{{RuleName: "unrelated", Severity: finding.SeverityHigh}}

	got := appendParamBruteFindings(base, srv.URL, paramBruteCfg(srv), finding.SeverityLow)

	if len(got) != 3 {
		t.Fatalf("got %d findings, want 3 (1 base + 2 parameters)", len(got))
	}
	for _, f := range got[1:] {
		if f.Severity != finding.SeverityHigh {
			t.Errorf("%s: Severity = %v, want HIGH (BruteForce only returns interesting parameters)", f.Secret, f.Severity)
		}
	}
	// The base collection must be appended to, not reordered or dropped.
	if got[0].RuleName != "unrelated" {
		t.Errorf("first finding = %q, want the base collection preserved", got[0].RuleName)
	}
}

// The bug: the append happened after collection with no severity floor, so
// --severity CRITICAL still printed HIGH-severity hidden_parameter rows.
// Batch 12 closed this invariant for credential-pair correlation
// (internal/scanner/correlation_wiring.go:62) and left this call site open.
//
// The floor must also keep what it should: --severity HIGH still reports an
// interesting parameter, and --severity LOW reports both the interesting and the
// merely reflected case.
func TestAppendParamBruteFindingsHonoursSeverityFloor(t *testing.T) {
	tests := []struct {
		name       string
		minSev     finding.Severity
		wantParams []string
	}{
		{"CRITICAL excludes HIGH parameters", finding.SeverityCritical, nil},
		{"HIGH keeps interesting parameters", finding.SeverityHigh, []string{"size_change", "reflect"}},
		{"LOW keeps everything", finding.SeverityLow, []string{"size_change", "reflect"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := paramBruteServer(t)
			got := appendParamBruteFindings(nil, srv.URL, paramBruteCfg(srv), tt.minSev)

			var params []string
			for _, f := range got {
				if f.RuleName != "hidden_parameter" {
					t.Fatalf("unexpected rule %q", f.RuleName)
				}
				if f.Severity < tt.minSev {
					t.Errorf("%s: Severity %v is below the %v floor", f.Secret, f.Severity, tt.minSev)
				}
				params = append(params, f.Secret)
			}
			if strings.Join(params, ",") != strings.Join(tt.wantParams, ",") {
				t.Errorf("parameters = %v, want %v", params, tt.wantParams)
			}
		})
	}
}
