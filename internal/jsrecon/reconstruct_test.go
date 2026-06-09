package jsrecon

import (
	"testing"

	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/rules"
)

func TestPropagateConstantsNoDeclarations(t *testing.T) {
	content := `console.log("hello");`
	results := propagateConstants(content)
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestPropagateConstantsSingleVar(t *testing.T) {
	content := `var a = "this_is_a_long_secret_";
var b = "value_for_testing_1234";
var c = a + b;`
	results := propagateConstants(content)
	if len(results) == 0 {
		t.Fatal("expected results, got none")
	}
	found := false
	for _, r := range results {
		if r.text == "this_is_a_long_secret_value_for_testing_1234" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected reconstructed value in results, got %v", results)
	}
}

func TestPropagateConstantsLetAndConst(t *testing.T) {
	content := `let x = "alpha_bravo_charlie_";
const y = "delta_echo_foxtrot";
const z = x + y + x;`
	results := propagateConstants(content)
	if len(results) == 0 {
		t.Fatal("expected results, got none")
	}
	found := false
	expected := "alpha_bravo_charlie_delta_echo_foxtrotalpha_bravo_charlie_"
	for _, r := range results {
		if r.text == expected {
			found = true
		}
	}
	if !found {
		t.Errorf("expected %q in results, got %v", expected, results)
	}
}

func TestPropagateConstantsPartialChain(t *testing.T) {
	content := `var a = "hel";
var b = "lo";
var c = unknown + a + b;`
	results := propagateConstants(content)
	for _, r := range results {
		if r.text == "hello" {
			t.Errorf("should not resolve partial chain with unknown identifier")
		}
	}
}

func TestPropagateConstantsShortResultSkipped(t *testing.T) {
	content := `var a = "hi";
var b = "lo";
var c = a + b;`
	results := propagateConstants(content)
	for _, r := range results {
		if r.text == "hilo" {
			t.Errorf("short result under minReconstructLen should be skipped")
		}
	}
}

func TestReconstructJoinsArbitrarySeparator(t *testing.T) {
	content := `var s = ["alpha_bravo_charlie","delta_echo_foxtrot"].join("-");`
	results := reconstructJoins(content)
	if len(results) == 0 {
		t.Fatal("expected results for join with '-' separator, got none")
	}
	found := false
	for _, r := range results {
		if r.text == "alpha_bravo_charlie-delta_echo_foxtrot" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'alpha_bravo_charlie-delta_echo_foxtrot' in results, got %v", results)
	}
}

func TestReconstructJoinsEmptySeparator(t *testing.T) {
	content := `var s = ["alpha_bravo_charlie","delta_echo_foxtrot"].join("");`
	results := reconstructJoins(content)
	if len(results) == 0 {
		t.Fatal("expected results for join with empty separator, got none")
	}
	found := false
	for _, r := range results {
		if r.text == "alpha_bravo_charliedelta_echo_foxtrot" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'alpha_bravo_charliedelta_echo_foxtrot' in results, got %v", results)
	}
}

func TestReconstructJoinsMultiCharSeparator(t *testing.T) {
	content := `var s = ["alpha_bravo_charlie","delta_echo_foxtrot"].join("::");`
	results := reconstructJoins(content)
	if len(results) == 0 {
		t.Fatal("expected results for join with '::' separator, got none")
	}
	found := false
	for _, r := range results {
		if r.text == "alpha_bravo_charlie::delta_echo_foxtrot" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'alpha_bravo_charlie::delta_echo_foxtrot' in results, got %v", results)
	}
}

func TestReconstructAndScanPropagatedVars(t *testing.T) {
	content := `var prefix = "AKIA";
var mid = "1234567890abcdef";
var key = a + b;`
	_ = ReconstructAndScan(content, "test.js", &rules.RuleSet{}, finding.Severity(0))
}
