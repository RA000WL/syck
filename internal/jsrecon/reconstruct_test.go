package jsrecon

import (
	"strings"
	"testing"

	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/rules"
)

func TestPropagateConstantsNoDeclarations(t *testing.T) {
	content := `console.log("hello");`
	results := propagateConstants(strings.Split(content, "\n"))
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestPropagateConstantsSingleVar(t *testing.T) {
	content := `var a = "this_is_a_long_secret_";
var b = "value_for_testing_1234";
var c = a + b;`
	results := propagateConstants(strings.Split(content, "\n"))
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
	results := propagateConstants(strings.Split(content, "\n"))
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
	results := propagateConstants(strings.Split(content, "\n"))
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
	results := propagateConstants(strings.Split(content, "\n"))
	for _, r := range results {
		if r.text == "hilo" {
			t.Errorf("short result under minReconstructLen should be skipped")
		}
	}
}

func TestReconstructJoinsArbitrarySeparator(t *testing.T) {
	content := `var s = ["alpha_bravo_charlie","delta_echo_foxtrot"].join("-");`
	results := reconstructJoins(strings.Split(content, "\n"))
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
	results := reconstructJoins(strings.Split(content, "\n"))
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
	results := reconstructJoins(strings.Split(content, "\n"))
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

func TestPropagateConstantsTernary(t *testing.T) {
	content := "var _isProduction=true;\nvar _secret=_isProduction?\"FAKEJWTSECRET_SuperSecure\":\"FAKEJWTSECRET_Dev_Weaker\";"
	results := reconstructTernaries(strings.Split(content, "\n"))
	if len(results) < 2 {
		t.Fatalf("expected at least 2 ternary results, got %d: %v", len(results), results)
	}
	foundA, foundB := false, false
	for _, r := range results {
		if r.text == "FAKEJWTSECRET_SuperSecure" {
			foundA = true
		}
		if r.text == "FAKEJWTSECRET_Dev_Weaker" {
			foundB = true
		}
	}
	if !foundA || !foundB {
		t.Errorf("expected both ternary branches in results, got %v", results)
	}
}

func TestPropagateConstantsTernaryNoStrings(t *testing.T) {
	content := "var x = a ? b : c;"
	results := reconstructTernaries(strings.Split(content, "\n"))
	for _, r := range results {
		if r.text == "a" || r.text == "b" || r.text == "c" {
			t.Errorf("should not emit unresolved ternary branch: %v", r)
		}
	}
}

func TestPropagateConstantsArrayIndex(t *testing.T) {
	content := "var _parts=[\"AKIAIOSFODNN7FAKETEST\",\"FAKE\",\"wJalrXUtnFEMI/K7MDENG/bPxRfiCYFAKESECRETKEY\",\"KEY\"];\nvar _awsId=_parts[0];\nvar _awsSecret=_parts[2];"
	results := propagateConstants(strings.Split(content, "\n"))
	foundA, foundB := false, false
	for _, r := range results {
		if r.text == "AKIAIOSFODNN7FAKETEST" {
			foundA = true
		}
		if r.text == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYFAKESECRETKEY" {
			foundB = true
		}
	}
	if !foundA {
		t.Errorf("expected _parts[0] resolved to AKIAIOSFODNN7FAKETEST, got %v", results)
	}
	if !foundB {
		t.Errorf("expected _parts[2] resolved to the AWS secret, got %v", results)
	}
}

func TestPropagateConstantsArrayIndexOOB(t *testing.T) {
	content := "var arr=[\"short\"];\nvar x=arr[99];"
	results := propagateConstants(strings.Split(content, "\n"))
	for _, r := range results {
		if r.text == "short" {
			t.Errorf("should not resolve out-of-bounds array index")
		}
	}
}
