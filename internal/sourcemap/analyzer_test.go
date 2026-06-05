package sourcemap

import (
	"testing"
)

func TestDetectInlineMap(t *testing.T) {
	content := "console.log('hello');\n//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImEuanMiXSwic291cmNlc0NvbnRlbnQiOlsiZnVuY3Rpb24gKCkge30iXSwibWFwcGluZ3MiOiJBQUFBIn0="
	refs := DetectRefs(content, "bundle.js")
	if len(refs) == 0 {
		t.Fatal("no source map references detected")
	}
	if refs[0].Kind != "inline" {
		t.Errorf("Kind = %q, want inline", refs[0].Kind)
	}
}

func TestDetectFileMap(t *testing.T) {
	content := "console.log('hello');\n//# sourceMappingURL=bundle.js.map"
	refs := DetectRefs(content, "bundle.js")
	if len(refs) == 0 {
		t.Fatal("no source map references detected")
	}
	if refs[0].Kind != "file" {
		t.Errorf("Kind = %q, want file", refs[0].Kind)
	}
	if refs[0].Target != "bundle.js.map" {
		t.Errorf("Target = %q, want bundle.js.map", refs[0].Target)
	}
}

func TestDecodeInlineMap(t *testing.T) {
	base64Data := "eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImEuanMiXSwic291cmNlc0NvbnRlbnQiOlsiZnVuY3Rpb24gaGVsbG8oKSB7IHJldHVybiA0MjsgfSJdLCJtYXBwaW5ncyI6IkFBQUEifQ=="
	ref := SourceMapRef{Kind: "inline", Target: "data:application/json;base64," + base64Data}
	sm, err := FetchMap(ref)
	if err != nil {
		t.Fatal(err)
	}
	sources := ReconstructSource(sm)
	if len(sources) != 1 {
		t.Fatalf("expected 1 source, got %d", len(sources))
	}
	if sources["a.js"] != "function hello() { return 42; }" {
		t.Errorf("reconstructed source = %q, want 'function hello() { return 42; }'", sources["a.js"])
	}
}
