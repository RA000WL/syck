package sourcemap

import (
	"testing"
)

func TestParseSourceMap(t *testing.T) {
	data := `{"version":3,"sources":["a.js"],"sourcesContent":["hello"],"mappings":"AAAA"}`
	sm, err := ParseSourceMap([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if sm.Version != 3 {
		t.Errorf("Version = %d, want 3", sm.Version)
	}
	if len(sm.Sources) != 1 || sm.Sources[0] != "a.js" {
		t.Errorf("Sources = %v, want [a.js]", sm.Sources)
	}
	if len(sm.SourcesContent) != 1 || sm.SourcesContent[0] != "hello" {
		t.Errorf("SourcesContent = %v, want [hello]", sm.SourcesContent)
	}
}

func TestReconstructSource(t *testing.T) {
	data := `{"version":3,"sources":["a.js"],"sourcesContent":["function hello() { return 42; }"],"mappings":"AAAA"}`
	sm, _ := ParseSourceMap([]byte(data))
	sources := ReconstructSource(sm)
	if len(sources) != 1 {
		t.Fatalf("expected 1 source, got %d", len(sources))
	}
	if sources["a.js"] != "function hello() { return 42; }" {
		t.Errorf("Reconstructed source mismatch")
	}
}
