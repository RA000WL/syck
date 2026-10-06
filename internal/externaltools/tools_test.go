package externaltools

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// allTools returns one instance of each concrete tool so table tests stay
// in sync with the set of tools GetAvailableTools knows about.
func allTools() []ExternalTool {
	return []ExternalTool{
		&SubfinderTool{},
		&AmassTool{},
		&HttpxTool{},
		&KatanaTool{},
	}
}

func TestParseOutputDedupesAndTrims(t *testing.T) {
	input := "a.example.com\n\n  b.example.com  \na.example.com\n"
	want := []string{"a.example.com", "b.example.com"}
	for _, tool := range allTools() {
		got := tool.ParseOutput(input)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s.ParseOutput(%q) = %#v, want %#v", tool.Name(), input, got, want)
		}
	}
}

func TestParseOutputEmptyInput(t *testing.T) {
	for _, in := range []string{"", "\n\n", "   \n\t\n"} {
		for _, tool := range allTools() {
			got := tool.ParseOutput(in)
			if len(got) != 0 {
				t.Errorf("%s.ParseOutput(%q) = %#v, want empty", tool.Name(), in, got)
			}
		}
	}
}

func TestToolTypesAreDistinct(t *testing.T) {
	tests := []struct {
		tool ExternalTool
		want ToolType
	}{
		{&SubfinderTool{}, ToolSubfinder},
		{&AmassTool{}, ToolAmass},
		{&HttpxTool{}, ToolHttpx},
		{&KatanaTool{}, ToolKatana},
	}
	seen := make(map[ToolType]bool)
	names := make(map[ToolType]bool)
	if len(allTools()) != len(tests) {
		t.Fatalf("expected %d tools, got %d", len(tests), len(allTools()))
	}
	for _, tc := range tests {
		if got := tc.tool.Name(); got != tc.want {
			t.Errorf("%T.Name() = %v, want %v", tc.tool, got, tc.want)
		}
		if seen[tc.want] {
			t.Errorf("duplicate tool name %q", tc.want)
		}
		seen[tc.want] = true
	}
	// Assert uniqueness directly over the runtime Name() values — a
	// uniqueness map over compile-time constant literals can never fire.
	for _, tool := range allTools() {
		if names[tool.Name()] {
			t.Errorf("duplicate Name() %q across allTools()", tool.Name())
		}
		names[tool.Name()] = true
	}
}

func TestCheckToolInstallationHandlesMissingBinary(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // empty dir: no tool resolvable

	for _, tt := range []ToolType{ToolSubfinder, ToolAmass, ToolHttpx, ToolKatana, ToolNuclei, ToolType("bogus")} {
		if CheckToolInstallation(tt) {
			t.Errorf("CheckToolInstallation(%q) = true with empty PATH, want false", tt)
		}
	}
	for _, tool := range allTools() {
		if tool.IsInstalled() {
			t.Errorf("%s.IsInstalled() = true with empty PATH, want false", tool.Name())
		}
	}
	if got := GetAvailableTools(); len(got) != 0 {
		t.Errorf("GetAvailableTools() = %v with empty PATH, want empty", got)
	}

	// Run must fail cleanly (not panic) when the binary is absent.
	for _, tool := range allTools() {
		if _, err := tool.Run("example.com", ToolConfig{Timeout: 5}); err == nil {
			t.Errorf("%s.Run with empty PATH: want error, got nil", tool.Name())
		}
	}
}

// TestExtraArgsAreSplitNotShellInterpreted uses a fake "subfinder" placed on
// PATH that echoes its argv, one per line. This exercises the real Run
// arg-construction path without the genuine third-party binary.
func TestExtraArgsAreSplitNotShellInterpreted(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "pwned")
	fake := "#!/bin/sh\nfor a in \"$@\"; do echo \"$a\"; done\n"
	if err := os.WriteFile(filepath.Join(dir, "subfinder"), []byte(fake), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)

	tool := &SubfinderTool{}
	res, err := tool.Run("example.com", ToolConfig{
		Timeout:   5,
		ExtraArgs: "-x  -y; touch " + marker,
	})
	if err != nil {
		t.Fatalf("Run with fake subfinder: %v", err)
	}
	// strings.Fields splits on whitespace, so "-y;" and the two words of the
	// touch command arrive as distinct literal argv elements — the shell
	// metacharacters are NOT interpreted as a command.
	wantExtra := []string{"-x", "-y;", "touch", marker}
	idx := -1
	for i, got := range res.Output {
		if got == "-x" {
			idx = i
			break
		}
	}
	if idx < 0 {
		t.Fatalf("extra args not found at all in argv echo %v", res.Output)
	}
	if got := res.Output[idx:]; !reflect.DeepEqual(got, wantExtra) {
		t.Errorf("extra-args subslice = %v, want %v (full argv %v)", got, wantExtra, res.Output)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Errorf("shell metacharacters interpreted: marker file %s exists", marker)
	}
}

func TestRunErrorWhenToolMissing(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if _, err := RunSubfinder("example.com", ToolConfig{}); err == nil ||
		!strings.Contains(err.Error(), "subfinder not installed") {
		t.Errorf("RunSubfinder: want 'subfinder not installed' error, got %v", err)
	}
	if _, err := RunAmass("example.com", ToolConfig{}); err == nil ||
		!strings.Contains(err.Error(), "amass not installed") {
		t.Errorf("RunAmass: want 'amass not installed' error, got %v", err)
	}
	if _, err := RunHttpx([]string{"https://example.com"}, ToolConfig{}); err == nil ||
		!strings.Contains(err.Error(), "httpx not installed") {
		t.Errorf("RunHttpx: want 'httpx not installed' error, got %v", err)
	}
	if _, err := RunKatana("https://example.com", ToolConfig{}); err == nil ||
		!strings.Contains(err.Error(), "katana not installed") {
		t.Errorf("RunKatana: want 'katana not installed' error, got %v", err)
	}
}
