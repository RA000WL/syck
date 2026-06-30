package fileutil

import (
	"sort"
	"testing"
)

func TestTextExtensionsSize(t *testing.T) {
	if len(TextExtensions) == 0 {
		t.Fatal("TextExtensions is empty")
	}
}

func TestTextExtensionsValues(t *testing.T) {
	for ext, val := range TextExtensions {
		if !val {
			t.Errorf("TextExtensions[%q] = false, want true", ext)
		}
	}
}

func TestTextExtensionsAllExpectedKeys(t *testing.T) {
	expected := []string{
		".txt", ".go", ".py", ".js", ".ts",
		".jsx", ".tsx", ".json", ".yaml", ".yml",
		".toml", ".ini", ".cfg", ".conf", ".env",
		".sh", ".bash", ".zsh", ".fish", ".bat",
		".ps1", ".rb", ".rs", ".java", ".kt",
		".swift", ".c", ".cpp", ".h", ".hpp",
		".cs", ".php", ".pl", ".pm", ".lua",
		".r", ".scala", ".clj", ".hs", ".erl",
		".ex", ".exs", ".md", ".rst", ".html",
		".htm", ".xml", ".svg", ".css", ".scss",
		".less", ".sql", ".graphql", ".gql",
		".dockerfile", ".makefile", ".gradle",
		".tf", ".tfvars", ".hcl", ".properties",
		".lock", ".log", ".csv", ".tsv",
		".pem", ".key", ".cert", ".crt",
		".pgp", ".gpg", ".asc",
	}
	for _, e := range expected {
		if !TextExtensions[e] {
			t.Errorf("TextExtensions missing expected key %q", e)
		}
	}
	if len(TextExtensions) != len(expected) {
		t.Errorf("TextExtensions has %d entries, expected %d", len(TextExtensions), len(expected))
	}
}

func TestIsTextExt(t *testing.T) {
	tests := []struct {
		name string
		ext  string
		want bool
	}{
		{"empty string", "", false},
		{"dot alone", ".", false},
		{"go", ".go", true},
		{"python", ".py", true},
		{"javascript", ".js", true},
		{"typescript", ".ts", true},
		{"json", ".json", true},
		{"yaml", ".yaml", true},
		{"yml", ".yml", true},
		{"env", ".env", true},
		{"env file", ".env.local", false},
		{"shell", ".sh", true},
		{"markdown", ".md", true},
		{"html", ".html", true},
		{"css", ".css", true},
		{"sql", ".sql", true},
		{"pem", ".pem", true},
		{"key", ".key", true},
		{"cert", ".cert", true},
		{"crt", ".crt", true},
		{"pgp", ".pgp", true},
		{"gpg", ".gpg", true},
		{"asc", ".asc", true},
		{"dockerfile", ".dockerfile", true},
		{"makefile", ".makefile", true},
		{"gradle", ".gradle", true},
		{"terraform", ".tf", true},
		{"tfvars", ".tfvars", true},
		{"hcl", ".hcl", true},
		{"properties", ".properties", true},
		{"lock", ".lock", true},
		{"log", ".log", true},
		{"csv", ".csv", true},
		{"tsv", ".tsv", true},
		{"binary exe", ".exe", false},
		{"binary so", ".so", false},
		{"binary dll", ".dll", false},
		{"image png", ".png", false},
		{"image jpg", ".jpg", false},
		{"image gif", ".gif", false},
		{"video mp4", ".mp4", false},
		{"audio mp3", ".mp3", false},
		{"zip", ".zip", false},
		{"archive tar", ".tar", false},
		{"archive gz", ".gz", false},
		{"uppercase GO", ".GO", false},
		{"uppercase JS", ".JS", false},
		{"no dot go", "go", false},
		{"double dot", "..go", false},
		{"whitespace", " ", false},
		{"random text", "foobar", false},
		{"java", ".java", true},
		{"kotlin", ".kt", true},
		{"swift", ".swift", true},
		{"c lang", ".c", true},
		{"cpp", ".cpp", true},
		{"header", ".h", true},
		{"hpp", ".hpp", true},
		{"csharp", ".cs", true},
		{"php", ".php", true},
		{"perl", ".pl", true},
		{"perl module", ".pm", true},
		{"lua", ".lua", true},
		{"r", ".r", true},
		{"scala", ".scala", true},
		{"clojure", ".clj", true},
		{"haskell", ".hs", true},
		{"erlang", ".erl", true},
		{"elixir", ".ex", true},
		{"elixir script", ".exs", true},
		{"restructuredtext", ".rst", true},
		{"htm", ".htm", true},
		{"xml", ".xml", true},
		{"svg", ".svg", true},
		{"scss", ".scss", true},
		{"less", ".less", true},
		{"graphql", ".graphql", true},
		{"gql", ".gql", true},
		{"toml", ".toml", true},
		{"ini", ".ini", true},
		{"cfg", ".cfg", true},
		{"conf", ".conf", true},
		{"bash", ".bash", true},
		{"zsh", ".zsh", true},
		{"fish", ".fish", true},
		{"bat", ".bat", true},
		{"ps1", ".ps1", true},
		{"rb", ".rb", true},
		{"rs", ".rs", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsTextExt(tt.ext)
			if got != tt.want {
				t.Errorf("IsTextExt(%q) = %v, want %v", tt.ext, got, tt.want)
			}
		})
	}
}

func TestIsTextExtMatchesMapLookup(t *testing.T) {
	for ext := range TextExtensions {
		if !IsTextExt(ext) {
			t.Errorf("IsTextExt(%q) = false but TextExtensions[%q] = true", ext, ext)
		}
	}
}

func TestTextExtensionsSortedKeys(t *testing.T) {
	keys := make([]string, 0, len(TextExtensions))
	for k := range TextExtensions {
		keys = append(keys, k)
	}
	sorted := make([]string, len(keys))
	copy(sorted, keys)
	sort.Strings(sorted)
	for i, k := range keys {
		if k != sorted[i] {
			t.Skip("TextExtensions iteration order not guaranteed sorted; skipping sorted comparison")
		}
	}
}

func TestTextExtensionsNoDuplicates(t *testing.T) {
	if len(TextExtensions) == 0 {
		t.Skip("empty map")
	}
	seen := make(map[string]bool, len(TextExtensions))
	for ext := range TextExtensions {
		if seen[ext] {
			t.Errorf("duplicate key %q in TextExtensions", ext)
		}
		seen[ext] = true
	}
}

func TestTextExtensionsKeysStartWithDot(t *testing.T) {
	for ext := range TextExtensions {
		if len(ext) == 0 || ext[0] != '.' {
			t.Errorf("TextExtensions key %q does not start with '.'", ext)
		}
	}
}

func BenchmarkIsTextExt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		IsTextExt(".go")
	}
}

func BenchmarkIsTextExtMiss(b *testing.B) {
	for i := 0; i < b.N; i++ {
		IsTextExt(".exe")
	}
}
