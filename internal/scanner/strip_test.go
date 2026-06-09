package scanner

import "testing"

func TestStripLineComments_HashComment(t *testing.T) {
	input := "# this is a comment\npassword=secret123"
	want := "\npassword=secret123"
	got := StripLineComments(input)
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestStripLineComments_SlashSlash(t *testing.T) {
	input := "// this is a comment\nkey=value"
	want := "\nkey=value"
	got := StripLineComments(input)
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestStripLineComments_NoComments(t *testing.T) {
	input := "password=secret123\napi_key=abc123"
	got := StripLineComments(input)
	if got != input {
		t.Fatalf("expected no change, got %q", got)
	}
}

func TestStripLineComments_URLPreserved(t *testing.T) {
	input := `const url = "http://example.com/api/key=abc123";`
	got := StripLineComments(input)
	if got != input {
		t.Fatalf("expected URL unchanged, got %q", got)
	}
}

func TestStripLineComments_LineOnly(t *testing.T) {
	input := "config=value\n// inline comment"
	want := "config=value\n"
	got := StripLineComments(input)
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}
