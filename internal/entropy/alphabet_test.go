package entropy

import "testing"

func TestDetectAlphabet(t *testing.T) {
	cases := []struct {
		in   string
		want Alphabet
	}{
		{"deadbeef", AlphabetLowerHex},
		{"DEADBEEF", AlphabetUpperHex},
		{"DEadBeEf", AlphabetUpperHex},
		{"aGVsbG8=", AlphabetBase64},
		{"aGVsbG8", AlphabetUnknown},
		{"aGVsbG8-_aGVsbG8", AlphabetJWT},
		{"github_pat_AAAaaa111", AlphabetBase64URL},
		{"a", AlphabetLowerHex},
	}
	for _, c := range cases {
		got := DetectAlphabet(c.in)
		if got != c.want {
			t.Errorf("DetectAlphabet(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
