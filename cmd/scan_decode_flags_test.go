package cmd

import "testing"

// TestDecodeNewFlagsDefaultOff asserts the 4 Batch 2a decoder flags exist
// and default to off. Fails pre-implementation (flags unregistered).
func TestDecodeNewFlagsDefaultOff(t *testing.T) {
	for _, name := range []string{
		"decode-base64url",
		"decode-jwt",
		"decode-double-base64",
		"decode-charcode",
	} {
		f := scanCmd.Flags().Lookup(name)
		if f == nil {
			t.Fatalf("flag --%s not registered", name)
		}
		if f.DefValue != "false" {
			t.Errorf("flag --%s default = %q, want \"false\"", name, f.DefValue)
		}
	}
}
