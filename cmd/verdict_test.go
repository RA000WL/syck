package cmd

import (
	"testing"
)

func TestVerdictRequiresArgs(t *testing.T) {
	cmd := verdictCmd
	cmd.SetArgs([]string{"--cache-db", t.TempDir() + "/test.db"})
	err := cmd.Execute()
	if err == nil {
		t.Error("expected error when no args and no --stats")
	}
}
