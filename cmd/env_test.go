package cmd

import (
	"os"
	"testing"

	"github.com/spf13/cobra"
)

func TestBindEnvToFlags(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	var severityVal string
	var workersVal int
	cmd.Flags().StringVar(&severityVal, "severity", "LOW", "")
	cmd.Flags().IntVar(&workersVal, "workers", 10, "")

	t.Setenv("SYCK_TEST_SEVERITY", "HIGH")
	t.Setenv("SYCK_TEST_WORKERS", "42")

	bindEnvToFlags(cmd)

	if severityVal != "HIGH" {
		t.Errorf("severity = %q, want %q", severityVal, "HIGH")
	}
	if workersVal != 42 {
		t.Errorf("workers = %d, want %d", workersVal, 42)
	}
}

func TestBindEnvToFlags_EmptyEnvIgnored(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	var severityVal string
	cmd.Flags().StringVar(&severityVal, "severity", "LOW", "")

	t.Setenv("SYCK_TEST_SEVERITY", "")

	bindEnvToFlags(cmd)

	if severityVal != "LOW" {
		t.Errorf("severity = %q, want %q (default preserved)", severityVal, "LOW")
	}
}

func TestBindEnvToFlags_DashToUnderscore(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	var maxFileVal string
	cmd.Flags().StringVar(&maxFileVal, "max-file-size", "5M", "")

	t.Setenv("SYCK_TEST_MAX_FILE_SIZE", "10M")

	bindEnvToFlags(cmd)

	if maxFileVal != "10M" {
		t.Errorf("max-file-size = %q, want %q", maxFileVal, "10M")
	}
}

func TestBindEnvToFlags_NilCmd(t *testing.T) {
	bindEnvToFlags(nil)
}

func TestBindEnvToFlags_NilEnv(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	var severityVal string
	cmd.Flags().StringVar(&severityVal, "severity", "LOW", "")

	if err := os.Unsetenv("SYCK_TEST_SEVERITY"); err != nil {
		t.Fatal(err)
	}

	bindEnvToFlags(cmd)

	if severityVal != "LOW" {
		t.Errorf("severity = %q, want %q (default preserved)", severityVal, "LOW")
	}
}
