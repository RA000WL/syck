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

func TestBindEnvScanFlags(t *testing.T) {
	oldWorkers := workers
	t.Cleanup(func() { workers = oldWorkers })

	t.Setenv("SYCK_SCAN_WORKERS", "7")

	bindEnvToFlags(scanCmd)

	if workers != 7 {
		t.Errorf("workers = %d, want %d (SYCK_SCAN_WORKERS not bound)", workers, 7)
	}
}

func TestWorkersClamp(t *testing.T) {
	if got := clampWorkers(0); got <= 0 {
		t.Fatalf("workers 0 must clamp positive, got %d", got)
	}
	if got := clampWorkers(-3); got <= 0 {
		t.Fatalf("negative workers must clamp positive, got %d", got)
	}
	if got := clampWorkers(7); got != 7 {
		t.Fatalf("positive workers must pass through, got %d", got)
	}
}
