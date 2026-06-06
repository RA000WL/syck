package progress

import (
	"bytes"
	"strings"
	"testing"
)

func TestBar_TickAdvancesCounter(t *testing.T) {
	var buf bytes.Buffer
	b := New(&buf)

	b.Tick(1, 0)
	b.Tick(2, 1)
	b.Tick(3, 5)

	if b.findings.Load() != 5 {
		t.Errorf("findings = %d, want 5", b.findings.Load())
	}

	b.Finish()
	out := buf.String()
	if !strings.Contains(out, "scanned 3 files") {
		t.Errorf("Finish output missing file count: %q", out)
	}
	if !strings.Contains(out, "5 findings") {
		t.Errorf("Finish output missing findings count: %q", out)
	}
}

func TestBar_TickWithNoProgressNoOp(t *testing.T) {
	var buf bytes.Buffer
	b := New(&buf)

	b.Tick(0, 0)
	b.Finish()

	if !strings.Contains(buf.String(), "scanned 0 files") {
		t.Errorf("expected 0 files in output: %q", buf.String())
	}
}

func TestBar_Add(t *testing.T) {
	var buf bytes.Buffer
	b := New(&buf)

	b.Add(5)
	b.Add(3)

	if b.pb.State().CurrentNum != 8 {
		t.Errorf("current = %d, want 8", b.pb.State().CurrentNum)
	}
}
