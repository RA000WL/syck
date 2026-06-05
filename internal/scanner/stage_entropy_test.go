package scanner

import "testing"

func TestEntropyStageNoContext(t *testing.T) {
	s := NewEntropyStage()
	got := s.Process("hello world", "x.txt", 1)
	if got != nil {
		t.Errorf("want nil (no secret context), got %v", got)
	}
}
