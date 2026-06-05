package sourcemap

import "testing"

func TestDecodeSingleVLQ(t *testing.T) {
	segments, err := DecodeMappings("AAAA")
	if err != nil {
		t.Fatal(err)
	}
	if len(segments) != 1 || len(segments[0]) != 1 {
		t.Fatalf("expected 1 line with 1 segment, got %d lines %d segs", len(segments), len(segments[0]))
	}
	s := segments[0][0]
	if s.Col != 0 || s.SourceIdx != 0 || s.SourceLine != 0 || s.SourceCol != 0 {
		t.Errorf("segment = %+v, want {0 0 0 0}", s)
	}
}

func TestDecodeVLQMultipleSegments(t *testing.T) {
	// "AACA" = A=0|A=0|CA=1,0|A=0 = segment (0,0,1,0,0)
	segments, err := DecodeMappings("AACA")
	if err != nil {
		t.Fatal(err)
	}
	if len(segments) != 1 || len(segments[0]) != 1 {
		t.Fatalf("expected 1 segment, got %d", len(segments[0]))
	}
	s := segments[0][0]
	if s.SourceIdx != 0 || s.SourceLine != 1 || s.SourceCol != 0 {
		t.Errorf("segment = %+v, want sourceIdx=0 sourceLine=1 sourceCol=0", s)
	}
}

func TestDecodeVLQMultipleLines(t *testing.T) {
	// "AAAA;AACA" = 2 lines
	segments, err := DecodeMappings("AAAA;AACA")
	if err != nil {
		t.Fatal(err)
	}
	if len(segments) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(segments))
	}
}
