package decoder

import "testing"

func TestMaxRecursionDepthIs3(t *testing.T) {
	if MaxRecursionDepth != 3 {
		t.Errorf("MaxRecursionDepth = %d, want 3", MaxRecursionDepth)
	}
}
