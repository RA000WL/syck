package sourcemap

import (
	"fmt"
	"strings"
)

type VLQSegment struct {
	Col        int
	SourceIdx  int
	SourceLine int
	SourceCol  int
}

var base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

func base64Value(b byte) (int, error) {
	for i := 0; i < len(base64Chars); i++ {
		if base64Chars[i] == b {
			return i, nil
		}
	}
	return 0, fmt.Errorf("invalid base64 char: %c", b)
}

func decodeVLQSeq(s string) ([]int, error) {
	var vals []int
	i := 0
	for i < len(s) {
		val, shift := 0, 0
		for {
			if i >= len(s) {
				return nil, fmt.Errorf("truncated VLQ at position %d", i)
			}
			bv, err := base64Value(s[i])
			if err != nil {
				return nil, err
			}
			cont := (bv & 32) != 0
			val |= (bv & 31) << shift
			shift += 5
			i++
			if !cont {
				break
			}
		}
		signed := val >> 1
		if val&1 != 0 {
			signed = -signed
		}
		vals = append(vals, signed)
	}
	return vals, nil
}

func DecodeMappings(mappings string) ([][]VLQSegment, error) {
	if mappings == "" {
		return nil, nil
	}
	var lines [][]VLQSegment
	for _, lineStr := range strings.Split(mappings, ";") {
		var segments []VLQSegment
		for _, segStr := range strings.Split(lineStr, ",") {
			if segStr == "" {
				continue
			}
			vals, err := decodeVLQSeq(segStr)
			if err != nil {
				return nil, err
			}
			if len(vals) < 4 {
				continue
			}
			segments = append(segments, VLQSegment{
				Col:        vals[0],
				SourceIdx:  vals[1],
				SourceLine: vals[2],
				SourceCol:  vals[3],
			})
		}
		lines = append(lines, segments)
	}
	return lines, nil
}
