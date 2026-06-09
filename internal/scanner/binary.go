package scanner

import (
	"fmt"
	"math"
	"os"
	"unicode/utf8"
)

const minBinaryStrLen = 8
const maxBinaryMB = 100

type binaryString struct {
	text   string
	offset int
}

// Line() approximates line number from byte offset; results are approximate for binary files
func (s binaryString) Line() int {
	return int(math.Floor(float64(s.offset)/40)) + 1
}

func ExtractBinaryStrings(path string) ([]binaryString, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > int64(maxBinaryMB*1024*1024) {
		return nil, fmt.Errorf("binary file too large (%d MB, max %d MB)", info.Size()/(1024*1024), maxBinaryMB)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var strs []binaryString
	start := -1
	for i := 0; i < len(data); {
		r, size := utf8.DecodeRune(data[i:])
		if r == utf8.RuneError && size == 1 {
			if start >= 0 && i-start >= minBinaryStrLen {
				strs = append(strs, binaryString{text: string(data[start:i]), offset: start})
			}
			start = -1
			i++
			continue
		}
		if r >= 0x20 && r <= 0x7e || r == '\n' || r == '\t' || r > 0x7f {
			if start < 0 {
				start = i
			}
		} else {
			if start >= 0 && i-start >= minBinaryStrLen {
				strs = append(strs, binaryString{text: string(data[start:i]), offset: start})
			}
			start = -1
		}
		i += size
	}
	if start >= 0 && len(data)-start >= minBinaryStrLen {
		strs = append(strs, binaryString{text: string(data[start:]), offset: start})
	}
	return strs, nil
}
