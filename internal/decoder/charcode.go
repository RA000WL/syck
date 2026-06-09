package decoder

import (
	"regexp"
	"strconv"
	"strings"
)

var fromCharCodeRE = regexp.MustCompile(`String\.fromCharCode\s*\(([^)]+)\)`)

func tryCharCode(line string) []DecodeResult {
	var results []DecodeResult
	matches := fromCharCodeRE.FindAllStringSubmatch(line, -1)
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		decoded := decodeCharCodes(m[1])
		if decoded != "" {
			results = append(results, DecodeResult{SourceTag: "charcode", Text: decoded})
		}
	}
	return results
}

func decodeCharCodes(args string) string {
	parts := strings.Split(args, ",")
	var sb strings.Builder
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil {
			continue
		}
		if n < 0 || n > 0x10FFFF {
			continue
		}
		sb.WriteRune(rune(n))
	}
	return sb.String()
}
