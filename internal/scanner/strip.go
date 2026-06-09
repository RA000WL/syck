package scanner

import "strings"

func StripLineComments(content string) string {
	lines := strings.Split(content, "\n")
	var result []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") ||
			strings.HasPrefix(trimmed, "#") ||
			strings.HasPrefix(trimmed, ";") ||
			strings.HasPrefix(trimmed, "--") {
			result = append(result, "")
			continue
		}
		clean := line
		if idx := strings.Index(clean, "//"); idx >= 0 {
			before := strings.TrimSpace(clean[:idx])
			if before != "" && !strings.HasPrefix(before, "\"") && !strings.HasPrefix(before, "'") {
				clean = before
			}
		}
		result = append(result, clean)
	}
	return strings.Join(result, "\n")
}
