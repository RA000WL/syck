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
		result = append(result, line)
	}
	return strings.Join(result, "\n")
}
