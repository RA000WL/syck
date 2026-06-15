package scanner

import (
	"net/http"
	"strings"
)

// ParseCookies parses a browser-style cookie header string ("name1=value1; name2=value2")
// into individual *http.Cookie values. Uses a custom parser because Go's
// http.ParseCookie is designed for Set-Cookie headers, not Cookie request headers.
func ParseCookies(cookieStr string) []*http.Cookie {
	if strings.TrimSpace(cookieStr) == "" {
		return nil
	}

	var cookies []*http.Cookie
	parts := strings.Split(cookieStr, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		eqIdx := strings.Index(part, "=")
		if eqIdx < 0 {
			continue
		}
		name := strings.TrimSpace(part[:eqIdx])
		value := strings.TrimSpace(part[eqIdx+1:])
		if name == "" {
			continue
		}
		if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
			value = value[1 : len(value)-1]
		}
		cookies = append(cookies, &http.Cookie{
			Name:  name,
			Value: value,
		})
	}
	return cookies
}
