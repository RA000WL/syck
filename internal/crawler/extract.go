package crawler

import (
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

var jsImportRe = regexp.MustCompile(
	`(?:"|')` +
		`((?:https?://[^\s"']+|[./][^\s"']+))` +
		`(?:["' ])`,
)

// ExtractURLs extracts linked resources from HTML or JS content.
// base is the URL of the fetched content (for resolving relative URLs).
func ExtractURLs(content string, base *url.URL, contentType string) []string {
	if strings.Contains(contentType, "html") {
		return extractHTML(content, base)
	}
	if strings.Contains(contentType, "javascript") || strings.HasSuffix(base.Path, ".js") {
		return extractJS(content, base)
	}
	return nil
}

func extractHTML(content string, base *url.URL) []string {
	var urls []string
	tokenizer := html.NewTokenizer(strings.NewReader(content))

	for {
		tt := tokenizer.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt != html.StartTagToken {
			continue
		}

		token := tokenizer.Token()
		tagName := token.Data

		var attrName string
		switch tagName {
		case "script":
			attrName = "src"
		case "link":
			attrName = "href"
		case "a":
			attrName = "href"
		default:
			continue
		}

		for _, attr := range token.Attr {
			if attr.Key == attrName {
				resolved := resolveURL(attr.Val, base)
				if resolved != "" {
					urls = append(urls, resolved)
				}
				break
			}
		}
	}

	return urls
}

func extractJS(content string, base *url.URL) []string {
	var urls []string
	matches := jsImportRe.FindAllStringSubmatch(content, -1)
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		resolved := resolveURL(m[1], base)
		if resolved != "" {
			urls = append(urls, resolved)
		}
	}
	return urls
}

func resolveURL(raw string, base *url.URL) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "#") || strings.HasPrefix(raw, "data:") {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if base != nil {
		u = base.ResolveReference(u)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return ""
	}
	return u.String()
}