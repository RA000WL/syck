package crawler

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/RA000WL/syck/internal/endpoints"
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
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(content))
	if err != nil {
		return nil
	}

	var urls []string
	seen := make(map[string]bool)

	addURL := func(raw string) {
		resolved := resolveURL(raw, base)
		if resolved != "" && !seen[resolved] {
			seen[resolved] = true
			urls = append(urls, resolved)
		}
	}

	// a[href], a[ping]
	doc.Find("a").Each(func(i int, s *goquery.Selection) {
		if href, ok := s.Attr("href"); ok {
			addURL(href)
		}
		if ping, ok := s.Attr("ping"); ok {
			addURL(ping)
		}
	})

	// link[href]
	doc.Find("link[href]").Each(func(i int, s *goquery.Selection) {
		if href, ok := s.Attr("href"); ok {
			addURL(href)
		}
	})

	// script[src]
	doc.Find("script[src]").Each(func(i int, s *goquery.Selection) {
		if src, ok := s.Attr("src"); ok {
			addURL(src)
		}
	})

	// img[src], img[srcset]
	doc.Find("img").Each(func(i int, s *goquery.Selection) {
		for _, attr := range []string{"src", "dynsrc", "lowsrc", "longdesc"} {
			if val, ok := s.Attr(attr); ok && val != "" && val != "#" {
				addURL(val)
			}
		}
		if srcset, ok := s.Attr("srcset"); ok {
			for _, v := range parseSrcset(srcset) {
				addURL(v)
			}
		}
	})

	// iframe[src]
	doc.Find("iframe").Each(func(i int, s *goquery.Selection) {
		if src, ok := s.Attr("src"); ok {
			addURL(src)
		}
	})

	// frame[src]
	doc.Find("frame[src]").Each(func(i int, s *goquery.Selection) {
		if src, ok := s.Attr("src"); ok {
			addURL(src)
		}
	})

	// embed[src]
	doc.Find("embed[src]").Each(func(i int, s *goquery.Selection) {
		if src, ok := s.Attr("src"); ok {
			addURL(src)
		}
	})

	// object[data], object[codebase]
	doc.Find("object").Each(func(i int, s *goquery.Selection) {
		if data, ok := s.Attr("data"); ok {
			addURL(data)
		}
		if cb, ok := s.Attr("codebase"); ok {
			addURL(cb)
		}
	})

	// video[src], video[poster]
	doc.Find("video").Each(func(i int, s *goquery.Selection) {
		if src, ok := s.Attr("src"); ok {
			addURL(src)
		}
		if poster, ok := s.Attr("poster"); ok {
			addURL(poster)
		}
	})

	// audio[src], source[src], source[srcset]
	doc.Find("audio").Each(func(i int, s *goquery.Selection) {
		if src, ok := s.Attr("src"); ok {
			addURL(src)
		}
		s.Find("source").Each(func(i int, s *goquery.Selection) {
			if src, ok := s.Attr("src"); ok {
				addURL(src)
			}
			if srcset, ok := s.Attr("srcset"); ok {
				for _, v := range parseSrcset(srcset) {
					addURL(v)
				}
			}
		})
	})

	// source[src], source[srcset] (outside audio/video)
	doc.Find("source").Each(func(i int, s *goquery.Selection) {
		if src, ok := s.Attr("src"); ok {
			addURL(src)
		}
		if srcset, ok := s.Attr("srcset"); ok {
			for _, v := range parseSrcset(srcset) {
				addURL(v)
			}
		}
	})

	// table[background], td[background]
	doc.Find("table[background]").Each(func(i int, s *goquery.Selection) {
		if bg, ok := s.Attr("background"); ok {
			addURL(bg)
		}
	})
	doc.Find("td[background]").Each(func(i int, s *goquery.Selection) {
		if bg, ok := s.Attr("background"); ok {
			addURL(bg)
		}
	})

	// body[background]
	doc.Find("body[background]").Each(func(i int, s *goquery.Selection) {
		if bg, ok := s.Attr("background"); ok {
			addURL(bg)
		}
	})

	// button[formaction]
	doc.Find("button[formaction]").Each(func(i int, s *goquery.Selection) {
		if fa, ok := s.Attr("formaction"); ok {
			addURL(fa)
		}
	})

	// blockquote[cite]
	doc.Find("blockquote[cite]").Each(func(i int, s *goquery.Selection) {
		if cite, ok := s.Attr("cite"); ok {
			addURL(cite)
		}
	})

	// input[type=image][src]
	doc.Find("input[type='image' i]").Each(func(i int, s *goquery.Selection) {
		if src, ok := s.Attr("src"); ok {
			addURL(src)
		}
	})

	// area[ping]
	doc.Find("area[ping]").Each(func(i int, s *goquery.Selection) {
		if ping, ok := s.Attr("ping"); ok {
			addURL(ping)
		}
	})

	// base[href]
	doc.Find("base[href]").Each(func(i int, s *goquery.Selection) {
		if href, ok := s.Attr("href"); ok {
			addURL(href)
		}
	})

	// meta[content] (refresh URLs)
	doc.Find("meta[content]").Each(func(i int, s *goquery.Selection) {
		if content, ok := s.Attr("content"); ok {
			if idx := strings.Index(strings.ToLower(content), "url="); idx >= 0 {
				addURL(content[idx+4:])
			}
		}
	})

	// html[manifest]
	doc.Find("html[manifest]").Each(func(i int, s *goquery.Selection) {
		if manifest, ok := s.Attr("manifest"); ok {
			addURL(manifest)
		}
	})

	// htmx attributes: hx-get, hx-post, hx-put, hx-patch
	doc.Find("[hx-get],[hx-post],[hx-put],[hx-patch]").Each(func(i int, s *goquery.Selection) {
		for _, attr := range []string{"hx-get", "hx-post", "hx-put", "hx-patch"} {
			if val, ok := s.Attr(attr); ok {
				addURL(val)
			}
		}
	})

	// svg image/script href (including legacy xlink:href)
	doc.Find("svg").Each(func(i int, sel *goquery.Selection) {
		sel.Find("image").Each(func(i int, imgSel *goquery.Selection) {
			if href, ok := imgSel.Attr("href"); ok {
				addURL(href)
			} else if href, ok := imgSel.Attr("xlink:href"); ok {
				addURL(href)
			}
		})
		sel.Find("script").Each(func(i int, scriptSel *goquery.Selection) {
			if href, ok := scriptSel.Attr("href"); ok {
				addURL(href)
			} else if href, ok := scriptSel.Attr("xlink:href"); ok {
				addURL(href)
			}
		})
	})

	// Inline script content — extract relative endpoints
	doc.Find("script").Each(func(i int, s *goquery.Selection) {
		text := s.Text()
		if text == "" {
			return
		}
		for _, m := range jsImportRe.FindAllStringSubmatch(text, -1) {
			if len(m) >= 2 {
				addURL(m[1])
			}
		}
	})

	return urls
}

func extractJS(content string, base *url.URL) []string {
	var urls []string
	seen := make(map[string]bool)

	// Existing: extract import URLs
	matches := jsImportRe.FindAllStringSubmatch(content, -1)
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		resolved := resolveURL(m[1], base)
		if resolved != "" && !seen[resolved] {
			seen[resolved] = true
			urls = append(urls, resolved)
		}
	}

	// V1.1: also extract API/endpoint URLs from JS content
	for _, ep := range endpoints.ExtractEndpoints(base.String(), content) {
		if strings.HasPrefix(ep.Endpoint, "http://") || strings.HasPrefix(ep.Endpoint, "https://") {
			if !seen[ep.Endpoint] {
				seen[ep.Endpoint] = true
				urls = append(urls, ep.Endpoint)
			}
		} else {
			resolved := resolveURL(ep.Endpoint, base)
			if resolved != "" && !seen[resolved] {
				seen[resolved] = true
				urls = append(urls, resolved)
			}
		}
	}

	return urls
}

func resolveURL(raw string, base *url.URL) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "#") || strings.HasPrefix(raw, "data:") {
		return ""
	}
	lc := strings.ToLower(raw)
	if strings.HasPrefix(lc, "mailto:") || strings.HasPrefix(lc, "javascript:") || strings.HasPrefix(lc, "vbscript:") {
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

// parseSrcset splits a srcset attribute value into individual URLs.
func parseSrcset(srcset string) []string {
	var urls []string
	for _, part := range strings.Split(srcset, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		fields := strings.Fields(part)
		if len(fields) > 0 {
			urls = append(urls, fields[0])
		}
	}
	return urls
}
