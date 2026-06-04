package crawler

import (
	"net/url"
	"testing"
)

func TestExtractHTMLScripts(t *testing.T) {
	html := `<html><body>
<script src="/app.js"></script>
<script src="https://cdn.example.com/lib.js"></script>
<link href="/styles.css">
<a href="/about">About</a>
</body></html>`

	base, _ := url.Parse("https://target.com/index.html")
	urls := ExtractURLs(html, base, "text/html")

	if len(urls) != 4 {
		t.Fatalf("expected 4 URLs, got %d: %v", len(urls), urls)
	}
	expected := []string{
		"https://target.com/app.js",
		"https://cdn.example.com/lib.js",
		"https://target.com/styles.css",
		"https://target.com/about",
	}
	for i, want := range expected {
		if urls[i] != want {
			t.Errorf("urls[%d] = %q, want %q", i, urls[i], want)
		}
	}
}

func TestExtractJSImport(t *testing.T) {
	js := `import { foo } from './utils.js'; require("https://cdn.example.com/lib.js");`
	base, _ := url.Parse("https://target.com/src/main.js")
	urls := ExtractURLs(js, base, "application/javascript")

	if len(urls) < 2 {
		t.Fatalf("expected >= 2 URLs, got %d: %v", len(urls), urls)
	}
	if urls[0] != "https://target.com/src/utils.js" {
		t.Errorf("urls[0] = %q, want %q", urls[0], "https://target.com/src/utils.js")
	}
}

func TestExtractSkipsDataURI(t *testing.T) {
	html := `<script src="data:text/javascript,alert(1)"></script>`
	base, _ := url.Parse("https://target.com/")
	urls := ExtractURLs(html, base, "text/html")

	if len(urls) != 0 {
		t.Errorf("expected 0 URLs, got %d: %v", len(urls), urls)
	}
}