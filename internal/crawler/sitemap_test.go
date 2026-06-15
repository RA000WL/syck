package crawler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseSitemap(t *testing.T) {
	xml := `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://example.com/page1</loc>
    <lastmod>2026-01-01</lastmod>
    <changefreq>daily</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>https://example.com/page2</loc>
  </url>
</urlset>`
	urls := ParseSitemap(xml)
	if len(urls) != 2 {
		t.Fatalf("expected 2 URLs, got %d", len(urls))
	}
	if urls[0].Loc != "https://example.com/page1" {
		t.Errorf("unexpected loc: %s", urls[0].Loc)
	}
	if urls[0].LastMod != "2026-01-01" {
		t.Errorf("unexpected lastmod: %s", urls[0].LastMod)
	}
	if urls[1].Loc != "https://example.com/page2" {
		t.Errorf("unexpected loc: %s", urls[1].Loc)
	}
}

func TestParseSitemapIndex(t *testing.T) {
	xml := `<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <sitemap>
    <loc>https://example.com/sitemap1.xml</loc>
  </sitemap>
  <sitemap>
    <loc>https://example.com/sitemap2.xml</loc>
  </sitemap>
</sitemapindex>`
	sitemaps := ParseSitemapIndex(xml)
	if len(sitemaps) != 2 {
		t.Fatalf("expected 2 sitemaps, got %d", len(sitemaps))
	}
	if sitemaps[0] != "https://example.com/sitemap1.xml" {
		t.Errorf("unexpected sitemap: %s", sitemaps[0])
	}
}

func TestFetchSitemaps_RobotsDirectives(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://example.com/robots-sitemap-page</loc></url></urlset>`))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	fetcher := &SitemapFetcher{client: ts.Client(), ua: "test"}
	urls := fetcher.FetchSitemaps("example.com", []string{ts.URL + "/sitemap.xml"})
	if len(urls) != 1 {
		t.Fatalf("expected 1 URL, got %d: %v", len(urls), urls)
	}
}

func TestFetchSitemaps_DeduplicatesStandardPaths(t *testing.T) {
	standardCalled := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
		standardCalled++
		w.WriteHeader(200)
		w.Write([]byte(`<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://example.com/standard</loc></url></urlset>`))
	})
	mux.HandleFunc("/custom-sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://example.com/custom</loc></url></urlset>`))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	fetcher := &SitemapFetcher{client: ts.Client(), ua: "test"}
	urls := fetcher.FetchSitemaps("example.com", []string{ts.URL + "/custom-sitemap.xml"})
	_ = urls
	if standardCalled != 0 {
		t.Errorf("expected 0 standard path fetches (already in robots), got %d", standardCalled)
	}
}
