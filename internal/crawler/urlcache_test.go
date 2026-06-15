package crawler

import (
	"path/filepath"
	"testing"
)

func TestURLCache_RecordAndIsSeen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	cache, err := OpenURLCache(path)
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()

	if cache.IsSeen("https://example.com/page1") {
		t.Error("expected IsSeen=false for new URL")
	}

	isNew, err := cache.Record("https://example.com/page1", 200, "<html>hello</html>")
	if err != nil {
		t.Fatal(err)
	}
	if !isNew {
		t.Error("expected isNew=true for first record")
	}

	if !cache.IsSeen("https://example.com/page1") {
		t.Error("expected IsSeen=true after recording")
	}

	isNew, err = cache.Record("https://example.com/page1", 200, "<html>hello</html>")
	if err != nil {
		t.Fatal(err)
	}
	if isNew {
		t.Error("expected isNew=false for duplicate record")
	}
}

func TestURLCache_IsSeen_Non200(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	cache, err := OpenURLCache(path)
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()

	cache.Record("https://example.com/404", 404, "not found")

	if cache.IsSeen("https://example.com/404") {
		t.Error("expected IsSeen=false for 404 status")
	}
}

func TestURLCache_GetContentHash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	cache, err := OpenURLCache(path)
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()

	if h := cache.GetContentHash("https://example.com/new"); h != "" {
		t.Error("expected empty hash for uncached URL")
	}

	cache.Record("https://example.com/page", 200, "content-v1")

	h1 := cache.GetContentHash("https://example.com/page")
	if h1 == "" {
		t.Fatal("expected non-empty hash")
	}

	cache.Record("https://example.com/page", 200, "content-v2")

	h2 := cache.GetContentHash("https://example.com/page")
	if h2 == "" {
		t.Fatal("expected non-empty hash after update")
	}
	if h1 == h2 {
		t.Error("expected different content hash after content change")
	}
}

func TestURLCache_Count(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	cache, err := OpenURLCache(path)
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()

	count, _ := cache.Count()
	if count != 0 {
		t.Errorf("expected 0, got %d", count)
	}

	cache.Record("https://a.com", 200, "a")
	cache.Record("https://b.com", 200, "b")

	count, _ = cache.Count()
	if count != 2 {
		t.Errorf("expected 2, got %d", count)
	}
}

func TestURLHash_Deterministic(t *testing.T) {
	h1 := URLHash("https://example.com")
	h2 := URLHash("https://example.com")
	if h1 != h2 {
		t.Error("URLHash should be deterministic")
	}
	if len(h1) != 32 {
		t.Errorf("expected 32-char hex, got %d", len(h1))
	}
}

func TestContentHash_DifferentContent(t *testing.T) {
	h1 := ContentHash("content-a")
	h2 := ContentHash("content-b")
	if h1 == h2 {
		t.Error("different content should produce different hashes")
	}
}
