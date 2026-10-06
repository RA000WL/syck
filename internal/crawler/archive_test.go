package crawler

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
)

func TestScanArchive_Zip(t *testing.T) {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, _ := w.Create("config.txt")
	f.Write([]byte("password=supersecret123"))
	f2, _ := w.Create("readme.md")
	f2.Write([]byte("# Hello"))
	w.Close()
	members, err := ScanArchive(buf.Bytes(), "test.zip")
	if err != nil || len(members) != 2 {
		t.Fatalf("expected 2 members, got %d (err=%v)", len(members), err)
	}
}

func TestScanArchive_TarGz(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	tw.WriteHeader(&tar.Header{Name: "config.txt", Size: int64(len("key=value"))})
	tw.Write([]byte("key=value"))
	tw.Close()
	gz.Close()
	members, err := ScanArchive(buf.Bytes(), "config.tar.gz")
	if err != nil || len(members) != 1 {
		t.Fatalf("expected 1 member, got %d (err=%v)", len(members), err)
	}
}

// TestScanZipOversizeSkipsNotSlices asserts the size guard directly: an
// oversize input must produce a clean size/skip error. We do not build a
// real >100MB zip (too expensive); instead we pass maxArchiveTotalBytes+1
// zero bytes. If the guard regresses to slicing, zip.NewReader would fail
// with "zip: not a valid zip file" on the truncated slice and this test
// would catch it.
func TestScanZipOversizeSkipsNotSlices(t *testing.T) {
	data := make([]byte, maxArchiveTotalBytes+1)
	_, err := ScanArchive(data, "big.zip")
	if err == nil {
		t.Fatal("expected error for oversize zip")
	}
	if strings.Contains(err.Error(), "not a valid zip file") {
		t.Fatalf("got zip format error instead of size guard: %v", err)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "size") &&
		!strings.Contains(strings.ToLower(err.Error()), "large") &&
		!strings.Contains(strings.ToLower(err.Error()), "skip") {
		t.Fatalf("expected size/skip error, got: %v", err)
	}

	// Same guard must apply to tar variants.
	if _, err := ScanArchive(data, "big.tar"); err == nil || strings.Contains(err.Error(), "not a valid zip file") {
		t.Fatalf("expected clean size error for tar, got: %v", err)
	}
	if _, err := ScanArchive(data, "big.tar.gz"); err == nil {
		t.Fatal("expected clean size error for tar.gz")
	} else if strings.Contains(err.Error(), "gzip:") {
		t.Fatalf("got gzip format error instead of size guard: %v", err)
	}
}
