package crawler

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
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
