package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractBinaryStrings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")
	data := []byte{0x00, 0x01, 0x02, 'A', 'P', 'I', '_', 'K', 'E', 'Y', '=', '1', '2', '3',
		0xFF, 0xFE, 'h', 't', 't', 'p', 's', ':', '/', '/', 'a', 'p', 'i', '.', 'e', 'x',
		'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', '/', 'v', '1', '/', 0x00, 0xFF}
	os.WriteFile(path, data, 0644)
	strs, err := ExtractBinaryStrings(path)
	if err != nil || len(strs) < 2 {
		t.Fatalf("expected >=2 strings, got %d (err=%v)", len(strs), err)
	}
}

func TestExtractBinaryStrings_Empty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.bin")
	os.WriteFile(path, []byte{0x00, 0x01, 0x02}, 0644)
	strs, err := ExtractBinaryStrings(path)
	if err != nil || len(strs) != 0 {
		t.Fatalf("expected 0 strings, got %d (err=%v)", len(strs), err)
	}
}
