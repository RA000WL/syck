package crawler

import (
	"testing"
)

func TestDetectEncodingFromContentType(t *testing.T) {
	tests := []struct {
		ct   string
		want string
	}{
		{"text/html; charset=utf-8", "utf-8"},
		{"text/html; charset=ISO-8859-1", "iso-8859-1"},
		{"text/html; charset=\"windows-1252\"", "windows-1252"},
		{"text/html", ""},
		{"application/json; charset=utf-8", "utf-8"},
	}
	for _, tt := range tests {
		got := DetectEncoding(tt.ct, nil)
		if got != tt.want {
			t.Errorf("DetectEncoding(%q, nil) = %q, want %q", tt.ct, got, tt.want)
		}
	}
}

func TestDetectEncodingFromMeta(t *testing.T) {
	tests := []struct {
		html string
		want string
	}{
		{`<html><head><meta charset="utf-8"></head></html>`, "utf-8"},
		{`<html><head><meta charset="iso-8859-1"></head></html>`, "iso-8859-1"},
		{`<html><head><meta http-equiv="Content-Type" content="text/html; charset=windows-1252"></head></html>`, "windows-1252"},
		{`<html><head><title>No charset</title></head></html>`, ""},
	}
	for _, tt := range tests {
		got := DetectEncoding("text/html", []byte(tt.html))
		if got != tt.want {
			t.Errorf("DetectEncoding with html = %q, got %q, want %q", tt.html, got, tt.want)
		}
	}
}

func TestDetectEncodingFromBOM(t *testing.T) {
	// UTF-8 BOM
	body := []byte{0xEF, 0xBB, 0xBF, '<', 'h', 't', 'm', 'l'}
	got := DetectEncoding("", body)
	if got != "utf-8" {
		t.Errorf("expected utf-8 from BOM, got %q", got)
	}
}

func TestConvertToUTF8ISO8859(t *testing.T) {
	// ISO-8859-1 byte 0xE9 = é
	body := []byte{0x68, 0x65, 0x6C, 0x6C, 0x6F, 0xE9}
	got, ok := ConvertToUTF8(body, "iso-8859-1")
	if !ok {
		t.Fatal("expected conversion to occur")
	}
	expected := "helloé"
	if string(got) != expected {
		t.Errorf("expected %q, got %q", expected, string(got))
	}
}

func TestConvertToUTF8Windows1252(t *testing.T) {
	// Windows-1252 byte 0x80 = €
	body := []byte{0x24, 0x80}
	got, ok := ConvertToUTF8(body, "windows-1252")
	if !ok {
		t.Fatal("expected conversion to occur")
	}
	expected := "$€"
	if string(got) != expected {
		t.Errorf("expected %q, got %q", expected, string(got))
	}
}

func TestConvertToUTF8Noop(t *testing.T) {
	body := []byte("hello")
	got, ok := ConvertToUTF8(body, "utf-8")
	if ok {
		t.Error("expected no conversion for utf-8")
	}
	if string(got) != "hello" {
		t.Errorf("expected unchanged content, got %q", string(got))
	}
}
