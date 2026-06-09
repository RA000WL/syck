package crawler

import "testing"

func TestScanPackageFile_NpmToken(t *testing.T) {
	content := "//registry.npmjs.org/:_authToken=npm_abc123"
	entries := ScanPackageFile("package.json", content)
	if len(entries) != 1 || entries[0].Secret != "npm_abc123" {
		t.Fatalf("expected npm token, got %+v", entries)
	}
}

func TestScanPackageFile_Wildcard(t *testing.T) {
	entries := ScanPackageFile("package.json", `{"dependencies": {"foo": "*"}}`)
	if len(entries) != 1 || !entries[0].Mutable {
		t.Fatalf("expected mutable dep, got %+v", entries)
	}
}

func TestScanPackageFile_Requirements(t *testing.T) {
	content := "requests>=2.0.0\ngit+https://github.com/user/repo.git"
	entries := ScanPackageFile("requirements.txt", content)
	if len(entries) != 1 {
		t.Fatalf("expected 1 git+http entry, got %d", len(entries))
	}
}
