package crawler

import "testing"

func TestExtractCloudStorage_S3(t *testing.T) {
	content := `my-bucket.s3.amazonaws.com and s3://my-bucket/path`
	refs := ExtractCloudStorage(content)
	if len(refs) < 2 {
		t.Fatalf("expected at least 2 refs, got %d", len(refs))
	}
}

func TestExtractCloudStorage_GCS(t *testing.T) {
	content := `storage.googleapis.com/my-bucket and gs://my-bucket/path`
	refs := ExtractCloudStorage(content)
	if len(refs) < 2 {
		t.Fatalf("expected at least 2 refs, got %d", len(refs))
	}
}

func TestExtractCloudStorage_Azure(t *testing.T) {
	content := `myaccount.blob.core.windows.net`
	refs := ExtractCloudStorage(content)
	if len(refs) != 1 {
		t.Fatalf("expected 1 ref, got %d", len(refs))
	}
}
