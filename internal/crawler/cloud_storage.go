package crawler

import "regexp"

var (
	s3URLRe     = regexp.MustCompile(`\b([a-z0-9\-]+\.)?s3([.\-][a-z0-9\-]+)?\.amazonaws\.com\b`)
	s3PathRe    = regexp.MustCompile(`\bs3://([a-z0-9.\-]+)/?\b`)
	gcsURLRe    = regexp.MustCompile(`\bstorage\.googleapis\.com\b`)
	gcsPathRe   = regexp.MustCompile(`\bgs://([a-z0-9.\-_]+)/?\b`)
	azureURLRe  = regexp.MustCompile(`\b([a-z0-9\-]+)\.blob\.core\.windows\.net\b`)
	azurePathRe = regexp.MustCompile(`\b([a-z0-9\-]+)\.blob\.storage\.azure\.net\b`)
)

type CloudStorageRef struct {
	URL      string
	Bucket   string
	Provider string
}

func ExtractCloudStorage(content string) []CloudStorageRef {
	var refs []CloudStorageRef
	seen := make(map[string]bool)

	add := func(url, bucket, provider string) {
		if !seen[url] {
			seen[url] = true
			refs = append(refs, CloudStorageRef{URL: url, Bucket: bucket, Provider: provider})
		}
	}

	for _, m := range s3URLRe.FindAllString(content, -1) {
		add(m, "", "aws_s3")
	}
	for _, m := range s3PathRe.FindAllStringSubmatch(content, -1) {
		if len(m) >= 2 {
			add(m[0], m[1], "aws_s3")
		}
	}
	for _, m := range gcsURLRe.FindAllString(content, -1) {
		add(m, "", "gcs")
	}
	for _, m := range gcsPathRe.FindAllStringSubmatch(content, -1) {
		if len(m) >= 2 {
			add(m[0], m[1], "gcs")
		}
	}
	for _, m := range azureURLRe.FindAllStringSubmatch(content, -1) {
		if len(m) >= 2 {
			add(m[0], m[1], "azure_blob")
		}
	}
	for _, m := range azurePathRe.FindAllStringSubmatch(content, -1) {
		if len(m) >= 2 {
			add(m[0], m[1], "azure_blob")
		}
	}

	return refs
}
