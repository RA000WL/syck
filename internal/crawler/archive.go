package crawler

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type ArchiveMember struct {
	Path    string
	Content string
	Size    int64
}

const maxArchiveMemberBytes = 10 << 20
const maxArchiveTotalBytes = 100 << 20

func ScanArchive(data []byte, filename string) ([]ArchiveMember, error) {
	lower := strings.ToLower(filename)
	switch {
	case strings.HasSuffix(lower, ".zip") || strings.HasSuffix(lower, ".jar") || strings.HasSuffix(lower, ".war") || strings.HasSuffix(lower, ".ear"):
		return scanZip(data)
	case strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz"):
		return scanTarGzip(data)
	case strings.HasSuffix(lower, ".tar"):
		return scanTar(data)
	default:
		return nil, fmt.Errorf("unsupported archive format: %s", filename)
	}
}

func scanZip(data []byte) ([]ArchiveMember, error) {
	if len(data) > maxArchiveTotalBytes {
		data = data[:maxArchiveTotalBytes]
	}
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	var members []ArchiveMember
	var totalRead int64
	for _, f := range r.File {
		clean := filepath.Clean(f.Name)
		if strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
			continue
		}
		if f.FileInfo().IsDir() || f.UncompressedSize > maxArchiveMemberBytes {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		content, readErr := func() ([]byte, error) {
			defer rc.Close()
			return io.ReadAll(io.LimitReader(rc, maxArchiveMemberBytes))
		}()
		if readErr != nil {
			fmt.Fprintf(os.Stderr, "[debug] read archive member %s: %v\n", f.Name, readErr)
		}
		totalRead += int64(len(content))
		if totalRead > maxArchiveTotalBytes {
			break
		}
		if isTextContent(content) {
			members = append(members, ArchiveMember{Path: f.Name, Content: string(content), Size: int64(len(content))})
		}
	}
	return members, nil
}

func scanTarGzip(data []byte) ([]ArchiveMember, error) {
	if len(data) > maxArchiveTotalBytes {
		data = data[:maxArchiveTotalBytes]
	}
	gzr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer gzr.Close()
	return scanTarReader(tar.NewReader(gzr))
}

func scanTar(data []byte) ([]ArchiveMember, error) {
	if len(data) > maxArchiveTotalBytes {
		data = data[:maxArchiveTotalBytes]
	}
	return scanTarReader(tar.NewReader(bytes.NewReader(data)))
}

func scanTarReader(tr *tar.Reader) ([]ArchiveMember, error) {
	var members []ArchiveMember
	var totalRead int64
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil || hdr == nil {
			continue
		}
		clean := filepath.Clean(hdr.Name)
		if strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
			continue
		}
		if hdr.FileInfo().IsDir() || hdr.Size > maxArchiveMemberBytes {
			continue
		}
		content, readErr := io.ReadAll(io.LimitReader(tr, maxArchiveMemberBytes))
		if readErr != nil {
			fmt.Fprintf(os.Stderr, "[debug] read tar member %s: %v\n", hdr.Name, readErr)
		}
		totalRead += int64(len(content))
		if totalRead > maxArchiveTotalBytes {
			break
		}
		if isTextContent(content) {
			members = append(members, ArchiveMember{Path: hdr.Name, Content: string(content), Size: int64(len(content))})
		}
	}
	return members, nil
}

func isTextContent(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	nulls := 0
	for _, b := range data {
		if b == 0 {
			nulls++
		}
		if nulls > 10 {
			return false
		}
	}
	return true
}
