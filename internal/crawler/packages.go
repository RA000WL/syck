package crawler

import (
	"path/filepath"
	"regexp"
	"strings"
)

type PackageEntry struct {
	Name    string
	Version string
	Source  string
	Line    int
	Mutable bool
	Secret  string
}

var npmTokenRe = regexp.MustCompile(`//registry\.npmjs\.org/:_authToken\s*=\s*(\S+)`)

func ScanPackageFile(path, content string) []PackageEntry {
	base := filepath.Base(path)
	lower := strings.ToLower(base)

	switch {
	case lower == "package.json" || lower == "package-lock.json":
		return scanNpmPackage(path, content, lower == "package-lock.json")
	case lower == "requirements.txt":
		return scanRequirementsTxt(path, content)
	case lower == "yarn.lock":
		return scanYarnLock(path, content)
	case lower == "go.mod":
		return scanGoMod(path, content)
	case lower == "cargo.toml":
		return scanCargoToml(path, content)
	}
	return nil
}

func scanNpmPackage(path, content string, isLock bool) []PackageEntry {
	if !isLock {
		for i, l := range strings.Split(content, "\n") {
			if m := npmTokenRe.FindStringSubmatch(l); len(m) >= 2 {
				return []PackageEntry{{Name: ".npmrc", Source: "package.json", Line: i + 1, Secret: m[1]}}
			}
		}
	}
	var deps []PackageEntry
	for i, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "\"*\"") || strings.Contains(trimmed, "latest") {
			deps = append(deps, PackageEntry{Name: trimmed, Source: path, Line: i + 1, Mutable: true})
		}
	}
	return deps
}

func scanRequirementsTxt(path, content string) []PackageEntry {
	var deps []PackageEntry
	for i, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "-") {
			continue
		}
		if strings.Contains(trimmed, "git+") || strings.Contains(trimmed, "@") {
			deps = append(deps, PackageEntry{Name: trimmed, Source: "requirements.txt", Line: i + 1, Mutable: strings.Contains(trimmed, ">=")})
		}
	}
	return deps
}

func scanYarnLock(path, content string) []PackageEntry {
	var deps []PackageEntry
	for i, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(line, "  resolved \"") && (strings.Contains(line, "http://") || strings.Contains(line, "https://")) {
			deps = append(deps, PackageEntry{Name: strings.TrimSpace(line), Source: "yarn.lock", Line: i + 1})
		}
	}
	return deps
}

func scanGoMod(path, content string) []PackageEntry {
	var deps []PackageEntry
	for i, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			continue
		}
		if strings.HasSuffix(trimmed, "// indirect") {
			deps = append(deps, PackageEntry{Name: trimmed, Source: "go.mod", Line: i + 1})
		}
	}
	return deps
}

func scanCargoToml(path, content string) []PackageEntry {
	var deps []PackageEntry
	inDeps := false
	for i, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "[dependencies]" {
			inDeps = true
			continue
		}
		if inDeps && strings.HasPrefix(trimmed, "[") {
			inDeps = false
		}
		if inDeps && strings.Contains(trimmed, "=") && !strings.Contains(trimmed, "path") {
			if strings.Contains(trimmed, "\"*\"") || strings.Contains(trimmed, "git =") || strings.Contains(trimmed, "git+") {
				deps = append(deps, PackageEntry{Name: trimmed, Source: "Cargo.toml", Line: i + 1, Mutable: true})
			}
		}
	}
	return deps
}
