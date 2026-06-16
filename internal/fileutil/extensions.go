package fileutil

// TextExtensions is the set of file extensions considered text files for scanning.
var TextExtensions = map[string]bool{
	".txt": true, ".go": true, ".py": true, ".js": true, ".ts": true,
	".jsx": true, ".tsx": true, ".json": true, ".yaml": true, ".yml": true,
	".toml": true, ".ini": true, ".cfg": true, ".conf": true, ".env": true,
	".sh": true, ".bash": true, ".zsh": true, ".fish": true, ".bat": true,
	".ps1": true, ".rb": true, ".rs": true, ".java": true, ".kt": true,
	".swift": true, ".c": true, ".cpp": true, ".h": true, ".hpp": true,
	".cs": true, ".php": true, ".pl": true, ".pm": true, ".lua": true,
	".r": true, ".scala": true, ".clj": true, ".hs": true, ".erl": true,
	".ex": true, ".exs": true, ".md": true, ".rst": true, ".html": true,
	".htm": true, ".xml": true, ".svg": true, ".css": true, ".scss": true,
	".less": true, ".sql": true, ".graphql": true, ".gql": true,
	".dockerfile": true, ".makefile": true, ".gradle": true,
	".tf": true, ".tfvars": true, ".hcl": true, ".properties": true,
	".lock": true, ".log": true, ".csv": true, ".tsv": true,
	".pem": true, ".key": true, ".cert": true, ".crt": true,
	".pgp": true, ".gpg": true, ".asc": true,
}

// IsTextExt returns true if the extension is in the text extensions set.
func IsTextExt(ext string) bool {
	return TextExtensions[ext]
}
