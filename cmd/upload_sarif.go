package cmd

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var (
	uploadSarifFile   string
	uploadSarifRepo   string
	uploadSarifCommit string
	uploadSarifBase   string
)

var uploadSarifCmd = &cobra.Command{
	Use:   "upload-sarif",
	Short: "Upload a SARIF file to GitHub Code Scanning",
	Long: `Upload a SARIF file to GitHub Code Scanning using the REST API.

Requires GITHUB_TOKEN env var with code-scanning:write scope. The --commit
flag should be the SHA being analyzed. Use --base to upload against a
specific ref (default: empty string uses commit ref).

Example:
  syck scan . --format sarif -o results.sarif
  syck upload-sarif --file results.sarif --repo OWNER/REPO --commit $GITHUB_SHA`,
	Args: cobra.NoArgs,
	RunE: runUploadSarif,
}

func init() {
	uploadSarifCmd.Flags().StringVar(&uploadSarifFile, "file", "", "path to SARIF file (required)")
	uploadSarifCmd.Flags().StringVar(&uploadSarifRepo, "repo", "", "OWNER/REPO (required)")
	uploadSarifCmd.Flags().StringVar(&uploadSarifCommit, "commit", "", "commit SHA being analyzed (required)")
	uploadSarifCmd.Flags().StringVar(&uploadSarifBase, "base", "", "ref to upload against (default: commit ref)")

	_ = uploadSarifCmd.MarkFlagRequired("file")
	_ = uploadSarifCmd.MarkFlagRequired("repo")
	_ = uploadSarifCmd.MarkFlagRequired("commit")
}

func runUploadSarif(cmd *cobra.Command, args []string) error {
	bindEnvToFlags(cmd)

	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return fmt.Errorf("GITHUB_TOKEN env var required")
	}
	if !strings.Contains(uploadSarifRepo, "/") {
		return fmt.Errorf("invalid --repo %q: expected OWNER/REPO", uploadSarifRepo)
	}

	sarifBytes, err := os.ReadFile(uploadSarifFile)
	if err != nil {
		return fmt.Errorf("read sarif file: %w", err)
	}
	if !bytes.HasPrefix(bytes.TrimSpace(sarifBytes), []byte("{")) {
		return fmt.Errorf("file does not appear to be valid SARIF JSON")
	}

	url := fmt.Sprintf("https://api.github.com/repos/%s/code-scanning/sarifs", uploadSarifRepo)
	body := fmt.Sprintf(`{"commit_sha":%q,"ref":%q,"sarif":%s}`,
		uploadSarifCommit, uploadSarifBase, string(sarifBytes))

	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "syck-go")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("upload failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("upload failed: HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	fmt.Fprintf(cmd.OutOrStdout(), "SARIF uploaded successfully: %d bytes accepted\n", len(sarifBytes))
	return nil
}
