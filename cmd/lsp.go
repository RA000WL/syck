package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/RA000WL/syck/internal/lsp"
)

var lspCmd = &cobra.Command{
	Use:   "lsp",
	Short: "Start the LSP server for IDE integration",
	Long: `Start a Language Server Protocol (LSP) server that provides
real-time secret scanning diagnostics in supported IDEs.

Supported editors: VS Code (via syck-lsp extension), Neovim, Helix,
and any editor with LSP client support.

The server reads LSP messages from stdin and writes to stdout.
It scans files on open, change, and save, publishing findings
as diagnostics with severity mapped from SYCK's severity levels.

Usage with VS Code settings.json:
  {
    "syck-lsp.command": "syck",
    "syck-lsp.args": ["lsp"]
  }

Usage with Neovim (nvim-lspconfig):
  vim.lsp.start({
    name = "syck",
    cmd = {"syck", "lsp"},
    root_dir = vim.fs.dirname(vim.fs.find({".git"}, { upward = true })[1]),
  })`,
	RunE: func(cmd *cobra.Command, args []string) error {
		server := lsp.NewServer()
		fmt.Fprintln(cmd.ErrOrStderr(), "syck-lsp: starting language server...")
		return server.Run()
	},
}

func init() {
	rootCmd.AddCommand(lspCmd)
}
