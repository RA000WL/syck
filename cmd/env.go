package cmd

import (
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func bindEnvToFlags(cmd *cobra.Command) {
	if cmd == nil {
		return
	}
	prefix := "SYCK_" + strings.ToUpper(strings.ReplaceAll(cmd.Name(), "-", "_")) + "_"
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		envKey := prefix + strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))
		if val, ok := os.LookupEnv(envKey); ok && val != "" {
			_ = cmd.Flags().Set(f.Name, val)
		}
	})
}
