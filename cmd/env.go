package cmd

import (
	"fmt"
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
		if f.Changed {
			return // explicit CLI flag wins over env
		}
		envKey := prefix + strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))
		if val, ok := os.LookupEnv(envKey); ok && val != "" {
			if err := cmd.Flags().Set(f.Name, val); err != nil {
				fmt.Fprintf(os.Stderr, "WARNING: invalid value %q for %s (flag --%s): %v\n", val, envKey, f.Name, err)
			}
		}
	})
}
