package main

import "github.com/RA000WL/syck/cmd"

var (
	version = "1.1.0"
	commit  = "none"
	date    = "unknown"
)

func main() {
	cmd.SetVersionInfo(version, commit, date)
	cmd.Execute()
}
