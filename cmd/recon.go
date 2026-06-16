package cmd

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/RA000WL/syck/internal/discovery"
	"github.com/RA000WL/syck/internal/httpclient"
	"github.com/spf13/cobra"
)

var (
	reconDomain       string
	reconOutput       string
	reconResolve      bool
	reconLiveCheck    bool
	reconWayback      bool
	reconWaybackLim   int
	reconScope        string
	reconTimeout      string
	reconProxy        string
	reconSubfinderFile string
)

var reconCmd = &cobra.Command{
	Use:   "recon <domain>",
	Short: "Reconnaissance — discover subdomains, historical URLs, and live hosts",
	Long: `Perform bug bounty reconnaissance on a target domain.

Discovers subdomains via certificate transparency (crt.sh),
fetches historical URLs from the Wayback Machine, and checks
which hosts are live.

Examples:
  syck recon example.com
  syck recon example.com --wayback --live-check
  syck recon example.com --resolve --output hosts.txt
  syck recon example.com --scope "\\.example\\.com$"`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runRecon(args[0])
	},
}

func init() {
	reconCmd.Flags().StringVarP(&reconOutput, "output", "o", "", "write output to file")
	reconCmd.Flags().BoolVar(&reconResolve, "resolve", false, "DNS-resolve discovered subdomains")
	reconCmd.Flags().BoolVar(&reconLiveCheck, "live-check", false, "HTTP check which hosts are alive")
	reconCmd.Flags().BoolVar(&reconWayback, "wayback", false, "fetch historical URLs from Wayback Machine")
	reconCmd.Flags().IntVar(&reconWaybackLim, "wayback-limit", 500, "max Wayback URLs to fetch")
	reconCmd.Flags().StringVar(&reconScope, "scope", "", "regex to filter results by domain/path")
	reconCmd.Flags().StringVar(&reconTimeout, "timeout", "10s", "HTTP timeout")
	reconCmd.Flags().StringVar(&reconProxy, "proxy", "", "HTTP proxy URL")
	reconCmd.Flags().StringVar(&reconSubfinderFile, "subfinder-file", "", "import subdomains from subfinder/amass output file (one per line)")

	rootCmd.AddCommand(reconCmd)
}

func runRecon(domain string) error {
	timeout, err := time.ParseDuration(reconTimeout)
	if err != nil {
		return fmt.Errorf("invalid timeout: %w", err)
	}
	client := httpclient.NewClient(timeout, reconProxy, false)

	fmt.Fprintf(os.Stderr, "Reconnaissance for %s\n\n", domain)

	var allURLs []string
	var scopeRegex *regexp.Regexp
	if reconScope != "" {
		var err error
		scopeRegex, err = regexp.Compile(reconScope)
		if err != nil {
			return fmt.Errorf("invalid scope regex: %w", err)
		}
	}

	// Phase 1: Subdomain enumeration
	fmt.Fprintf(os.Stderr, "[*] Enumerating subdomains via crt.sh...\n")
	subs, err := discovery.EnumerateSubdomains(domain, client, reconResolve)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  [!] crt.sh error: %v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "  [+] Found %d subdomains\n", len(subs))
		for _, s := range subs {
			url := "https://" + s.Subdomain
			if scopeRegex != nil && !scopeRegex.MatchString(url) {
				continue
			}
			allURLs = append(allURLs, url)
			fmt.Fprintf(os.Stderr, "      %s (%s)\n", s.Subdomain, s.Source)
		}
	}

	// Phase 1b: Import from subfinder/amass output file
	if reconSubfinderFile != "" {
		fmt.Fprintf(os.Stderr, "\n[*] Importing subdomains from %s...\n", reconSubfinderFile)
		imported := importSubdomainsFromFile(reconSubfinderFile, domain)
		fmt.Fprintf(os.Stderr, "  [+] Imported %d subdomains\n", len(imported))
		for _, sub := range imported {
			url := "https://" + sub
			if scopeRegex != nil && !scopeRegex.MatchString(url) {
				continue
			}
			allURLs = append(allURLs, url)
		}
	}

	// Phase 2: Live host check
	if reconLiveCheck && len(allURLs) > 0 {
		fmt.Fprintf(os.Stderr, "\n[*] Checking live hosts...\n")
		hosts := discovery.HostsFromSubdomains(subs)
		hostResults := discovery.CheckLiveHosts(hosts, client, timeout)
		alive := discovery.FilterAliveHosts(hostResults)
		fmt.Fprintf(os.Stderr, "  [+] %d/%d hosts alive\n", len(alive), len(hosts))

		// Rebuild URL list from alive hosts only
		allURLs = nil
		for _, h := range alive {
			url := "https://" + h
			if scopeRegex != nil && !scopeRegex.MatchString(url) {
				continue
			}
			allURLs = append(allURLs, url)
		}
	}

	// Phase 3: Wayback URLs
	if reconWayback {
		fmt.Fprintf(os.Stderr, "\n[*] Fetching Wayback Machine URLs (limit: %d)...\n", reconWaybackLim)
		wayback, err := discovery.FetchWaybackURLs(domain, client, reconWaybackLim)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  [!] Wayback error: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "  [+] Found %d historical URLs\n", len(wayback))
			for _, w := range wayback {
				if scopeRegex != nil && !scopeRegex.MatchString(w.URL) {
					continue
				}
				allURLs = append(allURLs, w.URL)
			}
		}
	}

	// Deduplicate
	seen := make(map[string]bool)
	var unique []string
	for _, u := range allURLs {
		if !seen[u] {
			seen[u] = true
			unique = append(unique, u)
		}
	}

	fmt.Fprintf(os.Stderr, "\n[*] Total unique URLs: %d\n\n", len(unique))

	// Output
	if reconOutput != "" && reconOutput != "o" {
		f, err := os.Create(reconOutput)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer f.Close()
		for _, u := range unique {
			fmt.Fprintln(f, u)
		}
		fmt.Fprintf(os.Stderr, "[+] URLs written to %s\n", reconOutput)
	} else {
		for _, u := range unique {
			fmt.Println(u)
		}
	}

	return nil
}

// importSubdomainsFromFile reads subdomains from a file (one per line).
// Compatible with subfinder, amass, httpx, and similar tool outputs.
func importSubdomainsFromFile(path string, domain string) []string {
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  [!] Error opening file: %v\n", err)
		return nil
	}
	defer f.Close()

	domainLower := strings.ToLower(domain)
	seen := make(map[string]bool)
	var subs []string

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Strip protocol if present
		line = strings.TrimPrefix(line, "https://")
		line = strings.TrimPrefix(line, "http://")
		// Strip path
		if idx := strings.Index(line, "/"); idx > 0 {
			line = line[:idx]
		}
		line = strings.ToLower(line)
		if line == "" {
			continue
		}
		// Must be subdomain of target
		if line != domainLower && !strings.HasSuffix(line, "."+domainLower) {
			continue
		}
		if !seen[line] {
			seen[line] = true
			subs = append(subs, line)
		}
	}

	return subs
}
