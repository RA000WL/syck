package progress

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/RA000WL/syck/internal/finding"
)

// BannerConfig holds scan configuration for the startup banner.
type BannerConfig struct {
	Target       string
	Scope        string
	Workers      int
	RateLimit    int
	CrawlLimit   int
	CrawlDepth   int
	Timeout      string
	UserAgent    string
	Headless     bool
	ExtractLinks bool
	Endpoints    bool
	Proxy        string
}

// PrintBanner displays a feroxbuster-style startup banner.
func PrintBanner(w io.Writer, cfg BannerConfig) {
	target := cfg.Target
	if len(target) > 50 {
		target = target[:47] + "..."
	}
	scope := cfg.Scope
	if scope == "" {
		scope = "(auto)"
	}

	threads := fmt.Sprintf("%d", cfg.Workers)
	if cfg.RateLimit > 0 {
		threads = fmt.Sprintf("%d (rate-limited: %d req/s)", cfg.Workers, cfg.RateLimit)
	}

	lines := []struct{ label, value string }{
		{"🎯  Target Url", target},
		{"🚩  In-Scope Url", scope},
		{"🚀  Threads", threads},
		{"📖  Crawl Limit", fmt.Sprintf("%d URLs", cfg.CrawlLimit)},
		{"🔀  Recursion Depth", fmt.Sprintf("%d", cfg.CrawlDepth)},
		{"💥  Timeout", cfg.Timeout},
		{"🦡  User-Agent", cfg.UserAgent},
		{"🔗  Extract Links", boolStr(cfg.ExtractLinks)},
		{"🔍  Endpoints", boolStr(cfg.Endpoints)},
	}

	if cfg.Headless {
		lines = append(lines, struct{ label, value string }{"🖥️  Headless Chrome", "enabled"})
	}
	if cfg.Proxy != "" {
		lines = append(lines, struct{ label, value string }{"🔀  Proxy", cfg.Proxy})
	}

	maxLabel := 0
	for _, l := range lines {
		if len(l.label) > maxLabel {
			maxLabel = len(l.label)
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "───────────────────────────┬──────────────────────")
	for _, l := range lines {
		fmt.Fprintf(w, " %-*s │ %s\n", maxLabel, l.label, l.value)
	}
	fmt.Fprintln(w, "───────────────────────────┴──────────────────────")
	fmt.Fprintln(w)
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// URLProgress holds real-time scan state for URL scanning mode.
type URLProgress struct {
	mu          sync.Mutex
	w           io.Writer
	start       time.Time
	urlsScanned atomic.Int64
	totalURLs   int
	currentURL  string
	findings    atomic.Int64
	severity    [5]atomic.Int64 // INFO=0, LOW=1, MEDIUM=2, HIGH=3, CRITICAL=4
	lastPrint   time.Time
}

// NewURLProgress creates a feroxbuster-style progress display.
func NewURLProgress(w io.Writer, totalURLs int) *URLProgress {
	return &URLProgress{
		w:         w,
		start:     time.Now(),
		totalURLs: totalURLs,
	}
}

// SetCurrentURL updates the URL currently being processed.
func (p *URLProgress) SetCurrentURL(url string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	// Truncate long URLs for display
	if len(url) > 80 {
		p.currentURL = url[:77] + "..."
	} else {
		p.currentURL = url
	}
}

// AddFindings records findings with severity breakdown.
func (p *URLProgress) AddFindings(findings []finding.Finding) {
	p.findings.Add(int64(len(findings)))
	for _, f := range findings {
		switch f.Severity {
		case finding.SeverityCritical:
			p.severity[4].Add(1)
		case finding.SeverityHigh:
			p.severity[3].Add(1)
		case finding.SeverityMedium:
			p.severity[2].Add(1)
		case finding.SeverityLow:
			p.severity[1].Add(1)
		default:
			p.severity[0].Add(1)
		}
	}
}

// TickURL increments the scanned URL count and refreshes the display.
func (p *URLProgress) TickURL() {
	p.urlsScanned.Add(1)
	p.printStatus()
}

// printStatus renders the feroxbuster-style status line.
func (p *URLProgress) printStatus() {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	// Rate-limit output to every 200ms to avoid flicker
	if now.Sub(p.lastPrint) < 200*time.Millisecond {
		return
	}
	p.lastPrint = now

	scanned := p.urlsScanned.Load()
	elapsed := time.Since(p.start)
	rate := float64(0)
	if elapsed.Seconds() > 0 {
		rate = float64(scanned) / elapsed.Seconds()
	}

	crit := p.severity[4].Load()
	high := p.severity[3].Load()
	med := p.severity[2].Load()
	low := p.severity[1].Load()
	info := p.severity[0].Load()

	// Build severity breakdown string
	var sevParts []string
	if crit > 0 {
		sevParts = append(sevParts, fmt.Sprintf("\033[31m%d CRIT\033[0m", crit))
	}
	if high > 0 {
		sevParts = append(sevParts, fmt.Sprintf("\033[33m%d HIGH\033[0m", high))
	}
	if med > 0 {
		sevParts = append(sevParts, fmt.Sprintf("\033[36m%d MED\033[0m", med))
	}
	if low > 0 {
		sevParts = append(sevParts, fmt.Sprintf("\033[32m%d LOW\033[0m", low))
	}
	if info > 0 {
		sevParts = append(sevParts, fmt.Sprintf("%d INFO", info))
	}
	sevStr := strings.Join(sevParts, " | ")
	if sevStr == "" {
		sevStr = "0 findings"
	}

	// Progress bar
	barWidth := 30
	filled := 0
	pct := 0.0
	if p.totalURLs > 0 {
		filled = int(float64(barWidth) * float64(scanned) / float64(p.totalURLs))
		if filled > barWidth {
			filled = barWidth
		}
		pct = float64(scanned) / float64(p.totalURLs) * 100
		if pct > 100 {
			pct = 100
		}
	}

	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)

	// Current URL line
	urlLine := p.currentURL
	if urlLine == "" {
		urlLine = "(starting...)"
	}

	// Build output
	fmt.Fprintf(p.w, "\r\033[2K") // clear line
	fmt.Fprintf(p.w, "  \033[1m%s\033[0m\n", urlLine)
	if p.totalURLs > 0 {
		fmt.Fprintf(p.w, "  %s %.0f%% | %d/%d URLs | %.1f req/s | %s | elapsed %s\n",
			bar, pct, scanned, p.totalURLs, rate, sevStr,
			elapsed.Round(time.Second))
	} else {
		fmt.Fprintf(p.w, "  %s | %d URLs scanned | %.1f req/s | %s | elapsed %s\n",
			bar, scanned, rate, sevStr,
			elapsed.Round(time.Second))
	}
}

// Finish prints the final summary line.
func (p *URLProgress) Finish() {
	p.mu.Lock()
	defer p.mu.Unlock()

	scanned := p.urlsScanned.Load()
	total := p.findings.Load()
	elapsed := time.Since(p.start)

	crit := p.severity[4].Load()
	high := p.severity[3].Load()
	med := p.severity[2].Load()
	low := p.severity[1].Load()
	info := p.severity[0].Load()

	fmt.Fprintf(p.w, "\r\033[2K") // clear line
	fmt.Fprintf(p.w, "  \033[1mScan complete\033[0m\n")
	fmt.Fprintf(p.w, "  %d URLs scanned in %s | %d findings (%d crit, %d high, %d med, %d low, %d info)\n",
		scanned, elapsed.Round(time.Second), total, crit, high, med, low, info)
}
