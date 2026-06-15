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
	NoColor      bool
}

// ANSI color codes
const (
	colorReset   = "\033[0m"
	colorBold    = "\033[1m"
	colorDim     = "\033[2m"

	// Gradient: green → cyan → blue → purple
	colorGreen   = "\033[38;2;0;255;136m"
	colorCyan    = "\033[38;2;0;220;255m"
	colorBlue    = "\033[38;2;80;120;255m"
	colorPurple  = "\033[38;2;180;80;255m"
	colorTeal    = "\033[38;2;0;230;200m"

	// Value colors (matching screenshot)
	colorValCyan    = "\033[38;2;0;220;255m"
	colorValGreen   = "\033[38;2;80;255;136m"
	colorValRed     = "\033[38;2;255;80;80m"
	colorValYellow  = "\033[38;2;255;200;0m"
	colorValWhite   = "\033[38;2;220;220;220m"

	// Icon colors (matching screenshot)
	colorIconGold    = "\033[38;2;255;200;0m"
	colorIconYellow  = "\033[38;2;255;220;0m"
	colorIconGreen   = "\033[38;2;80;255;136m"
	colorIconCyan    = "\033[38;2;0;220;255m"
	colorIconPink    = "\033[38;2;255;80;180m"
	colorIconRed     = "\033[38;2;255;80;80m"
	colorIconPurple  = "\033[38;2;180;120;255m"
	colorIconOrange  = "\033[38;2;255;160;0m"
)

// PrintBanner displays a feroxbuster-style startup banner with block font and color accents.
func PrintBanner(w io.Writer, cfg BannerConfig) {
	c := func(code string) string {
		if cfg.NoColor {
			return ""
		}
		return code
	}

	target := cfg.Target
	if len(target) > 48 {
		target = target[:45] + "..."
	}

	ua := cfg.UserAgent
	if ua == "" {
		ua = "syck/1.0"
	}

	// Block font ASCII art for "SYCK"
	ascii := []string{
		" ███████╗██╗   ██╗ ██████╗██╗  ██╗",
		" ██╔════╝╚██╗ ██╔╝██╔════╝██║ ██╔╝",
		" ███████╗ ╚████╔╝ ██║     █████╔╝ ",
		" ╚════██║  ╚██╔╝  ██║     ██╔═██╗ ",
		" ███████║   ██║   ╚██████╗██║  ██╗",
		" ╚══════╝   ╚═╝    ╚═════╝╚═╝  ╚═╝",
	}

	// Print gradient title
	gradientColors := []string{colorTeal, colorTeal, colorCyan, colorCyan, colorBlue, colorPurple}
	fmt.Fprintln(w)
	for i, line := range ascii {
		fmt.Fprintf(w, "%s%s%s\n", c(gradientColors[i]), line, c(colorReset))
	}

	// Subtitle
	fmt.Fprintf(w, "%s%sby RA0WL %s· %ssecret scanner & recon engine %s· %sver 0.4.2%s\n\n",
		c(colorDim), c(colorBold),
		c(colorDim), c(colorDim),
		c(colorDim), c(colorDim), c(colorReset))

	// Separator
	sep := strings.Repeat("─", 38)
	fmt.Fprintf(w, "%s%s%s\n", c(colorDim), sep, c(colorReset))

	// Fields: icon (colored) | label (bold white) | value (colored)
	type row struct {
		icon     string
		iconClr  string
		label    string
		val      string
		valClr   string
	}

	rows := []row{
		{"◈", colorIconGold, "Target Domain", target, colorValCyan},
		{"⚡", colorIconYellow, "Goroutines", fmt.Sprintf("%d", cfg.Workers), colorValGreen},
		{"◎", colorIconGreen, "Patterns", "188 rules", colorValGreen},
		{"◇", colorIconCyan, "User-Agent", ua, colorValGreen},
		{"⊞", colorIconPink, "Config", "~/.config/syck/syck.yaml", colorValWhite},
		{"◉", colorIconRed, "Timeout (secs)", cfg.Timeout, colorValGreen},
		{"⬡", colorIconPurple, "Recursion Depth", fmt.Sprintf("%d", cfg.CrawlDepth), colorValGreen},
		{"↺", colorIconOrange, "Rate Limit", rateLimitStr(cfg.RateLimit), colorValGreen},
		{"▸", colorIconGold, "Endpoints", boolStr(cfg.Endpoints), colorValGreen},
	}

	if cfg.Headless {
		rows = append(rows, row{"⊞", colorIconPink, "Headless Chrome", "enabled", colorValGreen})
	}
	if cfg.Proxy != "" {
		rows = append(rows, row{"◎", colorIconCyan, "Proxy", cfg.Proxy, colorValCyan})
	}

	for _, r := range rows {
		fmt.Fprintf(w, "%s%s%s %s%s%s %s│%s %s%s%s\n",
			c(r.iconClr), r.icon, c(colorReset),
			c(colorBold), r.label, c(colorReset),
			c(colorDim), c(colorReset),
			c(r.valClr), r.val, c(colorReset))
	}

	// Bottom separator
	fmt.Fprintf(w, "%s%s%s\n", c(colorDim), sep, c(colorReset))
	fmt.Fprintf(w, "%s▸ Press [ENTER] to open the Scan Management Menu™%s\n\n", c(colorDim), c(colorReset))
}

func rateLimitStr(rps int) string {
	if rps <= 0 {
		return "unlimited"
	}
	return fmt.Sprintf("%d req/s", rps)
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
