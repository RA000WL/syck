package crawler

import (
	"fmt"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
)

// HeadlessBrowser wraps a go-rod browser instance for SPA crawling.
type HeadlessBrowser struct {
	browser  *rod.Browser
	launcher *launcher.Launcher
}

// NewHeadlessBrowser launches a headless Chrome instance.
func NewHeadlessBrowser() (*HeadlessBrowser, error) {
	l := launcher.New().
		Headless(true).
		Set("disable-gpu").
		Set("no-sandbox")

	url, err := l.Launch()
	if err != nil {
		return nil, fmt.Errorf("launch chrome: %w", err)
	}

	browser := rod.New().ControlURL(url)
	if err := browser.Connect(); err != nil {
		l.Kill()
		return nil, fmt.Errorf("connect to chrome: %w", err)
	}

	return &HeadlessBrowser{
		browser:  browser,
		launcher: l,
	}, nil
}

// FetchPage navigates to a URL with the headless browser, waits for JS to
// render, and returns the page content.
func (h *HeadlessBrowser) FetchPage(rawURL string, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}

	page, err := h.browser.Page(proto.TargetCreateTarget{URL: rawURL})
	if err != nil {
		return "", fmt.Errorf("create page: %w", err)
	}
	defer page.Close()

	// Wait for the page to be stable (no network activity for 1s or timeout)
	_ = page.WaitLoad()
	time.Sleep(2 * time.Second)

	content, err := page.Eval(`() => document.documentElement.outerHTML`)
	if err != nil {
		return "", fmt.Errorf("eval html: %w", err)
	}

	return content.Value.String(), nil
}

// Close shuts down the headless browser.
func (h *HeadlessBrowser) Close() {
	if h.browser != nil {
		h.browser.Close()
	}
	if h.launcher != nil {
		h.launcher.Kill()
	}
}
