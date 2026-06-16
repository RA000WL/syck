// Package externaltools provides integration with external security tools.
package externaltools

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"sync"
)

// ToolType represents the type of external tool
type ToolType string

const (
	ToolSubfinder ToolType = "subfinder"
	ToolAmass     ToolType = "amass"
	ToolHttpx     ToolType = "httpx"
	ToolNuclei    ToolType = "nuclei"
	ToolKatana    ToolType = "katana"
)

// ToolConfig holds configuration for external tool execution
type ToolConfig struct {
	Timeout     int    // timeout in seconds
	MaxResults  int    // max results to return
	ExtraArgs   string // additional arguments
	Wordlist    string // custom wordlist path
}

// ToolResult holds results from an external tool
type ToolResult struct {
	Tool      ToolType
	Output    []string
	RawOutput string
	Error     error
}

// ExternalTool interface for external tool integration
type ExternalTool interface {
	Name() ToolType
	IsInstalled() bool
	Run(target string, config ToolConfig) (*ToolResult, error)
	ParseOutput(output string) []string
}

// SubfinderTool implements subfinder integration
type SubfinderTool struct{}

func (t *SubfinderTool) Name() ToolType { return ToolSubfinder }

func (t *SubfinderTool) IsInstalled() bool {
	_, err := exec.LookPath("subfinder")
	return err == nil
}

func (t *SubfinderTool) Run(domain string, config ToolConfig) (*ToolResult, error) {
	if !t.IsInstalled() {
		return nil, fmt.Errorf("subfinder not installed")
	}

	args := []string{
		"-d", domain,
		"-silent",
		"-timeout", fmt.Sprintf("%d", config.Timeout),
	}

	if config.ExtraArgs != "" {
		args = append(args, strings.Fields(config.ExtraArgs)...)
	}

	cmd := exec.Command("subfinder", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return &ToolResult{
			Tool:      ToolSubfinder,
			Error:     fmt.Errorf("subfinder error: %w (stderr: %s)", err, stderr.String()),
			RawOutput: stderr.String(),
		}, err
	}

	output := t.ParseOutput(stdout.String())
	if config.MaxResults > 0 && len(output) > config.MaxResults {
		output = output[:config.MaxResults]
	}

	return &ToolResult{
		Tool:      ToolSubfinder,
		Output:    output,
		RawOutput: stdout.String(),
	}, nil
}

func (t *SubfinderTool) ParseOutput(output string) []string {
	var results []string
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || seen[line] {
			continue
		}
		seen[line] = true
		results = append(results, line)
	}
	return results
}

// AmassTool implements amass integration
type AmassTool struct{}

func (t *AmassTool) Name() ToolType { return ToolAmass }

func (t *AmassTool) IsInstalled() bool {
	_, err := exec.LookPath("amass")
	return err == nil
}

func (t *AmassTool) Run(domain string, config ToolConfig) (*ToolResult, error) {
	if !t.IsInstalled() {
		return nil, fmt.Errorf("amass not installed")
	}

	args := []string{
		"enum",
		"-passive",
		"-d", domain,
		"-timeout", fmt.Sprintf("%d", config.Timeout),
	}

	if config.ExtraArgs != "" {
		args = append(args, strings.Fields(config.ExtraArgs)...)
	}

	cmd := exec.Command("amass", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return &ToolResult{
			Tool:      ToolAmass,
			Error:     fmt.Errorf("amass error: %w (stderr: %s)", err, stderr.String()),
			RawOutput: stderr.String(),
		}, err
	}

	output := t.ParseOutput(stdout.String())
	if config.MaxResults > 0 && len(output) > config.MaxResults {
		output = output[:config.MaxResults]
	}

	return &ToolResult{
		Tool:      ToolAmass,
		Output:    output,
		RawOutput: stdout.String(),
	}, nil
}

func (t *AmassTool) ParseOutput(output string) []string {
	var results []string
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || seen[line] {
			continue
		}
		seen[line] = true
		results = append(results, line)
	}
	return results
}

// HttpxTool implements httpx integration
type HttpxTool struct{}

func (t *HttpxTool) Name() ToolType { return ToolHttpx }

func (t *HttpxTool) IsInstalled() bool {
	_, err := exec.LookPath("httpx")
	return err == nil
}

func (t *HttpxTool) Run(target string, config ToolConfig) (*ToolResult, error) {
	if !t.IsInstalled() {
		return nil, fmt.Errorf("httpx not installed")
	}

	args := []string{
		"-silent",
		"-status-code",
		"-title",
		"-tech-detect",
		"-follow-redirects",
		"-timeout", fmt.Sprintf("%d", config.Timeout),
	}

	if config.ExtraArgs != "" {
		args = append(args, strings.Fields(config.ExtraArgs)...)
	}

	// Pass target via stdin
	cmd := exec.Command("httpx", args...)
	cmd.Stdin = strings.NewReader(target)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return &ToolResult{
			Tool:      ToolHttpx,
			Error:     fmt.Errorf("httpx error: %w (stderr: %s)", err, stderr.String()),
			RawOutput: stderr.String(),
		}, err
	}

	output := t.ParseOutput(stdout.String())
	if config.MaxResults > 0 && len(output) > config.MaxResults {
		output = output[:config.MaxResults]
	}

	return &ToolResult{
		Tool:      ToolHttpx,
		Output:    output,
		RawOutput: stdout.String(),
	}, nil
}

func (t *HttpxTool) ParseOutput(output string) []string {
	var results []string
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || seen[line] {
			continue
		}
		seen[line] = true
		results = append(results, line)
	}
	return results
}

// KatanaTool implements katana (web crawler) integration
type KatanaTool struct{}

func (t *KatanaTool) Name() ToolType { return ToolKatana }

func (t *KatanaTool) IsInstalled() bool {
	_, err := exec.LookPath("katana")
	return err == nil
}

func (t *KatanaTool) Run(target string, config ToolConfig) (*ToolResult, error) {
	if !t.IsInstalled() {
		return nil, fmt.Errorf("katana not installed")
	}

	args := []string{
		"-u", target,
		"-silent",
		"-d", "3",
		"-timeout", fmt.Sprintf("%d", config.Timeout),
	}

	if config.ExtraArgs != "" {
		args = append(args, strings.Fields(config.ExtraArgs)...)
	}

	cmd := exec.Command("katana", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return &ToolResult{
			Tool:      ToolKatana,
			Error:     fmt.Errorf("katana error: %w (stderr: %s)", err, stderr.String()),
			RawOutput: stderr.String(),
		}, err
	}

	output := t.ParseOutput(stdout.String())
	if config.MaxResults > 0 && len(output) > config.MaxResults {
		output = output[:config.MaxResults]
	}

	return &ToolResult{
		Tool:      ToolKatana,
		Output:    output,
		RawOutput: stdout.String(),
	}, nil
}

func (t *KatanaTool) ParseOutput(output string) []string {
	var results []string
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || seen[line] {
			continue
		}
		seen[line] = true
		results = append(results, line)
	}
	return results
}

// RunSubfinder runs subfinder and returns discovered subdomains
func RunSubfinder(domain string, config ToolConfig) ([]string, error) {
	tool := &SubfinderTool{}
	result, err := tool.Run(domain, config)
	if err != nil {
		return nil, err
	}
	return result.Output, nil
}

// RunAmass runs amass and returns discovered subdomains
func RunAmass(domain string, config ToolConfig) ([]string, error) {
	tool := &AmassTool{}
	result, err := tool.Run(domain, config)
	if err != nil {
		return nil, err
	}
	return result.Output, nil
}

// RunHttpx runs httpx and returns live URLs with metadata
func RunHttpx(targets []string, config ToolConfig) ([]string, error) {
	tool := &HttpxTool{}
	input := strings.Join(targets, "\n")
	result, err := tool.Run(input, config)
	if err != nil {
		return nil, err
	}
	return result.Output, nil
}

// RunKatana runs katana crawler and returns discovered URLs
func RunKatana(target string, config ToolConfig) ([]string, error) {
	tool := &KatanaTool{}
	result, err := tool.Run(target, config)
	if err != nil {
		return nil, err
	}
	return result.Output, nil
}

// RunParallel runs multiple tools in parallel and combines results
func RunParallel(domain string, tools []ToolType, config ToolConfig) map[ToolType][]string {
	results := make(map[ToolType][]string)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, toolType := range tools {
		wg.Add(1)
		go func(tt ToolType) {
			defer wg.Done()

			var output []string
			var err error

			switch tt {
			case ToolSubfinder:
				output, err = RunSubfinder(domain, config)
			case ToolAmass:
				output, err = RunAmass(domain, config)
			}

			if err == nil && len(output) > 0 {
				mu.Lock()
				results[tt] = output
				mu.Unlock()
			}
		}(toolType)
	}

	wg.Wait()
	return results
}

// GetAvailableTools returns which tools are installed
func GetAvailableTools() []ToolType {
	var available []ToolType

	tools := []ExternalTool{
		&SubfinderTool{},
		&AmassTool{},
		&HttpxTool{},
		&KatanaTool{},
	}

	for _, tool := range tools {
		if tool.IsInstalled() {
			available = append(available, tool.Name())
		}
	}

	return available
}

// CheckToolInstallation checks if a specific tool is installed
func CheckToolInstallation(tool ToolType) bool {
	switch tool {
	case ToolSubfinder:
		return (&SubfinderTool{}).IsInstalled()
	case ToolAmass:
		return (&AmassTool{}).IsInstalled()
	case ToolHttpx:
		return (&HttpxTool{}).IsInstalled()
	case ToolKatana:
		return (&KatanaTool{}).IsInstalled()
	default:
		return false
	}
}
