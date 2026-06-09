package formatters

import (
	"encoding/json"
	"strings"

	"github.com/RA000WL/syck/internal/finding"
)

type SARIFFormatter struct{}

var sevToSARIFLevel = map[finding.Severity]string{
	finding.SeverityCritical: "error",
	finding.SeverityHigh:     "error",
	finding.SeverityMedium:   "warning",
	finding.SeverityLow:      "note",
	finding.SeverityInfo:     "note",
}

type sarifOutput struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string         `json:"id"`
	Name                 string         `json:"name"`
	ShortDescription     sarifTextBlock `json:"shortDescription"`
	DefaultConfiguration sarifConfig    `json:"defaultConfiguration"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifTextBlock struct {
	Text string `json:"text"`
}

type sarifProperties struct {
	Confidence         string `json:"confidence"`
	VerificationStatus string `json:"verificationStatus"`
	RiskScore          int    `json:"riskScore,omitempty"`
}

type sarifResult struct {
	RuleID     string          `json:"ruleId"`
	RuleIndex  int             `json:"ruleIndex"`
	Level      string          `json:"level"`
	Message    sarifTextBlock  `json:"message"`
	Locations  []sarifLocation `json:"locations"`
	Properties sarifProperties `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int           `json:"startLine"`
	EndLine     int           `json:"endLine"`
	StartColumn int           `json:"startColumn,omitempty"`
	Snippet     *sarifSnippet `json:"snippet,omitempty"`
}

type sarifSnippet struct {
	Text string `json:"text"`
}

func versionOrDefault(v string) string {
	if v == "" {
		return "dev"
	}
	return v
}

func (f *SARIFFormatter) Format(findings []finding.Finding, opts FormatOptions) (string, error) {
	rulesIndex := make(map[string]int)
	var rulesList []sarifRule
	for _, finding := range findings {
		if _, exists := rulesIndex[finding.RuleName]; !exists {
			rulesIndex[finding.RuleName] = len(rulesList)
			level := sevToSARIFLevel[finding.Severity]
			if level == "" {
				level = "warning"
			}
			rulesList = append(rulesList, sarifRule{
				ID:   finding.RuleName,
				Name: finding.RuleName,
				ShortDescription: sarifTextBlock{
					Text: "Detects " + finding.RuleName + ".",
				},
				DefaultConfiguration: sarifConfig{Level: level},
			})
		}
	}

	var results []sarifResult
	for _, f := range findings {
		secret := f.Secret
		if opts.Redact {
			secret = RedactSecret(f.Secret)
		}

		level := sevToSARIFLevel[f.Severity]
		if level == "" {
			level = "warning"
		}

		region := sarifRegion{
			StartLine: f.Line,
			EndLine:   f.Line,
		}
		if f.Column > 0 {
			region.StartColumn = f.Column
		}
		ctx := f.Context
		if opts.Redact {
			ctx = strings.ReplaceAll(ctx, f.Secret, secret)
		}
		if len(ctx) > 200 {
			ctx = ctx[:200]
		}
		if ctx != "" {
			region.Snippet = &sarifSnippet{Text: ctx}
		}

		results = append(results, sarifResult{
			RuleID:    f.RuleName,
			RuleIndex: rulesIndex[f.RuleName],
			Level:     level,
			Message:   sarifTextBlock{Text: "Potential " + f.RuleName + " exposed."},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: f.File},
					Region:           region,
				},
			}},
			Properties: sarifProperties{
				Confidence:         f.Confidence,
				VerificationStatus: f.VerificationStatus,
				RiskScore:          f.RiskScore,
			},
		})
	}

	sarif := sarifOutput{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Documents/2.1.0/sarif-2-1.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:           "syck",
					Version:        versionOrDefault(opts.Version),
					InformationURI: "https://github.com/RA000WL/syck",
					Rules:          rulesList,
				},
			},
			Results: results,
		}},
	}

	data, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}
