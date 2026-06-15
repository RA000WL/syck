package scanner

import (
	"path/filepath"
	"strings"

	"github.com/RA000WL/syck/internal/finding"
)

func DetectSourceTech(content, path string) []finding.Finding {
	fileName := filepath.Base(path)
	ext := strings.ToLower(filepath.Ext(path))
	baseName := strings.ToLower(fileName)

	detected := make(map[string]bool)
	var results []finding.Finding

	addFinding := func(tech, category string, severity finding.Severity) {
		if detected[tech] {
			return
		}
		detected[tech] = true
		results = append(results, finding.Finding{
			File:           path,
			Line:           1,
			RuleName:       "tech_source_" + tech,
			Severity:       severity,
			ConfidenceBand: "HIGH",
			Context:        category + ": " + tech,
			Secret:         tech,
		})
	}

	// --- Package manifest detection ---
	lower := strings.ToLower(content)

	switch {
	case baseName == "package.json":
		for _, r := range packageManifestRules {
			if strings.Contains(lower, r.Pattern) {
				addFinding(r.Technology, r.Category, r.Severity)
			}
		}

	case baseName == "composer.json":
		for _, r := range phpManifestRules {
			if strings.Contains(lower, r.Pattern) {
				addFinding(r.Technology, r.Category, r.Severity)
			}
		}

	case baseName == "gemfile":
		for _, r := range rubyManifestRules {
			if strings.Contains(lower, r.Pattern) {
				addFinding(r.Technology, r.Category, r.Severity)
			}
		}

	case baseName == "requirements.txt":
		for _, r := range pythonManifestRules {
			if strings.Contains(lower, r.Pattern) {
				addFinding(r.Technology, r.Category, r.Severity)
			}
		}

	case baseName == "go.mod":
		for _, r := range goManifestRules {
			if strings.Contains(lower, r.Pattern) {
				addFinding(r.Technology, r.Category, r.Severity)
			}
		}

	case baseName == "cargo.toml":
		for _, r := range rustManifestRules {
			if strings.Contains(lower, r.Pattern) {
				addFinding(r.Technology, r.Category, r.Severity)
			}
		}

	case baseName == "pom.xml":
		if strings.Contains(lower, "spring-boot") {
			addFinding("spring_boot", "framework", finding.SeverityMedium)
		}

	case baseName == "build.gradle":
		if strings.Contains(lower, "spring-boot") {
			addFinding("spring_boot", "framework", finding.SeverityMedium)
		}
	}

	// --- Config file detection ---
	configBase := strings.ToLower(fileName)

	switch {
	case configBase == "next.config.js" || configBase == "next.config.mjs" || configBase == "next.config.ts":
		addFinding("nextjs", "framework", finding.SeverityMedium)

	case configBase == "nuxt.config.js" || configBase == "nuxt.config.ts":
		addFinding("nuxtjs", "framework", finding.SeverityMedium)

	case configBase == "gatsby-config.js":
		addFinding("gatsby", "framework", finding.SeverityMedium)

	case configBase == "wp-config.php":
		addFinding("wordpress", "cms", finding.SeverityHigh)

	case configBase == "settings.py" && (strings.Contains(lower, "installed_apps") || strings.Contains(lower, "django.conf.settings")):
		addFinding("django", "framework", finding.SeverityMedium)
	}

	// --- Import pattern detection (JS/TS files only) ---
	switch ext {
	case ".js", ".ts", ".jsx", ".tsx", ".vue", ".mjs":
		for _, r := range importPatternRules {
			if strings.Contains(content, r.Pattern) {
				addFinding(r.Technology, r.Category, r.Severity)
			}
		}
	}

	return results
}

type manifestRule struct {
	Pattern    string
	Technology string
	Category   string
	Severity   finding.Severity
}

var packageManifestRules = []manifestRule{
	{`"next":`, "nextjs", "framework", finding.SeverityMedium},
	{`"nuxt":`, "nuxtjs", "framework", finding.SeverityMedium},
	{`"gatsby":`, "gatsby", "framework", finding.SeverityMedium},
	{`"express":`, "express", "framework", finding.SeverityMedium},
	{`"react":`, "react", "library", finding.SeverityLow},
	{`"vue":`, "vue", "library", finding.SeverityLow},
	{`"@angular/core":`, "angular", "library", finding.SeverityLow},
}

var pythonManifestRules = []manifestRule{
	{`django`, "django", "framework", finding.SeverityMedium},
	{`flask`, "flask", "framework", finding.SeverityMedium},
}

var goManifestRules = []manifestRule{
	{`gin-gonic/gin`, "gin", "framework", finding.SeverityMedium},
	{`gorilla/mux`, "gorilla", "framework", finding.SeverityMedium},
}

var phpManifestRules = []manifestRule{
	{`"laravel/framework":`, "laravel", "framework", finding.SeverityMedium},
}

var rubyManifestRules = []manifestRule{
	{"gem 'rails'", "rails", "framework", finding.SeverityMedium},
	{`gem "rails"`, "rails", "framework", finding.SeverityMedium},
}

var rustManifestRules = []manifestRule{
	{`actix-web`, "actix", "framework", finding.SeverityMedium},
	{`axum`, "axum", "framework", finding.SeverityMedium},
}

type importPattern struct {
	Pattern    string
	Technology string
	Category   string
	Severity   finding.Severity
}

var importPatternRules = []importPattern{
	{`from 'react'`, "react", "library", finding.SeverityLow},
	{`require('react')`, "react", "library", finding.SeverityLow},
	{`from 'vue'`, "vue", "library", finding.SeverityLow},
	{`from '@angular'`, "angular", "library", finding.SeverityLow},
	{`@Component`, "angular", "library", finding.SeverityLow},
	{`from 'express'`, "express", "framework", finding.SeverityMedium},
	{`from 'next/`, "nextjs", "framework", finding.SeverityMedium},
	{`import flask`, "flask", "framework", finding.SeverityMedium},
	{`from django`, "django", "framework", finding.SeverityMedium},
}
