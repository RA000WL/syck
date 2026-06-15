package scanner

import (
	"testing"

	"github.com/RA000WL/syck/internal/finding"
)

func TestDetectSourceTech_PackageJSON_NextJS(t *testing.T) {
	content := `{"dependencies": {"next": "^14.0.0", "react": "^18.0.0"}}`
	findings := DetectSourceTech(content, "app/package.json")
	assertHasTech(t, findings, "nextjs")
	assertHasTech(t, findings, "react")
}

func TestDetectSourceTech_PackageJSON_Express(t *testing.T) {
	content := `{"dependencies": {"express": "^4.18.0"}}`
	findings := DetectSourceTech(content, "server/package.json")
	assertHasTech(t, findings, "express")
}

func TestDetectSourceTech_PackageJSON_Vue(t *testing.T) {
	content := `{"dependencies": {"vue": "^3.0.0"}}`
	findings := DetectSourceTech(content, "frontend/package.json")
	assertHasTech(t, findings, "vue")
}

func TestDetectSourceTech_PackageJSON_Angular(t *testing.T) {
	content := `{"dependencies": {"@angular/core": "^17.0.0"}}`
	findings := DetectSourceTech(content, "client/package.json")
	assertHasTech(t, findings, "angular")
}

func TestDetectSourceTech_PackageJSON_Nuxt(t *testing.T) {
	content := `{"dependencies": {"nuxt": "^3.0.0"}}`
	findings := DetectSourceTech(content, "web/package.json")
	assertHasTech(t, findings, "nuxtjs")
}

func TestDetectSourceTech_PackageJSON_Gatsby(t *testing.T) {
	content := `{"dependencies": {"gatsby": "^5.0.0"}}`
	findings := DetectSourceTech(content, "site/package.json")
	assertHasTech(t, findings, "gatsby")
}

func TestDetectSourceTech_ComposerJSON_Laravel(t *testing.T) {
	content := `{"require": {"laravel/framework": "^10.0"}}`
	findings := DetectSourceTech(content, "composer.json")
	assertHasTech(t, findings, "laravel")
}

func TestDetectSourceTech_Gemfile_Rails(t *testing.T) {
	content := `gem 'rails', '~> 7.0'`
	findings := DetectSourceTech(content, "Gemfile")
	assertHasTech(t, findings, "rails")
}

func TestDetectSourceTech_Gemfile_RailsDoubleQuote(t *testing.T) {
	content := `gem "rails", "~> 7.0"`
	findings := DetectSourceTech(content, "Gemfile")
	assertHasTech(t, findings, "rails")
}

func TestDetectSourceTech_RequirementsTxt_Django(t *testing.T) {
	content := `Django==4.2\npsycopg2`
	findings := DetectSourceTech(content, "requirements.txt")
	assertHasTech(t, findings, "django")
}

func TestDetectSourceTech_RequirementsTxt_Flask(t *testing.T) {
	content := `Flask==3.0\nWerkzeug`
	findings := DetectSourceTech(content, "requirements.txt")
	assertHasTech(t, findings, "flask")
}

func TestDetectSourceTech_GoMod_Gin(t *testing.T) {
	content := `require github.com/gin-gonic/gin v1.9.1`
	findings := DetectSourceTech(content, "go.mod")
	assertHasTech(t, findings, "gin")
}

func TestDetectSourceTech_GoMod_Gorilla(t *testing.T) {
	content := `require github.com/gorilla/mux v1.8.0`
	findings := DetectSourceTech(content, "go.mod")
	assertHasTech(t, findings, "gorilla")
}

func TestDetectSourceTech_CargoToml_Actix(t *testing.T) {
	content := `[dependencies]\nactix-web = "4"`
	findings := DetectSourceTech(content, "Cargo.toml")
	assertHasTech(t, findings, "actix")
}

func TestDetectSourceTech_CargoToml_Axum(t *testing.T) {
	content := `[dependencies]\naxum = "0.7"`
	findings := DetectSourceTech(content, "Cargo.toml")
	assertHasTech(t, findings, "axum")
}

func TestDetectSourceTech_PomXml_SpringBoot(t *testing.T) {
	content := `<dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot</artifactId></dependency>`
	findings := DetectSourceTech(content, "pom.xml")
	assertHasTech(t, findings, "spring_boot")
}

func TestDetectSourceTech_BuildGradle_SpringBoot(t *testing.T) {
	content := `implementation 'org.springframework.boot:spring-boot:3.2.0'`
	findings := DetectSourceTech(content, "build.gradle")
	assertHasTech(t, findings, "spring_boot")
}

func TestDetectSourceTech_ConfigFile_NextJS(t *testing.T) {
	content := `/** @type {import('next').NextConfig} */`
	findings := DetectSourceTech(content, "next.config.js")
	assertHasTech(t, findings, "nextjs")
}

func TestDetectSourceTech_ConfigFile_NextJSTS(t *testing.T) {
	content := `import type { NextConfig } from 'next'`
	findings := DetectSourceTech(content, "next.config.ts")
	assertHasTech(t, findings, "nextjs")
}

func TestDetectSourceTech_ConfigFile_NuxtJS(t *testing.T) {
	content := `export default defineNuxtConfig({})`
	findings := DetectSourceTech(content, "nuxt.config.js")
	assertHasTech(t, findings, "nuxtjs")
}

func TestDetectSourceTech_ConfigFile_Gatsby(t *testing.T) {
	content := `module.exports = { siteMetadata: {} }`
	findings := DetectSourceTech(content, "gatsby-config.js")
	assertHasTech(t, findings, "gatsby")
}

func TestDetectSourceTech_ConfigFile_Wordpress(t *testing.T) {
	content := `<?php define('DB_NAME', 'wordpress');`
	findings := DetectSourceTech(content, "wp-config.php")
	assertHasTech(t, findings, "wordpress")
}

func TestDetectSourceTech_ImportPattern_React(t *testing.T) {
	content := `import React from 'react';`
	findings := DetectSourceTech(content, "app.jsx")
	assertHasTech(t, findings, "react")
}

func TestDetectSourceTech_ImportPattern_Vue(t *testing.T) {
	content := `import { ref } from 'vue';`
	findings := DetectSourceTech(content, "App.vue")
	assertHasTech(t, findings, "vue")
}

func TestDetectSourceTech_ImportPattern_Express(t *testing.T) {
	content := `import express from 'express';`
	findings := DetectSourceTech(content, "server.js")
	assertHasTech(t, findings, "express")
}

func TestDetectSourceTech_ImportPattern_NextJS(t *testing.T) {
	content := `import Link from 'next/link';`
	findings := DetectSourceTech(content, "pages/index.tsx")
	assertHasTech(t, findings, "nextjs")
}

func TestDetectSourceTech_ImportPattern_Flask(t *testing.T) {
	content := `import flask`
	findings := DetectSourceTech(content, "app.py")
	// .py files are not in the JS/TS filter list, so no import detection
	assertNoTech(t, findings, "flask")
}

func TestDetectSourceTech_ImportPattern_Django(t *testing.T) {
	content := `from django.shortcuts import render`
	findings := DetectSourceTech(content, "views.py")
	// .py files are not in the JS/TS filter list, so no import detection
	assertNoTech(t, findings, "django")
}

func TestDetectSourceTech_ImportPattern_Angular_Component(t *testing.T) {
	content := `@Component({ selector: 'app-root' })`
	findings := DetectSourceTech(content, "app.component.ts")
	assertHasTech(t, findings, "angular")
}

func TestDetectSourceTech_NoFalsePositive_PlainText(t *testing.T) {
	content := `This is just a plain text file with no special content.`
	findings := DetectSourceTech(content, "readme.txt")
	if len(findings) != 0 {
		t.Errorf("expected no findings for plain text, got %d", len(findings))
	}
}

func TestDetectSourceTech_NoFalsePositive_UnknownFileType(t *testing.T) {
	content := `some random binary-like content`
	findings := DetectSourceTech(content, "data.bin")
	if len(findings) != 0 {
		t.Errorf("expected no findings for unknown file type, got %d", len(findings))
	}
}

func TestDetectSourceTech_Deduplication(t *testing.T) {
	content := `import React from 'react';`
	findings := DetectSourceTech(content, "app.jsx")
	reactCount := 0
	for _, f := range findings {
		if f.Secret == "react" {
			reactCount++
		}
	}
	if reactCount != 1 {
		t.Errorf("expected 1 react finding (deduped), got %d", reactCount)
	}
}

func TestDetectSourceTech_PackageJSON_DedupWithImport(t *testing.T) {
	content := `{"dependencies": {"react": "^18.0.0"}}`
	findings := DetectSourceTech(content, "package.json")
	reactCount := 0
	for _, f := range findings {
		if f.Secret == "react" {
			reactCount++
		}
	}
	if reactCount != 1 {
		t.Errorf("expected 1 react finding (deduped from manifest), got %d", reactCount)
	}
}

func TestDetectSourceTech_OutputFormat(t *testing.T) {
	content := `{"dependencies": {"next": "^14.0.0"}}`
	findings := DetectSourceTech(content, "app/package.json")
	if len(findings) == 0 {
		t.Fatal("expected at least 1 finding")
	}
	f := findings[0]
	if f.RuleName != "tech_source_nextjs" {
		t.Errorf("expected RuleName 'tech_source_nextjs', got '%s'", f.RuleName)
	}
	if f.Line != 1 {
		t.Errorf("expected Line 1, got %d", f.Line)
	}
	if f.ConfidenceBand != "HIGH" {
		t.Errorf("expected ConfidenceBand 'HIGH', got '%s'", f.ConfidenceBand)
	}
	if f.Context != "framework: nextjs" {
		t.Errorf("expected Context 'framework: nextjs', got '%s'", f.Context)
	}
	if f.Secret != "nextjs" {
		t.Errorf("expected Secret 'nextjs', got '%s'", f.Secret)
	}
	if f.File != "app/package.json" {
		t.Errorf("expected File 'app/package.json', got '%s'", f.File)
	}
}

func TestDetectSourceTech_VueSFC(t *testing.T) {
	content := `<template><div/></template><script>import { ref } from 'vue'</script>`
	findings := DetectSourceTech(content, "Component.vue")
	assertHasTech(t, findings, "vue")
}

func TestDetectSourceTech_MJSFile(t *testing.T) {
	content := `import express from 'express';`
	findings := DetectSourceTech(content, "server.mjs")
	assertHasTech(t, findings, "express")
}

func TestDetectSourceTech_RequireReact(t *testing.T) {
	content := `const React = require('react');`
	findings := DetectSourceTech(content, "app.js")
	assertHasTech(t, findings, "react")
}

// --- helpers ---

func assertHasTech(t *testing.T, findings []finding.Finding, tech string) {
	t.Helper()
	for _, f := range findings {
		if f.Secret == tech {
			return
		}
	}
	t.Errorf("expected finding with secret '%s', got %d findings: %v", tech, len(findings), summarize(findings))
}

func assertNoTech(t *testing.T, findings []finding.Finding, tech string) {
	t.Helper()
	for _, f := range findings {
		if f.Secret == tech {
			t.Errorf("did not expect finding with secret '%s'", tech)
		}
	}
}

func summarize(findings []finding.Finding) []string {
	var names []string
	for _, f := range findings {
		names = append(names, f.RuleName)
	}
	return names
}
