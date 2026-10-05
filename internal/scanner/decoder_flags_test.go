package scanner

import (
	"encoding/base64"
	"strconv"
	"strings"
	"testing"

	"github.com/RA000WL/syck/internal/finding"
)

const newDecoderSecret = "AKIAIOSFODNN7EXAMPLE"

func base64URLFixture(secret string) string {
	// High bytes sit mid-payload: the blob must start with a word char so
	// the base64url candidate regex (\b...) matches the full token, while
	// still containing -/_ so the std-base64 path cannot claim it.
	raw := secret + "\xfb\xef\xff" + strings.Repeat("B", 30)
	return `token = "` + base64.RawURLEncoding.EncodeToString([]byte(raw)) + `"`
}

func jwtDecoderFixture(secret string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"service":"payments","aws_key":"` + secret + `"}`))
	return `auth = "` + header + "." + payload + `.c2lnbmF0dXJl"`
}

func charCodeFixture(secret string) string {
	codes := make([]string, 0, len(secret))
	for i := 0; i < len(secret); i++ {
		codes = append(codes, strconv.Itoa(int(secret[i])))
	}
	return "var k = String.fromCharCode(" + strings.Join(codes, ",") + ");"
}

func doubleBase64Fixture(secret string) string {
	payload := strings.Repeat("Z", 80) + secret
	once := base64.StdEncoding.EncodeToString([]byte(payload))
	twice := base64.StdEncoding.EncodeToString([]byte(once))
	return `const blob = "` + twice + `"`
}

func combinedNewDecoderFixture(secret string) string {
	return strings.Join([]string{
		base64URLFixture(secret),
		jwtDecoderFixture(secret),
		charCodeFixture(secret),
		doubleBase64Fixture(secret),
	}, "\n")
}

func hasSecret(findings []finding.Finding, secret string) bool {
	for _, f := range findings {
		if f.Secret == secret {
			return true
		}
	}
	return false
}

func hasRulePrefixWithSecret(findings []finding.Finding, prefix, secret string) bool {
	for _, f := range findings {
		if strings.HasPrefix(f.RuleName, prefix) && f.Secret == secret {
			return true
		}
	}
	return false
}

func hasAnyRulePrefix(findings []finding.Finding, prefixes ...string) (string, bool) {
	for _, f := range findings {
		for _, p := range prefixes {
			if strings.HasPrefix(f.RuleName, p) {
				return f.RuleName, true
			}
		}
	}
	return "", false
}

var decodedTagPrefixes = []string{"base64url_", "jwt_", "charcode_", "doublebase64_"}

func TestNewDecodersDefaultOff(t *testing.T) {
	cfg := Config{Rules: loadMinimalRules(t)}
	content := combinedNewDecoderFixture(newDecoderSecret)
	findings := ScanContent(content, "fixture.txt", cfg)
	if hasSecret(findings, newDecoderSecret) {
		t.Fatalf("decoders off: found plaintext secret in findings: %+v", findings)
	}
	if name, ok := hasAnyRulePrefix(findings, decodedTagPrefixes...); ok {
		t.Fatalf("decoders off: found decoded finding %q: %+v", name, findings)
	}
}

func TestNewDecodersOptIn(t *testing.T) {
	rs := loadMinimalRules(t)
	content := combinedNewDecoderFixture(newDecoderSecret)
	cases := []struct {
		name   string
		cfg    Config
		prefix string
	}{
		{"base64url", Config{Rules: rs, DecodeBase64URL: true}, "base64url_"},
		{"jwt", Config{Rules: rs, DecodeJWT: true}, "jwt_"},
		{"charcode", Config{Rules: rs, DecodeCharCode: true}, "charcode_"},
		{"doublebase64", Config{Rules: rs, DecodeDoubleBase64: true}, "doublebase64_"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := ScanContent(content, "fixture.txt", tc.cfg)
			if !hasRulePrefixWithSecret(findings, tc.prefix, newDecoderSecret) {
				t.Fatalf("flag on: want %q finding with secret, got: %+v", tc.prefix, findings)
			}
		})
	}
}

func TestCharCodeDerivationPreserved(t *testing.T) {
	cfg := Config{Rules: loadMinimalRules(t), DecodeHex: true}
	findings := ScanContent(charCodeFixture(newDecoderSecret), "fixture.js", cfg)
	if !hasRulePrefixWithSecret(findings, "charcode_", newDecoderSecret) {
		t.Fatalf("DecodeHex: want charcode_ finding without explicit DecodeCharCode, got: %+v", findings)
	}
}
