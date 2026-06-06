package ruletest

import (
	"fmt"
	"math/rand"
	"strings"
)

func init() { rand.Seed(42) }

func GeneratePositive(ruleName string) []string {
	gen, ok := positiveGenerators[ruleName]
	if !ok {
		return nil
	}
	return gen()
}

func GenerateNegative() []string {
	return generateNegativeCorpus()
}

var alphanum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
var lowerNum = "abcdefghijklmnopqrstuvwxyz0123456789"
var upperNum = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
var hexLower = "0123456789abcdef"
var hexUpper = "0123456789ABCDEF"
var hexBoth = "0123456789abcdefABCDEF"
var alphaUnderscore = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"

func randStr(length int, charset string) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func prefixLines(prefix string, charset string, length int, count int) []string {
	lines := make([]string, count)
	for i := range lines {
		lines[i] = prefix + randStr(length, charset)
	}
	return lines
}

var positiveGenerators = map[string]func() []string{
	"anthropic_api_key": func() []string {
		return prefixLines("sk-ant-", alphanum, 30, 8)
	},
	"aws_access_key_id": func() []string {
		prefixes := []string{"AKIA", "AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA", "ASIA"}
		lines := make([]string, 8)
		for i := range lines {
			lines[i] = prefixes[i%len(prefixes)] + randStr(16, upperNum)
		}
		return lines
	},
	"aws_appsync_key": func() []string {
		return prefixLines("da2-", lowerNum, 26, 8)
	},
	"azure_connection_string": func() []string {
		accounts := []string{"prodstorage", "devtest", "backup01", "metrics", "logs", "archive", "synapse", "warehouse"}
		keys := make([]string, 8)
		for i := range keys {
			account := accounts[i]
			keys[i] = fmt.Sprintf("DefaultEndpointsProtocol=https;AccountName=%s;AccountKey=%s;EndpointSuffix=core.windows.net", account, randStr(68, alphanum))
		}
		return keys
	},
	"fireworks_api_key": func() []string {
		return prefixLines("fw_", alphanum, 36, 8)
	},
	"github_app_token": func() []string {
		prefixes := []string{"ghu_", "ghs_"}
		lines := make([]string, 8)
		for i := range lines {
			lines[i] = prefixes[i%2] + randStr(36, alphanum)
		}
		return lines
	},
	"github_fine_grained_token": func() []string {
		return prefixLines("github_pat_", alphaUnderscore, 82, 8)
	},
	"github_oauth_access_token": func() []string {
		return prefixLines("gho_", alphanum, 36, 8)
	},
	"github_personal_access_token": func() []string {
		return prefixLines("ghp_", alphanum, 36, 8)
	},
	"gitlab_personal_token": func() []string {
		return prefixLines("glpat-", alphanum, 26, 8)
	},
	"gitlab_runner_token": func() []string {
		return prefixLines("GR1348941", alphanum, 16, 8)
	},
	"google_api_key": func() []string {
		return prefixLines("AIza", alphanum, 35, 8)
	},
	"groq_api_key": func() []string {
		return prefixLines("gsk_", alphanum, 36, 8)
	},
	"huggingface_api_token": func() []string {
		return prefixLines("hf_", alphanum, 30, 8)
	},
	"mailgun_api_key": func() []string {
		return prefixLines("key-", hexLower, 32, 8)
	},
	"npm_token": func() []string {
		return prefixLines("npm_", alphanum, 36, 8)
	},
	"openai_api_key": func() []string {
		return prefixLines("sk-proj-", alphanum, 30, 8)
	},
	"perplexity_api_key": func() []string {
		return prefixLines("pplx-", alphanum, 30, 8)
	},
	"replicate_api_token": func() []string {
		return prefixLines("r8_", hexBoth, 48, 8)
	},
	"sendgrid_api_token": func() []string {
		lines := make([]string, 8)
		for i := range lines {
			part1 := randStr(24, alphanum)
			part2 := randStr(43, alphanum)
			lines[i] = fmt.Sprintf("SG.%s.%s", part1, part2)
		}
		return lines
	},
	"shopify_custom_app_token": func() []string {
		return prefixLines("shpat_", hexUpper, 32, 8)
	},
	"slack_app_level_token": func() []string {
		return prefixLines("xapp-", alphanum, 60, 8)
	},
	"slack_bot_token": func() []string {
		return prefixLines("xoxb-", alphanum, 50, 8)
	},
	"slack_webhook_url": func() []string {
		lines := make([]string, 8)
		for i := range lines {
			tID := randStr(8, upperNum)
			bID := randStr(8, upperNum)
			secret := randStr(24, alphanum)
			lines[i] = fmt.Sprintf("https://hooks.slack.com/services/T%s/B%s/%s", tID, bID, secret)
		}
		return lines
	},
	"stripe_publishable_key": func() []string {
		prefixes := []string{"pk_test_", "pk_live_"}
		lines := make([]string, 8)
		for i := range lines {
			lines[i] = prefixes[i%2] + randStr(30, alphanum)
		}
		return lines
	},
	"stripe_restricted_key": func() []string {
		prefixes := []string{"rk_test_", "rk_live_"}
		lines := make([]string, 8)
		for i := range lines {
			lines[i] = prefixes[i%2] + randStr(30, alphanum)
		}
		return lines
	},
	"stripe_secret_key": func() []string {
		prefixes := []string{"sk_test_", "sk_live_"}
		lines := make([]string, 8)
		for i := range lines {
			lines[i] = prefixes[i%2] + randStr(30, alphanum)
		}
		return lines
	},
	"stripe_webhook_signing_secret": func() []string {
		return prefixLines("whsec_", alphanum, 36, 8)
	},
	"telegram_bot_token": func() []string {
		lines := make([]string, 8)
		for i := range lines {
			digits := randStr(10, "0123456789")
			secret := randStr(35, alphanum)
			lines[i] = digits + ":" + secret
		}
		return lines
	},
	"twilio_account_sid": func() []string {
		return prefixLines("AC", lowerNum, 32, 8)
	},
	"test_rule": func() []string {
		return []string{"abc123", "abc456", "abc789", "abcabc", "abcxyz", "abc000", "abc999", "abc444"}
	},
}

func generateNegativeCorpus() []string {
	templates := []string{
		"func Test%s(t *testing.T) {",
		"var %s = \"%s\"",
		"const %s = \"%s\"",
		"%s := %d",
		"log.Printf(\"%s: %%d\", %s)",
		"json.Unmarshal([]byte(`{\"%s\": \"%s\"}`), &%s)",
		"for i := 0; i < %d; i++ {",
		"if %s != nil {",
		"switch %s {",
		"case \"%s\":",
		"return fmt.Errorf(\"%s: %%w\", err)",
		"type %s struct {",
		"Name string `json:\"name\"`",
		"func new%s() *%s {",
		"%s.%s(%s)",
		"// TODO: implement %s",
		"/* %s block comment */",
		"cfg := &Config{",
		"response, err := http.Get(url)",
		"defer resp.Body.Close()",
		"select {",
		"case <-ctx.Done():",
		"default:",
		"map[string]interface{}{",
		"\"%s\": \"%s\",",
		"package %s",
		"import \"%s\"",
		"github.com/%s/%s",
		"user@example.com",
		"127.0.0.1:8080",
		"localhost:3000",
		"getUserByID(42)",
		"processBatch(items)",
		"renderTemplate(\"index.html\", data)",
		"validateInput(r.FormValue(\"email\"))",
	}

	words := []string{"foo", "bar", "baz", "qux", "test", "data", "item", "user", "config",
		"handler", "service", "repo", "model", "view", "ctrl", "util", "helper",
		"app", "module", "system", "main", "index", "page", "form", "field",
		"value", "result", "output", "input", "source", "target", "source"}

	var lines []string
	for i := 0; i < 1000; i++ {
		tpl := templates[i%len(templates)]
		substCount := strings.Count(tpl, "%s") + strings.Count(tpl, "%d")
		args := make([]interface{}, substCount)
		for j := range args {
			args[j] = words[rand.Intn(len(words))]
		}
		lines = append(lines, fmt.Sprintf(tpl, args...))
	}
	return lines
}
