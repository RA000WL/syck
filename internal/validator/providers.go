package validator

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

var httpClient = &http.Client{
	Timeout: 5 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

// httpDo executes req and returns the response. Caller must close Body.
func httpDo(req *http.Request) (*http.Response, error) {
	return httpClient.Do(req)
}

// --- GitHub ---

type githubValidator struct{}

func (githubValidator) Name() string { return "github_personal_access_token" }

func (githubValidator) Validate(secret string) ValidationResult {
	req, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		return ValidationResult{Detail: "error: " + err.Error()}
	}
	req.Header.Set("Authorization", "token "+secret)
	resp, err := httpDo(req)
	if err != nil {
		return ValidationResult{Detail: "error: " + err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		var body struct {
			Login string `json:"login"`
		}
		json.NewDecoder(resp.Body).Decode(&body)
		if body.Login != "" {
			return ValidationResult{Valid: true, Detail: "login: " + body.Login}
		}
		return ValidationResult{Valid: true, Detail: "HTTP 200"}
	}
	return ValidationResult{Detail: fmt.Sprintf("HTTP %d", resp.StatusCode)}
}

// --- GitLab ---

type gitlabValidator struct{}

func (gitlabValidator) Name() string { return "gitlab_token" }

func (gitlabValidator) Validate(secret string) ValidationResult {
	req, err := http.NewRequest("GET", "https://gitlab.com/api/v4/user", nil)
	if err != nil {
		return ValidationResult{Detail: "error: " + err.Error()}
	}
	req.Header.Set("PRIVATE-TOKEN", secret)
	resp, err := httpDo(req)
	if err != nil {
		return ValidationResult{Detail: "error: " + err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		return ValidationResult{Valid: true, Detail: "HTTP 200"}
	}
	return ValidationResult{Detail: fmt.Sprintf("HTTP %d", resp.StatusCode)}
}

// --- Slack ---

type slackValidator struct{}

func (slackValidator) Name() string { return "slack_token" }

func (slackValidator) Validate(secret string) ValidationResult {
	data := []byte("token=" + secret)
	req, err := http.NewRequest("POST", "https://slack.com/api/auth.test", bytes.NewReader(data))
	if err != nil {
		return ValidationResult{Detail: "error: " + err.Error()}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := httpDo(req)
	if err != nil {
		return ValidationResult{Detail: "error: " + err.Error()}
	}
	defer resp.Body.Close()
	var body struct {
		OK   bool   `json:"ok"`
		User string `json:"user"`
	}
	json.NewDecoder(resp.Body).Decode(&body)
	if body.OK {
		detail := "HTTP 200"
		if body.User != "" {
			detail = "user: " + body.User
		}
		return ValidationResult{Valid: true, Detail: detail}
	}
	return ValidationResult{Detail: fmt.Sprintf("HTTP %d", resp.StatusCode)}
}

// --- Stripe ---

type stripeValidator struct{}

func (stripeValidator) Name() string { return "stripe_secret_key" }

func (stripeValidator) Validate(secret string) ValidationResult {
	req, err := http.NewRequest("GET", "https://api.stripe.com/v1/balance", nil)
	if err != nil {
		return ValidationResult{Detail: "error: " + err.Error()}
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	resp, err := httpDo(req)
	if err != nil {
		return ValidationResult{Detail: "error: " + err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		return ValidationResult{Valid: true, Detail: "HTTP 200"}
	}
	return ValidationResult{Detail: fmt.Sprintf("HTTP %d", resp.StatusCode)}
}

// --- OpenAI ---

type openaiValidator struct{}

func (openaiValidator) Name() string { return "openai_api_key" }

func (openaiValidator) Validate(secret string) ValidationResult {
	req, err := http.NewRequest("GET", "https://api.openai.com/v1/models", nil)
	if err != nil {
		return ValidationResult{Detail: "error: " + err.Error()}
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	resp, err := httpDo(req)
	if err != nil {
		return ValidationResult{Detail: "error: " + err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		return ValidationResult{Valid: true, Detail: "HTTP 200"}
	}
	return ValidationResult{Detail: fmt.Sprintf("HTTP %d", resp.StatusCode)}
}

// --- Anthropic ---

type anthropicValidator struct{}

func (anthropicValidator) Name() string { return "anthropic_api_key" }

func (anthropicValidator) Validate(secret string) ValidationResult {
	body := []byte(`{"model":"claude-3-haiku-20240307","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}`)
	req, err := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", bytes.NewReader(body))
	if err != nil {
		return ValidationResult{Detail: "error: " + err.Error()}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", secret)
	req.Header.Set("anthropic-version", "2023-06-01")
	resp, err := httpDo(req)
	if err != nil {
		return ValidationResult{Detail: "error: " + err.Error()}
	}
	defer resp.Body.Close()
	// 200 = valid key with good request; 400 = valid key but bad request; 401 = invalid
	if resp.StatusCode == 200 || resp.StatusCode == 400 {
		return ValidationResult{Valid: true, Detail: fmt.Sprintf("HTTP %d", resp.StatusCode)}
	}
	return ValidationResult{Detail: fmt.Sprintf("HTTP %d", resp.StatusCode)}
}

// --- SendGrid ---

type sendgridValidator struct{}

func (sendgridValidator) Name() string { return "sendgrid_api_key" }

func (sendgridValidator) Validate(secret string) ValidationResult {
	req, err := http.NewRequest("GET", "https://api.sendgrid.com/v3/user/profile", nil)
	if err != nil {
		return ValidationResult{Detail: "error: " + err.Error()}
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	resp, err := httpDo(req)
	if err != nil {
		return ValidationResult{Detail: "error: " + err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		return ValidationResult{Valid: true, Detail: "HTTP 200"}
	}
	return ValidationResult{Detail: fmt.Sprintf("HTTP %d", resp.StatusCode)}
}

// --- Twilio ---

type twilioValidator struct{}

func (twilioValidator) Name() string { return "twilio_api_key" }

func (twilioValidator) Validate(secret string) ValidationResult {
	encoded := base64.StdEncoding.EncodeToString([]byte(secret))
	req, err := http.NewRequest("GET", "https://api.twilio.com/2010-04-01/Accounts.json", nil)
	if err != nil {
		return ValidationResult{Detail: "error: " + err.Error()}
	}
	req.Header.Set("Authorization", "Basic "+encoded)
	resp, err := httpDo(req)
	if err != nil {
		return ValidationResult{Detail: "error: " + err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		return ValidationResult{Valid: true, Detail: "HTTP 200"}
	}
	return ValidationResult{Detail: fmt.Sprintf("HTTP %d", resp.StatusCode)}
}

// --- npm ---

type npmValidator struct{}

func (npmValidator) Name() string { return "npm_token" }

func (npmValidator) Validate(secret string) ValidationResult {
	req, err := http.NewRequest("GET", "https://registry.npmjs.org/-/whoami", nil)
	if err != nil {
		return ValidationResult{Detail: "error: " + err.Error()}
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	resp, err := httpDo(req)
	if err != nil {
		return ValidationResult{Detail: "error: " + err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		var body struct {
			Username string `json:"username"`
		}
		json.NewDecoder(resp.Body).Decode(&body)
		if body.Username != "" {
			return ValidationResult{Valid: true, Detail: "user: " + body.Username}
		}
		return ValidationResult{Valid: true, Detail: "HTTP 200"}
	}
	return ValidationResult{Detail: fmt.Sprintf("HTTP %d", resp.StatusCode)}
}

// --- HuggingFace ---

type huggingfaceValidator struct{}

func (huggingfaceValidator) Name() string { return "huggingface_token" }

func (huggingfaceValidator) Validate(secret string) ValidationResult {
	req, err := http.NewRequest("GET", "https://huggingface.co/api/whoami-v2", nil)
	if err != nil {
		return ValidationResult{Detail: "error: " + err.Error()}
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	resp, err := httpDo(req)
	if err != nil {
		return ValidationResult{Detail: "error: " + err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		var body struct {
			Name string `json:"name"`
		}
		json.NewDecoder(resp.Body).Decode(&body)
		if body.Name != "" {
			return ValidationResult{Valid: true, Detail: "user: " + body.Name}
		}
		return ValidationResult{Valid: true, Detail: "HTTP 200"}
	}
	return ValidationResult{Detail: fmt.Sprintf("HTTP %d", resp.StatusCode)}
}

// --- AWS (stub) ---

type awsValidator struct{}

func (awsValidator) Name() string { return "aws_access_key_id" }

func (awsValidator) Validate(secret string) ValidationResult {
	return ValidationResult{Detail: "skipped: needs secret key + STS signing"}
}

// --- Slack Webhook ---

type slackWebhookValidator struct{}

func (slackWebhookValidator) Name() string { return "slack_webhook_url" }

func (slackWebhookValidator) Validate(secret string) ValidationResult {
	payload := []byte(`{"text":"syck validate"}`)
	resp, err := http.Post(secret, "application/json", bytes.NewReader(payload))
	if err != nil {
		return ValidationResult{Detail: "error: " + err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		return ValidationResult{Valid: true, Detail: "HTTP 200"}
	}
	return ValidationResult{Detail: fmt.Sprintf("HTTP %d", resp.StatusCode)}
}

// --- OpenAI key prefix helper (also catches sk-...) ---
type openaiKeyValidator struct{}

func (openaiKeyValidator) Name() string { return "openai_key" }

func (openaiKeyValidator) Validate(secret string) ValidationResult {
	if !strings.HasPrefix(secret, "sk-") {
		return ValidationResult{Detail: "not an OpenAI key (missing sk- prefix)"}
	}
	v := openaiValidator{}
	return v.Validate(secret)
}

func init() {
	Register("github_personal_access_token", githubValidator{})
	Register("github_oauth_access_token", githubValidator{})
	Register("gitlab_token", gitlabValidator{})
	Register("slack_token", slackValidator{})
	Register("stripe_secret_key", stripeValidator{})
	Register("openai_api_key", openaiValidator{})
	Register("openai_key", openaiKeyValidator{})
	Register("anthropic_api_key", anthropicValidator{})
	Register("sendgrid_api_key", sendgridValidator{})
	Register("twilio_api_key", twilioValidator{})
	Register("npm_token", npmValidator{})
	Register("huggingface_token", huggingfaceValidator{})
	Register("aws_access_key_id", awsValidator{})
	Register("slack_webhook_url", slackWebhookValidator{})
}
