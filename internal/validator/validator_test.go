package validator

import "testing"

func TestValidateUnknownRule(t *testing.T) {
	_, ok := Validate("totally_fake_rule", "secret123")
	if ok {
		t.Error("expected false for unknown rule")
	}
}

func TestRegistryLookup(t *testing.T) {
	// Clean prefix stripping: "base64_github_personal_access_token" → "github_personal_access_token"
	if _, ok := Validate("base64_github_personal_access_token", "ghp_fake"); !ok {
		t.Error("expected prefix-stripped rule to be found")
	}
}

func TestRegistryDirect(t *testing.T) {
	if _, ok := Validate("github_personal_access_token", "ghp_fake"); !ok {
		t.Error("expected direct rule to be found")
	}
}

func TestFakeTokenReturnsInvalid(t *testing.T) {
	result, ok := Validate("github_personal_access_token", "ghp_fake123456789012345678901234567890")
	if !ok {
		t.Fatal("expected validator to be found")
	}
	if result.Valid {
		t.Error("expected fake token to be invalid")
	}
}

func TestAWSSkips(t *testing.T) {
	result, ok := Validate("aws_access_key_id", "AKIAIOSFODNN7EXAMPLE")
	if !ok {
		t.Fatal("expected aws validator to be registered")
	}
	if result.Valid {
		t.Error("expected AWS to return skipped/invalid")
	}
}

func TestAllRegistered(t *testing.T) {
	expected := []string{
		"github_personal_access_token",
		"github_oauth_access_token",
		"gitlab_token",
		"slack_token",
		"stripe_secret_key",
		"openai_api_key",
		"openai_key",
		"anthropic_api_key",
		"sendgrid_api_key",
		"twilio_api_key",
		"npm_token",
		"huggingface_token",
		"aws_access_key_id",
		"slack_webhook_url",
	}
	for _, name := range expected {
		if _, ok := registry[name]; !ok {
			t.Errorf("missing registered validator: %s", name)
		}
	}
}
