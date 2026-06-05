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
	if result.State != StateLikely {
		t.Errorf("expected AWS to return StateLikely, got State %d", result.State)
	}
}

func TestAWSSTSReturnsPotentialForFake(t *testing.T) {
	result, ok := Validate("aws_access_key_id", "AKIA")
	if !ok {
		t.Fatal("expected aws validator to be registered")
	}
	if result.State != StatePotential {
		t.Errorf("expected fake/too-short AWS key to return StatePotential, got State %d", result.State)
	}
}

func TestStateEnumValues(t *testing.T) {
	if StateUnknown != 0 {
		t.Error("StateUnknown should be 0")
	}
	if StatePotential != 1 {
		t.Error("StatePotential should be 1")
	}
	if StateLikely != 2 {
		t.Error("StateLikely should be 2")
	}
	if StateVerified != 3 {
		t.Error("StateVerified should be 3")
	}
}

func TestValidationResultState(t *testing.T) {
	r := ValidationResult{Valid: true, Detail: "login: test", State: StateVerified}
	if !r.Valid {
		t.Error("Valid should be true")
	}
	if r.State != StateVerified {
		t.Error("State should be StateVerified")
	}
}

func TestProviderInterface(t *testing.T) {
	var p Provider = githubValidator{}
	if p.Name() == "" {
		t.Error("Name() should not be empty")
	}
}

func TestRateLimiterAllowsRequest(t *testing.T) {
	rl := NewRateLimiter(100)
	ok := rl.Allow("test-host")
	if !ok {
		t.Error("expected rate limiter to allow first request")
	}
}

func TestRateLimiterBlocksExcess(t *testing.T) {
	rl := NewRateLimiter(0.01)
	_ = rl.Allow("test-host")
	ok := rl.Allow("test-host")
	if ok {
		t.Error("expected rate limiter to block second request at 0.01 RPS")
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
