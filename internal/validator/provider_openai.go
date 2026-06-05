package validator

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type openaiValidator struct{}

func (openaiValidator) Name() string { return "openai_api_key" }

func (openaiValidator) Validate(secret string) ValidationResult {
	req, err := http.NewRequest("GET", "https://api.openai.com/v1/models", nil)
	if err != nil {
		return ValidationResult{Detail: "error: " + err.Error(), State: StateUnknown}
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	resp, err := httpDo(req)
	if err != nil {
		return ValidationResult{Detail: "error: " + err.Error(), State: StateUnknown}
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		body, _ := io.ReadAll(resp.Body)
		var modelResp struct {
			Data []struct{} `json:"data"`
		}
		if json.Unmarshal(body, &modelResp) == nil {
			return ValidationResult{
				Valid:  true,
				Detail: fmt.Sprintf("%d models accessible", len(modelResp.Data)),
				State:  StateVerified,
			}
		}
		return ValidationResult{Valid: true, Detail: "HTTP 200", State: StateLikely}
	}
	return ValidationResult{Detail: fmt.Sprintf("HTTP %d", resp.StatusCode), State: StatePotential}
}

func init() {
	Register("openai_api_key", openaiValidator{})
}
