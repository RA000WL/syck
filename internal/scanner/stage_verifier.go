package scanner

import (
	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/validator"
)

type VerifierStage struct{}

func NewVerifierStage() *VerifierStage { return &VerifierStage{} }

func (s *VerifierStage) Process(in []finding.Finding) []finding.Finding {
	for i := range in {
		res, ok := validator.Validate(in[i].RuleName, in[i].Secret)
		if !ok {
			continue
		}
		if res.Valid {
			in[i].VerificationStatus = "VERIFIED"
		} else {
			in[i].VerificationStatus = "POTENTIAL"
		}
	}
	return in
}
