package scanner

import (
	"testing"

	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/rules"
)

func TestDecoderStagePassthrough(t *testing.T) {
	rs := &rules.RuleSet{}
	_ = rs.CompileAll()
	d := NewDecoderStage(rs, finding.ParseSeverity("LOW"), DecoderFlags{})
	findings := d.Process("plain text without any secrets", "x.txt", 1)
	_ = findings
}
