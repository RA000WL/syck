package rules

// Subsumption gate for Batch 2b Task 4: the rules listed as deleted below
// must be absent from builtin.yaml, and every representative positive of a
// deleted rule must still match its keeper rule. Added rules must be present.
// Count: baseline 202 + 2 additions - 5 deletions = 199.

import "testing"

// deleted rule -> keeper rule that subsumes it.
var subsumedPairs = []struct {
	deleted string
	keeper  string
}{
	{"discord_webhook", "discord_webhook_url"},
	{"postgres_connection_url", "postgres_url"},
	{"mysql_connection_url", "mysql_url"},
	{"mongodb_connection_string", "mongodb_url"},
	{"gitlab_runner_registration_token", "gitlab_runner_token"},
}

// Representative positives shaped like the deleted rules' generators.
var deletedPositives = map[string][]string{
	"discord_webhook": {
		"https://discord.com/api/webhooks/123456789/AbCdef-_XyZ09",
		"https://discordapp.com/api/webhooks/987654321/token_abc-XYZ_12",
	},
	"postgres_connection_url": {
		"postgres://admin:s3cr3tP@db.example.com:5432/mydb",
		"postgresql://appuser:p4ssw0rd@pg.internal:5432/shop",
	},
	"mysql_connection_url": {
		"mysql://root:p4ssw0rd@db.example.com:3306/shop",
		"mysql://app:secret12@mysql.internal:3306/appdb",
	},
	"mongodb_connection_string": {
		"mongodb://admin:s3cret12@cluster0.example.com/mydb",
		"mongodb+srv://appuser:pw123456@cluster0.ex.com/appdb",
	},
	"gitlab_runner_registration_token": {
		"GR1348941AbCdefGh12_Xy-34zZ",
		"GR1348941abcdefghij1234567890",
	},
}

var addedRules = []string{"openai_legacy_key", "slack_user_token"}

func TestDeletedRuleSubsumption(t *testing.T) {
	rs, err := LoadDefault()
	if err != nil {
		t.Fatalf("LoadDefault: %v", err)
	}
	byName := make(map[string]*Rule, len(rs.Rules))
	for i := range rs.Rules {
		byName[rs.Rules[i].Name] = &rs.Rules[i]
	}

	for _, p := range subsumedPairs {
		if _, ok := byName[p.deleted]; ok {
			t.Errorf("deleted rule %q still present in builtin.yaml", p.deleted)
		}
		keeper, ok := byName[p.keeper]
		if !ok {
			t.Errorf("keeper rule %q missing from builtin.yaml", p.keeper)
			continue
		}
		for _, line := range deletedPositives[p.deleted] {
			if len(keeper.MatchAll(line)) == 0 {
				t.Errorf("keeper %q does not match deleted %q positive %q (not subsumed)",
					p.keeper, p.deleted, line)
			}
		}
	}

	for _, name := range addedRules {
		if _, ok := byName[name]; !ok {
			t.Errorf("added rule %q missing from builtin.yaml", name)
		}
	}

	const want = 199 // 202 baseline + 2 additions - 5 deletions
	if len(rs.Rules) != want {
		t.Errorf("builtin rule count = %d, want %d", len(rs.Rules), want)
	}
}
