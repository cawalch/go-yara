package engine

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestSelectableExamples(t *testing.T) {
	raw, err := os.ReadFile("examples.json")
	if err != nil {
		t.Fatal(err)
	}
	var examples []struct {
		ID, Rules, Input                string
		Evidence                        bool
		ExpectedRules, ExpectedStatuses []string
	}
	if err := json.Unmarshal(raw, &examples); err != nil {
		t.Fatal(err)
	}
	for _, example := range examples {
		t.Run(example.ID, func(t *testing.T) {
			result := Scan(example.Rules, []byte(example.Input), example.Evidence)
			if result.Error != "" {
				t.Fatal(result.Error)
			}
			if !reflect.DeepEqual(result.Rules, example.ExpectedRules) {
				t.Fatalf("rules: %v", result.Rules)
			}
			statuses := []string{}
			for _, finding := range result.Evidence {
				statuses = append(statuses, finding.Status)
			}
			if !reflect.DeepEqual(statuses, example.ExpectedStatuses) {
				t.Fatalf("statuses: %v", statuses)
			}
			if result.EvidenceEnabled != example.Evidence {
				t.Fatal("evidence option ignored")
			}
		})
	}
}

const evidenceRules = `rule credential {
 strings:
  $host = /endpoint=([^ \n]+)/ capture(endpoint = 1)
  $user = /username=([^ \n]+)/ capture(username = 1)
  $pass = /password=([^ \n]+)/ capture(secret = 1)
 evidence: account = (endpoint, username, secret) within 96 of secret
 condition: $pass
}`

func TestRedactionBeforeEncoding(t *testing.T) {
	input := "endpoint=private.example.test\nusername=USER_SENTINEL\npassword=SECRET_SENTINEL"
	result := Scan(evidenceRules, []byte(input), true)
	if result.Error != "" || len(result.Evidence) != 1 || result.Evidence[0].Status != "ready" {
		t.Fatalf("unexpected summary: %+v", result)
	}
	encoded := Encode(result)
	for _, value := range []string{"private.example.test", "USER_SENTINEL", "SECRET_SENTINEL", `"data":`, `"anchor":`} {
		if strings.Contains(encoded, value) {
			t.Fatalf("captured data leaked into encoded reply: %s", value)
		}
	}
	for _, field := range result.Evidence[0].Fields {
		if field.Missing || field.DataTruncated || field.Length == 0 || field.Offset < 0 {
			t.Fatalf("invalid capture span: %+v", field)
		}
	}
	disabled := Scan(evidenceRules, []byte(input), false)
	if len(disabled.Evidence) != 0 || disabled.EvidenceEnabled {
		t.Fatal("evidence should be opt-in")
	}
	invalid := Scan(`rule bad { condition: "SOURCE_SECRET_SENTINEL" + true }`, nil, true)
	if invalid.Error == "" || strings.Contains(Encode(invalid), "SOURCE_SECRET_SENTINEL") {
		t.Fatal("compiler diagnostic exposed source")
	}
}

func TestEvidenceDisplayBudgetsAndConditions(t *testing.T) {
	input := strings.Repeat("endpoint=db\nusername=one\nusername=two\nusername=three\npassword=value\n"+strings.Repeat("#", 128)+"\n", 30)
	result := Scan(evidenceRules, []byte(input), true)
	if result.Error != "" || result.EvidenceCount != 30 || result.EvidenceRowCount != 150 {
		t.Fatalf("unexpected totals: %+v", result)
	}
	if len(result.Evidence) != Limits.EvidenceFindings || evidenceRows(result.Evidence) != Limits.EvidenceRows {
		t.Fatal("display budgets not applied")
	}
	for _, finding := range result.Evidence {
		if finding.Status != "ambiguous" {
			t.Fatal("display truncation changed status")
		}
	}
	var wire Reply
	if err := json.Unmarshal([]byte(Encode(result)), &wire); err != nil {
		t.Fatal(err)
	}
	if !wire.Truncated {
		t.Fatal("missing truncation notice")
	}
	counted := Scan(`rule counted { strings: $a="a" capture(token=0) evidence: item=(token) within 0 of token condition: #a == 300 and @a[300] == 299 }`, []byte(strings.Repeat("a", 300)), true)
	if counted.Error != "" || !reflect.DeepEqual(counted.Rules, []string{"counted"}) || counted.EvidenceCount != 300 {
		t.Fatal("evidence display cap changed rule evaluation")
	}
	// Long identifiers consume the byte budget even with a bounded number of rows.
	long := strings.Replace(evidenceRules, "rule credential", "rule r"+strings.Repeat("x", 4000), 1)
	encoded := Encode(Scan(long, []byte(input), true))
	if len(encoded) > Limits.OutputBytes || !json.Valid([]byte(encoded)) {
		t.Fatal("evidence exceeded wire budget")
	}
	if err := json.Unmarshal([]byte(encoded), &wire); err != nil {
		t.Fatal(err)
	}
	if !wire.Truncated || len(wire.Evidence) >= Limits.EvidenceFindings {
		t.Fatal("byte truncation was not reported")
	}
}
