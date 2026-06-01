package compiler

import (
	"testing"
)

// --- Tags & Metadata ---

func TestRuleTagsStored(t *testing.T) {
	source := `rule test : malware trojan { condition: true }`
	compiler := NewCompiler()
	program, err := compiler.CompileSource(source)
	if err != nil {
		t.Fatalf("CompileSource: %v", err)
	}

	if len(program.Rules) != 1 {
		t.Fatalf("Expected 1 rule, got %d", len(program.Rules))
	}

	rule := program.Rules[0]
	if len(rule.Tags) != 2 {
		t.Fatalf("Expected 2 tags, got %d", len(rule.Tags))
	}
	if rule.Tags[0] != "malware" || rule.Tags[1] != "trojan" {
		t.Errorf("Expected tags [malware, trojan], got %v", rule.Tags)
	}
}

func TestRuleMetaStored(t *testing.T) {
	source := `
rule test {
	meta:
		author = "test"
		version = 1
		active = true
	condition:
		true
}`
	compiler := NewCompiler()
	program, err := compiler.CompileSource(source)
	if err != nil {
		t.Fatalf("CompileSource: %v", err)
	}

	rule := program.Rules[0]
	if len(rule.Meta) != 3 {
		t.Fatalf("Expected 3 meta entries, got %d", len(rule.Meta))
	}

	if rule.Meta["author"] != "test" {
		t.Errorf("Expected author=test, got %v", rule.Meta["author"])
	}
	if rule.Meta["version"] != int64(1) {
		t.Errorf("Expected version=1, got %v", rule.Meta["version"])
	}
	if rule.Meta["active"] != true {
		t.Errorf("Expected active=true, got %v", rule.Meta["active"])
	}
}

func TestRuleTagsAndMetaInMatch(t *testing.T) {
	source := `
rule test : malware {
	meta:
		author = "test"
	condition:
		true
}`
	compiler := NewCompiler()
	program, err := compiler.CompileSource(source)
	if err != nil {
		t.Fatalf("CompileSource: %v", err)
	}

	scanner := NewScanner(program)
	defer scanner.Close()

	result, err := scanner.Scan([]byte("dummy"))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if len(result.MatchedRules) != 1 {
		t.Fatalf("Expected 1 match, got %d", len(result.MatchedRules))
	}

	match := result.MatchedRules[0]
	if len(match.Tags) != 1 || match.Tags[0] != "malware" {
		t.Errorf("Expected tags [malware], got %v", match.Tags)
	}
	if match.Meta["author"] != "test" {
		t.Errorf("Expected meta author=test, got %v", match.Meta["author"])
	}
}

// --- Global Rules ---

func TestGlobalRuleAllMatch(t *testing.T) {
	// All global rules match -> non-global rules are evaluated
	source := `
global rule global1 {
	condition: true
}
global rule global2 {
	condition: true
}
rule normal {
	condition: true
}`
	compiler := NewCompiler()
	program, err := compiler.CompileSource(source)
	if err != nil {
		t.Fatalf("CompileSource: %v", err)
	}

	scanner := NewScanner(program)
	defer scanner.Close()

	result, err := scanner.Scan([]byte("dummy"))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	// All 3 rules should match
	if len(result.MatchedRules) != 3 {
		t.Fatalf("Expected 3 matches, got %d", len(result.MatchedRules))
	}
}

func TestGlobalRuleOneFails(t *testing.T) {
	// One global rule fails -> non-global rules are skipped
	source := `
global rule global1 {
	condition: true
}
global rule global2 {
	condition: false
}
rule normal {
	condition: true
}`
	compiler := NewCompiler()
	program, err := compiler.CompileSource(source)
	if err != nil {
		t.Fatalf("CompileSource: %v", err)
	}

	scanner := NewScanner(program)
	defer scanner.Close()

	result, err := scanner.Scan([]byte("dummy"))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	// Only global1 should appear in results (global2 fails, normal is skipped)
	if len(result.MatchedRules) != 1 {
		t.Fatalf("Expected 1 match, got %d: %v", len(result.MatchedRules), result.MatchedRules)
	}
	if result.MatchedRules[0].Rule != "global1" {
		t.Errorf("Expected global1, got %s", result.MatchedRules[0].Rule)
	}
}

func TestGlobalRuleWithData(t *testing.T) {
	// Global rule checks data — if it fails, normal rules are skipped
	source := `
global rule mustContain {
	strings:
		$a = "HEADER"
	condition:
		$a
}
rule normal {
	strings:
		$b = "FOOTER"
	condition:
		$b
}`
	compiler := NewCompiler()
	program, err := compiler.CompileSource(source)
	if err != nil {
		t.Fatalf("CompileSource: %v", err)
	}

	scanner := NewScanner(program)
	defer scanner.Close()

	// Data without "HEADER" — global rule fails, normal is skipped
	result, err := scanner.Scan([]byte("FOOTER only"))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if len(result.MatchedRules) != 0 {
		t.Fatalf("Expected 0 matches (global failed), got %d", len(result.MatchedRules))
	}

	// Data with both "HEADER" and "FOOTER" — both should match
	result, err = scanner.Scan([]byte("HEADER and FOOTER"))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if len(result.MatchedRules) != 2 {
		t.Fatalf("Expected 2 matches, got %d", len(result.MatchedRules))
	}
}

// --- Private Rules ---

func TestPrivateRuleNotReported(t *testing.T) {
	source := `
private rule private1 {
	condition: true
}
rule normal {
	condition: true
}`
	compiler := NewCompiler()
	program, err := compiler.CompileSource(source)
	if err != nil {
		t.Fatalf("CompileSource: %v", err)
	}

	scanner := NewScanner(program)
	defer scanner.Close()

	result, err := scanner.Scan([]byte("dummy"))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	// Private rule should not appear in results
	if len(result.MatchedRules) != 1 {
		t.Fatalf("Expected 1 match, got %d", len(result.MatchedRules))
	}
	if result.MatchedRules[0].Rule != "normal" {
		t.Errorf("Expected normal, got %s", result.MatchedRules[0].Rule)
	}

	// But the rule result should still be tracked internally
	if !result.RuleResults["private1"] {
		t.Error("Expected private1 to have matched internally")
	}
}

func TestPrivateRuleCanMatch(t *testing.T) {
	// Private rule still executes and can be referenced
	source := `
private rule helper {
	strings:
		$a = "SECRET"
	condition:
		$a
}
rule normal {
	condition:
		true
}`
	compiler := NewCompiler()
	program, err := compiler.CompileSource(source)
	if err != nil {
		t.Fatalf("CompileSource: %v", err)
	}

	scanner := NewScanner(program)
	defer scanner.Close()

	result, err := scanner.Scan([]byte("SECRET data"))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	// Private rule should not be in MatchedRules
	if len(result.MatchedRules) != 1 {
		t.Fatalf("Expected 1 match, got %d", len(result.MatchedRules))
	}
	if result.MatchedRules[0].Rule != "normal" {
		t.Errorf("Expected normal, got %s", result.MatchedRules[0].Rule)
	}

	// But internally it should have matched
	if !result.RuleResults["helper"] {
		t.Error("Expected helper to have matched internally")
	}
}

// --- Combined Global + Private ---

func TestGlobalPrivateCombined(t *testing.T) {
	source := `
global rule global_check {
	condition: true
}
private rule private_check {
	condition: true
}
rule normal {
	condition: true
}`
	compiler := NewCompiler()
	program, err := compiler.CompileSource(source)
	if err != nil {
		t.Fatalf("CompileSource: %v", err)
	}

	scanner := NewScanner(program)
	defer scanner.Close()

	result, err := scanner.Scan([]byte("dummy"))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	// Only global_check and normal should appear (private_check is hidden)
	if len(result.MatchedRules) != 2 {
		t.Fatalf("Expected 2 matches, got %d", len(result.MatchedRules))
	}

	// Verify internal results
	if !result.RuleResults["global_check"] {
		t.Error("Expected global_check to match")
	}
	if !result.RuleResults["private_check"] {
		t.Error("Expected private_check to match internally")
	}
	if !result.RuleResults["normal"] {
		t.Error("Expected normal to match")
	}
}

// --- CompiledRule fields ---

func TestCompiledRuleModifierFields(t *testing.T) {
	source := `
global private rule gp {
	condition: true
}
private rule p {
	condition: true
}
global rule g {
	condition: true
}
rule n {
	condition: true
}`
	compiler := NewCompiler()
	program, err := compiler.CompileSource(source)
	if err != nil {
		t.Fatalf("CompileSource: %v", err)
	}

	expect := map[string]struct{ global, private bool }{
		"gp": {true, true},
		"p":  {false, true},
		"g":  {true, false},
		"n":  {false, false},
	}

	for _, rule := range program.Rules {
		e, ok := expect[rule.Name]
		if !ok {
			t.Errorf("Unexpected rule %s", rule.Name)
			continue
		}
		if rule.IsGlobal != e.global {
			t.Errorf("%s: IsGlobal=%v, want %v", rule.Name, rule.IsGlobal, e.global)
		}
		if rule.IsPrivate != e.private {
			t.Errorf("%s: IsPrivate=%v, want %v", rule.Name, rule.IsPrivate, e.private)
		}
	}
}
