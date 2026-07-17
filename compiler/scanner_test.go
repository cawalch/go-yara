package compiler

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/parser"
)

// compileSources compiles multiple YARA rule source strings into a CompiledProgram.
func compileSources(sources []string) (*CompiledProgram, error) {
	program := &ast.Program{
		Rules: make([]*ast.Rule, 0, len(sources)),
	}
	for _, src := range sources {
		l := lexer.New(src)
		p := parser.New(l)
		parsed, err := p.ParseRulesWithContext(context.Background())
		if err != nil {
			return nil, err
		}
		program.Rules = append(program.Rules, parsed.Rules...)
	}
	rc := NewRuleCompiler()
	rules, err := rc.CompileProgram(program)
	if err != nil {
		return nil, err
	}
	return &CompiledProgram{Rules: rules}, nil
}

func BenchmarkScanner(b *testing.B) {
	// Simple rule match
	ruleSource := `rule test { condition: true }`
	compiler := NewCompiler()
	program, err := compiler.CompileSource(ruleSource)
	if err != nil {
		b.Fatalf("CompileSource: %v", err)
	}

	scanner := NewScanner(program)
	defer scanner.Close()

	data := []byte("dummy data")
	result, err := scanner.Scan(data)
	if err != nil {
		b.Fatalf("Scan: %v", err)
	}

	if len(result.MatchedRules) != 1 {
		b.Fatalf("Expected 1 match, got %d", len(result.MatchedRules))
	}
	if result.MatchedRules[0].Rule != "test" {
		b.Errorf("Expected rule 'test', got '%s'", result.MatchedRules[0].Rule)
	}

	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := scanner.Scan(data); err != nil {
			b.Fatal(err)
		}
	}
}

func TestScannerMultiRuleDependency(t *testing.T) {
	// Rule B depends on Rule A
	ruleSource := `
		rule A { condition: true }
		rule B { condition: A }
	`
	compiler := NewCompiler()
	program, err := compiler.CompileSource(ruleSource)
	if err != nil {
		t.Fatalf("CompileSource: %v", err)
	}

	scanner := NewScanner(program)
	defer scanner.Close()

	result, err := scanner.Scan([]byte("data"))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if len(result.MatchedRules) != 2 {
		// Log which rules matched
		var matched []string
		for _, m := range result.MatchedRules {
			matched = append(matched, m.Rule)
		}
		t.Fatalf("Expected 2 matches, got %d: %v", len(result.MatchedRules), matched)
	}
}

func TestScannerStringMatch(t *testing.T) {
	ruleSource := `rule match_foo { strings: $a = "foo" condition: $a }`
	compiler := NewCompiler()
	program, err := compiler.CompileSource(ruleSource)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	scanner := NewScanner(program)
	defer scanner.Close()

	data := []byte("bar foo baz")
	result, err := scanner.Scan(data)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if len(result.MatchedRules) != 1 {
		t.Fatalf("Expected 1 match, got %d", len(result.MatchedRules))
	}

	match := result.MatchedRules[0]
	if match.Rule != "match_foo" {
		t.Errorf("Wrong rule: %s", match.Rule)
	}

	// Check match details
	matches, ok := match.Matches["$a"]
	if !ok || len(matches) != 1 {
		t.Fatalf("Expected match for $a")
	}
	if matches[0].Offset != 4 {
		t.Errorf("Offset expected 4, got %d", matches[0].Offset)
	}
}

func TestScannerReportedMatchesOnly(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
		private rule helper {
			strings: $helper = "needle"
			condition: $helper
		}
		rule accepted {
			strings:
				$public = "needle"
				$hidden = "needle" private
			condition: $public and $hidden and helper
		}
		rule rejected {
			strings: $rejected = "needle"
			condition: false
		}
	`)
	if err != nil {
		t.Fatalf("CompileSource: %v", err)
	}

	defaultScanner := NewScanner(program)
	defer defaultScanner.Close()
	defaultResult, err := defaultScanner.Scan([]byte("needle"))
	if err != nil {
		t.Fatalf("default Scan: %v", err)
	}
	for _, rule := range []string{"helper", "accepted", "rejected"} {
		if _, ok := defaultResult.Matches[rule]; !ok {
			t.Errorf("default result omitted matches for evaluated rule %q", rule)
		}
	}

	reportedScanner := NewScanner(program, WithReportedMatchesOnly())
	defer reportedScanner.Close()
	reportedResult, err := reportedScanner.Scan([]byte("needle"))
	if err != nil {
		t.Fatalf("reported-only Scan: %v", err)
	}
	if len(reportedResult.Matches) != 1 {
		t.Fatalf("reported-only Matches = %v, want accepted only", reportedResult.Matches)
	}
	accepted, ok := reportedResult.Matches["accepted"]
	if !ok {
		t.Fatalf("reported-only result omitted accepted rule: %v", reportedResult.Matches)
	}
	if len(accepted["$public"]) != 1 {
		t.Fatalf("accepted public matches = %v, want one", accepted["$public"])
	}
	if _, ok := accepted["$hidden"]; ok {
		t.Fatal("reported-only result included a private string")
	}
	if len(reportedResult.MatchedRules) != 1 || reportedResult.MatchedRules[0].Rule != "accepted" {
		t.Fatalf("MatchedRules = %v, want accepted only", reportedResult.MatchedRules)
	}
	if !reportedResult.RuleResults["helper"] || !reportedResult.RuleResults["accepted"] || reportedResult.RuleResults["rejected"] {
		t.Fatalf("RuleResults changed in reported-only mode: %v", reportedResult.RuleResults)
	}
}

func TestScannerMatchEvidenceDefaultDisabled(t *testing.T) {
	ruleSource := `rule match_foo { strings: $a = "foo" condition: $a }`
	compiler := NewCompiler()
	program, err := compiler.CompileSource(ruleSource)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	for _, tt := range []struct {
		name string
		opts []ScannerOption
	}{
		{name: "default"},
		{name: "zero match data", opts: []ScannerOption{WithMatchData(0)}},
		{name: "negative match data", opts: []ScannerOption{WithMatchData(-1)}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			scanner := NewScanner(program, tt.opts...)
			defer scanner.Close()

			result, err := scanner.Scan([]byte("bar foo baz"))
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}

			match := result.MatchedRules[0].Matches["$a"][0]
			if match.MatchedData != nil {
				t.Fatalf("MatchedData = %q, want nil", match.MatchedData)
			}
			if match.ContextBefore != nil {
				t.Fatalf("ContextBefore = %q, want nil", match.ContextBefore)
			}
			if match.ContextAfter != nil {
				t.Fatalf("ContextAfter = %q, want nil", match.ContextAfter)
			}
			if match.MatchedDataTruncated {
				t.Fatalf("MatchedDataTruncated = true, want false")
			}
		})
	}
}

func TestMatchContextResetReusesMatchStorage(t *testing.T) {
	ctx := &MatchContext{
		Matches:      make(map[string][]Match),
		matchBuffers: make(map[string][]Match),
	}
	ctx.Reset(nil)
	for offset := range 128 {
		ctx.AddMatch(Match{Pattern: "$a", Offset: int64(offset), Length: 1})
	}
	first := &ctx.Matches["$a"][0]

	ctx.Reset(nil)
	ctx.AddMatch(Match{Pattern: "$a", Offset: 7, Length: 1})
	if second := &ctx.Matches["$a"][0]; first != second {
		t.Fatal("Reset discarded the reusable match backing array")
	}
}

func TestScannerMatchDataTruncation(t *testing.T) {
	ruleSource := `rule match_blob { strings: $a = "abcdef" condition: $a }`
	compiler := NewCompiler()
	program, err := compiler.CompileSource(ruleSource)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	scanner := NewScanner(program, WithMatchData(3))
	defer scanner.Close()

	data := []byte("xxabcdefyy")
	result, err := scanner.Scan(data)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	match := result.MatchedRules[0].Matches["$a"][0]
	if string(match.MatchedData) != "abc" {
		t.Fatalf("MatchedData = %q, want %q", match.MatchedData, "abc")
	}
	if !match.MatchedDataTruncated {
		t.Fatalf("MatchedDataTruncated = false, want true")
	}

	data[2] = 'z'
	if string(match.MatchedData) != "abc" {
		t.Fatalf("MatchedData was not copied, got %q after mutating input", match.MatchedData)
	}
}

func TestCompiledProgramNewScannerOptions(t *testing.T) {
	ruleSource := `rule match_blob { strings: $a = "abcdef" condition: $a }`
	compiler := NewCompiler()
	program, err := compiler.CompileSource(ruleSource)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	scanner := program.NewScanner(WithMatchData(4))
	defer scanner.Close()

	result, err := scanner.Scan([]byte("xxabcdefyy"))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	match := result.MatchedRules[0].Matches["$a"][0]
	if string(match.MatchedData) != "abcd" {
		t.Fatalf("MatchedData = %q, want %q", match.MatchedData, "abcd")
	}
	if !match.MatchedDataTruncated {
		t.Fatalf("MatchedDataTruncated = false, want true")
	}
}

func TestScannerMatchContextBoundaries(t *testing.T) {
	ruleSource := `rule boundary { strings: $start = "foo" $end = "bar" condition: all of them }`
	compiler := NewCompiler()
	program, err := compiler.CompileSource(ruleSource)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	scanner := NewScanner(program, WithMatchContext(10, 10))
	defer scanner.Close()

	result, err := scanner.Scan([]byte("foo--bar"))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	matches := result.MatchedRules[0].Matches
	start := matches["$start"][0]
	if start.ContextBefore == nil || string(start.ContextBefore) != "" {
		t.Fatalf("start ContextBefore = %q, want empty copied slice", start.ContextBefore)
	}
	if string(start.ContextAfter) != "--bar" {
		t.Fatalf("start ContextAfter = %q, want %q", start.ContextAfter, "--bar")
	}

	end := matches["$end"][0]
	if string(end.ContextBefore) != "foo--" {
		t.Fatalf("end ContextBefore = %q, want %q", end.ContextBefore, "foo--")
	}
	if end.ContextAfter == nil || string(end.ContextAfter) != "" {
		t.Fatalf("end ContextAfter = %q, want empty copied slice", end.ContextAfter)
	}
}

func TestScannerHexMatch(t *testing.T) {
	ruleSource := `rule match_hex { strings: $a = { DE AD BE EF } condition: $a }`
	compiler := NewCompiler()
	program, err := compiler.CompileSource(ruleSource)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	result, err := program.Scan([]byte{0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x00})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if len(result.MatchedRules) != 1 {
		t.Fatalf("Expected 1 match, got %d", len(result.MatchedRules))
	}
	matches := result.MatchedRules[0].Matches["$a"]
	if len(matches) != 1 {
		t.Fatalf("Expected 1 hex match, got %d", len(matches))
	}
	if matches[0].Offset != 1 || matches[0].Length != 4 {
		t.Fatalf("Expected hex match at offset 1 length 4, got offset %d length %d", matches[0].Offset, matches[0].Length)
	}
}

func TestScannerWideTextSharedAutomaton(t *testing.T) {
	ruleSource := `rule match_wide { strings: $a = "hi" wide condition: $a }`
	compiler := NewCompiler()
	program, err := compiler.CompileSource(ruleSource)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if program.SharedAutomaton == nil || len(program.SharedLookup) == 0 {
		t.Fatalf("expected compiled program to build shared automaton")
	}

	result, err := program.Scan([]byte{'h', 0, 'i', 0})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(result.MatchedRules) != 1 {
		t.Fatalf("Expected wide text match via shared automaton, got %d", len(result.MatchedRules))
	}
}

func TestCompiledProgramExternalVariables(t *testing.T) {
	ruleSource := `
		external gate
		external threshold
		rule gate_rule { condition: gate }
		rule threshold_rule { condition: threshold == 7 }
	`
	compiler := NewCompiler()
	program, err := compiler.CompileSource(ruleSource)
	if err != nil {
		t.Fatalf("CompileSource: %v", err)
	}

	if err := program.SetExternalVariables(map[string]any{
		"gate":      true,
		"threshold": uint(7),
	}); err != nil {
		t.Fatalf("SetExternalVariables: %v", err)
	}
	result, err := program.Scan([]byte("data"))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !result.RuleResults["gate_rule"] || !result.RuleResults["threshold_rule"] {
		t.Fatalf("expected external values to satisfy rule")
	}

	if err := program.SetExternalVariables(map[string]any{
		"gate":      false,
		"threshold": int64(7),
	}); err != nil {
		t.Fatalf("SetExternalVariables false gate: %v", err)
	}
	result, err = program.Scan([]byte("data"))
	if err != nil {
		t.Fatalf("Scan false gate: %v", err)
	}
	if result.RuleResults["gate_rule"] {
		t.Fatalf("expected false external value to prevent match")
	}
	if !result.RuleResults["threshold_rule"] {
		t.Fatalf("expected integer external value to continue satisfying rule")
	}
}

func TestScannerStringExternalVariable(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
		external marker
		rule r { condition: marker == "needle" }
	`)
	if err != nil {
		t.Fatalf("CompileSource: %v", err)
	}

	scanner := NewScanner(program, WithExternalVariables(map[string]any{"marker": "needle"}))
	defer scanner.Close()

	result, err := scanner.Scan([]byte("data"))
	if err != nil {
		t.Fatalf("Scan matching marker: %v", err)
	}
	if !result.RuleResults["r"] {
		t.Fatalf("expected string external value to satisfy rule")
	}

	if err := scanner.SetExternalVariables(map[string]any{"marker": "other"}); err != nil {
		t.Fatalf("SetExternalVariables other marker: %v", err)
	}
	result, err = scanner.Scan([]byte("data"))
	if err != nil {
		t.Fatalf("Scan nonmatching marker: %v", err)
	}
	if result.RuleResults["r"] {
		t.Fatalf("expected nonmatching string external value to prevent match")
	}
}

func TestScannerExternalVariables(t *testing.T) {
	ruleSource := `
		external gate
		rule r {
			strings:
				$a = "needle"
			condition:
				gate and $a
		}
	`
	compiler := NewCompiler()
	program, err := compiler.CompileSource(ruleSource)
	if err != nil {
		t.Fatalf("CompileSource: %v", err)
	}

	scanner := NewScanner(program, WithExternalVariables(map[string]any{"gate": true}))
	defer scanner.Close()

	result, err := scanner.Scan([]byte("needle"))
	if err != nil {
		t.Fatalf("Scan true gate: %v", err)
	}
	if !result.RuleResults["r"] {
		t.Fatalf("expected scanner external value and string match to satisfy rule")
	}

	if err := scanner.SetExternalVariables(map[string]any{"gate": false}); err != nil {
		t.Fatalf("SetExternalVariables false gate: %v", err)
	}
	result, err = scanner.Scan([]byte("needle"))
	if err != nil {
		t.Fatalf("Scan false gate: %v", err)
	}
	if result.RuleResults["r"] {
		t.Fatalf("expected scanner external override to prevent match")
	}
}

func TestExternalVariablesRejectInvalidInput(t *testing.T) {
	compiler := NewCompiler()
	program, err := compiler.CompileSource(`external gate rule r { condition: gate }`)
	if err != nil {
		t.Fatalf("CompileSource: %v", err)
	}

	if err := program.SetExternalVariables(map[string]any{"missing": true}); err == nil {
		t.Fatalf("expected undeclared external variable to be rejected")
	}
	if err := program.SetExternalVariables(map[string]any{"gate": uint64(1 << 63)}); err == nil {
		t.Fatalf("expected out-of-range unsigned integer to be rejected")
	}

	scanner := NewScanner(program, WithExternalVariables(map[string]any{"missing": true}))
	defer scanner.Close()
	if _, err := scanner.Scan([]byte("data")); err == nil {
		t.Fatalf("expected scanner option error to be reported by Scan")
	}
}

func TestScannerRead64Functions(t *testing.T) {
	tests := []struct {
		name string
		rule string
		data []byte
	}{
		{name: "uint64", rule: `rule r { condition: uint64(0) == 1 }`, data: []byte{1, 0, 0, 0, 0, 0, 0, 0}},
		{name: "int64", rule: `rule r { condition: int64(0) == 1 }`, data: []byte{1, 0, 0, 0, 0, 0, 0, 0}},
		{name: "uint64be", rule: `rule r { condition: uint64be(0) == 1 }`, data: []byte{0, 0, 0, 0, 0, 0, 0, 1}},
		{name: "int64be", rule: `rule r { condition: int64be(0) == 1 }`, data: []byte{0, 0, 0, 0, 0, 0, 0, 1}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compiler := NewCompiler()
			program, err := compiler.CompileSource(tt.rule)
			if err != nil {
				t.Fatalf("CompileSource: %v", err)
			}
			result, err := program.Scan(tt.data)
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			if !result.RuleResults["r"] {
				t.Fatalf("expected %s rule to match", tt.name)
			}
		})
	}
}

func TestScannerReuse(t *testing.T) {
	// Test reusing scanner for multiple scans
	ruleSource := `rule find_foo { strings: $a = "foo" condition: $a }`
	compiler := NewCompiler()
	program, err := compiler.CompileSource(ruleSource)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	scanner := NewScanner(program)
	defer scanner.Close()

	// Scan 1: match
	res1, err := scanner.Scan([]byte("foo"))
	if err != nil {
		t.Fatalf("Scan 1: %v", err)
	}
	if len(res1.MatchedRules) != 1 {
		t.Errorf("Scan 1 expected match")
	}

	// Scan 2: no match
	res2, err := scanner.Scan([]byte("bar"))
	if err != nil {
		t.Fatalf("Scan 2: %v", err)
	}
	if len(res2.MatchedRules) != 0 {
		t.Errorf("Scan 2 expected no match")
	}

	// Scan 3: match again
	res3, err := scanner.Scan([]byte("foo bar"))
	if err != nil {
		t.Fatalf("Scan 3: %v", err)
	}
	if len(res3.MatchedRules) != 1 {
		t.Errorf("Scan 3 expected match")
	}
}

// BenchmarkMultiRuleScanner tests the performance of the Scanner engine when executing a massive amount of rules simultaneously
func BenchmarkMultiRuleScanner(b *testing.B) {
	// Create a large number of simple rules
	const numRules = 1000
	var ruleSource strings.Builder
	for i := range numRules {
		// Use simple true conditions and a string pattern so we engage the AC automaton
		fmt.Fprintf(&ruleSource, "rule r%d { strings: $a = \"test_pattern\" condition: $a }\n", i)
	}

	compiler := NewCompiler()
	program, err := compiler.CompileSource(ruleSource.String())
	if err != nil {
		b.Fatalf("compile failed: %v", err)
	}

	scanner := NewScanner(program)
	defer scanner.Close()

	data := []byte("some random data with test_pattern inside it for matching")

	b.ResetTimer()
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))

	for b.Loop() {
		// We execute the scanner against the same payload repeatedly
		_, err := scanner.Scan(data)
		if err != nil {
			b.Fatalf("scan failed: %v", err)
		}
	}
}

// BenchmarkProductionScanner tests the performance of the Scanner engine using a realistic
// mix of large rulesets, regex patterns, complex conditions, and various modifiers to simulate
// a production scanning workload. This specifically targets interpreter/virtual machine throughput.
func BenchmarkProductionScanner(b *testing.B) {
	// Provide a realistic but scalable workload for benchmark profiling
	const numRules = 20
	var ruleSource strings.Builder

	// Generate a mix of moderately complex rules
	for i := range numRules {
		// Even rules: hex strings and conditions
		// Odd rules: regex strings and text modifiers
		if i%2 == 0 {
			fmt.Fprintf(&ruleSource, `
			rule r_%d {
				strings:
					$hex1 = { 0a 0b [2-4] 0c 0d }
					$hex2 = { DE AD BE EF }
				condition:
					$hex1 or ($hex2 at 0)
			}
			`, i)
		} else {
			fmt.Fprintf(&ruleSource, `
			rule r_%d {
				strings:
					$str1 = "suspicious_payload" wide nocase
					$re1 = /malwa[a-z]{1,2}\.exe/i
				condition:
					$str1 and $re1
			}
			`, i)
		}
	}

	compiler := NewCompiler()
	program, err := compiler.CompileSource(ruleSource.String())
	if err != nil {
		b.Fatalf("compile failed: %v", err)
	}

	scanner := NewScanner(program)
	defer scanner.Close()

	// A realistic 100KB payload mimicking a binary
	data := make([]byte, 100*1024)
	for i := range data {
		data[i] = byte(i % 256)
	}

	// Inject some patterns that will match
	copy(data[50:], []byte{0xDE, 0xAD, 0xBE, 0xEF})
	copy(data[8000:], "suspicious_payload in a wide format maybe?")
	copy(data[50000:], "some malware_variant.exe running")
	copy(data[70000:], []byte{0x0a, 0x0b, 0x00, 0x00, 0x00, 0x0c, 0x0d})

	b.ResetTimer()
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))

	for b.Loop() {
		_, err := scanner.Scan(data)
		if err != nil {
			b.Fatalf("scan failed: %v", err)
		}
	}
}

func BenchmarkProductionScannerUniquePatterns(b *testing.B) {
	const numRules = 20
	var source strings.Builder
	for i := range numRules {
		if i%2 == 0 {
			fmt.Fprintf(&source, `
				rule unique_hex_%d {
					strings:
						$hex = { %02X %02X [2-4] 0C 0D }
					condition: $hex
				}
			`, i, 0x20+i, 0x40+i)
		} else {
			fmt.Fprintf(&source, `
				rule unique_regex_%d {
					strings:
						$text = "unique_text_%d" nocase
						$re = /family%d_[a-z]{1,2}\.exe/i
					condition: $text or $re
				}
			`, i, i, i)
		}
	}

	program, err := NewCompiler().CompileSource(source.String())
	if err != nil {
		b.Fatal(err)
	}
	scanner := NewScanner(program)
	defer scanner.Close()
	data := make([]byte, 100*1024)
	for i := range data {
		data[i] = byte(i % 256)
	}

	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := scanner.Scan(data); err != nil {
			b.Fatal(err)
		}
	}
}

func TestScannerSharedPatternsPreserveRuleMatches(t *testing.T) {
	source := `
		rule regex_a {
			strings: $a = /malwa[a-z]{1,2}\.exe/i
			condition: #a == 2
		}
		rule regex_b {
			strings: $other = /malwa[a-z]{1,2}\.exe/i
			condition: #other == 2
		}
		rule hex_a {
			strings: $h = { DE AD BE EF }
			condition: $h
		}
		rule hex_b {
			strings: $bytes = { DE AD BE EF }
			condition: $bytes
		}
		rule text_a {
			strings: $text = "shared literal"
			condition: $text
		}
		rule text_b {
			strings: $other_text = "shared literal"
			condition: $other_text
		}
	`
	program, err := NewCompiler().CompileSource(source)
	if err != nil {
		t.Fatal(err)
	}
	scanner := NewScanner(program)
	defer scanner.Close()

	data := append([]byte("MALWARE.EXE then malware.exe shared literal "), 0xDE, 0xAD, 0xBE, 0xEF)
	result, err := scanner.Scan(data)
	if err != nil {
		t.Fatal(err)
	}
	for rule, id := range map[string]string{
		"regex_a": "$a",
		"regex_b": "$other",
		"hex_a":   "$h",
		"hex_b":   "$bytes",
		"text_a":  "$text",
		"text_b":  "$other_text",
	} {
		if !result.RuleResults[rule] {
			t.Errorf("rule %s did not match", rule)
			continue
		}
		matches := result.Matches[rule][id]
		if len(matches) == 0 {
			t.Errorf("rule %s has no matches for %s", rule, id)
			continue
		}
		for _, match := range matches {
			if match.Pattern != id {
				t.Errorf("rule %s match pattern = %q, want %q", rule, match.Pattern, id)
			}
		}
	}
}

func TestScannerSharedRegexPatternsWithoutTextAutomaton(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
		rule first {
			strings: $a = /prefix_[a-z]+/i
			condition: #a == 2
		}
		rule second {
			strings: $b = /prefix_[a-z]+/i
			condition: #b == 2
		}
	`)
	if err != nil {
		t.Fatal(err)
	}
	if len(program.SharedLookup) != 0 {
		t.Fatalf("SharedLookup has %d text entries, want 0", len(program.SharedLookup))
	}
	scanner := NewScanner(program)
	defer scanner.Close()
	result, err := scanner.Scan([]byte("PREFIX_one prefix_two"))
	if err != nil {
		t.Fatal(err)
	}
	for rule, id := range map[string]string{"first": "$a", "second": "$b"} {
		if !result.RuleResults[rule] || len(result.Matches[rule][id]) != 2 {
			t.Errorf("%s results = %v, matches = %v", rule, result.RuleResults[rule], result.Matches[rule][id])
		}
	}
}

func TestScannerPrivateStringsFiltered(t *testing.T) {
	sources := []string{
		`rule test_rule { strings: $pub = "hello" $priv = "world" private condition: $pub and $priv }`,
	}
	program, err := compileSources(sources)
	if err != nil {
		t.Fatal(err)
	}

	scanner := NewScanner(program, WithMatchData(16), WithMatchContext(3, 3))
	defer scanner.Close()

	data := []byte("hello world")
	result, err := scanner.Scan(data)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.MatchedRules) != 1 {
		t.Fatalf("expected 1 matched rule, got %d", len(result.MatchedRules))
	}

	matches := result.MatchedRules[0].Matches
	if _, ok := matches["$priv"]; ok {
		t.Error("private string $priv should not appear in matches")
	}
	if _, ok := matches["$pub"]; !ok {
		t.Error("public string $pub should appear in matches")
	}
	if _, ok := result.Matches["test_rule"]["$priv"]; ok {
		t.Error("private string $priv should not appear in result.Matches")
	}
	pubMatches := result.Matches["test_rule"]["$pub"]
	if len(pubMatches) != 1 {
		t.Fatalf("expected public match in result.Matches, got %d", len(pubMatches))
	}
	if string(pubMatches[0].MatchedData) != "hello" {
		t.Fatalf("public MatchedData = %q, want %q", pubMatches[0].MatchedData, "hello")
	}
}

func TestScanWithContextCancellation(t *testing.T) {
	ruleSource := `rule match_foo { strings: $a = "foo" condition: $a }`
	compiler := NewCompiler()
	program, err := compiler.CompileSource(ruleSource)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := program.ScanWithContext(ctx, []byte("foo")); !errors.Is(err, context.Canceled) {
		t.Fatalf("CompiledProgram.ScanWithContext error = %v, want context.Canceled", err)
	}

	scanner := NewScanner(program)
	defer scanner.Close()
	if _, err := scanner.ScanWithContext(ctx, []byte("foo")); !errors.Is(err, context.Canceled) {
		t.Fatalf("Scanner.ScanWithContext error = %v, want context.Canceled", err)
	}
	if _, err := program.ScanReaderWithContext(ctx, strings.NewReader("foo")); !errors.Is(err, context.Canceled) {
		t.Fatalf("CompiledProgram.ScanReaderWithContext error = %v, want context.Canceled", err)
	}
	if _, err := program.ScanFileWithContext(ctx, "unused.bin"); !errors.Is(err, context.Canceled) {
		t.Fatalf("CompiledProgram.ScanFileWithContext error = %v, want context.Canceled", err)
	}
	if _, err := scanner.ScanReaderWithContext(ctx, strings.NewReader("foo")); !errors.Is(err, context.Canceled) {
		t.Fatalf("Scanner.ScanReaderWithContext error = %v, want context.Canceled", err)
	}
	if _, err := scanner.ScanFileWithContext(ctx, "unused.bin"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Scanner.ScanFileWithContext error = %v, want context.Canceled", err)
	}
}

func TestScannerTagsFilter(t *testing.T) {
	sources := []string{
		`rule test_a : tag1 { strings: $a = "hello" condition: $a }`,
		`rule test_b : tag2 { strings: $b = "world" condition: $b }`,
		`rule test_c : tag3 { strings: $c = "foo" condition: $c }`,
	}
	program, err := compileSources(sources)
	if err != nil {
		t.Fatal(err)
	}

	scanner := NewScanner(program, WithTagsFilter([]string{"tag2"}))
	defer scanner.Close()

	data := []byte("hello world foo")
	result, err := scanner.Scan(data)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.MatchedRules) != 1 {
		t.Errorf("expected 1 matched rule, got %d", len(result.MatchedRules))
	}
	if len(result.MatchedRules) > 0 && result.MatchedRules[0].Rule != "test_b" {
		t.Errorf("expected test_b, got %s", result.MatchedRules[0].Rule)
	}
}

func TestScannerTagsFilterMultiple(t *testing.T) {
	sources := []string{
		`rule test_a : tag1 { strings: $a = "hello" condition: $a }`,
		`rule test_b : tag2 { strings: $b = "world" condition: $b }`,
		`rule test_c : tag3 { strings: $c = "foo" condition: $c }`,
	}
	program, err := compileSources(sources)
	if err != nil {
		t.Fatal(err)
	}

	scanner := NewScanner(program, WithTagsFilter([]string{"tag1", "tag3"}))
	defer scanner.Close()

	data := []byte("hello world foo")
	result, err := scanner.Scan(data)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.MatchedRules) != 2 {
		t.Errorf("expected 2 matched rules, got %d", len(result.MatchedRules))
	}
}

func TestScannerTagsFilterNoneMatch(t *testing.T) {
	sources := []string{
		`rule test_a : tag1 { strings: $a = "hello" condition: $a }`,
	}
	program, err := compileSources(sources)
	if err != nil {
		t.Fatal(err)
	}

	scanner := NewScanner(program, WithTagsFilter([]string{"nonexistent"}))
	defer scanner.Close()

	data := []byte("hello")
	result, err := scanner.Scan(data)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.MatchedRules) != 0 {
		t.Errorf("expected 0 matched rules, got %d", len(result.MatchedRules))
	}
}

func TestScannerTagsFilterGlobalAlwaysEvaluated(t *testing.T) {
	sources := []string{
		`global rule global_rule { strings: $g = "goodbye" condition: $g }`,
		`rule test_a : tag1 { strings: $a = "hello" condition: $a }`,
	}
	program, err := compileSources(sources)
	if err != nil {
		t.Fatal(err)
	}

	// Filter for tag1 only; global_rule has no matching tag.
	// Global rules are always evaluated, so if global_rule doesn't match,
	// test_a should also be skipped.
	scanner := NewScanner(program, WithTagsFilter([]string{"tag1"}))
	defer scanner.Close()

	data := []byte("hello") // matches test_a but NOT global_rule
	result, err := scanner.Scan(data)
	if err != nil {
		t.Fatal(err)
	}

	// global_rule doesn't match, so test_a should be skipped (all global must match)
	if len(result.MatchedRules) != 0 {
		t.Errorf("expected 0 matched rules (global failed), got %d", len(result.MatchedRules))
	}
}

func TestScannerItersmax(t *testing.T) {
	src := `
rule test {
    condition:
        for any i in (0..1000) : (
            i > 0
        )
}`
	c := NewCompiler()
	program, err := c.CompileSource(src)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}

	// Without limit — should match
	scanner := NewScanner(program)
	result, err := scanner.Scan([]byte("test"))
	if err != nil {
		t.Fatalf("Scan() without limit error = %v", err)
	}
	if len(result.MatchedRules) != 1 {
		t.Errorf("expected 1 match, got %d", len(result.MatchedRules))
	}

	// With limit of 100 — should exceed (1001 iterations)
	scanner = NewScanner(program, WithItersmax(100))
	_, err = scanner.Scan([]byte("test"))
	if err == nil {
		t.Fatal("expected iteration limit error, got nil")
	}
	if err.Error() != "iteration limit exceeded (itersmax=100)" {
		t.Errorf("unexpected error message: %v", err)
	}

	// With limit of 1001 — should succeed (exactly at limit)
	scanner = NewScanner(program, WithItersmax(1001))
	result, err = scanner.Scan([]byte("test"))
	if err != nil {
		t.Fatalf("Scan() with limit 1001 error = %v", err)
	}
	if len(result.MatchedRules) != 1 {
		t.Errorf("expected 1 match, got %d", len(result.MatchedRules))
	}

	// With limit of 1000 — should exceed (1001 > 1000)
	scanner = NewScanner(program, WithItersmax(1000))
	_, err = scanner.Scan([]byte("test"))
	if err == nil {
		t.Fatal("expected iteration limit error, got nil")
	}
}
