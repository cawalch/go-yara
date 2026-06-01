package compiler

import (
	"context"
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

	result, err := scanner.Scan([]byte("dummy data"))
	if err != nil {
		b.Fatalf("Scan: %v", err)
	}

	if len(result.MatchedRules) != 1 {
		b.Fatalf("Expected 1 match, got %d", len(result.MatchedRules))
	}
	if result.MatchedRules[0].Rule != "test" {
		b.Errorf("Expected rule 'test', got '%s'", result.MatchedRules[0].Rule)
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

	for b.Loop() {
		_, err := scanner.Scan(data)
		if err != nil {
			b.Fatalf("scan failed: %v", err)
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

	scanner := NewScanner(program)
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
