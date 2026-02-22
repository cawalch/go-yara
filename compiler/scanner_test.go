package compiler

import (
	"fmt"
	"strings"
	"testing"
)

func TestScannerSimple(t *testing.T) {
	// Simple rule match
	ruleSource := `rule test { condition: true }`
	compiler := NewCompiler()
	program, err := compiler.CompileSource(ruleSource)
	if err != nil {
		t.Fatalf("CompileSource: %v", err)
	}

	scanner := NewScanner(program)
	defer scanner.Close()

	result, err := scanner.Scan([]byte("dummy data"))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if len(result.MatchedRules) != 1 {
		t.Fatalf("Expected 1 match, got %d", len(result.MatchedRules))
	}
	if result.MatchedRules[0].Rule != "test" {
		t.Errorf("Expected rule 'test', got '%s'", result.MatchedRules[0].Rule)
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
