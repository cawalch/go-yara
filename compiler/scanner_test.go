package compiler

import (
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/ast"
)

// --- Scanner types (moved from scanner.go — dead in production, kept for tests/benchmarks) ---

// Scanner provides a reusable, allocation-efficient YARA scanning engine.
//
// A Scanner is safe to reuse across multiple Scan calls but is NOT safe
// for concurrent use. Use one Scanner per goroutine.
type Scanner struct {
	program     *CompiledProgram
	interp      *Interpreter    // reused across calls
	matchCtx    *MatchContext   // reused across calls
	ruleResults map[string]bool // reused across calls
}

// ScanResult represents the result of scanning data against compiled rules.
type ScanResult struct {
	MatchedRules []RuleMatch
}

// RuleMatch represents a single rule match with details.
type RuleMatch struct {
	Rule    string
	Matches map[string][]Match // pattern -> matches (string-keyed for public API)
}

// NewScanner creates a new Scanner for the given compiled program.
func NewScanner(program *CompiledProgram) *Scanner {
	interp := interpreterPool.Get().(*Interpreter)
	interp.SetCompiledRules(program.Rules)
	interp.PreserveRuleResults = true // We manage this manually in Scan()

	ctx := matchContextPool.Get().(*MatchContext)

	return &Scanner{
		program:     program,
		interp:      interp,
		matchCtx:    ctx,
		ruleResults: make(map[string]bool),
	}
}

// Close releases resources held by the Scanner.
func (s *Scanner) Close() {
	if s.interp != nil {
		s.interp.Release()
		s.interp = nil
	}
	if s.matchCtx != nil {
		s.matchCtx.Release()
		s.matchCtx = nil
	}
}

// globalMatchEntry is a match routed by integer indices from the shared automaton.
type globalMatchEntry struct {
	strID string // string identifier (e.g. "$a")
	m     Match  // the match itself
}

// Scan scans the provided byte slice against the compiled rules.
func (s *Scanner) Scan(data []byte) (*ScanResult, error) {
	result := &ScanResult{
		MatchedRules: make([]RuleMatch, 0),
	}

	// 1. One-pass scan over all static strings using the SharedAutomaton.
	// Route matches by rule index using the SharedLookup table (O(1) integer routing,
	// no colon parsing or string allocation).
	globalByRule := make(map[int][]globalMatchEntry)

	if s.program.SharedAutomaton != nil {
		s.extractGlobalMatchesInt(data, globalByRule)
	}

	// Reset rule results for next Scan
	clear(s.ruleResults)

	for _, rule := range s.program.Rules {
		// Populate context specific to this rule
		s.matchCtx.Reset(data)

		// 2. Add static matches found in the fast global pass
		s.addStaticMatchesInt(rule, data, globalByRule[rule.Index])

		// 3. Process Regex (and un-analyzable) patterns locally since they require dynamic scans
		for id, regexInfo := range rule.RegexPatterns {
			modifiers := rule.StringModifiers[id]
			addRegexMatchesWithModifiers(s.matchCtx, id, regexInfo, data, modifiers)
		}

		s.interp.SetCurrentRule(rule.Name)
		s.interp.SetMatchContext(s.matchCtx)
		s.interp.SetRuleResults(s.ruleResults)

		if err := s.interp.Execute(); err != nil {
			return nil, err
		}

		// If matched, deep copy matches for the result.
		if s.interp.GetRuleResults()[rule.Name] {
			matches := make(map[string][]Match, len(s.matchCtx.Matches))
			for k, v := range s.matchCtx.Matches {
				dst := make([]Match, len(v))
				copy(dst, v)
				matches[k] = dst
			}

			result.MatchedRules = append(result.MatchedRules, RuleMatch{
				Rule:    rule.Name,
				Matches: matches,
			})
		}
	}

	// Reset rule results for next Scan
	clear(s.ruleResults)

	return result, nil
}

// ScanReader reads from the reader and scans the data.
func (s *Scanner) ScanReader(r io.Reader) (*ScanResult, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return s.Scan(data)
}

// ScanFile scans the given file.
func (s *Scanner) ScanFile(filename string) (*ScanResult, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return s.Scan(data)
}

// extractGlobalMatchesInt uses the SharedLookup table for O(1) integer routing
// instead of parsing colon-delimited string IDs.
func (s *Scanner) extractGlobalMatchesInt(data []byte, globalByRule map[int][]globalMatchEntry) {
	lookup := s.program.SharedLookup
	rules := s.program.Rules
	for match := range s.program.SharedAutomaton.SearchIter(data) {
		if match.StringIndex < 0 || match.StringIndex >= len(lookup) {
			continue
		}

		entry := lookup[match.StringIndex]
		length := 0
		if match.StringIndex >= 0 && match.StringIndex < len(s.program.SharedAutomaton.Strings) {
			info := s.program.SharedAutomaton.Strings[match.StringIndex]
			length = info.Length
		}

		var strID string
		if entry.RuleIndex >= 0 && entry.RuleIndex < len(rules) {
			rule := rules[entry.RuleIndex]
			if entry.StringIdx >= 0 && entry.StringIdx < len(rule.IndexToStringID) {
				strID = rule.IndexToStringID[entry.StringIdx]
			}
		}

		globalByRule[entry.RuleIndex] = append(globalByRule[entry.RuleIndex], globalMatchEntry{
			strID: strID,
			m: Match{
				Pattern: strID,
				Offset:  int64(match.Backtrack),
				Length:  length,
			},
		})
	}
}

// addStaticMatchesInt adds matches routed by integer indices to the match context.
func (s *Scanner) addStaticMatchesInt(rule *CompiledRule, data []byte, entries []globalMatchEntry) {
	for _, e := range entries {
		m := e.m
		if rule.StringKinds != nil && rule.StringKinds[m.Pattern] == StringKindText {
			isWide := false
			modifiers := rule.StringModifiers[m.Pattern]
			for _, mod := range modifiers {
				if mod.Type == ast.StringModifierWide {
					isWide = true
					break
				}
			}
			if matchPassesModifiers(data, m, modifiers, isWide) {
				s.matchCtx.AddMatch(m)
			}
		} else if matchPassesModifiers(data, m, rule.StringModifiers[m.Pattern], false) {
			s.matchCtx.AddMatch(m)
		}
	}
}

// --- End Scanner types ---

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
