package compiler

import (
	"context"
	"testing"
)

func TestScannerWithoutMatchesAndRuleResults(t *testing.T) {
	ruleSource := `
		rule alpha {
			strings:
				$a = "needle_alpha"
			condition:
				$a
		}
		rule beta {
			strings:
				$b = "needle_beta"
			condition:
				$b
		}
		rule gamma {
			strings:
				$c = "needle_gamma"
			condition:
				$c
		}
	`

	compiler := NewCompiler()
	program, err := compiler.CompileSource(ruleSource)
	if err != nil {
		t.Fatalf("CompileSource failed: %v", err)
	}

	data := []byte("here is needle_alpha and needle_beta but not the third")

	t.Run("default_materializes_matches_and_rule_results", func(t *testing.T) {
		scanner := NewScanner(program)
		defer scanner.Close()

		res, err := scanner.Scan(data)
		if err != nil {
			t.Fatalf("Scan failed: %v", err)
		}

		if len(res.MatchedRules) != 2 {
			t.Fatalf("expected 2 matched rules, got %d", len(res.MatchedRules))
		}
		if res.RuleResults == nil || !res.RuleResults["alpha"] || !res.RuleResults["beta"] || res.RuleResults["gamma"] {
			t.Fatalf("unexpected RuleResults: %v", res.RuleResults)
		}
		if res.Matches == nil || len(res.Matches["alpha"]["$a"]) != 1 {
			t.Fatalf("expected matches in ScanResult.Matches, got %v", res.Matches)
		}
		if len(res.MatchedRules[0].Matches) == 0 {
			t.Fatalf("expected matches in RuleMatch.Matches, got %v", res.MatchedRules[0].Matches)
		}
	})

	t.Run("without_matches_omits_match_maps", func(t *testing.T) {
		scanner := NewScanner(program, WithoutMatches())
		defer scanner.Close()

		res, err := scanner.Scan(data)
		if err != nil {
			t.Fatalf("Scan failed: %v", err)
		}

		if len(res.MatchedRules) != 2 {
			t.Fatalf("expected 2 matched rules, got %d", len(res.MatchedRules))
		}
		// RuleResults is still populated by default
		if res.RuleResults == nil || !res.RuleResults["alpha"] || !res.RuleResults["beta"] {
			t.Fatalf("expected RuleResults populated, got: %v", res.RuleResults)
		}
		// Matches must be nil
		if res.Matches != nil {
			t.Fatalf("expected res.Matches to be nil, got: %v", res.Matches)
		}
		for _, match := range res.MatchedRules {
			if match.Matches != nil {
				t.Fatalf("expected RuleMatch.Matches to be nil, got: %v", match.Matches)
			}
		}
	})

	t.Run("without_rule_results_omits_rule_results_map", func(t *testing.T) {
		scanner := NewScanner(program, WithoutRuleResults())
		defer scanner.Close()

		res, err := scanner.Scan(data)
		if err != nil {
			t.Fatalf("Scan failed: %v", err)
		}

		if len(res.MatchedRules) != 2 {
			t.Fatalf("expected 2 matched rules, got %d", len(res.MatchedRules))
		}
		if res.RuleResults != nil {
			t.Fatalf("expected res.RuleResults to be nil, got: %v", res.RuleResults)
		}
		// Matches are still populated
		if res.Matches == nil || len(res.Matches["alpha"]["$a"]) != 1 {
			t.Fatalf("expected matches in ScanResult.Matches, got: %v", res.Matches)
		}
	})

	t.Run("without_matches_and_without_rule_results", func(t *testing.T) {
		scanner := NewScanner(program, WithoutMatches(), WithoutRuleResults())
		defer scanner.Close()

		res, err := scanner.Scan(data)
		if err != nil {
			t.Fatalf("Scan failed: %v", err)
		}

		if len(res.MatchedRules) != 2 {
			t.Fatalf("expected 2 matched rules, got %d", len(res.MatchedRules))
		}
		if res.RuleResults != nil {
			t.Fatalf("expected res.RuleResults to be nil, got: %v", res.RuleResults)
		}
		if res.Matches != nil {
			t.Fatalf("expected res.Matches to be nil, got: %v", res.Matches)
		}
		for _, match := range res.MatchedRules {
			if match.Matches != nil {
				t.Fatalf("expected RuleMatch.Matches to be nil, got: %v", match.Matches)
			}
		}
	})

	t.Run("matching_rules_with_without_matches", func(t *testing.T) {
		scanner := NewScanner(program, WithoutMatches())
		defer scanner.Close()

		matches, err := scanner.MatchingRulesWithContext(context.Background(), data)
		if err != nil {
			t.Fatalf("MatchingRulesWithContext failed: %v", err)
		}

		if len(matches) != 2 {
			t.Fatalf("expected 2 matched rules, got %d", len(matches))
		}
		for _, m := range matches {
			if m.Matches != nil {
				t.Fatalf("expected RuleMatch.Matches to be nil, got: %v", m.Matches)
			}
		}
	})

	t.Run("with_include_matches_toggle", func(t *testing.T) {
		scanner := NewScanner(program, WithIncludeMatches(false), WithIncludeRuleResults(false))
		defer scanner.Close()

		res, err := scanner.Scan(data)
		if err != nil {
			t.Fatalf("Scan failed: %v", err)
		}
		if res.Matches != nil || res.RuleResults != nil {
			t.Fatalf("expected nil matches and rule results, got matches=%v ruleResults=%v", res.Matches, res.RuleResults)
		}
		if len(res.MatchedRules) != 2 {
			t.Fatalf("expected 2 matched rules, got %d", len(res.MatchedRules))
		}
	})
}

func TestScannerZeroAllocationReject(t *testing.T) {
	ruleSource := `
		rule reject_me {
			strings:
				$a = "needle_not_found"
			condition:
				$a
		}
	`
	compiler := NewCompiler()
	program, err := compiler.CompileSource(ruleSource)
	if err != nil {
		t.Fatalf("CompileSource failed: %v", err)
	}

	scanner := NewScanner(program, WithoutMatches(), WithoutRuleResults(), WithFastScan())
	defer scanner.Close()

	data := []byte("completely unrelated payload without the target needle")

	// Warm-up
	if _, err := scanner.MatchingRules(data); err != nil {
		t.Fatalf("warm-up failed: %v", err)
	}

	allocs := testing.AllocsPerRun(100, func() {
		matches, scanErr := scanner.MatchingRules(data)
		if scanErr != nil || len(matches) != 0 {
			t.Fatalf("unexpected result: matches=%v err=%v", matches, scanErr)
		}
	})

	if allocs != 0 {
		t.Errorf("expected 0 allocs for clean reject with WithoutMatches, got %f", allocs)
	}
}
