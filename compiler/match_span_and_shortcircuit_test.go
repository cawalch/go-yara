package compiler

import (
	"strings"
	"testing"
)

func TestScannerWithMaxMatchSpan(t *testing.T) {
	source := `
rule long_match {
    strings:
        $url = /https?:\/\/[^\s]+/
    condition:
        $url
}
`
	program, err := NewCompiler().CompileSource(source)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}

	input := []byte("https://example.com/" + strings.Repeat("a", 5000))
	expectedFullLen := 4096 // libyara limits forward verification from the http atom.

	t.Run("DefaultVerificationDistance", func(t *testing.T) {
		s := NewScanner(program)
		defer s.Close()
		res, err := s.Scan(input)
		if err != nil {
			t.Fatalf("Scan() error = %v", err)
		}
		matches := res.Matches["long_match"]["$url"]
		if len(matches) != 1 {
			t.Fatalf("got %d matches, want 1", len(matches))
		}
		if matches[0].Length != expectedFullLen {
			t.Fatalf("got match length %d, want %d", matches[0].Length, expectedFullLen)
		}
	})

	t.Run("BoundedTo100Bytes", func(t *testing.T) {
		s := NewScanner(program, WithMaxMatchSpan(100))
		defer s.Close()
		res, err := s.Scan(input)
		if err != nil {
			t.Fatalf("Scan() error = %v", err)
		}
		matches := res.Matches["long_match"]["$url"]
		if len(matches) != 1 {
			t.Fatalf("got %d matches, want 1", len(matches))
		}
		if matches[0].Length != 100 {
			t.Fatalf("got match length %d, want 100", matches[0].Length)
		}
	})

	t.Run("ZeroAndNegativeUseDefaultDistance", func(t *testing.T) {
		for _, span := range []int{0, -1, -100} {
			s := NewScanner(program, WithMaxMatchSpan(span))
			defer s.Close()
			res, err := s.Scan(input)
			if err != nil {
				t.Fatalf("Scan() error = %v", err)
			}
			matches := res.Matches["long_match"]["$url"]
			if len(matches) != 1 || matches[0].Length != expectedFullLen {
				t.Fatalf("span=%d: got length %d, want %d", span, matches[0].Length, expectedFullLen)
			}
		}
	})

	t.Run("MatchingRulesWithBoundedSpan", func(t *testing.T) {
		s := NewScanner(program, WithMaxMatchSpan(64))
		defer s.Close()
		rules, err := s.MatchingRules(input)
		if err != nil {
			t.Fatalf("MatchingRules() error = %v", err)
		}
		if len(rules) != 1 {
			t.Fatalf("got %d matching rules, want 1", len(rules))
		}
		matches := rules[0].Matches["$url"]
		if len(matches) != 1 || matches[0].Length != 64 {
			t.Fatalf("got match length %d, want 64", matches[0].Length)
		}
	})

	t.Run("MatchesBooleanMode", func(t *testing.T) {
		s := NewScanner(program, WithMaxMatchSpan(50))
		defer s.Close()
		matched, err := s.Matches(input)
		if err != nil {
			t.Fatalf("Matches() error = %v", err)
		}
		if !matched {
			t.Fatal("expected Matches to return true")
		}
	})
}

func TestMonotonicConditionShortCircuit(t *testing.T) {
	source := `
rule mixed_any {
    strings:
        $text = "marker"
        $re = /https?:\/\/[^\s]+/
    condition:
        any of them
}

rule mixed_or {
    strings:
        $text = "marker"
        $re = /https?:\/\/[^\s]+/
    condition:
        $text or $re
}

rule mixed_not {
    strings:
        $text = "marker"
        $re = /forbidden[0-9]+/
    condition:
        $text and not $re
}
`
	program, err := NewCompiler().CompileSource(source)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}

	rAny, ok := program.GetRuleByName("mixed_any")
	if !ok || !rAny.ConditionMonotonic {
		t.Fatalf("mixed_any ConditionMonotonic=%v, want true", rAny.ConditionMonotonic)
	}

	rOr, ok := program.GetRuleByName("mixed_or")
	if !ok || !rOr.ConditionMonotonic {
		t.Fatalf("mixed_or ConditionMonotonic=%v, want true", rOr.ConditionMonotonic)
	}

	rNot, ok := program.GetRuleByName("mixed_not")
	if !ok || rNot.ConditionMonotonic {
		t.Fatalf("mixed_not ConditionMonotonic=%v, want false", rNot.ConditionMonotonic)
	}

	t.Run("MatchesCorrectnessWithForbiddenPresent", func(t *testing.T) {
		input := []byte("marker https://example.com/test forbidden123")
		s := NewScanner(program)
		defer s.Close()

		res, err := s.Scan(input)
		if err != nil {
			t.Fatalf("Scan() error = %v", err)
		}
		if !res.RuleResults["mixed_any"] {
			t.Fatal("mixed_any should match")
		}
		if !res.RuleResults["mixed_or"] {
			t.Fatal("mixed_or should match")
		}
		if res.RuleResults["mixed_not"] {
			t.Fatal("mixed_not should NOT match because forbidden123 is present")
		}

		matched, err := s.Matches(input)
		if err != nil {
			t.Fatalf("Matches() error = %v", err)
		}
		if !matched {
			t.Fatal("Matches() should return true (mixed_any and mixed_or match)")
		}
	})

	t.Run("MatchesCorrectnessWithoutForbidden", func(t *testing.T) {
		input := []byte("marker only without anything forbidden")
		s := NewScanner(program)
		defer s.Close()

		res, err := s.Scan(input)
		if err != nil {
			t.Fatalf("Scan() error = %v", err)
		}
		if !res.RuleResults["mixed_not"] {
			t.Fatal("mixed_not should match when forbidden is absent")
		}
	})
}

func TestSerializationConditionMonotonic(t *testing.T) {
	source := `
rule mono_any {
    strings:
        $a = "test"
        $b = /re[0-9]+/
    condition:
        any of them
}

rule non_mono {
    strings:
        $a = "test"
        $b = /re[0-9]+/
    condition:
        $a and not $b
}
`
	program, err := NewCompiler().CompileSource(source)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}

	blob, err := program.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	unmarshaled, err := UnmarshalCompiledProgram(blob)
	if err != nil {
		t.Fatalf("UnmarshalCompiledProgram() error = %v", err)
	}

	monoRule, ok := unmarshaled.GetRuleByName("mono_any")
	if !ok || !monoRule.ConditionMonotonic {
		t.Fatalf("deserialized mono_any ConditionMonotonic=%v, want true", monoRule.ConditionMonotonic)
	}

	nonMonoRule, ok := unmarshaled.GetRuleByName("non_mono")
	if !ok || nonMonoRule.ConditionMonotonic {
		t.Fatalf("deserialized non_mono ConditionMonotonic=%v, want false", nonMonoRule.ConditionMonotonic)
	}
}
