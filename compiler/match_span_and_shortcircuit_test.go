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

func TestBooleanRoutingDisabledWithMaxMatchSpan(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
rule bounded_routing {
    strings:
        $a = /TOKENXYZ12345678.{0,20}END/
    condition:
        $a
}
`)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}

	input := []byte("TOKENXYZ12345678" + strings.Repeat("a", 15) + "END")

	routedDefault := NewScanner(program, WithBooleanRouting())
	defer routedDefault.Close()
	if routedDefault.booleanRouting == nil {
		t.Fatal("expected booleanRouting active when maxMatchSpan == 0")
	}
	if matched, err := routedDefault.Matches(input); err != nil || !matched {
		t.Fatalf("routedDefault Matches = %v, %v; want true", matched, err)
	}

	routedZeroSpan := NewScanner(program, WithBooleanRouting(), WithMaxMatchSpan(0))
	defer routedZeroSpan.Close()
	if routedZeroSpan.booleanRouting == nil {
		t.Fatal("expected booleanRouting active with WithMaxMatchSpan(0)")
	}

	routedBounded := NewScanner(program, WithBooleanRouting(), WithMaxMatchSpan(20))
	defer routedBounded.Close()
	if routedBounded.booleanRouting != nil {
		t.Fatal("booleanRouting must be disabled when WithMaxMatchSpan > 0")
	}
	got, err := routedBounded.Matches(input)
	if err != nil {
		t.Fatalf("routedBounded Matches() error = %v", err)
	}

	plainBounded := NewScanner(program, WithMaxMatchSpan(20))
	defer plainBounded.Close()
	want, err := plainBounded.Matches(input)
	if err != nil {
		t.Fatalf("plainBounded Matches() error = %v", err)
	}
	if got != want || got {
		t.Fatalf("WithBooleanRouting + WithMaxMatchSpan(20) = %v, want %v (false)", got, want)
	}
}

func TestWithMaxMatchSpanNoSyntheticEOF(t *testing.T) {
	tests := []struct {
		name    string
		source  string
		span    int
		input   []byte
		wantLen int // -1 means no match
	}{
		{
			name:    "dollar_rejected_before_eof",
			source:  `rule r { strings: $s = /abc[0-9]+$/ condition: $s }`,
			span:    6,
			input:   []byte("abc123456"),
			wantLen: -1,
		},
		{
			name:    "dollar_matches_at_real_eof",
			source:  `rule r { strings: $s = /abc[0-9]+$/ condition: $s }`,
			span:    6,
			input:   []byte("abc123"),
			wantLen: 6,
		},
		{
			name:    "word_boundary_rejected_before_word_char",
			source:  `rule r { strings: $s = /abc[0-9]+\b/ condition: $s }`,
			span:    6,
			input:   []byte("abc123456"),
			wantLen: -1,
		},
		{
			name:    "word_boundary_matches_before_nonword",
			source:  `rule r { strings: $s = /abc[0-9]+\b/ condition: $s }`,
			span:    6,
			input:   []byte("abc123!"),
			wantLen: 6,
		},
		{
			name:    "non_word_boundary_matches_before_word_char",
			source:  `rule r { strings: $s = /abc[0-9]{3}\B/ condition: $s }`,
			span:    6,
			input:   []byte("abc123456"),
			wantLen: 6,
		},
		{
			name:    "non_word_boundary_rejected_at_real_eof",
			source:  `rule r { strings: $s = /abc[0-9]{3}\B/ condition: $s }`,
			span:    6,
			input:   []byte("abc123"),
			wantLen: -1,
		},
		{
			name:    "greedy_truncation_without_anchor_preserved",
			source:  `rule r { strings: $s = /abc[0-9]+/ condition: $s }`,
			span:    6,
			input:   []byte("abc123456"),
			wantLen: 6,
		},
		{
			name:    "bounded_verification_dollar_rejected_before_eof",
			source:  `rule r { strings: $s = /^a+[0-9]+$/ condition: $s }`,
			span:    5003,
			input:   []byte(strings.Repeat("a", 5000) + "123456"),
			wantLen: -1,
		},
		{
			name:    "bounded_verification_dollar_matches_at_real_eof",
			source:  `rule r { strings: $s = /^a+[0-9]+$/ condition: $s }`,
			span:    5003,
			input:   []byte(strings.Repeat("a", 5000) + "123"),
			wantLen: 5003,
		},
		{
			name:    "wide_dollar_rejected_before_eof",
			source:  `rule r { strings: $s = /abc[0-9]+$/ wide condition: $s }`,
			span:    12,
			input:   []byte{'a', 0, 'b', 0, 'c', 0, '1', 0, '2', 0, '3', 0, '4', 0},
			wantLen: -1,
		},
		{
			name:    "wide_dollar_matches_at_real_eof",
			source:  `rule r { strings: $s = /abc[0-9]+$/ wide condition: $s }`,
			span:    12,
			input:   []byte{'a', 0, 'b', 0, 'c', 0, '1', 0, '2', 0, '3', 0},
			wantLen: 12,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			program, err := NewCompiler().CompileSource(tc.source)
			if err != nil {
				t.Fatalf("CompileSource() error = %v", err)
			}
			s := NewScanner(program, WithMaxMatchSpan(tc.span))
			defer s.Close()
			res, err := s.Scan(tc.input)
			if err != nil {
				t.Fatalf("Scan() error = %v", err)
			}
			matches := res.Matches["r"]["$s"]
			if tc.wantLen < 0 {
				if len(matches) != 0 {
					t.Fatalf("got %+v, want no match", matches)
				}
				return
			}
			if len(matches) != 1 || matches[0].Length != tc.wantLen {
				t.Fatalf("got %+v, want 1 match of length %d", matches, tc.wantLen)
			}
		})
	}
}
