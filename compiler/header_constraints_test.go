package compiler

import (
	"strings"
	"testing"
)

func TestIntegerHeaderConstraintPrunesRule(t *testing.T) {
	c := NewCompiler()
	program, err := c.CompileSource(`
rule elf_payload {
    strings:
        $payload = "payload"
    condition:
        uint32(0) == 0x464c457f and $payload
}
`)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}
	rule, _ := program.GetRuleByName("elf_payload")
	if len(rule.HeaderConstraints) != 1 {
		t.Fatalf("HeaderConstraints = %+v, want one", rule.HeaderConstraints)
	}

	wrong, err := program.Scan([]byte("NOT! payload"))
	if err != nil {
		t.Fatalf("Scan(wrong header) error = %v", err)
	}
	if wrong.RuleResults["elf_payload"] {
		t.Fatal("wrong header matched elf_payload")
	}
	if len(wrong.PrunedRules) != 1 || wrong.PrunedRules[0] != "elf_payload" {
		t.Fatalf("PrunedRules = %v, want [elf_payload]", wrong.PrunedRules)
	}
	if _, exists := wrong.Matches["elf_payload"]; exists {
		t.Fatalf("pruned rule materialized matches: %v", wrong.Matches["elf_payload"])
	}

	matching, err := program.Scan([]byte("\x7fELF payload"))
	if err != nil {
		t.Fatalf("Scan(ELF header) error = %v", err)
	}
	if !matching.RuleResults["elf_payload"] || len(matching.PrunedRules) != 0 {
		t.Fatalf("matching result = %+v", matching)
	}
}

func TestStringAtHeaderConstraintPrunesRule(t *testing.T) {
	c := NewCompiler()
	program, err := c.CompileSource(`
rule mz_payload {
    strings:
        $magic = "MZ"
        $payload = "payload"
    condition:
        $magic at 0 and $payload
}
`)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}
	rule, _ := program.GetRuleByName("mz_payload")
	if len(rule.HeaderConstraints) != 1 || rule.HeaderConstraints[0].String != "$magic" {
		t.Fatalf("HeaderConstraints = %+v, want $magic at 0", rule.HeaderConstraints)
	}

	result, err := program.Scan([]byte("XX payload MZ"))
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if result.RuleResults["mz_payload"] || len(result.PrunedRules) != 1 {
		t.Fatalf("result = %+v, want pruned non-match", result)
	}
}

func TestHeaderConstraintsStayConservativeAcrossOr(t *testing.T) {
	c := NewCompiler()
	program, err := c.CompileSource(`
rule alternative_headers {
    strings:
        $payload = "payload"
    condition:
        (uint8(0) == 1 and $payload) or (uint8(0) == 2 and $payload)
}
rule constrained_or_unconstrained {
    strings:
        $magic = "MZ"
    condition:
        $magic at 0 or $magic
}
`)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}
	for _, name := range []string{"alternative_headers", "constrained_or_unconstrained"} {
		rule, _ := program.GetRuleByName(name)
		if len(rule.HeaderConstraints) != 0 {
			t.Fatalf("%s HeaderConstraints = %+v, want none", name, rule.HeaderConstraints)
		}
	}

	result, err := program.Scan(append([]byte{2}, []byte(" payload MZ")...))
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if !result.RuleResults["alternative_headers"] || !result.RuleResults["constrained_or_unconstrained"] {
		t.Fatalf("RuleResults = %v", result.RuleResults)
	}
	if len(result.PrunedRules) != 0 {
		t.Fatalf("PrunedRules = %v, want none", result.PrunedRules)
	}
}

func TestHeaderStringAtWideFullwordASCIIBoundary(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
rule wide_fullword_atomless {
    strings:
        $r = /[a-z]{3}/ wide fullword
    condition:
        $r at 2
}
`)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}
	rule, _ := program.GetRuleByName("wide_fullword_atomless")
	if len(rule.HeaderConstraints) != 1 || rule.HeaderConstraints[0].Kind != HeaderStringAt {
		t.Fatalf("HeaderConstraints = %+v, want one HeaderStringAt", rule.HeaderConstraints)
	}

	scanner := program.NewScanner()
	defer scanner.Close()

	// Offset 2 is preceded by 'a!' (byte 1 is '!', an ASCII non-word byte) while byte 0 is 'a'.
	// regexASCIIWordBoundary requires checking byte 1 (not wide offset 0).
	for _, tc := range []struct {
		name string
		data []byte
		want bool
	}{
		{name: "ascii non-word at offset 1", data: []byte("a!a\x00b\x00c\x00"), want: true},
		{name: "ascii word at offset 1", data: []byte("xa\x00b\x00c\x00"), want: false},
		{name: "ascii word at offset 1 with leading byte", data: []byte("!aa\x00b\x00c\x00"), want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := scanner.Matches(tc.data)
			if err != nil {
				t.Fatal(err)
			}
			scanner.prefilterDisabled = true
			want, err := scanner.Matches(tc.data)
			scanner.prefilterDisabled = false
			if err != nil || got != want || got != tc.want {
				t.Fatalf("data=%q: got=%v want=%v expected=%v err=%v", tc.data, got, want, tc.want, err)
			}
		})
	}
}

func TestHeaderStringAtForwardOnlyFullword(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
rule forward_only_fullword {
    strings:
        $r = /[a-z]+/ fullword
    condition:
        $r at 0
}
`)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}
	rule, _ := program.GetRuleByName("forward_only_fullword")
	if !rule.RegexPatterns["$r"].verification.ForwardOnly {
		t.Fatal("fixture regex must use ForwardOnly verification")
	}

	scanner := program.NewScanner()
	defer scanner.Close()

	longTail := strings.Repeat("x", regexVerificationDistance+100)
	for _, tc := range []struct {
		name string
		data []byte
		want bool
	}{
		{name: "non-matching prefix long input", data: []byte("12345" + longTail), want: false},
		{name: "matching bounded word long input", data: []byte("hello!" + longTail), want: true},
		{name: "word exceeds verification distance", data: []byte("hello" + longTail), want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := scanner.Matches(tc.data)
			if err != nil {
				t.Fatal(err)
			}
			scanner.prefilterDisabled = true
			want, err := scanner.Matches(tc.data)
			scanner.prefilterDisabled = false
			if err != nil || got != want || got != tc.want {
				t.Fatalf("got=%v want=%v expected=%v err=%v", got, want, tc.want, err)
			}
		})
	}

	// Simulate an unpruned ForwardOnly + fullword check when ends[0] fails fullword
	// (e.g. "a" followed by "a!" + longTail on a lazy regex): compiledPatternMatchesAtWithCancel
	// must not falsely reject before the full evaluator runs.
	lazyProgram, err := NewCompiler().CompileSource(`
rule lazy_forward_only {
    strings:
        $r = /[a-z]+?/ fullword
    condition:
        $r at 0
}
`)
	if err != nil {
		t.Fatalf("CompileSource(lazy) error = %v", err)
	}
	lazyRule, _ := lazyProgram.GetRuleByName("lazy_forward_only")
	if !lazyRule.RegexPatterns["$r"].verification.ForwardOnly {
		t.Fatal("lazy fixture regex must use ForwardOnly verification")
	}
	if !compiledPatternMatchesAtWithCancel(lazyRule, "$r", []byte("aa!"+longTail), 0, nil) {
		t.Fatal("ForwardOnly fullword check falsely rejected when ends[0] failed fullword")
	}
	if compiledPatternMatchesAtWithCancel(lazyRule, "$r", []byte("12345"+longTail), 0, nil) {
		t.Fatal("ForwardOnly fullword check failed to reject non-matching input")
	}
}
