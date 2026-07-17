package compiler

import "testing"

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
