package parser

import (
	"testing"

	"github.com/cawalch/go-yara/internal/lexer"
)

func TestSkipInvalidRulesKeepsFollowingValidRule(t *testing.T) {
	input := `
rule broken {
    condition:
        true

rule valid {
    condition:
        true
}
`

	p := New(lexer.New(input))
	p.SetErrorRecovery(true)
	p.SetSkipInvalidRules(true)

	program, err := p.ParseRules()
	if err == nil {
		t.Fatal("ParseRules() error = nil, want partial parse error")
	}
	if program == nil {
		t.Fatal("ParseRules() program = nil, want partial program")
	}
	if len(program.Rules) != 1 || program.Rules[0].Name != "valid" {
		t.Fatalf("ParseRules() rules = %#v, want only valid", program.Rules)
	}

	invalid := p.InvalidRules()
	if len(invalid) != 1 {
		t.Fatalf("InvalidRules() length = %d, want 1", len(invalid))
	}
	if invalid[0].Rule == nil || invalid[0].Rule.Name != "broken" {
		t.Fatalf("InvalidRules()[0].Rule = %#v, want broken", invalid[0].Rule)
	}
	if len(invalid[0].Errors) == 0 {
		t.Fatal("InvalidRules()[0].Errors is empty")
	}
	if got := p.ProgramErrors(); len(got) != 0 {
		t.Fatalf("ProgramErrors() = %v, want none", got)
	}
}

func TestSkipInvalidRulesDoesNotHideProgramErrors(t *testing.T) {
	p := New(lexer.New(`unexpected rule valid { condition: true }`))
	p.SetErrorRecovery(true)
	p.SetSkipInvalidRules(true)

	_, err := p.ParseRules()
	if err == nil {
		t.Fatal("ParseRules() error = nil, want partial parse error")
	}
	if got := p.ProgramErrors(); len(got) == 0 {
		t.Fatal("ProgramErrors() is empty, want top-level error")
	}
}
