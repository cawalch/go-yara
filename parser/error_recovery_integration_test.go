package parser

import (
	"errors"
	"testing"

	internal "github.com/cawalch/go-yara/internal/lexer"
)

func TestErrorRecoveryMode(t *testing.T) {
	input := `
rule InvalidRule {
	strings:
		$pattern = "valid"
	condition:
		$pattern

rule ValidRule {
	strings:
		$valid = "valid"
	condition:
		$valid
}
`

	t.Run("strict_parsing", func(t *testing.T) {
		l := internal.New(input)
		p := New(l)
		p.SetErrorRecovery(false) // Use strict parsing

		program, err := p.ParseRules()
		if err == nil {
			t.Errorf("Expected parsing error in strict mode, got none")
			t.Logf("Program: %+v", program)
		} else {
			t.Logf("Got expected error in strict mode: %v", err)
		}
		if program != nil {
			t.Errorf("Expected nil program in strict mode, got %v", program)
		}
	})

	t.Run("error_recovery_parsing", func(t *testing.T) {
		l := internal.New(input)
		p := New(l)
		p.SetErrorRecovery(true) // Use error recovery

		program, err := p.ParseRules()
		if err == nil {
			t.Errorf("Expected PartialParseError in recovery mode, got none")
		}

		var partialErr *PartialParseError
		if !errors.As(err, &partialErr) {
			t.Errorf("Expected PartialParseError, got %T", err)
		}

		if program == nil {
			t.Errorf("Expected partial program, got nil")
		} else if len(program.Rules) == 0 {
			// Should have parsed the valid rule despite the error in the first rule
			t.Errorf("Expected at least one rule to be parsed, got none")
		}

		if len(partialErr.Errors) == 0 {
			t.Errorf("Expected errors in partial parse, got none")
		}
	})
}
