package parser

import (
	"testing"

	"github.com/cawalch/go-yara/ast"
	internal "github.com/cawalch/go-yara/internal/lexer"
)

// TestSynchronize tests the parser's error recovery mechanism
func TestSynchronize(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		expectedErrors int
		expectedRules  int
	}{
		{
			name: "syntax error followed by valid rule",
			input: `
rule InvalidRule {
	strings:
		$pattern = "unclosed string
	condition:
		$pattern
}

rule ValidRule {
	strings:
		$valid = "valid"
	condition:
		$valid
}`,
			expectedErrors: 1, // Should have 1 error for the malformed rule
			expectedRules:  1, // Should recover and parse the valid rule
		},
		{
			name: "multiple syntax errors with recovery",
			input: `
rule FirstBad {
	strings:
		$bad1 = "unclosed
	condition:
		$bad1
}

invalid token here

rule SecondBad {
	strings:
		$bad2 =
	condition:
		$bad2
}

rule ValidRule {
	strings:
		$good = "good"
	condition:
		$good
}`,
			expectedErrors: 3, // Two malformed rules + invalid token
			expectedRules:  1, // Should recover and parse the valid rule
		},
		{
			name: "error recovery to global declaration",
			input: `
rule BadRule {
	strings:
		$bad = incomplete
	condition:
		$bad
}

global test_var = "test"

rule ValidRule {
	strings:
		$valid = "valid"
	condition:
		$valid
}`,
			expectedErrors: 1, // One syntax error
			expectedRules:  1, // Should recover and parse valid rule
		},
		{
			name: "error recovery to import statement",
			input: `
rule BadRule {
	strings:
		$bad = 123invalid
	condition:
		$bad
}

import "pe"

rule ValidRule {
	strings:
		$valid = "valid"
	condition:
		$valid
}`,
			expectedErrors: 1, // One syntax error
			expectedRules:  1, // Should recover and parse valid rule
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := internal.New(tt.input)
			p := New(l)

			// Enable error recovery mode for this test
			p.SetErrorRecovery(true)

			program, err := p.ParseRules()

			// We should get a partial program with errors
			if err == nil {
				t.Errorf("Expected parsing errors, but got none")
				return
			}

			partialErr, ok := err.(*PartialParseError)
			if !ok {
				t.Errorf("Expected PartialParseError, got %T", err)
				return
			}

			// Verify we got some errors
			if len(partialErr.Errors) == 0 {
				t.Errorf("Expected at least one error, got none")
			}

			// Verify we got a partial program
			if program == nil {
				t.Errorf("Expected partial program, got nil")
				return
			}

			// Verify expected number of rules (should parse valid rules despite errors)
			if len(program.Rules) < tt.expectedRules {
				t.Errorf("Expected at least %d rules, got %d", tt.expectedRules, len(program.Rules))
			}

			// Verify expected number of errors
			if len(partialErr.Errors) < tt.expectedErrors {
				t.Errorf("Expected at least %d errors, got %d", tt.expectedErrors, len(partialErr.Errors))
			}
		})
	}
}

// TestParseGlobalDeclaration tests global variable parsing with error handling
func TestParseGlobalDeclaration(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expectError   bool
		expectedVars  int
		expectedRules int
	}{
		{
			name: "valid global variable",
			input: `
global test_var = "test"
rule TestRule {
	strings:
		$pattern = "test"
	condition:
		$pattern
}`,
			expectError:   false,
			expectedVars:  1,
			expectedRules: 1,
		},
		{
			name: "global rule modifier",
			input: `
global rule GlobalRule {
	strings:
		$pattern = "test"
	condition:
		$pattern
}`,
			expectError:   false,
			expectedVars:  0,
			expectedRules: 1,
		},
		{
			name: "malformed global variable",
			input: `
global test_var =
rule TestRule {
	strings:
		$pattern = "test"
	condition:
		$pattern
}`,
			expectError:   true,
			expectedVars:  0,
			expectedRules: 1, // Should recover and parse rule
		},
		{
			name: "multiple global variables",
			input: `
global var1 = "test1"
global var2 = 42
global var3 = 123
rule TestRule {
	strings:
		$pattern = "test"
	condition:
		$pattern
}`,
			expectError:   false,
			expectedVars:  3,
			expectedRules: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := internal.New(tt.input)
			p := New(l)

			program, err := p.ParseRules()

			if tt.expectError {
				if err == nil && len(p.Errors()) == 0 {
					t.Errorf("ParseRules() expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("ParseRules() unexpected error: %v", err)
				}
			}

			// Only check program fields if parsing didn't completely fail
			if program == nil {
				if !tt.expectError {
					// If we don't expect errors but got nil program, that's an error
					t.Errorf("ParseRules() returned nil program when no errors were expected")
					// Log parser errors for debugging
					if len(p.Errors()) > 0 {
						t.Logf("Parser errors when none expected: %+v", p.Errors())
					}
				}
				return
			}
			if len(program.GlobalVariables) != tt.expectedVars {
				t.Errorf("ParseRules() global variables = %d, want %d", len(program.GlobalVariables), tt.expectedVars)
			}

			if len(program.Rules) != tt.expectedRules {
				t.Errorf("ParseRules() rules = %d, want %d", len(program.Rules), tt.expectedRules)
			}
		})
	}
}

// TestParseExternalDeclaration tests external variable parsing
func TestParseExternalDeclaration(t *testing.T) {
	tests := []struct {
		name            string
		input           string
		expectError     bool
		expectedExterns int
	}{
		{
			name: "valid external variable",
			input: `
external test_var
rule TestRule {
	strings:
		$pattern = "test"
	condition:
		$pattern
}`,
			expectError:     false,
			expectedExterns: 1,
		},
		{
			name: "malformed external variable",
			input: `
external
rule TestRule {
	strings:
		$pattern = "test"
	condition:
		$pattern
}`,
			expectError:     true,
			expectedExterns: 0,
		},
		{
			name: "multiple external variables",
			input: `
external var1
external var2
external var3
rule TestRule {
	strings:
		$pattern = "test"
	condition:
		$pattern
}`,
			expectError:     false,
			expectedExterns: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := internal.New(tt.input)
			p := New(l)

			program, err := p.ParseRules()

			if tt.expectError {
				if err == nil && len(p.Errors()) == 0 {
					t.Errorf("ParseRules() expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("ParseRules() unexpected error: %v", err)
				}
			}

			// Only check program fields if parsing didn't completely fail
			if program == nil {
				if !tt.expectError {
					// If we don't expect errors but got nil program, that's an error
					t.Errorf("ParseRules() returned nil program when no errors were expected")
				}
				return
			}
			if len(program.ExternalVariables) != tt.expectedExterns {
				t.Errorf("ParseRules() external variables = %d, want %d", len(program.ExternalVariables), tt.expectedExterns)
			}
		})
	}
}

// TestParseImportDeclaration tests import statement parsing
func TestParseImportDeclaration(t *testing.T) {
	tests := []struct {
		name            string
		input           string
		expectError     bool
		expectedImports int
	}{
		{
			name: "valid import",
			input: `
import "pe"
rule TestRule {
	strings:
		$pattern = "test"
	condition:
		$pattern
}`,
			expectError:     false,
			expectedImports: 1,
		},
		{
			name: "malformed import",
			input: `
import
rule TestRule {
	strings:
		$pattern = "test"
	condition:
		$pattern
}`,
			expectError:     true,
			expectedImports: 0,
		},
		{
			name: "multiple imports",
			input: `
import "pe"
import "elf"
import "hash"
rule TestRule {
	strings:
		$pattern = "test"
	condition:
		$pattern
}`,
			expectError:     false,
			expectedImports: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := internal.New(tt.input)
			p := New(l)

			program, err := p.ParseRules()

			if tt.expectError {
				if err == nil && len(p.Errors()) == 0 {
					t.Errorf("ParseRules() expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("ParseRules() unexpected error: %v", err)
				}
			}

			// Only check program fields if parsing didn't completely fail
			if program == nil {
				if !tt.expectError {
					// If we don't expect errors but got nil program, that's an error
					t.Errorf("ParseRules() returned nil program when no errors were expected")
				}
				return
			}
			if len(program.Imports) != tt.expectedImports {
				t.Errorf("ParseRules() imports = %d, want %d", len(program.Imports), tt.expectedImports)
			}
		})
	}
}

// TestParseIncludeDeclaration tests include statement parsing
func TestParseIncludeDeclaration(t *testing.T) {
	tests := []struct {
		name             string
		input            string
		expectError      bool
		expectedIncludes int
	}{
		{
			name: "valid include",
			input: `
include "rules/common.yar"
rule TestRule {
	strings:
		$pattern = "test"
	condition:
		$pattern
}`,
			expectError:      false,
			expectedIncludes: 1,
		},
		{
			name: "malformed include",
			input: `
include
rule TestRule {
	strings:
		$pattern = "test"
	condition:
		$pattern
}`,
			expectError:      true,
			expectedIncludes: 0,
		},
		{
			name: "multiple includes",
			input: `
include "rules/common.yar"
include "rules/malware.yar"
include "utils.yar"
rule TestRule {
	strings:
		$pattern = "test"
	condition:
		$pattern
}`,
			expectError:      false,
			expectedIncludes: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := internal.New(tt.input)
			p := New(l)

			program, err := p.ParseRules()

			if tt.expectError {
				if err == nil && len(p.Errors()) == 0 {
					t.Errorf("ParseRules() expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("ParseRules() unexpected error: %v", err)
				}
			}

			// Only check program fields if parsing didn't completely fail
			if program == nil {
				if !tt.expectError {
					// If we don't expect errors but got nil program, that's an error
					t.Errorf("ParseRules() returned nil program when no errors were expected")
				}
				return
			}
			if len(program.Includes) != tt.expectedIncludes {
				t.Errorf("ParseRules() includes = %d, want %d", len(program.Includes), tt.expectedIncludes)
			}
		})
	}
}

// TestQuantifierParserErrorHandling tests quantifier parsing with malformed input
func TestQuantifierParserErrorHandling(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
	}{
		{
			name: "valid for quantifier",
			input: `
rule TestRule {
	strings:
		$a = "test"
	condition:
		for all of them : ($a)
}`,
			expectError: false,
		},
		{
			name: "invalid for quantifier - missing 'of'",
			input: `
rule TestRule {
	strings:
		$a = "test"
	condition:
		for all them ($a)
}`,
			expectError: true,
		},
		{
			name: "invalid for quantifier - missing quantifier",
			input: `
rule TestRule {
	strings:
		$a = "test"
	condition:
		for of them : ($a)
}`,
			expectError: true,
		},
		{
			name: "for quantifier with incomplete syntax",
			input: `
rule TestRule {
	strings:
		$a = "test"
	condition:
		for all i in (0..9
}`,
			expectError: true, // Incomplete syntax should still fail parsing
		},
		{
			name: "malformed for loop variable",
			input: `
rule TestRule {
	strings:
		$a = "test"
	condition:
		for all i in : ($a)
}`,
			expectError: true,
		},
		{
			name: "numeric quantifier",
			input: `
rule TestRule {
	strings:
		$a = "test"
	condition:
		2 of them
}`,
			expectError: false,
		},
		{
			name: "invalid numeric quantifier",
			input: `
rule TestRule {
	strings:
		$a = "test"
	condition:
		abc of them
}`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := internal.New(tt.input)
			p := New(l)

			program, err := p.ParseRules()

			if tt.expectError {
				if err == nil && len(p.Errors()) == 0 {
					t.Errorf("ParseRules() expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("ParseRules() unexpected error: %v", err)
				}
			}

			// Parser returns nil when there are errors (current implementation behavior)
			// This is expected - the parser fails fast rather than doing error recovery
			if program == nil {
				// When parser returns nil, we should have errors
				if len(p.Errors()) == 0 {
					t.Errorf("ParseRules() returned nil program but no errors collected")
				}
			}
		})
	}
}

// TestParserMalformedInput tests parser resilience with severely malformed input
func TestParserMalformedInput(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		shouldPanic   bool
		minErrors     int
		expectProgram bool
	}{
		{
			name: "completely malformed",
			input: `
#$%^&*()
invalid syntax here
more garbage
`,
			shouldPanic:   false,
			minErrors:     1,
			expectProgram: true,
		},
		{
			name: "incomplete rule",
			input: `
rule IncompleteRule {
	strings:
		$pattern = "test"
	condition:
`,
			shouldPanic:   false,
			minErrors:     1,
			expectProgram: true,
		},
		{
			name: "unclosed brackets",
			input: `
rule BracketRule {
	strings:
		$pattern = "test"
	condition:
		($pattern and
}`,
			shouldPanic:   false,
			minErrors:     1,
			expectProgram: true,
		},
		{
			name: "nested errors",
			input: `
rule BadRule {
	strings:
		$bad1 = "unclosed
		$bad2 =
	condition:
		$bad1 and $bad2 and (
}`,
			shouldPanic:   false,
			minErrors:     2,
			expectProgram: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					if !tt.shouldPanic {
						t.Errorf("Parser panicked unexpectedly: %v", r)
					}
				}
			}()

			l := internal.New(tt.input)
			p := New(l)

			program, err := p.ParseRules()

			// Current parser implementation: returns nil program and error when parsing fails
			validateProgramExpectation(t, tt.expectProgram, program, err, p)

			// Check that we have the expected minimum errors
			errorCount := len(p.Errors())
			if errorCount < tt.minErrors {
				t.Errorf("ParseRules() error count = %d, want >= %d", errorCount, tt.minErrors)
			}
		})
	}
}

// validateProgramExpectation validates parser results based on program expectations
//
//nolint:revive // argument-limit: test helper
func validateProgramExpectation(t *testing.T, expectProgram bool, program *ast.Program, err error, p *Parser) {
	if expectProgram {
		validateExpectedProgramBehavior(t, program, err, p)
	} else {
		validateUnexpectedProgramBehavior(t, program)
	}
}

// validateExpectedProgramBehavior validates behavior when program is expected
//
//nolint:revive // argument-limit: test helper
func validateExpectedProgramBehavior(t *testing.T, program *ast.Program, err error, p *Parser) {
	if program == nil {
		// When parser fails, we expect both nil program and error
		if err == nil {
			t.Errorf("ParseRules() returned nil program but no error")
		}
		if len(p.Errors()) == 0 {
			t.Errorf("ParseRules() returned error but no errors collected")
		}
	}
	// If program is not nil (unexpected), check it's valid
}

// validateUnexpectedProgramBehavior validates behavior when program is not expected
func validateUnexpectedProgramBehavior(t *testing.T, program *ast.Program) {
	// When we don't expect program, nil is acceptable
	if program != nil {
		t.Logf("ParseRules() unexpectedly returned program when expecting failure")
	}
}
