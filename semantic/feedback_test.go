package semantic

import (
	"context"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/parser"
	"github.com/cawalch/go-yara/token"
)

func parseRules(t *testing.T, source string) *ast.Program {
	t.Helper()
	p := parser.New(lexer.New(source))
	prog, err := p.ParseRulesWithContext(context.Background())
	if err != nil {
		t.Fatalf("ParseRules failed: %v", err)
	}
	return prog
}

func findSemanticErrorByCode(errs []error, code ErrorCode) *Error {
	for _, err := range errs {
		if semErr, ok := err.(*Error); ok && semErr.Code == code {
			return semErr
		}
	}
	return nil
}

func TestIdentifierTypoSuggestions(t *testing.T) {
	tests := []struct {
		name           string
		source         string
		expectedCode   ErrorCode
		expectedSubstr string
		wantSuggestion string
	}{
		{
			name: "string typo in condition",
			source: `rule test {
				strings:
					$malware = "trojan"
				condition:
					$malwre
			}`,
			expectedCode:   ErrCodeUndefinedIdentifier,
			expectedSubstr: "undefined identifier: $malwre",
			wantSuggestion: "$malware",
		},
		{
			name: "string typo with transposition",
			source: `rule test {
				strings:
					$payload = "evil"
				condition:
					paylaod
			}`,
			expectedCode:   ErrCodeUndefinedIdentifier,
			expectedSubstr: "undefined identifier: paylaod",
			wantSuggestion: "$payload",
		},
		{
			name: "keyword typo",
			source: `rule test {
				condition:
					filesze > 100
			}`,
			expectedCode:   ErrCodeUndefinedIdentifier,
			expectedSubstr: "undefined identifier: filesze",
			wantSuggestion: "filesize",
		},
		{
			name: "rule reference typo",
			source: `rule base_rule {
				condition: true
			}
			rule dependent_rule {
				condition: base_rle
			}`,
			expectedCode:   ErrCodeUndefinedIdentifier,
			expectedSubstr: "undefined identifier: base_rle",
			wantSuggestion: "base_rule",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prog := parseRules(t, tt.source)
			v := NewValidator()
			errs := v.ValidateProgram(prog)

			semErr := findSemanticErrorByCode(errs, tt.expectedCode)
			if semErr == nil {
				t.Fatalf("expected error with code %q, got: %v", tt.expectedCode, errs)
			}
			if !strings.Contains(semErr.Message, tt.expectedSubstr) {
				t.Errorf("error message = %q, want containing %q", semErr.Message, tt.expectedSubstr)
			}
			if semErr.Suggestion != tt.wantSuggestion {
				t.Errorf("error suggestion = %q, want %q", semErr.Suggestion, tt.wantSuggestion)
			}
			if !strings.Contains(semErr.Error(), "; did you mean "+tt.wantSuggestion+"?") {
				t.Errorf("Error() formatted output = %q, want containing suggestion", semErr.Error())
			}
		})
	}
}

func TestDirectFindSimilarIdentifier(t *testing.T) {
	// Missing prefix
	sugg, ok := findSimilarIdentifier("payload", []string{"$payload", "$other"})
	if !ok || sugg != "$payload" {
		t.Errorf("expected $payload, got %q, %v", sugg, ok)
	}

	// Exact case insensitive
	sugg, ok = findSimilarIdentifier("PAYLOAD", []string{"$payload"})
	if !ok || sugg != "$payload" {
		t.Errorf("expected $payload, got %q, %v", sugg, ok)
	}

	// Levenshtein typo
	sugg, ok = findSimilarIdentifier("filesze", []string{"filesize", "entrypoint"})
	if !ok || sugg != "filesize" {
		t.Errorf("expected filesize, got %q, %v", sugg, ok)
	}
}

func TestUnsupportedModuleSuggestions(t *testing.T) {
	mods := ModuleFunctions{
		"hash.md5":    {ReturnType: TypeString},
		"hash.sha256": {ReturnType: TypeString},
		"math.mean":   {ReturnType: TypeFloat},
	}

	source := `import "hsh"
rule test {
	condition: true
}`
	prog := parseRules(t, source)
	v := NewValidatorWithModules(mods)
	errs := v.ValidateProgram(prog)

	semErr := findSemanticErrorByCode(errs, ErrCodeUnsupportedModule)
	if semErr == nil {
		t.Fatalf("expected ErrCodeUnsupportedModule, got: %v", errs)
	}
	if semErr.Suggestion != `"hash"` {
		t.Errorf("expected suggestion %q, got %q", `"hash"`, semErr.Suggestion)
	}
}

func TestModuleFunctionSuggestions(t *testing.T) {
	mods := ModuleFunctions{
		"hash.md5":    {ReturnType: TypeString},
		"hash.sha256": {ReturnType: TypeString},
	}

	source := `import "hash"
rule test {
	condition: hash.sha25(0, 10) == "abc"
}`
	prog := parseRules(t, source)
	v := NewValidatorWithModules(mods)
	errs := v.ValidateProgram(prog)

	semErr := findSemanticErrorByCode(errs, ErrCodeInvalidFunction)
	if semErr == nil {
		t.Fatalf("expected ErrCodeInvalidFunction, got: %v", errs)
	}
	if semErr.Suggestion != `"hash.sha256"` {
		t.Errorf("expected suggestion %q, got %q", `"hash.sha256"`, semErr.Suggestion)
	}
}

func TestBuiltinFunctionTypoSuggestions(t *testing.T) {
	source := `rule test {
	condition: tostrng(10) == "10"
}`
	prog := parseRules(t, source)
	v := NewValidator()
	errs := v.ValidateProgram(prog)

	semErr := findSemanticErrorByCode(errs, ErrCodeInvalidFunction)
	if semErr == nil {
		t.Fatalf("expected ErrCodeInvalidFunction, got: %v", errs)
	}
	if semErr.Suggestion != "tostring" {
		t.Errorf("expected suggestion 'tostring', got %q", semErr.Suggestion)
	}
}

func TestBitwiseBooleanSuggestion(t *testing.T) {
	tests := []struct {
		name           string
		source         string
		wantSuggestion string
	}{
		{
			name: "bitwise and on booleans",
			source: `rule test {
				strings:
					$a = "a"
					$b = "b"
				condition:
					$a & $b
			}`,
			wantSuggestion: "'and'",
		},
		{
			name: "bitwise or on booleans",
			source: `rule test {
				strings:
					$a = "a"
					$b = "b"
				condition:
					$a | $b
			}`,
			wantSuggestion: "'or'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prog := parseRules(t, tt.source)
			v := NewValidator()
			errs := v.ValidateProgram(prog)

			semErr := findSemanticErrorByCode(errs, ErrCodeTypeMismatch)
			if semErr == nil {
				t.Fatalf("expected ErrCodeTypeMismatch, got: %v", errs)
			}
			if semErr.Suggestion != tt.wantSuggestion {
				t.Errorf("expected suggestion %s, got %q", tt.wantSuggestion, semErr.Suggestion)
			}
		})
	}
}

func TestStringModifierValidation(t *testing.T) {
	tests := []struct {
		name           string
		source         string
		expectedCode   ErrorCode
		expectedSubstr string
	}{
		{
			name: "hex with nocase modifier",
			source: `rule test {
				strings:
					$hex = { 01 02 03 } nocase
				condition:
					$hex
			}`,
			expectedCode:   ErrCodeInvalidModifier,
			expectedSubstr: "cannot have 'nocase' modifier",
		},
		{
			name: "hex with wide modifier",
			source: `rule test {
				strings:
					$hex = { AA BB CC } wide
				condition:
					$hex
			}`,
			expectedCode:   ErrCodeInvalidModifier,
			expectedSubstr: "cannot have 'wide' modifier",
		},
		{
			name: "regex with base64 modifier",
			source: `rule test {
				strings:
					$re = /test[0-9]+/ base64
				condition:
					$re
			}`,
			expectedCode:   ErrCodeInvalidModifier,
			expectedSubstr: "base64 modifiers are only supported for text strings",
		},
		{
			name: "regex with xor modifier",
			source: `rule test {
				strings:
					$re = /pattern/ xor
				condition:
					$re
			}`,
			expectedCode:   ErrCodeInvalidModifier,
			expectedSubstr: "cannot have 'xor' modifier",
		},
		{
			name: "duplicate wide modifier",
			source: `rule test {
				strings:
					$s = "hello" wide wide
				condition:
					$s
			}`,
			expectedCode:   ErrCodeInvalidModifier,
			expectedSubstr: "declares duplicate modifier",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prog := parseRules(t, tt.source)
			v := NewValidator()
			errs := v.ValidateProgram(prog)

			semErr := findSemanticErrorByCode(errs, tt.expectedCode)
			if semErr == nil {
				t.Fatalf("expected error code %q, got: %v", tt.expectedCode, errs)
			}
			if !strings.Contains(semErr.Message, tt.expectedSubstr) {
				t.Errorf("error message = %q, want containing %q", semErr.Message, tt.expectedSubstr)
			}
		})
	}
}

func TestProgrammaticModifierValidation(t *testing.T) {
	pos := token.Position{Line: 1, Column: 1}

	tests := []struct {
		name           string
		modifiers      []ast.StringModifier
		expectedCode   ErrorCode
		expectedSubstr string
	}{
		{
			name: "base64 and base64wide conflict",
			modifiers: []ast.StringModifier{
				{Type: ast.StringModifierBase64},
				{Type: ast.StringModifierBase64Wide},
			},
			expectedCode:   ErrCodeInvalidModifier,
			expectedSubstr: "cannot use both 'base64' and 'base64wide'",
		},
		{
			name: "base64 invalid alphabet length",
			modifiers: []ast.StringModifier{
				{Type: ast.StringModifierBase64, Value: "too_short"},
			},
			expectedCode:   ErrCodeInvalidModifier,
			expectedSubstr: "invalid base64 alphabet length",
		},
		{
			name: "base64 alphabet containing =",
			modifiers: []ast.StringModifier{
				{Type: ast.StringModifierBase64, Value: "================================================================"},
			},
			expectedCode:   ErrCodeInvalidModifier,
			expectedSubstr: "'=' is not allowed",
		},
		{
			name: "xor value out of range",
			modifiers: []ast.StringModifier{
				{Type: ast.StringModifierXor, Value: 300},
			},
			expectedCode:   ErrCodeInvalidModifier,
			expectedSubstr: "xor value must be between 0 and 255",
		},
		{
			name: "xor range min greater than max",
			modifiers: []ast.StringModifier{
				{Type: ast.StringModifierXor, Value: [2]int{100, 50}},
			},
			expectedCode:   ErrCodeInvalidModifier,
			expectedSubstr: "xor range minimum cannot be greater than maximum",
		},
		{
			name: "xor range struct min greater than max",
			modifiers: []ast.StringModifier{
				{Type: ast.StringModifierXor, Value: ast.XorRange{Min: 150, Max: 50}},
			},
			expectedCode:   ErrCodeInvalidModifier,
			expectedSubstr: "xor range minimum cannot be greater than maximum",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prog := &ast.Program{
				Rules: []*ast.Rule{
					{
						Pos:  pos,
						Name: "prog_test",
						Strings: []*ast.String{
							{
								Pos:        pos,
								Identifier: "$s",
								Pattern:    &ast.TextString{Pos: pos, Value: "hello"},
								Modifiers:  tt.modifiers,
							},
						},
						Condition: &ast.Identifier{Pos: pos, Name: "$s"},
					},
				},
			}
			v := NewValidator()
			errs := v.ValidateProgram(prog)

			semErr := findSemanticErrorByCode(errs, tt.expectedCode)
			if semErr == nil {
				t.Fatalf("expected error code %q, got: %v", tt.expectedCode, errs)
			}
			if !strings.Contains(semErr.Message, tt.expectedSubstr) {
				t.Errorf("error message = %q, want containing %q", semErr.Message, tt.expectedSubstr)
			}
		})
	}
}

func TestSemanticErrorHelpers(t *testing.T) {
	pos := token.Position{Line: 10, Column: 5}
	err := NewError(ErrCodeUndefinedIdentifier, "identifier missing", pos).
		WithRule("rule_alpha").
		WithSuggestion("$alpha")

	if err.Code != ErrCodeUndefinedIdentifier {
		t.Errorf("Code = %v, want %v", err.Code, ErrCodeUndefinedIdentifier)
	}
	if err.Rule != "rule_alpha" {
		t.Errorf("Rule = %v, want rule_alpha", err.Rule)
	}
	if err.Suggestion != "$alpha" {
		t.Errorf("Suggestion = %v, want $alpha", err.Suggestion)
	}
	if !err.IsUndefinedIdentifier() {
		t.Error("expected IsUndefinedIdentifier() = true")
	}
	if err.IsTypeMismatch() {
		t.Error("expected IsTypeMismatch() = false")
	}

	formatted := err.Error()
	if !strings.Contains(formatted, "semantic error at 10:5:") {
		t.Errorf("formatted error %q missing position", formatted)
	}
	if !strings.Contains(formatted, "; did you mean $alpha?") {
		t.Errorf("formatted error %q missing suggestion", formatted)
	}
}
