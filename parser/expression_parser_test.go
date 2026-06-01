package parser

import (
	"strings"
	"testing"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/token"
)

func parseRule(t *testing.T, source string) *ast.Rule {
	t.Helper()
	l := lexer.New(source)
	p := New(l)
	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(program.Rules) == 0 {
		t.Fatal("expected at least one rule")
	}
	return program.Rules[0]
}

func TestPercentKeywordParsing(t *testing.T) {
	tests := []struct {
		name        string
		condition   string
		wantPercent bool
		wantError   bool
	}{
		{
			name:        "N percent of them",
			condition:   "50 percent of them",
			wantPercent: true,
			wantError:   false,
		},
		{
			name:        "N % of them",
			condition:   "50 % of them",
			wantPercent: true,
			wantError:   false,
		},
		{
			name:        "N percent of ($a, $b)",
			condition:   "33 percent of ($a, $b)",
			wantPercent: true,
			wantError:   false,
		},
		{
			name:        "N % of ($a, $b)",
			condition:   "33 % of ($a, $b)",
			wantPercent: true,
			wantError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build a minimal rule with the condition
			source := "rule test {\n\tstrings:\n\t\t$a = \"hello\"\n\t\t$b = \"world\"\n\tcondition:\n\t\t" + tt.condition + "\n}"

			l := lexer.New(source)
			p := New(l)
			program, err := p.ParseRules()

			if tt.wantError {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(program.Rules) == 0 {
				t.Fatal("expected at least one rule")
			}

			rule := program.Rules[0]
			ofExpr, ok := rule.Condition.(*ast.OfExpression)
			if !ok {
				t.Fatalf("expected *ast.OfExpression, got %T", rule.Condition)
			}

			_, ok = ofExpr.Count.(*ast.PercentExpression)
			if !ok {
				t.Fatalf("expected *ast.PercentExpression for count, got %T", ofExpr.Count)
			}
		})
	}
}

func TestPercentKeywordNotReserved(t *testing.T) {
	// Ensure "percent" as an identifier still works in non-keyword contexts
	// (e.g., in a string or as part of a larger identifier)
	source := `rule test {
		strings:
			$a = "percent"
		condition:
			$a
	}`

	l := lexer.New(source)
	p := New(l)
	_, err := p.ParseRules()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPercentToken(t *testing.T) {
	// Verify the PERCENT token type exists and has the right string
	if token.PERCENT.String() != "PERCENT" {
		t.Errorf("expected PERCENT token string, got %s", token.PERCENT.String())
	}
}

func TestCountInOfParsing(t *testing.T) {
	tests := []struct {
		name      string
		condition string
		wantError bool
	}{
		{"count_in_of_them", "#a in (1..3) of them", false},
		{"count_in_of_string_set", "#a in (1..3) of ($a, $b)", false},
		{"count_in_of_wildcard", "#a in (0..5) of ($a*)", false},
		{"count_in_of_all", "#a in (2..10) of all", true},
		{"count_in_no_of", "#a in (1..3)", false},
		{"bad_range_no_count", "1 in (1..3) of them", true}, // not valid YARA - range without count
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source := "rule test {\n\tstrings:\n\t\t$a = \"hello\"\n\t\t$b = \"world\"\ncondition:\n\t\t" + tt.condition + "\n}"

			l := lexer.New(source)
			p := New(l)
			program, err := p.ParseRules()

			if tt.wantError {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(program.Rules) == 0 {
				t.Fatal("expected at least one rule")
			}

			rule := program.Rules[0]

			// If condition contains "of", it should be an OfExpression
			if strings.Contains(tt.condition, " of ") {
				ofExpr, ok := rule.Condition.(*ast.OfExpression)
				if !ok {
					t.Fatalf("expected *ast.OfExpression, got %T", rule.Condition)
				}

				// Count should be StringCount (#a)
				if _, ok := ofExpr.Count.(*ast.StringCount); !ok {
					t.Errorf("expected *ast.StringCount for count, got %T", ofExpr.Count)
				}

				// InRange should be BinaryOp with DOT (range)
				if ofExpr.InRange == nil {
					t.Error("expected InRange to be set")
				} else {
					rangeOp, ok := ofExpr.InRange.(*ast.BinaryOp)
					if !ok {
						t.Errorf("expected *ast.BinaryOp for InRange, got %T", ofExpr.InRange)
					} else if rangeOp.Op != token.DOT {
						t.Errorf("expected DOT operator for range, got %s", rangeOp.Op)
					}
				}
			} else {
				// Without "of", it should be a plain BinaryOp with IN
				binOp, ok := rule.Condition.(*ast.BinaryOp)
				if !ok {
					t.Fatalf("expected *ast.BinaryOp, got %T", rule.Condition)
				}
				if binOp.Op != token.IN {
					t.Errorf("expected IN operator, got %s", binOp.Op)
				}
			}
		})
	}
}
