package parser

import (
	"strings"
	"testing"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/token"
)

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

// assertCountInOf validates the AST structure of a count-in-of condition.
func assertCountInOf(t *testing.T, rule *ast.Rule, condition string) {
	t.Helper()

	if strings.Contains(condition, " of ") {
		assertOfExpression(t, rule)
		return
	}
	assertInExpression(t, rule)
}

// assertOfExpression validates an OfExpression AST node.
func assertOfExpression(t *testing.T, rule *ast.Rule) {
	t.Helper()
	ofExpr, ok := rule.Condition.(*ast.OfExpression)
	if !ok {
		t.Fatalf("expected *ast.OfExpression, got %T", rule.Condition)
	}
	if _, ok := ofExpr.Count.(*ast.StringCount); !ok {
		t.Errorf("expected *ast.StringCount for count, got %T", ofExpr.Count)
	}
	if ofExpr.InRange == nil {
		t.Error("expected InRange to be set")
		return
	}
	rangeOp, ok := ofExpr.InRange.(*ast.BinaryOp)
	if !ok {
		t.Errorf("expected *ast.BinaryOp for InRange, got %T", ofExpr.InRange)
		return
	}
	if rangeOp.Op != token.DOT {
		t.Errorf("expected DOT operator for range, got %s", rangeOp.Op)
	}
}

// assertInExpression validates a plain BinaryOp(IN) AST node.
func assertInExpression(t *testing.T, rule *ast.Rule) {
	t.Helper()
	binOp, ok := rule.Condition.(*ast.BinaryOp)
	if !ok {
		t.Fatalf("expected *ast.BinaryOp, got %T", rule.Condition)
	}
	if binOp.Op != token.IN {
		t.Errorf("expected IN operator, got %s", binOp.Op)
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

			assertCountInOf(t, program.Rules[0], tt.condition)
		})
	}
}
