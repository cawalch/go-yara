package compiler

import (
	"testing"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

func TestNoStringLogicalTruthTable(t *testing.T) {
	values := []noStringTruth{noStringFalse, noStringTrue, noStringUnknown}
	for _, tc := range []struct {
		op   token.Type
		want [3][3]noStringTruth
	}{
		{token.AND, [3][3]noStringTruth{{noStringFalse, noStringFalse, noStringFalse}, {noStringFalse, noStringTrue, noStringUnknown}, {noStringFalse, noStringUnknown, noStringUnknown}}},
		{token.OR, [3][3]noStringTruth{{noStringFalse, noStringTrue, noStringUnknown}, {noStringTrue, noStringTrue, noStringTrue}, {noStringUnknown, noStringTrue, noStringUnknown}}},
	} {
		for i, left := range values {
			for j, right := range values {
				if got := logicalNoStringTruth(tc.op, left, right); got != tc.want[i][j] {
					t.Fatalf("%v: %d, %d = %d, want %d", tc.op, left, right, got, tc.want[i][j])
				}
			}
		}
	}
}

func TestNoStringBooleanAnalysisParity(t *testing.T) {
	var atoms []ast.Expression
	for _, condition := range []string{
		"true", "false", "$a", "filesize", "other_rule", "#a > 0", "#a == 0",
		"#a + #b >= 1", "$a at 0", "$a at filesize", "any of them", "none of them",
		"all of ($missing*)", "fail.check()", "uint8(0) == 1", "@a[fail.check()]",
		"for any of them : ($)", "not $a",
	} {
		parsed, err := NewCompiler().compileParseWithContext(t.Context(),
			"rule sample { condition: "+condition+" }")
		if err != nil {
			t.Fatal(err)
		}
		atoms = append(atoms, parsed.Rules[0].Condition)
	}
	check := func(expr ast.Expression) {
		t.Helper()
		truth, safe := analyzeNoStringBoolean(expr)
		if truth != truthWithoutStringMatches(expr) || safe != referenceEvaluationSafeWithoutStringMatches(expr) {
			t.Fatalf("analysis differs from separate truth/safety traversals: %#v", expr)
		}
	}
	for _, left := range atoms {
		for _, right := range atoms {
			for _, op := range []token.Type{token.AND, token.OR} {
				pair := &ast.BinaryOp{Left: left, Op: op, Right: right}
				check(pair)
				check(&ast.UnaryOp{Op: token.NOT, Right: pair})
				// Boolean subtrees can also occur inside atomic analyses.
				for _, arithmetic := range []token.Type{token.EQ, token.PLUS} {
					check(&ast.BinaryOp{Left: pair, Op: arithmetic, Right: &ast.Literal{Type: token.IntegerLit, Value: int64(0)}})
				}
				for _, third := range atoms {
					for _, outer := range []token.Type{token.AND, token.OR} {
						check(&ast.BinaryOp{Left: pair, Op: outer, Right: third})
						check(&ast.BinaryOp{Left: third, Op: outer, Right: pair})
					}
				}
			}
		}
	}
}

// Preserve the pre-optimization safety traversal as a differential oracle.
func referenceEvaluationSafeWithoutStringMatches(expr ast.Expression) bool {
	switch e := expr.(type) {
	case *ast.Literal, *ast.Identifier:
		return true
	case *ast.StringCount:
		return staticStringOccurrenceIndex(e.Index)
	case *ast.StringOffset:
		return staticStringOccurrenceIndex(e.Index)
	case *ast.StringLength:
		return staticStringOccurrenceIndex(e.Index)
	case *ast.UnaryOp:
		return e.Op == token.NOT && referenceEvaluationSafeWithoutStringMatches(e.Right)
	case *ast.BinaryOp:
		leftSafe := referenceEvaluationSafeWithoutStringMatches(e.Left)
		if !leftSafe {
			return false
		}
		leftTruth := truthWithoutStringMatches(e.Left)
		switch e.Op {
		case token.AND:
			if leftTruth&noStringTrue == 0 {
				return true
			}
			return referenceEvaluationSafeWithoutStringMatches(e.Right)
		case token.OR:
			if leftTruth&noStringFalse == 0 {
				return true
			}
			return referenceEvaluationSafeWithoutStringMatches(e.Right)
		case token.AT, token.IN:
			return staticStringConstraint(e.Op, e.Right)
		default:
			_, leftOK := integerWithoutStringMatches(e.Left)
			_, rightOK := integerWithoutStringMatches(e.Right)
			return leftOK && rightOK
		}
	case *ast.OfExpression:
		return isRuleStringSet(e.Strings) &&
			ofTruthWithoutStringMatches(e) != noStringUnknown
	case *ast.PercentExpression:
		_, ok := integerWithoutStringMatches(e.Value)
		return ok
	default:
		// Function calls and loops can return runtime errors. Keep evaluating
		// them unless an enclosing short-circuit proves they are unreachable.
		return false
	}
}
