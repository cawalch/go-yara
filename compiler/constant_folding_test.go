package compiler

import (
	"testing"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

func TestConstantFoldingBooleanLogic(t *testing.T) {
	tests := []struct {
		name     string
		expr     ast.Expression
		wantBool bool
	}{
		{"true and true", &ast.BinaryOp{Left: boolLiteral(true, token.Position{}), Op: token.AND, Right: boolLiteral(true, token.Position{})}, true},
		{"true and false", &ast.BinaryOp{Left: boolLiteral(true, token.Position{}), Op: token.AND, Right: boolLiteral(false, token.Position{})}, false},
		{"false and true", &ast.BinaryOp{Left: boolLiteral(false, token.Position{}), Op: token.AND, Right: boolLiteral(true, token.Position{})}, false},
		{"false and false", &ast.BinaryOp{Left: boolLiteral(false, token.Position{}), Op: token.AND, Right: boolLiteral(false, token.Position{})}, false},
		{"true or true", &ast.BinaryOp{Left: boolLiteral(true, token.Position{}), Op: token.OR, Right: boolLiteral(true, token.Position{})}, true},
		{"true or false", &ast.BinaryOp{Left: boolLiteral(true, token.Position{}), Op: token.OR, Right: boolLiteral(false, token.Position{})}, true},
		{"false or true", &ast.BinaryOp{Left: boolLiteral(false, token.Position{}), Op: token.OR, Right: boolLiteral(true, token.Position{})}, true},
		{"false or false", &ast.BinaryOp{Left: boolLiteral(false, token.Position{}), Op: token.OR, Right: boolLiteral(false, token.Position{})}, false},
		{"not true", &ast.UnaryOp{Op: token.NOT, Right: boolLiteral(true, token.Position{})}, false},
		{"not false", &ast.UnaryOp{Op: token.NOT, Right: boolLiteral(false, token.Position{})}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := FoldConstants(tt.expr)
			lit, ok := res.(*ast.Literal)
			if !ok {
				t.Fatalf("expected literal, got %T", res)
			}
			if tt.wantBool && lit.Type != token.TRUE {
				t.Fatalf("expected token.TRUE, got %v", lit.Type)
			}
			if !tt.wantBool && lit.Type != token.FALSE {
				t.Fatalf("expected token.FALSE, got %v", lit.Type)
			}
		})
	}
}

func TestConstantFoldingShortCircuitWithIdentifiers(t *testing.T) {
	ident := &ast.Identifier{Name: "$a"}

	t.Run("false and $a -> false", func(t *testing.T) {
		expr := &ast.BinaryOp{Left: boolLiteral(false, token.Position{}), Op: token.AND, Right: ident}
		res := FoldConstants(expr)
		if lit, ok := res.(*ast.Literal); !ok || lit.Type != token.FALSE {
			t.Fatalf("expected FALSE literal, got %v", res)
		}
	})

	t.Run("$a and false -> false", func(t *testing.T) {
		expr := &ast.BinaryOp{Left: ident, Op: token.AND, Right: boolLiteral(false, token.Position{})}
		res := FoldConstants(expr)
		if lit, ok := res.(*ast.Literal); !ok || lit.Type != token.FALSE {
			t.Fatalf("expected FALSE literal, got %v", res)
		}
	})

	t.Run("true or $a -> true", func(t *testing.T) {
		expr := &ast.BinaryOp{Left: boolLiteral(true, token.Position{}), Op: token.OR, Right: ident}
		res := FoldConstants(expr)
		if lit, ok := res.(*ast.Literal); !ok || lit.Type != token.TRUE {
			t.Fatalf("expected TRUE literal, got %v", res)
		}
	})

	t.Run("$a or true -> true", func(t *testing.T) {
		expr := &ast.BinaryOp{Left: ident, Op: token.OR, Right: boolLiteral(true, token.Position{})}
		res := FoldConstants(expr)
		if lit, ok := res.(*ast.Literal); !ok || lit.Type != token.TRUE {
			t.Fatalf("expected TRUE literal, got %v", res)
		}
	})

	t.Run("true and $a -> $a", func(t *testing.T) {
		expr := &ast.BinaryOp{Left: boolLiteral(true, token.Position{}), Op: token.AND, Right: ident}
		res := FoldConstants(expr)
		if id, ok := res.(*ast.Identifier); !ok || id.Name != "$a" {
			t.Fatalf("expected identifier $a, got %v", res)
		}
	})

	t.Run("$a and true -> $a", func(t *testing.T) {
		expr := &ast.BinaryOp{Left: ident, Op: token.AND, Right: boolLiteral(true, token.Position{})}
		res := FoldConstants(expr)
		if id, ok := res.(*ast.Identifier); !ok || id.Name != "$a" {
			t.Fatalf("expected identifier $a, got %v", res)
		}
	})

	t.Run("false or $a -> $a", func(t *testing.T) {
		expr := &ast.BinaryOp{Left: boolLiteral(false, token.Position{}), Op: token.OR, Right: ident}
		res := FoldConstants(expr)
		if id, ok := res.(*ast.Identifier); !ok || id.Name != "$a" {
			t.Fatalf("expected identifier $a, got %v", res)
		}
	})

	t.Run("$a or false -> $a", func(t *testing.T) {
		expr := &ast.BinaryOp{Left: ident, Op: token.OR, Right: boolLiteral(false, token.Position{})}
		res := FoldConstants(expr)
		if id, ok := res.(*ast.Identifier); !ok || id.Name != "$a" {
			t.Fatalf("expected identifier $a, got %v", res)
		}
	})
}

func TestConstantFoldingIntegerComparisons(t *testing.T) {
	tests := []struct {
		name     string
		left     int64
		op       token.Type
		right    int64
		wantBool bool
	}{
		{"1 == 1", 1, token.EQ, 1, true},
		{"1 == 2", 1, token.EQ, 2, false},
		{"1 != 2", 1, token.NEQ, 2, true},
		{"1 != 1", 1, token.NEQ, 1, false},
		{"1 < 2", 1, token.LT, 2, true},
		{"2 < 1", 2, token.LT, 1, false},
		{"1 <= 1", 1, token.LE, 1, true},
		{"2 <= 1", 2, token.LE, 1, false},
		{"2 > 1", 2, token.GT, 1, true},
		{"1 > 2", 1, token.GT, 2, false},
		{"2 >= 2", 2, token.GE, 2, true},
		{"1 >= 2", 1, token.GE, 2, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expr := &ast.BinaryOp{
				Left:  intLiteral(tt.left, token.Position{}),
				Op:    tt.op,
				Right: intLiteral(tt.right, token.Position{}),
			}
			res := FoldConstants(expr)
			lit, ok := res.(*ast.Literal)
			if !ok {
				t.Fatalf("expected literal, got %T", res)
			}
			if tt.wantBool && lit.Type != token.TRUE {
				t.Fatalf("expected token.TRUE, got %v", lit.Type)
			}
			if !tt.wantBool && lit.Type != token.FALSE {
				t.Fatalf("expected token.FALSE, got %v", lit.Type)
			}
		})
	}
}

func TestConstantFoldingIntegerArithmetic(t *testing.T) {
	t.Run("arithmetic combinations", func(t *testing.T) {
		c := NewCompiler()
		prog, err := c.CompileSource(`
			rule test_arithmetic {
				condition:
					(1 + 2 == 3) and
					(10 - 4 == 6) and
					(3 * 4 == 12) and
					(20 / 4 == 5) and
					(20 % 3 == 2) and
					(1 << 4 == 16) and
					(16 >> 2 == 4) and
					(3 & 1 == 1) and
					(2 | 1 == 3) and
					(3 ^ 1 == 2)
			}
		`)
		if err != nil {
			t.Fatalf("CompileSource failed: %v", err)
		}
		if len(prog.Rules) != 1 {
			t.Fatalf("expected 1 rule, got %d", len(prog.Rules))
		}
		if prog.Rules[0].IsDead {
			t.Fatalf("expected rule to be alive, got dead")
		}
	})

	t.Run("division by zero is not folded", func(t *testing.T) {
		expr := &ast.BinaryOp{
			Left:  intLiteral(10, token.Position{}),
			Op:    token.DIVIDE,
			Right: intLiteral(0, token.Position{}),
		}
		res := FoldConstants(expr)
		if _, ok := res.(*ast.BinaryOp); !ok {
			t.Fatalf("expected BinaryOp preserved for div by zero, got %T", res)
		}
	})
}

func TestConstantFoldingStringOperations(t *testing.T) {
	c := NewCompiler()
	prog, err := c.CompileSource(`
		rule test_strings {
			condition:
				("abc" == "abc") and
				("abc" != "def") and
				("hello world" contains "world") and
				("hello world" icontains "WORLD") and
				("prefix_test" startswith "prefix") and
				("test_suffix" endswith "suffix") and
				("ABC" iequals "abc")
		}
	`)
	if err != nil {
		t.Fatalf("CompileSource failed: %v", err)
	}
	if prog.Rules[0].IsDead {
		t.Fatalf("expected rule to be alive")
	}
}

func TestConstantFoldingRuleDeadFlag(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		wantDead bool
	}{
		{
			name: "statically false 1 == 2",
			source: `
				rule test_dead1 {
					strings:
						$a = "needle"
					condition:
						1 == 2
				}
			`,
			wantDead: true,
		},
		{
			name: "statically false false and $a",
			source: `
				rule test_dead2 {
					strings:
						$a = "needle"
					condition:
						false and $a
				}
			`,
			wantDead: true,
		},
		{
			name: "statically false 1 + 1 != 2",
			source: `
				rule test_dead3 {
					strings:
						$a = "needle"
					condition:
						1 + 1 != 2
				}
			`,
			wantDead: true,
		},
		{
			name: "statically false not true",
			source: `
				rule test_dead4 {
					strings:
						$a = "needle"
					condition:
						not true
				}
			`,
			wantDead: true,
		},
		{
			name: "statically true 1 == 1",
			source: `
				rule test_alive1 {
					strings:
						$a = "needle"
					condition:
						1 == 1
				}
			`,
			wantDead: false,
		},
		{
			name: "statically true true or $a",
			source: `
				rule test_alive2 {
					strings:
						$a = "needle"
					condition:
						true or $a
				}
			`,
			wantDead: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCompiler()
			prog, err := c.CompileSource(tt.source)
			if err != nil {
				t.Fatalf("CompileSource error: %v", err)
			}
			if len(prog.Rules) != 1 {
				t.Fatalf("expected 1 rule, got %d", len(prog.Rules))
			}
			rule := prog.Rules[0]
			if rule.IsDead != tt.wantDead {
				t.Fatalf("IsDead = %v, want %v", rule.IsDead, tt.wantDead)
			}
		})
	}
}
