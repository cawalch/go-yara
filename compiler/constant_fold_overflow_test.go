package compiler

import (
	"context"
	"math"
	"testing"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

func TestConstantFoldOverflowAndShiftCompileErrors(t *testing.T) {
	overflowExprs := []string{
		`9223372036854775807 + 1 == 0`,
		`~9223372036854775807 * 9223372036854775807 == 0`,
		`(-(9223372036854775807) - 1) \ -1 == 0`,
		`(-(9223372036854775807) - 1) / -1 == 0`,
		`0 - (-(9223372036854775807) - 1) == 0`,
		`-9223372036854775807 - 2 == 0`,
		`9223372036854775807 - (-1) == 0`,
		`1 \ (2 - 2) == 0`,
		`1 % (2 - 2) == 0`,
		`1 << -1 == 0`,
		`1 >> -1 == 0`,
		`defined(1 \ 0)`,
		`defined((-(9223372036854775807) - 1) \ -1)`,
	}
	for _, cond := range overflowExprs {
		if _, err := NewCompiler().CompileSourceWithContext(context.Background(), `rule r { condition: `+cond+` }`); err == nil {
			t.Errorf("condition %q compiled cleanly, want compile error", cond)
		}
	}
}

func TestConstantFoldAndRuntimeBoundaryParity(t *testing.T) {
	src := `
rule mod_min_undef { condition: not defined((-(9223372036854775807) - 1) % -1) }
rule unary_min_wrap { condition: -( -(9223372036854775807) - 1 ) == (-(9223372036854775807) - 1) }
rule shl_64_zero { condition: (1 << 64) == 0 }
rule shr_64_zero { condition: (-1 >> 64) == 0 }
rule shl_63_signbit { condition: (1 << 63) < 0 }
rule rt_shl_64_zero { condition: (1 << (filesize + 63)) == 0 }
rule rt_shr_64_zero { condition: (-1 >> (filesize + 63)) == 0 }
rule rt_shl_neg_undef { condition: not defined(1 << (filesize - 2)) }
rule rt_shr_neg_undef { condition: not defined(1 >> (filesize - 2)) }
rule rt_div_min_undef { condition: not defined(((-(9223372036854775807) - 1) + (filesize - 1)) \ -1) }
rule rt_mod_min_undef { condition: not defined(((-(9223372036854775807) - 1) + (filesize - 1)) % -1) }
`
	prog, err := NewCompiler().CompileSourceWithContext(context.Background(), src)
	if err != nil {
		t.Fatalf("CompileSourceWithContext() error = %v", err)
	}
	res, err := prog.Scan([]byte("a")) // filesize == 1
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	for _, r := range prog.Rules {
		if !res.RuleResults[r.Name] {
			t.Errorf("rule %s did not match", r.Name)
		}
	}
}

func TestFoldConstantsLeavesOverflowUnfolded(t *testing.T) {
	pos := token.Position{Line: 1, Column: 1}
	for _, expr := range []ast.Expression{
		&ast.BinaryOp{Pos: pos, Left: intLiteral(math.MaxInt64, pos), Op: token.PLUS, Right: intLiteral(1, pos)},
		&ast.BinaryOp{Pos: pos, Left: intLiteral(math.MinInt64, pos), Op: token.MINUS, Right: intLiteral(1, pos)},
		&ast.BinaryOp{Pos: pos, Left: intLiteral(math.MinInt64, pos), Op: token.MULTIPLY, Right: intLiteral(-1, pos)},
		&ast.BinaryOp{Pos: pos, Left: intLiteral(math.MinInt64, pos), Op: token.IntDivide, Right: intLiteral(-1, pos)},
		&ast.BinaryOp{Pos: pos, Left: intLiteral(math.MinInt64, pos), Op: token.MODULO, Right: intLiteral(-1, pos)},
		&ast.BinaryOp{Pos: pos, Left: intLiteral(1, pos), Op: token.LeftShift, Right: intLiteral(-1, pos)},
		&ast.BinaryOp{Pos: pos, Left: intLiteral(1, pos), Op: token.RightShift, Right: intLiteral(-1, pos)},
	} {
		got := FoldConstants(expr)
		if _, ok := got.(*ast.BinaryOp); !ok {
			t.Errorf("FoldConstants(%#v) folded to %#v, want unfolded *ast.BinaryOp", expr, got)
		}
	}

	// Shifts >= 64 fold to 0 cleanly.
	for _, op := range []token.Type{token.LeftShift, token.RightShift} {
		got := FoldConstants(&ast.BinaryOp{Pos: pos, Left: intLiteral(-1, pos), Op: op, Right: intLiteral(64, pos)})
		lit, ok := got.(*ast.Literal)
		if !ok || lit.Value != int64(0) {
			t.Errorf("FoldConstants(-1 %v 64) = %#v, want int64(0)", op, got)
		}
	}
}
