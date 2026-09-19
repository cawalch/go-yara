package compiler

import (
	"testing"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

// TestIntegerLiteralCompilation is a regression test for hex and octal integer
// literals in conditions. Previously parseIntLiteral used base 10, so any
// 0xNN or 0oNN literal failed strconv.ParseInt and silently compiled to 0.
// The two fuzz seeds that exercised this ("0x1000 == 4096", "int8(0) == 0x74")
// only asserted no-crash, which let the bug persist. These cases assert the
// actual runtime value.
func TestIntegerLiteralCompilation(t *testing.T) {
	tests := []struct {
		name      string
		condition string
		data      []byte
		wantMatch bool
	}{
		// Hex literals — the core regression. 0x41 == 65 ('A').
		{"hex equals decimal", `0x41 == 65`, nil, true},
		{"hex equals hex", `0x41 == 0x41`, nil, true},
		{"hex uppercase", `0xFF == 255`, nil, true},
		{"hex small", `0xA == 10`, nil, true},
		{"hex mismatch", `0x41 == 66`, nil, false},
		// Hex as a data-read offset argument: uint8(0) reads 'A' (0x41) from data.
		{"hex offset into data", `uint8(0) == 0x41`, []byte("ABCDEFGH"), true},
		{"hex offset mismatch", `uint8(0) == 0x42`, []byte("ABCDEFGH"), false},
		// Nested data read resolved via hex literal (the canonical PE-header
		// idiom from the YARA docs): uint32(uint32(0x3C)). We keep it simple
		// here — one level of hex-offset read.
		{"hex offset second byte", `uint8(0x1) == 0x42`, []byte("ABCDEFGH"), true},
		// Octal literals (0o prefix) — also broken by the base-10 bug.
		{"octal equals decimal", `0o101 == 65`, nil, true},
		{"octal mismatch", `0o17 == 16`, nil, false},
		// Decimal still works (regression guard for the base change).
		{"decimal equals", `65 == 65`, nil, true},
		{"decimal mismatch", `65 == 66`, nil, false},
		// Values above uint32 require the dedicated 64-bit operand contract.
		{"64-bit equals", `4294967296 == 4294967296`, nil, true},
		{"64-bit differs from zero", `4294967296 == 0`, nil, false},
		{"64-bit neighboring values", `4294967297 == 4294967296`, nil, false},
		{"max int64 equals", `9223372036854775807 == 9223372036854775807`, nil, true},
		{"max int64 mismatch", `9223372036854775807 == 9223372036854775806`, nil, false},
		{"min int64", `-9223372036854775808 < -9223372036854775807`, nil, true},
		{"min int64 not zero", `-9223372036854775808 == 0`, nil, false},
		{"hex signed bits", `0xffffffffffffffff == -1`, nil, true},
		{"hex sign bit", `0x8000000000000000 == -9223372036854775808`, nil, true},
		{"hex high bits", `0xfffffffffffffffe == -2`, nil, true},
		{"largest valid KB size", `9007199254740991KB == 9223372036854774784`, nil, true},
		{"octal signed maximum", `0o777777777777777777777 == 9223372036854775807`, nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := "rule lit_test { condition: " + tt.condition + " }"
			c := NewCompiler()
			program, err := c.CompileSource(src)
			if err != nil {
				t.Fatalf("CompileSource() error = %v", err)
			}

			data := tt.data
			if data == nil {
				data = []byte("x") // non-empty for filesize-based conditions
			}

			scanner := NewScanner(program)
			results, err := scanner.Scan(data)
			if err != nil {
				t.Fatalf("Scan() error = %v", err)
			}

			matched := len(results.MatchedRules) == 1
			if matched != tt.wantMatch {
				t.Errorf("condition %q on data %q: matched=%v, want %v",
					tt.condition, string(data), matched, tt.wantMatch)
			}
		})
	}
}

func TestIntegerLiteralOverflow(t *testing.T) {
	for _, literal := range []string{"9223372036854775808", "18446744073709551616", "-9223372036854775809", "0x10000000000000000", "0o1000000000000000000000", "9007199254740992KB", "8796093022208MB", "8589934592GB"} {
		if _, err := NewCompiler().CompileSource("rule r { condition: " + literal + " == 0 }"); err == nil {
			t.Errorf("out-of-range literal %s compiled successfully", literal)
		}
	}
}

func TestSignedIntegerASTLiteral(t *testing.T) {
	emitter := NewEmitter()
	cc := NewConditionCompiler(emitter, nil)
	if err := cc.CompileCondition(&ast.Condition{Expression: &ast.Literal{Type: token.IntegerLit, Value: int64(-7)}}); err != nil {
		t.Fatal(err)
	}
	emitter.EmitHalt(0, 0)
	code, err := emitter.GetBytecode()
	if err != nil {
		t.Fatal(err)
	}
	assertInterpreterResult(t, code, -7)
}
