package compiler

import (
	"testing"
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
