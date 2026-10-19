package regex

import "testing"

func TestLiteralPrefix(t *testing.T) {
	tests := []struct {
		pattern  string
		prefix   string
		anchored bool
	}{
		{pattern: "malwa[a-z]+", prefix: "malwa"},
		{pattern: "^header.*", prefix: "header", anchored: true},
		{pattern: "foo|bar"},
		{pattern: ".*suffix"},
	}
	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			ast, err := NewParser(ParserFlagEnableStrictEscapeSequences).Parse(tt.pattern)
			if err != nil {
				t.Fatal(err)
			}
			code, err := Compile(ast)
			if err != nil {
				t.Fatal(err)
			}
			prefix, anchored := LiteralPrefix(code)
			if string(prefix) != tt.prefix || anchored != tt.anchored {
				t.Fatalf("LiteralPrefix() = (%q, %v), want (%q, %v)", prefix, anchored, tt.prefix, tt.anchored)
			}
		})
	}
}

func TestEmitterSequence(t *testing.T) {
	e := NewEmitter()
	e.Emit(OpLiteral).EmitU8('A').Emit(OpJump).EmitI16(0x1234).Emit(OpMatch)
	b := e.Bytes()
	want := []byte{OpLiteral, 'A', OpJump, 0x34, 0x12, OpMatch}
	if len(b) != len(want) {
		t.Fatalf("len=%d, want %d", len(b), len(want))
	}
	for i := range want {
		if b[i] != want[i] {
			t.Fatalf("byte[%d]=0x%x, want 0x%x", i, b[i], want[i])
		}
	}
}

// TestLiteralPrefixEdgeCases pins the bounds handling in LiteralPrefix: empty
// and nil code, a dangling OpLiteral without its operand byte, and anchored
// prefixes.
func TestLiteralPrefixEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		code     []byte
		prefix   string
		anchored bool
	}{
		{name: "nil code", code: nil},
		{name: "empty code", code: []byte{}},
		{name: "dangling literal", code: []byte{OpLiteral}},
		{name: "two literals", code: []byte{OpLiteral, 'a', OpLiteral, 'b'}, prefix: "ab"},
		{name: "anchored only", code: []byte{OpMatchAtStart}, anchored: true},
		{name: "anchored literal", code: []byte{OpMatchAtStart, OpLiteral, 'x'}, prefix: "x", anchored: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefix, anchored := LiteralPrefix(tt.code)
			if string(prefix) != tt.prefix || anchored != tt.anchored {
				t.Fatalf("LiteralPrefix(%v) = (%q, %v), want (%q, %v)", tt.code, prefix, anchored, tt.prefix, tt.anchored)
			}
		})
	}
}
