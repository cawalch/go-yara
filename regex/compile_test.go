package regex

import (
	"slices"
	"strings"
	"testing"
)

func TestCompileLiteralAndAny(t *testing.T) {
	p := NewParser(0)
	ast, err := p.Parse("a.")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	code, err := Compile(ast)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	validateLiteralAndAnyCode(t, code)
}

func validateLiteralAndAnyCode(t *testing.T, code []byte) {
	if len(code) < 3 {
		t.Fatalf("short code: got %d bytes: %v", len(code), code)
	}
	if code[0] != OpLiteral || code[1] != 'a' {
		t.Fatalf("want literal 'a' at start, got: %v", code[:2])
	}
	if len(code) > 3 && code[2] != OpAny && code[3] != OpAny {
		t.Fatalf("want OpAny after 'a', got: %v", code[2:4])
	}
	if len(code) == 3 && code[2] != OpAny {
		t.Fatalf("want OpAny after 'a', got: %v (OpAny=%d)", code[2], OpAny)
	}
	if code[len(code)-1] != OpMatch {
		t.Fatalf("missing OpMatch at end, got: %v", code[len(code)-1])
	}
}

func TestCompileClassAndAnchors(t *testing.T) {
	p := NewParser(0)
	ast, err := p.Parse("^[a-c]$")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	code, err := Compile(ast)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	// Expect: OpMatchAtStart, OpClass, 32+1 bytes, OpMatchAtEnd, OpMatch
	if len(code) < 1+1+33+1+1 {
		t.Fatalf("code too short: %d", len(code))
	}
	if code[0] != OpMatchAtStart {
		t.Fatalf("want OpMatchAtStart")
	}
	if code[1] != OpClass {
		t.Fatalf("want OpClass after anchor start")
	}
	// bitmap occupies next 32 bytes, neg flag next 1 byte
	if code[1+1+32] != 0 && code[1+1+32] != 1 {
		t.Fatalf("bad class neg flag")
	}
	if code[len(code)-2] != OpMatchAtEnd {
		t.Fatalf("want OpMatchAtEnd before OpMatch")
	}
	if code[len(code)-1] != OpMatch {
		t.Fatalf("missing OpMatch")
	}
}

func TestCompileAlt(t *testing.T) {
	// Test cases for alternation compilation
	tests := []struct {
		name        string
		pattern     string
		expectSplit bool
		expectLits  []byte
		shouldMatch bool
	}{
		{
			name:        "simple alternation a|b",
			pattern:     "a|b",
			expectSplit: true,
			expectLits:  []byte{'a', 'b'},
			shouldMatch: true,
		},
		{
			name:        "complex alternation a|b|c",
			pattern:     "a|b|c",
			expectSplit: true,
			expectLits:  []byte{'a', 'b', 'c'},
			shouldMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewParser(0)
			ast, err := p.Parse(tt.pattern)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			code, err := Compile(ast)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}

			// Validate compilation structure
			validateAlternationCode(t, code, tt.expectSplit, tt.expectLits)
		})
	}
}

// Helper function to validate alternation compilation
//
//nolint:revive // argument-limit: test helper
func validateAlternationCode(t *testing.T, code []byte, expectSplit bool, expectedLits []byte) {
	t.Helper()

	// Check for OpMatch at end
	if code[len(code)-1] != OpMatch {
		t.Error("missing OpMatch at end of code")
	}

	// Validate split instruction
	if expectSplit && !hasOpcode(code, OpSplitA) {
		t.Error("expected split instruction but none found")
	}

	// Validate expected literals
	for _, expectedLit := range expectedLits {
		if !hasLiteral(code, expectedLit) {
			t.Errorf("expected literal '%c' not found", expectedLit)
		}
	}
}

// Helper to check if opcode exists in code
func hasOpcode(code []byte, opcode byte) bool {
	return slices.Contains(code, opcode)
}

// Helper to check if literal exists in code
func hasLiteral(code []byte, literal byte) bool {
	for i := 0; i+1 < len(code); i++ {
		if code[i] == OpLiteral && code[i+1] == literal {
			return true
		}
	}
	return false
}

func TestCompileConcat(t *testing.T) {
	p := NewParser(0)
	ast, err := p.Parse("ab")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	code, err := Compile(ast)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(code) < 5 || code[0] != OpLiteral || code[1] != 'a' || code[2] != OpLiteral || code[3] != 'b' {
		t.Fatalf("unexpected code for 'ab': %#v", code)
	}
	if code[len(code)-1] != OpMatch {
		t.Fatalf("missing OpMatch")
	}
}

func TestCompileStarPlusAndOptional(t *testing.T) {
	p := NewParser(0)
	cases := []string{"a*", "b+", "c?"}
	for _, pat := range cases {
		ast, err := p.Parse(pat)
		if err != nil {
			t.Fatalf("parse %q: %v", pat, err)
		}
		code, err := Compile(ast)
		if err != nil {
			t.Fatalf("compile %q: %v", pat, err)
		}
		if code[len(code)-1] != OpMatch {
			t.Fatalf("missing OpMatch for %q", pat)
		}
	}
}

func countLiteral(code []byte, ch byte) int {
	cnt := 0
	for i := 0; i+1 < len(code); i++ {
		if code[i] == OpLiteral && code[i+1] == ch {
			cnt++
		}
	}
	return cnt
}

func countOpcode(code []byte, op byte) int {
	c := 0
	for _, b := range code {
		if b == op {
			c++
		}
	}
	return c
}

func TestCompileRangeExact(t *testing.T) {
	p := NewParser(0)
	ast, err := p.Parse("a{3}")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	code, err := Compile(ast)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if countLiteral(code, 'a') != 3 {
		t.Fatalf("want 3 'a' literals, got %d", countLiteral(code, 'a'))
	}
	if code[len(code)-1] != OpMatch {
		t.Fatalf("missing OpMatch")
	}
}

func TestCompileRangeBoundedGreedy(t *testing.T) {
	p := NewParser(0)
	ast, err := p.Parse("b{2,4}")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	code, err := Compile(ast)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	// Expect 4 'b' literals present in code stream, and 2 splits for the two optionals.
	if countLiteral(code, 'b') != 4 {
		t.Fatalf("want 4 'b' literals, got %d", countLiteral(code, 'b'))
	}
	if countOpcode(code, OpSplitA)+countOpcode(code, OpSplitB) < 2 {
		t.Fatalf("want at least 2 splits")
	}
}

func TestCompileRangeUnboundedUngreedy(t *testing.T) {
	p := NewParser(0)
	ast, err := p.Parse("c{2,}?")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	code, err := Compile(ast)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if countLiteral(code, 'c') < 3 {
		t.Fatalf("expect at least 3 'c' occurrences (2 min + 1 in loop)")
	}
	if countOpcode(code, OpSplitB) == 0 {
		t.Fatalf("expect ungreedy loop to use OpSplitB")
	}
}

func TestCompileEmptyAlternationBranch(t *testing.T) {
	cases := []string{
		"(foo|)",
		"(|foo)",
		"foo|",
		"|foo",
		"(|)",
		"foo||bar",
	}
	p := NewParser(0)
	for _, pattern := range cases {
		ast, err := p.Parse(pattern)
		if err != nil {
			t.Fatalf("Parse(%q) unexpected error: %v", pattern, err)
		}
		code, err := Compile(ast)
		if err != nil {
			t.Fatalf("Compile(%q) unexpected error: %v", pattern, err)
		}
		if len(code) == 0 {
			t.Fatalf("Compile(%q) returned empty bytecode", pattern)
		}
	}
}

func TestCompileUnsupportedConstructEmptyExpression(t *testing.T) {
	p := NewParser(0)
	ast, err := p.Parse("")
	if err != nil {
		t.Fatalf("Parse(\"\") unexpected error: %v", err)
	}
	_, err = Compile(ast)
	if err == nil {
		t.Fatalf("Compile(\"\") expected error, got nil")
	}
	want := "unsupported regex construct: empty expression"
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("Compile(\"\") error = %v, want substring %q", err, want)
	}
}

func TestCompileUnsupportedUnknownNodeKind(t *testing.T) {
	ast := &AST{
		Root: &Node{
			Kind: NodeKind(999),
		},
	}
	_, err := Compile(ast)
	if err == nil {
		t.Fatalf("Compile expected error for unknown node kind, got nil")
	}
	want := "unsupported regex construct: node kind 999"
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("Compile error = %v, want substring %q", err, want)
	}
}

// TestToInt16CheckedBounds pins both inclusive int16 bounds. Values exactly at
// minI16/maxI16 must be accepted; one past either end must be rejected.
func TestToInt16CheckedBounds(t *testing.T) {
	tests := []struct {
		name   string
		v      int
		wantOK bool
	}{
		{name: "min", v: minI16, wantOK: true},
		{name: "max", v: maxI16, wantOK: true},
		{name: "zero", v: 0, wantOK: true},
		{name: "below min", v: minI16 - 1, wantOK: false},
		{name: "above max", v: maxI16 + 1, wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := toInt16Checked(tt.v)
			if (err == nil) != tt.wantOK {
				t.Fatalf("toInt16Checked(%d) error = %v, want ok=%v", tt.v, err, tt.wantOK)
			}
			if tt.wantOK && int(got) != tt.v {
				t.Fatalf("toInt16Checked(%d) = %d", tt.v, got)
			}
		})
	}
}

// TestCompileCapturesGroupBounds pins the capture-group range guard: group 0 and
// group GroupCount+1 are rejected while the last valid group is accepted.
func TestCompileCapturesGroupBounds(t *testing.T) {
	ast, err := NewParser(ParserFlagEnableStrictEscapeSequences).Parse("(a)(b)")
	if err != nil {
		t.Fatal(err)
	}
	if ast.GroupCount != 2 {
		t.Fatalf("GroupCount = %d, want 2", ast.GroupCount)
	}
	if _, err := CompileCaptures(ast, []int{0}); err == nil {
		t.Fatal("CompileCaptures(group 0) succeeded, want error")
	}
	if _, err := CompileCaptures(ast, []int{3}); err == nil {
		t.Fatal("CompileCaptures(group GroupCount+1) succeeded, want error")
	}
	if _, err := CompileCaptures(ast, []int{1, 2}); err != nil {
		t.Fatalf("CompileCaptures(valid groups) error = %v", err)
	}
}

// TestCompileCapturesSlotLimit pins the slot > 255 guard: slot 255 (the 256th
// group) is still valid.
func TestCompileCapturesSlotLimit(t *testing.T) {
	ast, err := NewParser(ParserFlagEnableStrictEscapeSequences).Parse(strings.Repeat("(a)", 256))
	if err != nil {
		t.Fatal(err)
	}
	if ast.GroupCount != 256 {
		t.Fatalf("GroupCount = %d, want 256", ast.GroupCount)
	}
	groups := make([]int, 256)
	for i := range groups {
		groups[i] = i + 1
	}
	if _, err := CompileCaptures(ast, groups); err != nil {
		t.Fatalf("CompileCaptures(256 groups) error = %v", err)
	}
}

// TestCompileCapturesEmitsSaveEnd pins the capture-group emission path: a group
// with a slot must emit both OpSaveStart and OpSaveEnd, and the trailing literal
// after the group must still be emitted.
func TestCompileCapturesEmitsSaveEnd(t *testing.T) {
	ast, err := NewParser(ParserFlagEnableStrictEscapeSequences).Parse("(ab)c")
	if err != nil {
		t.Fatal(err)
	}
	code, err := CompileCaptures(ast, []int{1})
	if err != nil {
		t.Fatal(err)
	}
	if countOpcode(code, OpSaveStart) == 0 {
		t.Fatalf("CompileCaptures missing OpSaveStart: %v", code)
	}
	if countOpcode(code, OpSaveEnd) == 0 {
		t.Fatalf("CompileCaptures missing OpSaveEnd: %v", code)
	}
	if !hasLiteral(code, 'c') {
		t.Fatalf("CompileCaptures missing trailing literal 'c': %v", code)
	}
}

// TestEmitNodeAtBytecodeSizeLimit pins the strict > comparison at the size cap:
// a compiler already at exactly MaxBytecodeSize may still emit one more node.
func TestEmitNodeAtBytecodeSizeLimit(t *testing.T) {
	c := NewCompiler()
	c.e.buf = make([]byte, MaxBytecodeSize)
	if err := c.emitNode(&Node{Kind: NodeLiteral, Value: 'a'}); err != nil {
		t.Fatalf("emitNode at exactly MaxBytecodeSize error = %v, want nil", err)
	}
}

// Mutation-test classification for regex/compile.go (gremlins v0.6.0,
// --workers 1):
//   - emitSimpleNode and the minI16/maxI16/MaxBytecodeSize const declarations
//     are reported NOT COVERED because Go coverage emits no block for switch
//     case conditions or constant expressions.
