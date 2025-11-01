package regex

import (
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
	if len(code) < 3 {
		t.Fatalf("short code")
	}
	if code[0] != OpLiteral || code[1] != 'a' {
		t.Fatalf("want literal 'a' at start")
	}
	if code[2] != OpAny && code[3] != OpAny {
		t.Fatalf("want OpAny after 'a'")
	}
	if code[len(code)-1] != OpMatch {
		t.Fatalf("missing OpMatch at end")
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
	p := NewParser(0)
	ast, err := p.Parse("a|b")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	code, err := Compile(ast)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	// Should contain a split and both literals
	hasSplit := false
	hasA := false
	hasB := false
	for i := range code {
		switch code[i] {
		case OpSplitA:
			hasSplit = true
		case OpLiteral:
			if i+1 < len(code) {
				if code[i+1] == 'a' {
					hasA = true
				}
				if code[i+1] == 'b' {
					hasB = true
				}
			}
		}
	}
	if !hasSplit || !hasA || !hasB {
		t.Fatalf("expected split and both literals; split=%v a=%v b=%v", hasSplit, hasA, hasB)
	}
	if code[len(code)-1] != OpMatch {
		t.Fatalf("missing OpMatch")
	}
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
