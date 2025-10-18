package regex

import "testing"

func TestCompileAndExec_NotLiteral_ByAST(t *testing.T) {
	ast := &AST{Root: &Node{Kind: NodeNotLiteral, Value: 'a', Greedy: true}}
	code, err := Compile(ast)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(code) < 3 || code[0] != OpNotLiteral || code[1] != 'a' || code[len(code)-1] != OpMatch {
		t.Fatalf("unexpected code: %#v", code)
	}
	if !Exec(code, []byte("b"), 0) {
		t.Fatalf("expect 'b' to match [^a]")
	}
	if Exec(code, []byte("a"), 0) {
		t.Fatalf("do not expect 'a' to match [^a]")
	}
}

func TestCompileAndExec_MaskedLiteral_ByAST(t *testing.T) {
	ast := &AST{Root: &Node{Kind: NodeMaskedLiteral, Value: 0xA0, Mask: 0xF0, Greedy: true}}
	code, err := Compile(ast)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(code) < 4 || code[0] != OpMaskedLiteral || code[1] != 0xA0 || code[2] != 0xF0 || code[len(code)-1] != OpMatch {
		t.Fatalf("unexpected code: %#v", code)
	}
	if !Exec(code, []byte{0xA5}, 0) {
		t.Fatalf("expect 0xA5 to match MaskedLiteral A0/F0")
	}
	if Exec(code, []byte{0xB5}, 0) {
		t.Fatalf("0xB5 should not match A0/F0")
	}
}

func TestCompileAndExec_MaskedNotLiteral_ByAST(t *testing.T) {
	ast := &AST{Root: &Node{Kind: NodeMaskedNotLiteral, Value: 0xA0, Mask: 0xF0, Greedy: true}}
	code, err := Compile(ast)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(code) < 4 || code[0] != OpMaskedNotLiteral || code[1] != 0xA0 || code[2] != 0xF0 || code[len(code)-1] != OpMatch {
		t.Fatalf("unexpected code: %#v", code)
	}
	if Exec(code, []byte{0xA5}, 0) {
		t.Fatalf("0xA5 should not match MaskedNotLiteral A0/F0")
	}
	if !Exec(code, []byte{0xB5}, 0) {
		t.Fatalf("0xB5 should match MaskedNotLiteral A0/F0")
	}
}

func TestVM_DOT_ALL_Flag(t *testing.T) {
	code := mustCompile(t, "a.b")
	if Exec(code, []byte("a\nb"), 0) {
		t.Fatalf("dot should not match newline without DOT_ALL")
	}
	if !Exec(code, []byte("a\nb"), FlagsDotAll) {
		t.Fatalf("dot should match newline with DOT_ALL")
	}
}

func TestVM_NO_CASE_Flag_Literal(t *testing.T) {
	code := mustCompile(t, "abc")
	if !Exec(code, []byte("xxAbCy"), FlagsNoCase|FlagsScan) {
		t.Fatalf("expect case-insensitive match")
	}
	if Exec(code, []byte("xxAbCy"), 0) {
		t.Fatalf("unexpected case-sensitive match")
	}
}

func TestVM_NO_CASE_Flag_Class(t *testing.T) {
	code := mustCompile(t, "[a]")
	if !Exec(code, []byte("A"), FlagsNoCase) {
		t.Fatalf("class should match with NO_CASE")
	}
	if Exec(code, []byte("A"), 0) {
		t.Fatalf("class should not match without NO_CASE")
	}
	code2 := mustCompile(t, "[^a]")
	if Exec(code2, []byte("A"), FlagsNoCase) {
		t.Fatalf("negated class should not match when folded member present")
	}
}
