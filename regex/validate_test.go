package regex

import "testing"

func TestValidateCompilerBytecode(t *testing.T) {
	for _, expr := range []string{"ab", "^(\\w|[0-9]){1,3}?z$", "(a?.)+", "(a|ab)*?", "(x?)+y"} {
		parsed, err := NewParser(0).Parse(expr)
		if err != nil {
			t.Fatal(err)
		}
		for _, compile := range []func(*AST) ([]byte, error){Compile, CompileForward} {
			code, err := compile(parsed)
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidateBytecode(code); err != nil {
				t.Errorf("%s: %v", expr, err)
			}
		}
		if parsed.GroupCount > 0 {
			for _, compile := range []func(*AST, []int) ([]byte, error){CompileCaptures, CompileForwardCaptures} {
				code, err := compile(parsed, []int{1})
				if err != nil {
					t.Fatal(err)
				}
				if err := ValidateCaptureBytecode(code, 1); err != nil {
					t.Errorf("%s: %v", expr, err)
				}
				if err := ValidateBytecode(code); err == nil {
					t.Errorf("%s: ordinary program accepted a capture operand", expr)
				}
			}
		}
	}
}

func TestValidateBytecodeBoundaries(t *testing.T) {
	if err := ValidateBytecode([]byte{OpMatch}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		code []byte
	}{
		{"empty", nil},
		{"missing match", []byte{OpLiteral, OpMatch}},
		{"incomplete operand", []byte{OpMaskedLiteral, 0x40}},
		{"unsupported instruction", []byte{OpRepeatAnyGreedy, OpMatch}},
		{"trailing instruction", []byte{OpMatch, OpMatch}},
		{"branch outside code", []byte{OpSplitA, 6, 0, OpLiteral, 'x', OpMatch}},
		{"branch inside operand", []byte{OpSplitB, 4, 0, OpLiteral, 'x', OpMatch}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateBytecode(tc.code); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
	capture := []byte{OpSaveStart, 1, OpLiteral, 'x', OpSaveEnd, 1, OpMatch}
	if err := ValidateCaptureBytecode(capture, 2); err != nil {
		t.Fatal(err)
	}
	for _, slots := range []int{-1, 1, 257} {
		if err := ValidateCaptureBytecode(capture, slots); err == nil {
			t.Errorf("accepted invalid slot count %d", slots)
		}
	}
}

func TestBytecodeSizeIncludesFinalMatch(t *testing.T) {
	c := NewCompiler()
	c.e.buf = make([]byte, MaxBytecodeSize-1, MaxBytecodeSize)
	for i := range c.e.buf {
		c.e.buf[i] = OpDigit
	}
	code, err := c.finish()
	if err != nil || len(code) != MaxBytecodeSize {
		t.Fatalf("final size=%d err=%v", len(code), err)
	}
	if err := ValidateBytecode(code); err != nil {
		t.Fatal(err)
	}
	if _, err := c.finish(); err == nil {
		t.Fatal("compiler exceeded bytecode limit")
	}
	if err := ValidateBytecode(append(code, OpMatch)); err == nil {
		t.Fatal("validator accepted oversized bytecode")
	}
}
