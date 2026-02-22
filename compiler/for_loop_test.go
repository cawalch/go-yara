package compiler

import "testing"

func TestForLoopUnrolledAny(t *testing.T) {
	source := `
rule ForLoopAny {
	condition:
		for any i in (1..3) : ( uint8(i) == 0 )
}`
	data := []byte{1, 0, 2, 3}

	compiler := NewCompiler()
	program, err := compiler.CompileSource(source)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(program.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(program.Rules))
	}
	ok, err := evaluateRule(program.Rules[0], program, data)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !ok {
		t.Fatalf("expected rule to match")
	}
}

func TestForLoopAnyOfStrings(t *testing.T) {
	source := `
rule ForAnyOf {
	strings:
		$a = "foo"
		$b = "bar"
	condition:
		for any of ($a, $b) : ( $ )
}`
	data := []byte("xxx foo yyy")

	compiler := NewCompiler()
	program, err := compiler.CompileSource(source)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	ok, err := evaluateRule(program.Rules[0], program, data)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !ok {
		t.Fatalf("expected rule to match")
	}
}

func TestForLoopAllOfStrings(t *testing.T) {
	source := `
rule ForAllOf {
	strings:
		$a = "foo"
		$b = "bar"
	condition:
		for all of ($a, $b) : ( $ )
}`
	data := []byte("foo ... bar")

	compiler := NewCompiler()
	program, err := compiler.CompileSource(source)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	ok, err := evaluateRule(program.Rules[0], program, data)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !ok {
		t.Fatalf("expected rule to match")
	}
}

func TestForLoopNumericOfStrings(t *testing.T) {
	source := `
rule ForNumericOf {
	strings:
		$a = "foo"
		$b = "bar"
		$c = "baz"
	condition:
		for 2 of ($a, $b, $c) : ( $ )
}`
	data := []byte("foo and baz")

	compiler := NewCompiler()
	program, err := compiler.CompileSource(source)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	ok, err := evaluateRule(program.Rules[0], program, data)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !ok {
		t.Fatalf("expected rule to match")
	}
}

func TestForLoopDynamicRange(t *testing.T) {
	source := `
rule ForDynamicRange {
	strings:
		$a = "foo"
		$b = "bar"
	condition:
		// #a is 2 (two 'foo's). (1..2) means i=1, i=2.
		// Let's use @a[i] to check offset.
		for all i in (1..#a) : ( i >= 1 )
}`
	data := []byte("foo and bar and foo")

	compiler := NewCompiler()
	program, err := compiler.CompileSource(source)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	ok, err := evaluateRule(program.Rules[0], program, data)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !ok {
		t.Fatalf("expected rule to match")
	}
}

func TestForLoopDynamicRangeMismatch(t *testing.T) {
	source := `
rule ForDynamicRangeMismatch {
	strings:
		$a = "foo"
	condition:
		for all i in (1..#a) : ( @a[i] > 10 ) // first foo is at offset 0, so this fails.
}`
	data := []byte("foo and bar and foo")

	compiler := NewCompiler()
	program, err := compiler.CompileSource(source)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	ok, err := evaluateRule(program.Rules[0], program, data)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if ok {
		t.Fatalf("expected rule to not match")
	}
}
