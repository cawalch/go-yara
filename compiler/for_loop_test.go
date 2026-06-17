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

// TestForLoopPlaceholderFailureDirection is the regression test for a bug where
// "$" inside a for-loop body compiled as OpOf against the whole rule's
// anonymous string set instead of resolving to the current iteration's
// string. With that bug, the loop body asked "does any string match?" on every
// iteration, so iter.Count was inflated to iter.Total whenever a single string
// matched. Result: "for all of them : ($)" and "for N of them : ($)" returned
// true even when the required number of strings did NOT match.
//
// The existing TestForLoopAllOfStrings missed this because its data matched
// BOTH strings, so the broken behavior coincidentally produced the right
// answer. These cases assert the failure direction: when strings are missing,
// for-all and for-N must return false.
func TestForLoopPlaceholderFailureDirection(t *testing.T) {
	// $a and $b match in data; $c does NOT.
	source := `
rule ForAllFail {
	strings:
		$a = "foo"
		$b = "bar"
		$c = "baz"
	condition:
		for all of ($a, $b, $c) : ($)
}`
	compiler := NewCompiler()
	program, err := compiler.CompileSource(source)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	t.Run("for_all_false_when_one_missing", func(t *testing.T) {
		// Only foo and bar present; baz missing -> for all must be false.
		ok, err := evaluateRule(program.Rules[0], program, []byte("foo bar here"))
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		if ok {
			t.Fatalf("for all of (...) : ($) matched with only 2/3 strings present (bug: $ did not resolve to current iteration)")
		}
	})

	t.Run("for_all_true_when_all_present", func(t *testing.T) {
		ok, err := evaluateRule(program.Rules[0], program, []byte("foo bar baz here"))
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		if !ok {
			t.Fatalf("for all of (...) : ($) did not match with all 3 strings present")
		}
	})

	// Numeric quantifier must also reflect per-iteration matching.
	numericSrc := `
rule ForThreeFail {
	strings:
		$a = "foo"
		$b = "bar"
		$c = "baz"
	condition:
		for 3 of ($a, $b, $c) : ($)
}`
	numericProg, err := compiler.CompileSource(numericSrc) //nolint:govet // shadow intentional
	if err != nil {
		t.Fatalf("compile numeric: %v", err)
	}

	t.Run("for_3_false_when_only_2_match", func(t *testing.T) {
		ok, err := evaluateRule(numericProg.Rules[0], numericProg, []byte("foo bar here"))
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		if ok {
			t.Fatalf("for 3 of (...) : ($) matched with only 2/3 strings present")
		}
	})

	t.Run("for_2_true_when_2_match", func(t *testing.T) {
		twoSrc := `
rule ForTwo {
	strings:
		$a = "foo"
		$b = "bar"
		$c = "baz"
	condition:
		for 2 of ($a, $b, $c) : ($)
}`
		twoProg, err := NewCompiler().CompileSource(twoSrc)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		ok, err := evaluateRule(twoProg.Rules[0], twoProg, []byte("foo bar here"))
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		if !ok {
			t.Fatalf("for 2 of (...) : ($) did not match with 2/3 strings present")
		}
	})

	// for none must be true when nothing matches the placeholder.
	noneSrc := `
rule ForNone {
	strings:
		$a = "foo"
	condition:
		for none of ($a) : ($)
}`
	noneProg, err := NewCompiler().CompileSource(noneSrc)
	if err != nil {
		t.Fatalf("compile none: %v", err)
	}
	t.Run("for_none_true_when_absent", func(t *testing.T) {
		ok, err := evaluateRule(noneProg.Rules[0], noneProg, []byte("nothing relevant"))
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		if !ok {
			t.Fatalf("for none of ($a) : ($) did not evaluate true when $a is absent")
		}
	})
	t.Run("for_none_false_when_present", func(t *testing.T) {
		ok, err := evaluateRule(noneProg.Rules[0], noneProg, []byte("foo here"))
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		if ok {
			t.Fatalf("for none of ($a) : ($) matched when $a is present")
		}
	})
}
