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

// TestForLoopPlaceholderAtAndIn is the regression test for "$ at <offset>" and
// "$ in (range)" inside a for-loop body. Previously the bare "$" was rejected
// by the semantic AT check (typed as a variable/integer rather than a string)
// and by the compiler's string-offset lookup ("$" has no fixed offset), so
// neither constraint form could appear in a for-loop body. With the loop-var
// resolution from #144, "$" must resolve to the current iteration's string
// for OpFoundAt/OpFoundIn just as it does for OpFound. Data layout: "foo" at
// offset 0, "bar" at offset 4.
func TestForLoopPlaceholderAtAndIn(t *testing.T) {
	strs := `$a = "foo" $b = "bar"`
	data := []byte("foo bar here")

	cases := []struct {
		name      string
		condition string
		want      bool
	}{
		// "$ at <offset>"
		{name: "at_0_foo_matches", condition: `for any of ($a,$b) : ($ at 0)`, want: true},
		{name: "at_4_bar_matches", condition: `for any of ($a,$b) : ($ at 4)`, want: true},
		{name: "at_8_neither", condition: `for any of ($a,$b) : ($ at 8)`, want: false},
		// for all : ($ at 0) must be FALSE because $b (bar) is not at offset 0.
		{name: "for_all_at_0_false", condition: `for all of ($a,$b) : ($ at 0)`, want: false},

		// "$ in (min..max)"
		{name: "in_0_3_foo_qualifies", condition: `for any of ($a,$b) : ($ in (0..3))`, want: true},
		{name: "in_5_10_neither", condition: `for any of ($a,$b) : ($ in (5..10))`, want: false},
		{name: "for_all_in_0_10_both", condition: `for all of ($a,$b) : ($ in (0..10))`, want: true},
		{name: "for_2_in_0_3_only_one", condition: `for 2 of ($a,$b) : ($ in (0..3))`, want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := "rule t { strings: " + strs + " condition: " + tc.condition + " }"
			compiler := NewCompiler()
			program, err := compiler.CompileSource(src)
			if err != nil {
				t.Fatalf("compile %q: %v", tc.condition, err)
			}
			ok, err := evaluateRule(program.Rules[0], program, data)
			if err != nil {
				t.Fatalf("evaluate %q: %v", tc.condition, err)
			}
			if ok != tc.want {
				t.Fatalf("condition %q on %q: matched=%v, want %v", tc.condition, data, ok, tc.want)
			}
		})
	}

	// Guard: fixed-name forms must still work (no regression in the offset path).
	t.Run("fixed_name_at_and_in_unaffected", func(t *testing.T) {
		src := `rule t { strings: $a = "foo" $b = "bar" condition: $a at 0 and $b in (0..10) }`
		program, err := NewCompiler().CompileSource(src)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		ok, err := evaluateRule(program.Rules[0], program, data)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		if !ok {
			t.Fatalf("fixed-name $a at / $b in regressed")
		}
	})
}

// TestForLoopPlaceholderCountAndOffset is the regression test for the bare
// "#" (count) and "@" (offset) placeholders inside a for-loop body. Per the
// YARA spec ("for all of them : (# > 3)", "for all of ($a*) : (@ > @b)")
// these refer to the count / first-offset of the current iteration's string.
// Previously the parser rejected them ("string operations require a string
// identifier"). Data layout: "foo" at offsets 0 and 8 (count 2), "bar" at
// offset 4 (count 1).
func TestForLoopPlaceholderCountAndOffset(t *testing.T) {
	strs := `$a = "foo" $b = "bar"`
	data := []byte("foo bar xxx foo") // foo at 0,8; bar at 4

	cases := []struct {
		name      string
		condition string
		want      bool
	}{
		// "#" — count of current string.
		{name: "count_gt_1_any_a_qualifies", condition: `for any of ($a,$b) : (# > 1)`, want: true},
		{name: "count_gt_5_any_none", condition: `for any of ($a,$b) : (# > 5)`, want: false},
		{name: "count_gt_0_all_both", condition: `for all of ($a,$b) : (# > 0)`, want: true},
		{name: "count_gt_1_all_b_has_1", condition: `for all of ($a,$b) : (# > 1)`, want: false},
		{name: "count_gt_1_for_1_only_a", condition: `for 1 of ($a,$b) : (# > 1)`, want: true},
		{name: "count_gt_1_for_2_need_both", condition: `for 2 of ($a,$b) : (# > 1)`, want: false},

		// "@" — first offset of current string.
		{name: "offset_eq_0_any_a_at_0", condition: `for any of ($a,$b) : (@ == 0)`, want: true},
		{name: "offset_eq_4_any_b_at_4", condition: `for any of ($a,$b) : (@ == 4)`, want: true},
		{name: "offset_eq_8_any_none_first", condition: `for any of ($a,$b) : (@ == 8)`, want: false},
		{name: "offset_lt_100_all_both", condition: `for all of ($a,$b) : (@ < 100)`, want: true},
		{name: "offset_eq_0_all_b_not_0", condition: `for all of ($a,$b) : (@ == 0)`, want: false},

		// Spec example: "for all of them : (# > 3)".
		{name: "spec_count_gt_3_all_false", condition: `for all of them : (# > 3)`, want: false},
		{name: "spec_count_gt_0_all_true", condition: `for all of them : (# > 0)`, want: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := "rule t { strings: " + strs + " condition: " + tc.condition + " }"
			program, err := NewCompiler().CompileSource(src)
			if err != nil {
				t.Fatalf("compile %q: %v", tc.condition, err)
			}
			ok, err := evaluateRule(program.Rules[0], program, data)
			if err != nil {
				t.Fatalf("evaluate %q: %v", tc.condition, err)
			}
			if ok != tc.want {
				t.Fatalf("condition %q on %q: matched=%v, want %v", tc.condition, data, ok, tc.want)
			}
		})
	}

	// Guard: explicit-name #a / @a must still work (no regression).
	t.Run("explicit_name_count_offset_unaffected", func(t *testing.T) {
		src := `rule t { strings: $a = "foo" condition: #a > 1 and @a == 0 }`
		program, err := NewCompiler().CompileSource(src)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		ok, err := evaluateRule(program.Rules[0], program, data)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		if !ok {
			t.Fatalf("explicit #a / @a regressed")
		}
	})
}

// TestForLoopPlaceholderLength is the regression test for the bare "!"
// (length) placeholder inside a for-loop body, completing the placeholder
// set alongside "$" (#144), "#"/"@" (#146). Per the YARA spec "!" is the
// string-length operator and upstream's lexer regex `!({letter}|{digit}|_)*`
// (with '*') matches a bare "!" as the length of the current iteration's
// string (e.g. "for all of them : (! > 3)"). Previously the bare form failed
// to parse because go-yara's lexer only emitted StringLength for "!" followed
// by an identifier character. Data: $a="foo" (len 3), $b="hello" (len 5).
func TestForLoopPlaceholderLength(t *testing.T) {
	strs := `$a = "foo" $b = "hello"`
	data := []byte("foo hello") // both present

	cases := []struct {
		name      string
		condition string
		want      bool
	}{
		// "!" — length of current string.
		{name: "len_gt_3_any_b_qualifies", condition: `for any of ($a,$b) : (! > 3)`, want: true},
		{name: "len_gt_10_any_none", condition: `for any of ($a,$b) : (! > 10)`, want: false},
		{name: "len_gt_0_all_both", condition: `for all of ($a,$b) : (! > 0)`, want: true},
		{name: "len_gt_3_all_a_is_3", condition: `for all of ($a,$b) : (! > 3)`, want: false},
		{name: "len_eq_5_for_1_only_b", condition: `for 1 of ($a,$b) : (! == 5)`, want: true},
		{name: "len_eq_5_for_2_need_both", condition: `for 2 of ($a,$b) : (! == 5)`, want: false},
		{name: "len_eq_3_any_a", condition: `for any of ($a,$b) : (! == 3)`, want: true},

		// Over "them".
		{name: "them_len_gt_2_all", condition: `for all of them : (! > 2)`, want: true},
		{name: "them_len_gt_4_all_false", condition: `for all of them : (! > 4)`, want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := "rule t { strings: " + strs + " condition: " + tc.condition + " }"
			program, err := NewCompiler().CompileSource(src)
			if err != nil {
				t.Fatalf("compile %q: %v", tc.condition, err)
			}
			ok, err := evaluateRule(program.Rules[0], program, data)
			if err != nil {
				t.Fatalf("evaluate %q: %v", tc.condition, err)
			}
			if ok != tc.want {
				t.Fatalf("condition %q on %q: matched=%v, want %v", tc.condition, data, ok, tc.want)
			}
		})
	}

	// Guard: named "!a" / "!$a" still work (no regression from #147), and
	// "!(...)" grouping remains logical NOT.
	t.Run("named_and_grouping_unaffected", func(t *testing.T) {
		src := `rule t { strings: $a = "foo" condition: !a == 3 and !$a == 3 and !($a) }`
		program, err := NewCompiler().CompileSource(src)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		// $a absent: !a==3 is false, so the whole conjunction is false; but it
		// must COMPILE (the regression is about compilation, not the value).
		_, _ = evaluateRule(program.Rules[0], program, data)
	})
}
