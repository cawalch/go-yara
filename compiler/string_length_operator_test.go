package compiler

import (
	"testing"
)

// TestStringLengthOperatorNoDollarPrefix is a regression test for the string
// length operator "!a" written without the "$" prefix. Upstream YARA's lexer
// matches `!({letter}|{digit}|_)*` as a single _STRING_LENGTH_ token, so
// "!a", "!foo", and "!$a" are all string-length operators. go-yara's lexer
// previously only treated "!" as StringLength when followed by "$", so "!a"
// lexed as NOT + IDENTIFIER("a") and parsed as logical-not-of-an-identifier
// ("undefined identifier: a"). The gap doc marked "!a / !a[i] (length)" as
// implemented (✅), which was only true for the "!$a" form.
//
// These cases assert the actual runtime length, not just compile success.
func TestStringLengthOperatorNoDollarPrefix(t *testing.T) {
	// $a = "foo" (length 3), $b = "hello" (length 5). Both present in data.
	cases := []struct {
		name      string
		condition string
		data      []byte
		want      bool
	}{
		// The core regression: "!a" without $ prefix compiles as length.
		{name: "no_dollar_eq_length", condition: `!a == 3`, data: []byte("foo here"), want: true},
		{name: "no_dollar_gt_zero", condition: `!a > 0`, data: []byte("foo here"), want: true},
		{name: "no_dollar_wrong_length", condition: `!a == 4`, data: []byte("foo here"), want: false},
		{name: "no_dollar_b_length", condition: `!b == 5`, data: []byte("hello there"), want: true},

		// The "$"-prefixed form must still work (no regression).
		{name: "dollar_eq_length", condition: `!$a == 3`, data: []byte("foo here"), want: true},

		// In a for-loop body, "!<name>" refers to that named string's length
		// (it is NOT the loop placeholder). $a="foo" has length 3, so !a>4 is
		// false on every iteration regardless of which string is current.
		{name: "for_any_named_length_false", condition: `for any of ($a, $b) : (!a > 4)`, data: []byte("foo hello"), want: false},
		{name: "for_any_named_length_true", condition: `for any of ($a, $b) : (!a > 2)`, data: []byte("foo hello"), want: true},

		// Indexed length !a[1] == !a (first match).
		{name: "indexed_first_match", condition: `!a[1] == 3`, data: []byte("foo here"), want: true},
	}

	strs := `$a = "foo" $b = "hello"`
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := "rule t { strings: " + strs + " condition: " + tc.condition + " }"
			program, err := NewCompiler().CompileSource(src)
			if err != nil {
				t.Fatalf("compile %q: %v", tc.condition, err)
			}
			ok, err := evaluateRule(program.Rules[0], program, tc.data)
			if err != nil {
				t.Fatalf("evaluate %q: %v", tc.condition, err)
			}
			if ok != tc.want {
				t.Fatalf("condition %q on %q: matched=%v, want %v", tc.condition, tc.data, ok, tc.want)
			}
		})
	}

	// Guard: logical NOT via "!" still works for grouped expressions. The
	// bare "!true" form is non-standard YARA (use "not"); "!" remains logical
	// NOT when followed by "(" or whitespace + expression.
	t.Run("not_via_grouping_still_works", func(t *testing.T) {
		src := `rule t { strings: $a = "foo" $b = "bar" condition: !($a and $b) }`
		program, err := NewCompiler().CompileSource(src)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		// Neither string present -> "not (false and false)" = not false = true.
		ok, err := evaluateRule(program.Rules[0], program, []byte("nothing here"))
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		if !ok {
			t.Fatalf("!($a and $b) on no-match data: expected true (logical NOT), got false")
		}
	})
}
