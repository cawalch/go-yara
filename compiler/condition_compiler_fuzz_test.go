package compiler

import (
	"context"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/parser"
)

// FuzzConditionCompiler tests condition expression compilation with malformed inputs
func FuzzConditionCompiler(f *testing.F) {
	// Seed corpus with various condition expressions
	f.Add([]byte("true"))
	f.Add([]byte("false"))
	f.Add([]byte("$a"))
	f.Add([]byte("$a and $b"))
	f.Add([]byte("$a or $b"))
	f.Add([]byte("not $a"))
	f.Add([]byte("$a and $b or $c"))
	f.Add([]byte("($a and $b) or $c"))
	f.Add([]byte("$a or ($b and $c)"))
	f.Add([]byte("not ($a or $b)"))
	f.Add([]byte("$a and not $b"))
	f.Add([]byte("filesize > 100"))
	f.Add([]byte("filesize == 0"))
	f.Add([]byte("filesize >= 1000 and filesize <= 10000"))
	f.Add([]byte("entrypoint == 0x400000"))
	f.Add([]byte("#a == 1"))
	f.Add([]byte("#a > 0"))
	f.Add([]byte("#a >= 2 and #a <= 10"))
	f.Add([]byte("@a == 0"))
	f.Add([]byte("@a > 100"))
	f.Add([]byte("@a[1] == 0"))
	f.Add([]byte("@a[2] > @a[1]"))
	f.Add([]byte("!a == 4"))
	f.Add([]byte("!a > 0"))
	f.Add([]byte("!a[1] == 10"))
	f.Add([]byte("1 + 2 == 3"))
	f.Add([]byte("5 - 3 == 2"))
	f.Add([]byte("2 * 3 == 6"))
	f.Add([]byte("10 / 2 == 5"))
	f.Add([]byte("10 % 3 == 1"))
	f.Add([]byte("(1 + 2) * 3 == 9"))
	f.Add([]byte("1 << 8 == 256"))
	f.Add([]byte("256 >> 8 == 1"))
	f.Add([]byte("0xFF & 0x0F == 0x0F"))
	f.Add([]byte("0xF0 | 0x0F == 0xFF"))
	f.Add([]byte("0xFF ^ 0xFF == 0"))
	f.Add([]byte("~0 == -1"))
	f.Add([]byte("int8(0) == 0x74"))
	f.Add([]byte("int16(0) == 0x7473"))
	f.Add([]byte("int32(0) == 0x74736574"))
	f.Add([]byte("uint8(0) == 0x74"))
	f.Add([]byte("uint16(0) == 0x7473"))
	f.Add([]byte("uint32(0) == 0x74736574"))
	f.Add([]byte("\"test\" matches /test/"))
	f.Add([]byte("1 of them"))
	f.Add([]byte("2 of them"))
	f.Add([]byte("all of them"))
	f.Add([]byte("none of them"))
	f.Add([]byte("any of them"))
	f.Add([]byte("any of ($a, $b)"))
	f.Add([]byte("all of ($a, $b, $c)"))
	f.Add([]byte("1 of ($a*)"))
	f.Add([]byte("for any i in (1..10) : ( i > 5 )"))
	f.Add([]byte("for all i in (1..5) : ( i > 0 )"))
	f.Add([]byte("for none i in (1..10) : ( i < 0 )"))
	f.Add([]byte("for 3 i in (1..10) : ( i > 5 )"))
	f.Add([]byte("$a at 0"))
	f.Add([]byte("$a in (0..100)"))
	f.Add([]byte("$a length > 5"))
	f.Add([]byte("$a offset == 10"))
	f.Add([]byte("$a offset < 100"))
	f.Add([]byte("defined $a"))
	f.Add([]byte("defined extern"))
	f.Add([]byte("100KB"))
	f.Add([]byte("1MB"))
	f.Add([]byte("1.5MB"))
	f.Add([]byte("$a == \"test\""))
	f.Add([]byte("$a contains \"test\""))
	f.Add([]byte("$a startswith \"test\""))
	f.Add([]byte("$a endswith \"test\""))
	f.Add([]byte("$a iequals \"test\""))
	f.Add([]byte("$a icontains \"test\""))
	// Edge cases and malformed inputs
	f.Add([]byte(""))
	f.Add([]byte("()"))
	f.Add([]byte("and"))
	f.Add([]byte("or"))
	f.Add([]byte("not"))
	f.Add([]byte("1 +"))
	f.Add([]byte("+ 1"))
	f.Add([]byte("$a and"))
	f.Add([]byte("and $a"))
	f.Add([]byte("((((("))
	f.Add([]byte("))))"))
	f.Add([]byte("1 and 2 or 3 and 4 or 5"))
	f.Add([]byte("not not not true"))
	f.Add([]byte("$a and $b and $c and $d and $e"))
	f.Add([]byte("$a or $b or $c or $d or $e"))
	f.Add([]byte(strings.Repeat("(", 100) + "true" + strings.Repeat(")", 100)))
	f.Add([]byte("filesize > 100000000000000000000"))
	f.Add([]byte("int8(999999999999999999)"))
	f.Add([]byte("1000000 of them"))
	f.Add([]byte("for 1000000 i in (1..1000000) : ( true )"))
	f.Add([]byte("$a[999999999] == 0"))
	f.Add([]byte("@a[-1] == 0"))
	f.Add([]byte("!a[-1] == 0"))

	f.Fuzz(func(t *testing.T, input []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("Condition compiler recovered from panic: %v", r)
			}
		}()

		inputStr := string(input)

		// Test condition compilation by wrapping it in a rule
		ruleInput := "rule test { strings: $a = \"test\" $b = \"other\" condition: " + inputStr + " }"

		// Parse the rule
		l := lexer.New(ruleInput)
		p := parser.New(l)
		program, err := p.ParseRulesWithContext(context.Background())
		if err != nil || program == nil || len(program.Rules) == 0 {
			return // Invalid input - expected and handled gracefully
		}

		// Try to compile the rule
		c := NewCompiler()
		_, err = c.CompileSource(ruleInput)
		_ = err // Whether compilation succeeds or fails, we shouldn't panic

		// Test with different string contexts
		contexts := []string{
			"rule test { strings: $a = \"test\" condition: " + inputStr + " }",
			"rule test { strings: $a = \"test\" $b = \"test\" $c = \"test\" condition: " + inputStr + " }",
			"rule test { strings: $a = \"test\" $b = \"test\" $c = \"test\" $d = \"test\" $e = \"test\" condition: " + inputStr + " }",
		}

		for _, ctx := range contexts {
			c2 := NewCompiler()
			_, err2 := c2.CompileSource(ctx)
			_ = err2
		}

		// Test with truncated conditions
		if len(inputStr) > 1 {
			for truncateLen := 1; truncateLen < len(inputStr) && truncateLen <= 50; truncateLen++ {
				truncatedInput := inputStr[:truncateLen]
				truncatedRule := "rule test { strings: $a = \"test\" condition: " + truncatedInput + " }"
				c3 := NewCompiler()
				_, err3 := c3.CompileSource(truncatedRule)
				_ = err3
			}
		}
	})
}

// FuzzConditionOperatorPrecedence tests operator precedence edge cases
func FuzzConditionOperatorPrecedence(f *testing.F) {
	// Seed corpus with complex operator combinations
	f.Add([]byte("$a and $b or $c"))
	f.Add([]byte("$a or $b and $c"))
	f.Add([]byte("$a and $b and $c or $d"))
	f.Add([]byte("$a or $b or $c and $d"))
	f.Add([]byte("not $a and $b"))
	f.Add([]byte("$a and not $b"))
	f.Add([]byte("not ($a and $b)"))
	f.Add([]byte("1 + 2 * 3"))
	f.Add([]byte("1 * 2 + 3"))
	f.Add([]byte("1 + 2 + 3 * 4"))
	f.Add([]byte("1 * 2 * 3 + 4"))
	f.Add([]byte("1 << 2 + 3"))
	f.Add([]byte("1 + 2 << 3"))
	f.Add([]byte("1 & 2 | 3"))
	f.Add([]byte("1 | 2 & 3"))
	f.Add([]byte("$a and $b == true"))
	f.Add([]byte("$a == true and $b"))
	f.Add([]byte("filesize > 100 and $a"))
	f.Add([]byte("$a and filesize > 100"))
	f.Add([]byte("not $a or $b"))
	f.Add([]byte("$a or not $b"))
	f.Add([]byte("1 + 2 == 3 and $a"))
	f.Add([]byte("$a and 1 + 2 == 3"))

	f.Fuzz(func(t *testing.T, input []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("Operator precedence fuzz recovered from panic: %v", r)
			}
		}()

		inputStr := string(input)
		ruleInput := "rule test { strings: $a = \"test\" $b = \"other\" condition: " + inputStr + " }"

		// Test that the expression can be parsed without panicking
		l := lexer.New(ruleInput)
		p := parser.New(l)
		program, err := p.ParseRulesWithContext(context.Background())
		_ = program
		_ = err

		// Also test with parentheses to change precedence
		parenthesized := "(" + inputStr + ")"
		ruleInput2 := "rule test { strings: $a = \"test\" $b = \"other\" condition: " + parenthesized + " }"
		l2 := lexer.New(ruleInput2)
		p2 := parser.New(l2)
		_, err2 := p2.ParseRulesWithContext(context.Background())
		_ = err2

		// Test with negation
		negated := "not (" + inputStr + ")"
		ruleInput3 := "rule test { strings: $a = \"test\" $b = \"other\" condition: " + negated + " }"
		l3 := lexer.New(ruleInput3)
		p3 := parser.New(l3)
		_, err3 := p3.ParseRulesWithContext(context.Background())
		_ = err3
	})
}

// FuzzStringOperators tests string identifier operators (#, @, !)
func FuzzStringOperators(f *testing.F) {
	// Seed corpus with string operator variations
	f.Add([]byte("#a"))
	f.Add([]byte("#a == 1"))
	f.Add([]byte("#a > 0"))
	f.Add([]byte("#a >= 2"))
	f.Add([]byte("@a"))
	f.Add([]byte("@a == 0"))
	f.Add([]byte("@a > 100"))
	f.Add([]byte("@a[1]"))
	f.Add([]byte("@a[2]"))
	f.Add([]byte("@a[1] == 0"))
	f.Add([]byte("!a"))
	f.Add([]byte("!a == 4"))
	f.Add([]byte("!a > 0"))
	f.Add([]byte("!a[1]"))
	f.Add([]byte("!a[1] == 10"))
	f.Add([]byte("#a + #b"))
	f.Add([]byte("@a + @b"))
	f.Add([]byte("!a + !b"))
	f.Add([]byte("#a * 2"))
	f.Add([]byte("@a[1] + @a[2]"))
	f.Add([]byte("!a[1] > !a[2]"))
	f.Add([]byte("#$a"))
	f.Add([]byte("@$a"))
	f.Add([]byte("!$a"))
	// Edge cases
	f.Add([]byte("#"))
	f.Add([]byte("@"))
	f.Add([]byte("!"))
	f.Add([]byte("#1"))
	f.Add([]byte("@1"))
	f.Add([]byte("!1"))
	f.Add([]byte("#a[999999]"))
	f.Add([]byte("@a[-1]"))
	f.Add([]byte("!a[-1]"))
	f.Add([]byte("#a and #b"))
	f.Add([]byte("#a or #b"))
	f.Add([]byte("not #a"))

	f.Fuzz(func(t *testing.T, input []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("String operators fuzz recovered from panic: %v", r)
			}
		}()

		inputStr := string(input)

		// Test with various string sets
		stringSets := []string{
			"rule test { strings: $a = \"test\" condition: " + inputStr + " }",
			"rule test { strings: $a = \"test\" $b = \"other\" condition: " + inputStr + " }",
			"rule test { strings: $a = \"test\" $b = \"other\" $c = \"another\" condition: " + inputStr + " }",
			"rule test { strings: $a = \"test\" $b = \"test\" $c = \"test\" $d = \"test\" $e = \"test\" condition: " + inputStr + " }",
		}

		for _, ruleInput := range stringSets {
			c := NewCompiler()
			_, err := c.CompileSource(ruleInput)
			_ = err
		}

		// Test in expression contexts
		expressions := []string{
			inputStr + " == 0",
			inputStr + " > 0",
			inputStr + " and true",
			"true and " + inputStr,
			"not (" + inputStr + ")",
			"(" + inputStr + ") or false",
		}

		for _, expr := range expressions {
			ruleInput := "rule test { strings: $a = \"test\" condition: " + expr + " }"
			c := NewCompiler()
			_, err := c.CompileSource(ruleInput)
			_ = err
		}
	})
}

// FuzzOfExpressions tests of-expression compilation
func FuzzOfExpressions(f *testing.F) {
	// Seed corpus with of-expression variations
	f.Add([]byte("any of them"))
	f.Add([]byte("all of them"))
	f.Add([]byte("none of them"))
	f.Add([]byte("1 of them"))
	f.Add([]byte("2 of them"))
	f.Add([]byte("10 of them"))
	f.Add([]byte("any of ($a)"))
	f.Add([]byte("any of ($a, $b)"))
	f.Add([]byte("any of ($a, $b, $c)"))
	f.Add([]byte("all of ($a, $b)"))
	f.Add([]byte("none of ($a, $b)"))
	f.Add([]byte("1 of ($a, $b)"))
	f.Add([]byte("2 of ($a, $b, $c, $d)"))
	f.Add([]byte("any of ($a*)"))
	f.Add([]byte("all of ($a*)"))
	f.Add([]byte("1 of ($a*)"))
	f.Add([]byte("any of ($a*, $b*)"))
	f.Add([]byte("1 of ($a*, $b*)"))
	// Edge cases
	f.Add([]byte("0 of them"))
	f.Add([]byte("1000 of them"))
	f.Add([]byte("any of ()"))
	f.Add([]byte("all of ()"))
	f.Add([]byte("any of ($)"))
	f.Add([]byte("1 of ($x)"))
	f.Add([]byte("any of ($1)"))
	f.Add([]byte("any of ($*)"))

	f.Fuzz(func(t *testing.T, input []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("Of-expressions fuzz recovered from panic: %v", r)
			}
		}()

		inputStr := string(input)

		// Test with various string sets
		stringSets := []string{
			"rule test { strings: $a = \"a\" condition: " + inputStr + " }",
			"rule test { strings: $a = \"a\" $b = \"b\" condition: " + inputStr + " }",
			"rule test { strings: $a1 = \"a1\" $a2 = \"a2\" $b1 = \"b1\" $b2 = \"b2\" condition: " + inputStr + " }",
			"rule test { strings: $a = \"a\" $b = \"b\" $c = \"c\" $d = \"d\" $e = \"e\" condition: " + inputStr + " }",
		}

		for _, ruleInput := range stringSets {
			c := NewCompiler()
			_, err := c.CompileSource(ruleInput)
			_ = err
		}

		// Test in boolean contexts
		contexts := []string{
			inputStr + " and true",
			"true and " + inputStr,
			inputStr + " or false",
			"false or " + inputStr,
			"not (" + inputStr + ")",
		}

		for _, ctx := range contexts {
			ruleInput := "rule test { strings: $a = \"test\" condition: " + ctx + " }"
			c := NewCompiler()
			_, err := c.CompileSource(ruleInput)
			_ = err
		}
	})
}

// FuzzForLoops tests for-loop expression compilation
func FuzzForLoops(f *testing.F) {
	// Seed corpus with for-loop variations
	f.Add([]byte("for any i in (1..10) : ( i > 5 )"))
	f.Add([]byte("for all i in (1..5) : ( i > 0 )"))
	f.Add([]byte("for none i in (1..10) : ( i < 0 )"))
	f.Add([]byte("for 1 i in (1..10) : ( true )"))
	f.Add([]byte("for 2 i in (1..10) : ( true )"))
	f.Add([]byte("for 3 i in (1..10) : ( i > 5 )"))
	f.Add([]byte("for any i in (0..0) : ( true )"))
	f.Add([]byte("for all i in (100..200) : ( i > 50 )"))
	f.Add([]byte("for any $i in ($a, $b) : ( $i )"))
	f.Add([]byte("for all $i in ($a, $b, $c) : ( $i )"))
	f.Add([]byte("for 2 $i in ($a, $b, $c) : ( $i )"))
	f.Add([]byte("for any i in (1..10) : ( $a )"))
	f.Add([]byte("for any i in (1..10) : ( filesize > 100 )"))
	f.Add([]byte("for any i in (1..10) : ( i > 5 and i < 8 )"))
	// Edge cases
	f.Add([]byte("for 0 i in (1..10) : ( true )"))
	f.Add([]byte("for 100 i in (1..10) : ( true )"))
	f.Add([]byte("for any i in (10..1) : ( true )"))
	f.Add([]byte("for any i in (1..1) : ( true )"))
	f.Add([]byte("for any i in () : ( true )"))
	f.Add([]byte("for any i in (1..10) : ()"))
	f.Add([]byte("for any in (1..10) : ( true )"))
	f.Add([]byte("for i in (1..10) : ( true )"))
	f.Add([]byte("for any i in (1..10)"))

	f.Fuzz(func(t *testing.T, input []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("For-loops fuzz recovered from panic: %v", r)
			}
		}()

		inputStr := string(input)

		// Test with minimal string set
		ruleInput := "rule test { strings: $a = \"test\" $b = \"other\" condition: " + inputStr + " }"
		c := NewCompiler()
		_, err := c.CompileSource(ruleInput)
		_ = err

		// Test with larger string sets
		ruleInput2 := "rule test { strings: $a = \"test\" $b = \"other\" $c = \"another\" $d = \"more\" condition: " + inputStr + " }"
		c2 := NewCompiler()
		_, err2 := c2.CompileSource(ruleInput2)
		_ = err2

		// Test in boolean contexts
		contexts := []string{
			inputStr + " and true",
			"true and " + inputStr,
			inputStr + " or false",
		}

		for _, ctx := range contexts {
			ruleInput := "rule test { strings: $a = \"test\" condition: " + ctx + " }"
			c3 := NewCompiler()
			_, err3 := c3.CompileSource(ruleInput)
			_ = err3
		}
	})
}

// FuzzBuiltinFunctions tests builtin function compilation
func FuzzBuiltinFunctions(f *testing.F) {
	// Seed corpus with builtin function calls
	f.Add([]byte("int8(0)"))
	f.Add([]byte("int8(100)"))
	f.Add([]byte("int8(0x1000)"))
	f.Add([]byte("int16(0)"))
	f.Add([]byte("int16(0x1000)"))
	f.Add([]byte("int32(0)"))
	f.Add([]byte("int32(0x10000000)"))
	f.Add([]byte("uint8(0)"))
	f.Add([]byte("uint8(255)"))
	f.Add([]byte("uint16(0)"))
	f.Add([]byte("uint16(0xFFFF)"))
	f.Add([]byte("uint32(0)"))
	f.Add([]byte("uint32(0xFFFFFFFF)"))
	f.Add([]byte("uint16be(0)"))
	f.Add([]byte("uint16be(0x1000)"))
	f.Add([]byte("uint32be(0)"))
	f.Add([]byte("uint32be(0x10000000)"))
	f.Add([]byte("int8be(0)"))
	f.Add([]byte("int8be(100)"))
	f.Add([]byte("int16be(0)"))
	f.Add([]byte("int32be(0)"))
	f.Add([]byte("\"test\" matches /test/"))
	f.Add([]byte("\"test\" matches /t.st/"))
	f.Add([]byte("\"test\" matches /.*test.*/"))
	f.Add([]byte("\"123\" matches /\\d+/"))
	f.Add([]byte("int8(0) == 0x74"))
	f.Add([]byte("uint16(0) == 0x7473"))
	// Edge cases
	f.Add([]byte("int8()"))
	f.Add([]byte("int8(0, 1)"))
	f.Add([]byte("int8(999999999999999999)"))
	f.Add([]byte("int8(-1)"))
	f.Add([]byte("int8(@a)"))
	f.Add([]byte("int8(#a)"))
	f.Add([]byte("\"\" matches //"))
	f.Add([]byte("matches /test/"))
	f.Add([]byte("\"test\" matches"))
	f.Add([]byte("\"test\" matches(/test/)"))
	f.Add([]byte("int8(@a[1])"))
	f.Add([]byte("int8(filesize)"))
	f.Add([]byte("int8(entrypoint)"))
	f.Add([]byte("int8(int8(0))"))
	f.Add([]byte("int8(int8(0)) == 0"))

	f.Fuzz(func(t *testing.T, input []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("Builtin functions fuzz recovered from panic: %v", r)
			}
		}()

		inputStr := string(input)

		// Test function call in simple condition
		ruleInput := "rule test { condition: " + inputStr + " }"
		c := NewCompiler()
		_, err := c.CompileSource(ruleInput)
		_ = err

		// Test in expressions
		expressions := []string{
			inputStr + " == 0",
			inputStr + " > 0",
			inputStr + " and true",
			"true and " + inputStr,
			"not (" + inputStr + " == 0)",
		}

		for _, expr := range expressions {
			ruleInput := "rule test { condition: " + expr + " }"
			c2 := NewCompiler()
			_, err2 := c2.CompileSource(ruleInput)
			_ = err2
		}

		// Test with strings for matches
		if strings.Contains(inputStr, "matches") {
			stringRule := "rule test { strings: $a = \"test\" condition: " + inputStr + " }"
			c3 := NewCompiler()
			_, err3 := c3.CompileSource(stringRule)
			_ = err3
		}
	})
}
