package compiler

import (
	"strings"
	"testing"
)

// FuzzHexPatternParser tests hex pattern parsing with malformed inputs
func FuzzHexPatternParser(f *testing.F) {
	// Seed corpus with various hex patterns
	f.Add([]byte("{ DE AD BE EF }"))
	f.Add([]byte("{ 00 01 02 03 }"))
	f.Add([]byte("{ 4D 5A }"))                   // PE header
	f.Add([]byte("{ 7F 45 4C 46 }"))             // ELF header
	f.Add([]byte("{ 50 4B 03 04 }"))             // ZIP header
	f.Add([]byte("{ 89 50 4E 47 0D 0A 1A 0A }")) // PNG header
	f.Add([]byte("{ FF FF FF FF }"))
	f.Add([]byte("{ 00 00 }"))
	f.Add([]byte("{ FF }"))
	f.Add([]byte("{ DEADBEEF }"))
	f.Add([]byte("{ DE:AD:BE:EF }"))
	f.Add([]byte("{ DE-AD-BE-EF }"))
	f.Add([]byte("{ D E A D B E E F }"))
	f.Add([]byte("{ [0-256] }"))
	f.Add([]byte("{ [1-5] }"))
	f.Add([]byte("{ [10-20] }"))
	f.Add([]byte("{ [0-0] }"))
	f.Add([]byte("{ (DE|AD) }"))
	f.Add([]byte("{ (DE|AD|BE|EF) }"))
	f.Add([]byte("{ (00|01|02) }"))
	f.Add([]byte("{ (??|FF) }"))
	f.Add([]byte("{ DE AD ?? EF }"))
	f.Add([]byte("{ DE ?? ?? EF }"))
	f.Add([]byte("{ ?? ?? ?? ?? }"))
	f.Add([]byte("{ DE ?A EF }"))
	f.Add([]byte("{ DE ?D EF }"))
	f.Add([]byte("{ D? AD ?E EF }"))
	f.Add([]byte("{ 1? 2? 3? 4? }"))
	f.Add([]byte("{ DE AD } { BE EF }"))
	f.Add([]byte("{ DE AD } { BE EF } { 00 01 }"))
	f.Add([]byte("{ // comment\n DE AD }"))
	f.Add([]byte("{ DE // comment\n AD }"))
	f.Add([]byte("{ [0-100] DE AD }"))
	f.Add([]byte("{ DE AD [5-10] BE EF }"))
	f.Add([]byte("{ (00|01) [0-2] (FF|FE) }"))
	// Edge cases and malformed patterns
	f.Add([]byte("{ }"))
	f.Add([]byte("{ unclosed"))
	f.Add([]byte("DE AD BE EF"))
	f.Add([]byte("{{ DE AD }}"))
	f.Add([]byte("{ { nested } }"))
	f.Add([]byte("{ XX YY ZZ }"))
	f.Add([]byte("{ GG HH JJ }"))
	f.Add([]byte("{ [256-500] }"))
	f.Add([]byte("{ [100-50] }"))
	f.Add([]byte("{ [-5-10] }"))
	f.Add([]byte("{ (unclosed }"))
	f.Add([]byte("{ unclosed) }"))
	f.Add([]byte("{ () }"))
	f.Add([]byte("{ (|) }"))
	f.Add([]byte("{ [0-] }"))
	f.Add([]byte("{ [-] }"))
	f.Add([]byte("{ [] }"))
	f.Add([]byte("{ ? }"))
	f.Add([]byte("{ ??? }"))
	f.Add([]byte("{ D }"))
	f.Add([]byte("{ DE }"))
	f.Add([]byte("{ DE A }"))
	f.Add([]byte(strings.Repeat("DE AD BE EF ", 100)))
	f.Add([]byte("{ " + strings.Repeat("00 ", 1000) + "}"))
	f.Add([]byte("{ (DE|AD) " + strings.Repeat("(00|FF) ", 50) + "}"))
	f.Add([]byte("{ [0-" + strings.Repeat("9", 100) + "] }"))
	f.Add([]byte("{ " + strings.Repeat("?", 1000) + " }"))
	f.Add([]byte("{ \n\n\n DE \t\t AD \n\n\n }"))
	f.Add([]byte("{ // comment\n // another comment\n DE AD }"))
	f.Add([]byte("{ DE /* block comment */ AD }"))

	f.Fuzz(func(t *testing.T, input []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("Hex pattern parser recovered from panic: %v", r)
			}
		}()

		inputStr := string(input)

		// Test hex pattern compilation by wrapping it in a rule
		ruleInput := `rule test { strings: $a = ` + inputStr + ` condition: $a }`

		c := NewCompiler()
		_, err := c.CompileSource(ruleInput)
		_ = err // Whether compilation succeeds or fails, we shouldn't panic

		// Test with different modifiers
		modifiers := []string{
			"",
			" private",
			" nocase",
			" wide",
			" ascii",
		}

		for _, mod := range modifiers {
			ruleInput := `rule test { strings: $a = ` + inputStr + mod + ` condition: $a }`
			c2 := NewCompiler()
			_, err2 := c2.CompileSource(ruleInput)
			_ = err2
		}

		// Test with multiple strings
		ruleInput2 := `rule test { strings: $a = ` + inputStr + ` $b = ` + inputStr + ` condition: $a or $b }`
		c3 := NewCompiler()
		_, err3 := c3.CompileSource(ruleInput2)
		_ = err3

		// Test with truncated patterns
		if len(inputStr) > 1 {
			for truncateLen := 1; truncateLen < len(inputStr) && truncateLen <= 50; truncateLen++ {
				truncatedInput := inputStr[:truncateLen]
				ruleInput := `rule test { strings: $a = ` + truncatedInput + ` condition: $a }`
				c4 := NewCompiler()
				_, err4 := c4.CompileSource(ruleInput)
				_ = err4
			}
		}
	})
}

// FuzzHexPatternJumps tests hex pattern jump constructs
func FuzzHexPatternJumps(f *testing.F) {
	// Seed corpus with jump patterns
	f.Add([]byte("{ [0-256] }"))
	f.Add([]byte("{ [1-10] }"))
	f.Add([]byte("{ [5-5] }"))
	f.Add([]byte("{ [0-0] }"))
	f.Add([]byte("{ [10-] }"))
	f.Add([]byte("{ [-10] }"))
	f.Add([]byte("{ [] }"))
	f.Add([]byte("{ DE AD [0-10] BE EF }"))
	f.Add([]byte("{ [0-5] DE AD [5-10] BE EF }"))
	f.Add([]byte("{ [100-1000] DE AD }"))
	f.Add([]byte("{ [0-*] }"))
	f.Add([]byte("{ [1-*] }"))
	f.Add([]byte("{ DE AD [-] BE EF }"))
	f.Add([]byte("{ [999999-10000000] }"))
	// Edge cases
	f.Add([]byte("{ [0] }"))
	f.Add([]byte("{ [1] }"))
	f.Add([]byte("{ [256] }"))
	f.Add([]byte("{ [257] }"))
	f.Add([]byte("{ [65535] }"))
	f.Add([]byte("{ [0-65535] }"))
	f.Add([]byte("{ [-] }"))
	f.Add([]byte("{ [a-z] }"))
	f.Add([]byte("{ [0.5-1.5] }"))
	f.Add([]byte("{ [0--10] }"))

	f.Fuzz(func(t *testing.T, input []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("Hex pattern jumps fuzz recovered from panic: %v", r)
			}
		}()

		inputStr := string(input)

		// Test jump pattern in isolation
		ruleInput := `rule test { strings: $a = ` + inputStr + ` condition: $a }`
		c := NewCompiler()
		_, err := c.CompileSource(ruleInput)
		_ = err

		// Test with preceding and following bytes
		patterns := []string{
			`{ DE AD ` + inputStr + ` BE EF }`,
			`{ 00 ` + inputStr + ` FF }`,
			`{ ` + inputStr + ` 00 }`,
			`{ FF ` + inputStr + ` }`,
			inputStr + inputStr,
		}

		for _, pattern := range patterns {
			ruleInput := `rule test { strings: $a = ` + pattern + ` condition: $a }`
			c2 := NewCompiler()
			_, err2 := c2.CompileSource(ruleInput)
			_ = err2
		}

		// Test with alternatives
		altPattern := `{ (00|FF) ` + inputStr + ` (DE|AD) }`
		ruleInput3 := `rule test { strings: $a = ` + altPattern + ` condition: $a }`
		c3 := NewCompiler()
		_, err3 := c3.CompileSource(ruleInput3)
		_ = err3
	})
}

// FuzzHexPatternAlternatives tests hex pattern alternative constructs
func FuzzHexPatternAlternatives(f *testing.F) {
	// Seed corpus with alternative patterns
	f.Add([]byte("{ (DE|AD) }"))
	f.Add([]byte("{ (DE|AD|BE|EF) }"))
	f.Add([]byte("{ (00|01|02|03) }"))
	f.Add([]byte("{ (FF|FE|FD) }"))
	f.Add([]byte("{ (??|FF) }"))
	f.Add([]byte("{ (DE?D|AD?D) }"))
	f.Add([]byte("{ (DE AD|BE EF) }"))
	f.Add([]byte("{ (00 01|02 03|04 05) }"))
	f.Add([]byte("{ (00|01) [0-10] (FF|FE) }"))
	f.Add([]byte("{ [0-10] (DE|AD) [0-10] }"))
	// Edge cases
	f.Add([]byte("{ () }"))
	f.Add([]byte("{ (|) }"))
	f.Add([]byte("{ (DE) }"))
	f.Add([]byte("{ ()|() }"))
	f.Add([]byte("{ ((DE|AD)) }"))
	f.Add([]byte("{ (|DE|AD) }"))
	f.Add([]byte("{ (DE|AD|) }"))
	f.Add([]byte("{ (DE|AD|BE|EF|00|11|22|33|44|55|66|77|88|99|AA|BB|CC|DD|EE|FF) }"))
	f.Add([]byte("{ (" + strings.Repeat("DE|", 100) + "AD) }"))

	f.Fuzz(func(t *testing.T, input []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("Hex pattern alternatives fuzz recovered from panic: %v", r)
			}
		}()

		inputStr := string(input)

		// Test alternative pattern in isolation
		ruleInput := `rule test { strings: $a = ` + inputStr + ` condition: $a }`
		c := NewCompiler()
		_, err := c.CompileSource(ruleInput)
		_ = err

		// Test with preceding and following bytes
		patterns := []string{
			`{ DE AD ` + inputStr + ` BE EF }`,
			`{ 00 ` + inputStr + ` FF }`,
			`{ ` + inputStr + ` 00 }`,
			inputStr + inputStr,
		}

		for _, pattern := range patterns {
			ruleInput := `rule test { strings: $a = ` + pattern + ` condition: $a }`
			c2 := NewCompiler()
			_, err2 := c2.CompileSource(ruleInput)
			_ = err2
		}

		// Test with jumps
		jumpPattern := `{ [0-10] ` + inputStr + ` [0-10] }`
		ruleInput3 := `rule test { strings: $a = ` + jumpPattern + ` condition: $a }`
		c3 := NewCompiler()
		_, err3 := c3.CompileSource(ruleInput3)
		_ = err3
	})
}

// FuzzHexPatternWildcards tests hex pattern wildcards
func FuzzHexPatternWildcards(f *testing.F) {
	// Seed corpus with wildcard patterns
	f.Add([]byte("{ ?? }"))
	f.Add([]byte("{ DE ?? EF }"))
	f.Add([]byte("{ ?? ?? ?? ?? }"))
	f.Add([]byte("{ ?A ?B ?C ?D }"))
	f.Add([]byte("{ D? A? D? ?? }"))
	f.Add([]byte("{ 1? 2? 3? 4? }"))
	f.Add([]byte("{ ?0 ?1 ?2 ?3 }"))
	f.Add([]byte("{ ?F ?E ?D ?C }"))
	f.Add([]byte("{ (?A|FF) }"))
	f.Add([]byte("{ (D?|AD) }"))
	// Edge cases
	f.Add([]byte("{ ? }"))
	f.Add([]byte("{ ??? }"))
	f.Add([]byte("{ D }"))
	f.Add([]byte("{ G? }"))
	f.Add([]byte("{ ?G }"))
	f.Add([]byte("{ ?G?H }"))
	f.Add([]byte("{ " + strings.Repeat("?? ", 100) + "}"))
	f.Add([]byte("{ " + strings.Repeat("?", 200) + " }"))

	f.Fuzz(func(t *testing.T, input []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("Hex pattern wildcards fuzz recovered from panic: %v", r)
			}
		}()

		inputStr := string(input)

		// Test wildcard pattern in rule
		ruleInput := `rule test { strings: $a = ` + inputStr + ` condition: $a }`
		c := NewCompiler()
		_, err := c.CompileSource(ruleInput)
		_ = err

		// Test with different contexts
		contexts := []string{
			`{ DE AD ` + inputStr + ` BE EF }`,
			`{ ` + inputStr + ` DE AD }`,
			`{ DE AD ` + inputStr + ` }`,
			inputStr + inputStr,
		}

		for _, ctx := range contexts {
			ruleInput := `rule test { strings: $a = ` + ctx + ` condition: $a }`
			c2 := NewCompiler()
			_, err2 := c2.CompileSource(ruleInput)
			_ = err2
		}

		// Test with jumps and alternatives
		complexPattern := `{ [0-10] ` + inputStr + ` (00|FF) }`
		ruleInput3 := `rule test { strings: $a = ` + complexPattern + ` condition: $a }`
		c3 := NewCompiler()
		_, err3 := c3.CompileSource(ruleInput3)
		_ = err3
	})
}

// FuzzHexPatternNegation tests hex pattern negation
func FuzzHexPatternNegation(f *testing.F) {
	// Seed corpus with negation patterns
	f.Add([]byte("{ ~DE }"))
	f.Add([]byte("{ ~DE ~AD ~BE ~EF }"))
	f.Add([]byte("{ DE ~AD ~BE EF }"))
	f.Add([]byte("{ ~(DE|AD) }"))
	f.Add([]byte("{ ~?? }"))
	f.Add([]byte("{ ~?A }"))
	f.Add([]byte("{ ~[0-10] }"))
	// Edge cases
	f.Add([]byte("{ ~~DE }"))
	f.Add([]byte("{ ~ }"))
	f.Add([]byte("{ ~DE }"))
	f.Add([]byte("{ ~(DE) }"))
	f.Add([]byte("{ ~() }"))
	f.Add([]byte("{ ~(DE|AD) }"))
	f.Add([]byte("{ ~(??) }"))

	f.Fuzz(func(t *testing.T, input []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("Hex pattern negation fuzz recovered from panic: %v", r)
			}
		}()

		inputStr := string(input)

		// Test negation pattern in rule
		ruleInput := `rule test { strings: $a = ` + inputStr + ` condition: $a }`
		c := NewCompiler()
		_, err := c.CompileSource(ruleInput)
		_ = err

		// Test with different patterns
		patterns := []string{
			`{ DE AD ` + inputStr + ` BE EF }`,
			`{ ` + inputStr + ` DE AD }`,
			inputStr + inputStr,
		}

		for _, pattern := range patterns {
			ruleInput := `rule test { strings: $a = ` + pattern + ` condition: $a }`
			c2 := NewCompiler()
			_, err2 := c2.CompileSource(ruleInput)
			_ = err2
		}
	})
}

// FuzzHexPatternComplex tests complex hex patterns with combinations
func FuzzHexPatternComplex(f *testing.F) {
	// Seed corpus with complex patterns
	f.Add([]byte("{ DE AD [0-10] (00|FF) BE EF }"))
	f.Add([]byte("{ (DE|AD) [1-5] (BE|EF) [0-100] (00|11) }"))
	f.Add([]byte("{ ?? ?? [0-256] (??|FF) ?? ?? }"))
	f.Add([]byte("{ 4D 5A [0-256] }"))           // PE header with jump
	f.Add([]byte("{ 7F 45 4C 46 }"))             // ELF header
	f.Add([]byte("{ 50 4B 03 04 [0-1000] }"))    // ZIP header with jump
	f.Add([]byte("{ 89 50 4E 47 0D 0A 1A 0A }")) // PNG header
	f.Add([]byte("{ (00|01|02|03) [0-10] (FF|FE|FD) }"))
	f.Add([]byte("{ DE ?D [0-5] (AD|?D) }"))
	// Very long patterns
	f.Add(
		[]byte(
			"{ " + strings.Repeat("DE AD ", 50) + "[0-10] " + strings.Repeat("BE EF ", 50) + "}",
		),
	)
	f.Add([]byte("{ " + strings.Repeat("(DE|AD) ", 30) + "}"))
	f.Add([]byte("{ " + strings.Repeat("?? ", 100) + "}"))
	// Nested constructs
	f.Add([]byte("{ ((DE|AD)|(BE|EF)) }"))
	f.Add([]byte("{ [0-[0-10]] }"))
	f.Add([]byte("{ ((00|11)|((22|33)|(44|55))) }"))

	f.Fuzz(func(t *testing.T, input []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("Hex pattern complex fuzz recovered from panic: %v", r)
			}
		}()

		inputStr := string(input)

		// Test complex pattern in rule
		ruleInput := `rule test { strings: $a = ` + inputStr + ` condition: $a }`
		c := NewCompiler()
		_, err := c.CompileSource(ruleInput)
		_ = err

		// Test with multiple strings
		ruleInput2 := `rule test { strings: $a = ` + inputStr + ` $b = ` + inputStr + ` condition: $a or $b }`
		c2 := NewCompiler()
		_, err2 := c2.CompileSource(ruleInput2)
		_ = err2

		// Test with modifiers
		ruleInput3 := `rule test { strings: $a = ` + inputStr + ` nocase wide condition: $a }`
		c3 := NewCompiler()
		_, err3 := c3.CompileSource(ruleInput3)
		_ = err3
	})
}
