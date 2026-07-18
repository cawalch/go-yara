package compiler

import (
	"strings"
	"testing"
)

func fuzzParseHexPatterns(inputs ...string) {
	for _, input := range inputs {
		sc := NewStringCompiler()
		pattern, err := sc.parseHexPattern(normalizeHexFuzzPattern(input))
		if err == nil {
			_ = pattern.Clone()
		}
	}
}

func normalizeHexFuzzPattern(input string) string {
	trimmed := strings.TrimSpace(input)
	if strings.HasPrefix(trimmed, "{") {
		return trimmed
	}
	return "{ " + input + " }"
}

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
				t.Errorf("Hex pattern parser panicked (fuzz input triggered crash): %v", r)
			}
		}()

		inputStr := string(input)

		fuzzParseHexPatterns(inputStr, inputStr+" "+inputStr)

		// Test with truncated patterns
		if len(inputStr) > 1 {
			for truncateLen := 1; truncateLen < len(inputStr) && truncateLen <= 50; truncateLen++ {
				truncatedInput := inputStr[:truncateLen]
				fuzzParseHexPatterns(truncatedInput)
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
				t.Errorf("Hex pattern jumps fuzz panicked (fuzz input triggered crash): %v", r)
			}
		}()

		inputStr := string(input)

		// Test with preceding and following bytes
		patterns := []string{
			inputStr,
			`{ DE AD ` + inputStr + ` BE EF }`,
			`{ 00 ` + inputStr + ` FF }`,
			`{ ` + inputStr + ` 00 }`,
			`{ FF ` + inputStr + ` }`,
			inputStr + inputStr,
		}

		for _, pattern := range patterns {
			fuzzParseHexPatterns(pattern)
		}

		// Test with alternatives
		altPattern := `{ (00|FF) ` + inputStr + ` (DE|AD) }`
		fuzzParseHexPatterns(altPattern)
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
				t.Errorf("Hex pattern alternatives fuzz panicked (fuzz input triggered crash): %v", r)
			}
		}()

		inputStr := string(input)

		// Test with preceding and following bytes
		patterns := []string{
			inputStr,
			`{ DE AD ` + inputStr + ` BE EF }`,
			`{ 00 ` + inputStr + ` FF }`,
			`{ ` + inputStr + ` 00 }`,
			inputStr + inputStr,
		}

		for _, pattern := range patterns {
			fuzzParseHexPatterns(pattern)
		}

		// Test with jumps
		jumpPattern := `{ [0-10] ` + inputStr + ` [0-10] }`
		fuzzParseHexPatterns(jumpPattern)
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
				t.Errorf("Hex pattern wildcards fuzz panicked (fuzz input triggered crash): %v", r)
			}
		}()

		inputStr := string(input)

		// Test with different contexts
		contexts := []string{
			inputStr,
			`{ DE AD ` + inputStr + ` BE EF }`,
			`{ ` + inputStr + ` DE AD }`,
			`{ DE AD ` + inputStr + ` }`,
			inputStr + inputStr,
		}

		for _, ctx := range contexts {
			fuzzParseHexPatterns(ctx)
		}

		// Test with jumps and alternatives
		complexPattern := `{ [0-10] ` + inputStr + ` (00|FF) }`
		fuzzParseHexPatterns(complexPattern)
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
				t.Errorf("Hex pattern negation fuzz panicked (fuzz input triggered crash): %v", r)
			}
		}()

		inputStr := string(input)

		// Test with different patterns
		patterns := []string{
			inputStr,
			`{ DE AD ` + inputStr + ` BE EF }`,
			`{ ` + inputStr + ` DE AD }`,
			inputStr + inputStr,
		}

		for _, pattern := range patterns {
			fuzzParseHexPatterns(pattern)
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
				t.Errorf("Hex pattern complex fuzz panicked (fuzz input triggered crash): %v", r)
			}
		}()

		inputStr := string(input)

		fuzzParseHexPatterns(inputStr, inputStr+" "+inputStr)
	})
}
