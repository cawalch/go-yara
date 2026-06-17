package compiler

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/parser"
)

// FuzzInterpreter tests bytecode interpretation with various rules and data
func FuzzInterpreter(f *testing.F) {
	// Seed corpus with rule and data combinations
	f.Add([]byte("rule test { condition: true }\x00"))
	f.Add([]byte("rule test { condition: false }\x00"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: $a }\x00test"))
	f.Add([]byte("rule test { strings: $a = \"hello\" condition: $a }\x00hello world"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: $a }\x00nomatch"))
	f.Add([]byte("rule test { condition: filesize > 0 }\x00test"))
	f.Add([]byte("rule test { condition: filesize > 100 }\x00" + strings.Repeat("x", 200)))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: #a == 1 }\x00test"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: #a > 0 }\x00test test test"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: @a == 0 }\x00test"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: !a == 4 }\x00test"))
	f.Add([]byte("rule test { strings: $a = \"test\" $b = \"test\" condition: all of them }\x00test"))
	f.Add([]byte("rule test { strings: $a = \"test\" $b = \"other\" condition: any of them }\x00test"))
	f.Add([]byte("rule test { strings: $a = \"test\" $b = \"test\" condition: 1 of them }\x00test"))
	f.Add([]byte("rule test { condition: 1 + 2 == 3 }\x00"))
	f.Add([]byte("rule test { condition: filesize > 10 and filesize < 100 }\x00" + strings.Repeat("x", 50)))
	f.Add([]byte("rule test { condition: not false }\x00"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: not $a }\x00nomatch"))
	f.Add([]byte("rule test { condition: int8(0) == 0x74 }\x00t"))
	f.Add([]byte("rule test { condition: \"test\" matches /test/ }\x00test"))
	// Edge cases
	f.Add([]byte("rule test { condition: true }\x00"))
	f.Add([]byte("rule test { condition: for any i in (1..10) : ( i > 5 ) }\x00"))
	f.Add([]byte("rule test { strings: $a = \"\\x00\" condition: $a }\x00\x00"))
	f.Add([]byte("rule test { strings: $a = \"\\xFF\" condition: $a }\x00\xFF"))
	f.Add([]byte("rule test { strings: $a = \"\\n\\r\\t\" condition: $a }\x00\n\r\t"))
	f.Add([]byte("rule test { strings: $a = \"\" condition: $a }\x00"))
	f.Add([]byte("rule test { strings: $a = \"x\" condition: $a }\x00x"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: $a }\x00" + strings.Repeat("x", 10000) + "test"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: $a }\x00test\x00test"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: $a }\x00\xFF\xFE\xFD\xFCtest"))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Interpreter panicked (fuzz input triggered crash): %v", r)
			}
		}()

		// Split data into rule and test data
		before, after, ok := bytes.Cut(data, []byte{0})
		if !ok {
			return
		}

		ruleBytes := before
		testData := after

		ruleStr := string(ruleBytes)

		// Parse and compile the rule
		l := lexer.New(ruleStr)
		p := parser.New(l)
		program, err := p.ParseRulesWithContext(context.Background())
		if err != nil || program == nil || len(program.Rules) == 0 {
			return // Invalid rule - expected
		}

		c := NewCompiler()
		compiledProgram, err := c.CompileSource(ruleStr)
		if err != nil || compiledProgram == nil {
			return // Compilation error - expected
		}

		// Try to execute each rule
		for _, rule := range compiledProgram.Rules {
			if len(rule.Bytecode) == 0 {
				continue
			}

			// Create interpreter
			interp := NewInterpreter(rule.Bytecode)
			interp.SetCurrentRule(rule.Name)
			interp.SetCompiledRules(compiledProgram.Rules)
			interp.SetRuleResults(make(map[string]bool))

			// Create match context with test data
			matchCtx := &MatchContext{
				Data:     testData,
				Matches:  make(map[string][]Match),
				FileSize: int64(len(testData)),
			}

			// Add string matches if the rule has strings
			for strID := range rule.Strings {
				pattern := strID
				// Try to find the pattern as a literal string
				if textData, ok := rule.TextPatterns[pattern]; ok {
					// Text patterns are stored as bytes
					textPattern := string(textData)
					// Find all occurrences
					offset := 0
					for {
						idx := bytes.Index(testData[offset:], []byte(textPattern))
						if idx == -1 {
							break
						}
						absOffset := int64(offset + idx)
						matchCtx.AddMatch(Match{
							Pattern: pattern,
							Offset:  absOffset,
							Length:  len(textPattern),
						})
						offset += idx + 1
					}
				}
			}

			interp.SetMatchContext(matchCtx)

			// Execute
			err = interp.Execute()
			_ = err // Whether execution succeeds or fails, we shouldn't panic

			// Test with truncated data
			if len(testData) > 1 {
				for truncateLen := 1; truncateLen < len(testData) && truncateLen <= 100; truncateLen += 10 {
					truncatedData := testData[:truncateLen]
					matchCtx2 := &MatchContext{
						Data:     truncatedData,
						Matches:  make(map[string][]Match),
						FileSize: int64(len(truncatedData)),
					}
					interp2 := NewInterpreter(rule.Bytecode)
					interp2.SetCurrentRule(rule.Name)
					interp2.SetCompiledRules(compiledProgram.Rules)
					interp2.SetRuleResults(make(map[string]bool))
					interp2.SetMatchContext(matchCtx2)
					err2 := interp2.Execute()
					_ = err2
				}
			}
		}
	})
}

// FuzzInterpreterMultipleRules tests interpreter with multiple rules
func FuzzInterpreterMultipleRules(f *testing.F) {
	// Seed corpus with multiple rules
	f.Add([]byte("rule test1 { condition: true } rule test2 { condition: false }\x00test"))
	f.Add([]byte("rule a { strings: $a = \"test\" condition: $a } rule b { strings: $b = \"other\" condition: $b }\x00test other"))
	f.Add([]byte("rule base { strings: $a = \"test\" condition: $a } rule derived { condition: base }\x00test"))
	f.Add([]byte("global rule g1 { condition: true } rule test { condition: g1 }\x00"))
	f.Add([]byte(strings.Repeat("rule test { condition: true } ", 10) + "\x00test"))
	f.Add([]byte("rule a { strings: $a = \"a\" condition: $a } rule b { strings: $b = \"b\" condition: $b } rule c { strings: $c = \"c\" condition: $c }\x00a b c"))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Multiple rules interpreter panicked (fuzz input triggered crash): %v", r)
			}
		}()

		// Split into rules and test data
		before, after, ok := bytes.Cut(data, []byte{0})
		if !ok {
			return
		}

		ruleBytes := before
		testData := after

		ruleStr := string(ruleBytes)

		// Parse and compile
		l := lexer.New(ruleStr)
		p := parser.New(l)
		program, err := p.ParseRulesWithContext(context.Background())
		if err != nil || program == nil || len(program.Rules) == 0 {
			return
		}

		c := NewCompiler()
		compiledProgram, err := c.CompileSource(ruleStr)
		if err != nil || compiledProgram == nil {
			return
		}

		// Execute all rules
		ruleResults := make(map[string]bool)
		for _, rule := range compiledProgram.Rules {
			if len(rule.Bytecode) == 0 {
				ruleResults[rule.Name] = false
				continue
			}

			interp := NewInterpreter(rule.Bytecode)
			interp.SetCurrentRule(rule.Name)
			interp.SetCompiledRules(compiledProgram.Rules)
			interp.SetRuleResults(ruleResults)

			matchCtx := &MatchContext{
				Data:     testData,
				Matches:  make(map[string][]Match),
				FileSize: int64(len(testData)),
			}
			interp.SetMatchContext(matchCtx)

			err = interp.Execute()
			if err == nil {
				// Result is stored in ruleResults by the interpreter
			} else {
				ruleResults[rule.Name] = false
			}
		}
	})
}

// FuzzInterpreterBytecode tests interpreter with raw bytecode
func FuzzInterpreterBytecode(f *testing.F) {
	// Seed corpus with simple bytecode sequences
	f.Add([]byte("\x01\x00\x00\x00\x00"))                     // OpPushTrue
	f.Add([]byte("\x02\x00\x00\x00\x00"))                     // OpPushFalse
	f.Add([]byte("\x03\x01\x00\x00\x00\x0A\x00\x00\x00\x00")) // OpPushInt 10
	f.Add([]byte("\x04\x01\x00\x00\x00\x74"))                 // OpPushStr "t"
	f.Add([]byte("\x05\x00\x00\x00\x00"))                     // OpPop
	f.Add([]byte("\x06\x00\x00\x00\x00"))                     // OpDup
	f.Add([]byte("\x07\x00\x00\x00\x00"))                     // OpNot
	f.Add([]byte("\x10\x00\x00\x00\x00"))                     // OpAnd
	f.Add([]byte("\x11\x00\x00\x00\x00"))                     // OpOr
	f.Add([]byte("\x12\x00\x00\x00\x00"))                     // OpAdd
	f.Add([]byte("\x13\x00\x00\x00\x00"))                     // OpSub
	f.Add([]byte("\x14\x00\x00\x00\x00"))                     // OpMul
	f.Add([]byte("\x15\x00\x00\x00\x00"))                     // OpDiv
	f.Add([]byte("\x16\x00\x00\x00\x00"))                     // OpMod
	f.Add([]byte("\x17\x00\x00\x00\x00"))                     // OpShl
	f.Add([]byte("\x18\x00\x00\x00\x00"))                     // OpShr
	f.Add([]byte("\x19\x00\x00\x00\x00"))                     // OpBAnd
	f.Add([]byte("\x1A\x00\x00\x00\x00"))                     // OpBOr
	f.Add([]byte("\x1B\x00\x00\x00\x00"))                     // OpBXor
	f.Add([]byte("\x1C\x00\x00\x00\x00"))                     // OpBNot
	f.Add([]byte("\x01\x00\x00\x00\x00\xFF"))                 // Valid + invalid

	f.Fuzz(func(t *testing.T, bytecode []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Bytecode interpreter panicked (fuzz input triggered crash): %v", r)
			}
		}()

		if len(bytecode) == 0 {
			return
		}

		// Create interpreter with bytecode
		interp := NewInterpreter(bytecode)
		interp.SetCurrentRule("test")
		interp.SetCompiledRules([]*CompiledRule{})
		interp.SetRuleResults(make(map[string]bool))

		// Create match context
		matchCtx := &MatchContext{
			Data:     []byte("test"),
			Matches:  make(map[string][]Match),
			FileSize: 4,
		}
		interp.SetMatchContext(matchCtx)

		// Execute
		err := interp.Execute()
		_ = err

		// Test with truncated bytecode
		if len(bytecode) > 1 {
			for truncateLen := 1; truncateLen < len(bytecode); truncateLen++ {
				truncatedBytecode := bytecode[:truncateLen]
				interp2 := NewInterpreter(truncatedBytecode)
				interp2.SetCurrentRule("test")
				interp2.SetCompiledRules([]*CompiledRule{})
				interp2.SetRuleResults(make(map[string]bool))
				interp2.SetMatchContext(matchCtx)
				err2 := interp2.Execute()
				_ = err2
			}
		}
	})
}

// FuzzInterpreterStack tests interpreter stack behavior with various instruction sequences
func FuzzInterpreterStack(f *testing.F) {
	// Seed corpus with instruction sequences
	f.Add([]byte("\x01\x00\x00\x00\x00\x06\x00\x00\x00\x00\x05\x00\x00\x00\x00"))                                         // push true, dup, pop
	f.Add([]byte("\x03\x01\x00\x00\x00\x0A\x00\x00\x00\x00\x03\x01\x00\x00\x00\x14\x00\x00\x00\x00\x12\x00\x00\x00\x00")) // push 10, push 20, add
	f.Add([]byte("\x03\x01\x00\x00\x00\x0A\x00\x00\x00\x00\x03\x01\x00\x00\x00\x05\x00\x00\x00\x00\x13\x00\x00\x00\x00")) // push 10, push 5, mul
	f.Add([]byte("\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x10\x00\x00\x00\x00"))                                         // true, true, and
	f.Add([]byte("\x01\x00\x00\x00\x00\x02\x00\x00\x00\x00\x11\x00\x00\x00\x00"))                                         // true, false, or
	f.Add([]byte("\x01\x00\x00\x00\x00\x07\x00\x00\x00\x00"))                                                             // true, not
	f.Add([]byte(strings.Repeat("\x01\x00\x00\x00\x00", 100)))                                                            // 100 push true
	f.Add([]byte(strings.Repeat("\x03\x01\x00\x00\x00\x01\x00\x00\x00\x00", 50)))                                         // 50 push 1

	f.Fuzz(func(t *testing.T, bytecode []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Stack interpreter panicked (fuzz input triggered crash): %v", r)
			}
		}()

		if len(bytecode) == 0 {
			return
		}

		// Create interpreter
		interp := NewInterpreter(bytecode)
		interp.SetCurrentRule("test")
		interp.SetCompiledRules([]*CompiledRule{})
		interp.SetRuleResults(make(map[string]bool))

		matchCtx := &MatchContext{
			Data:     []byte("test"),
			Matches:  make(map[string][]Match),
			FileSize: 4,
		}
		interp.SetMatchContext(matchCtx)

		// Execute
		err := interp.Execute()
		_ = err

		// Test with different stack depths
		if len(bytecode) < 1000 {
			// Pre-fill stack with values
			for stackSize := 0; stackSize <= 100; stackSize += 10 {
				interp2 := NewInterpreter(bytecode)
				interp2.SetCurrentRule("test")
				interp2.SetCompiledRules([]*CompiledRule{})
				interp2.SetRuleResults(make(map[string]bool))
				interp2.SetMatchContext(matchCtx)

				// Push some values onto stack first
				for i := 0; i < stackSize; i++ {
					interp2.stack = append(interp2.stack, Value{Type: ValueTypeInt, IntVal: int64(i)})
				}

				err2 := interp2.Execute()
				_ = err2
			}
		}
	})
}

// FuzzInterpreterMemory tests interpreter memory operations
func FuzzInterpreterMemory(f *testing.F) {
	// Seed corpus with memory operations
	// Note: Actual opcodes depend on implementation
	f.Add([]byte("\x03\x01\x00\x00\x00\x42\x00\x00\x00\x00"))                      // push 0x42
	f.Add([]byte(strings.Repeat("\x03\x01\x00\x00\x00\x00\x00\x00\x00\x00", 256))) // 256 push 0

	f.Fuzz(func(t *testing.T, bytecode []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Memory interpreter panicked (fuzz input triggered crash): %v", r)
			}
		}()

		if len(bytecode) == 0 {
			return
		}

		// Create interpreter
		interp := NewInterpreter(bytecode)
		interp.SetCurrentRule("test")
		interp.SetCompiledRules([]*CompiledRule{})
		interp.SetRuleResults(make(map[string]bool))

		// Pre-fill memory with values
		for i := range 256 {
			interp.memory[i] = Value{Type: ValueTypeInt, IntVal: int64(i)}
		}

		matchCtx := &MatchContext{
			Data:     []byte("test"),
			Matches:  make(map[string][]Match),
			FileSize: 4,
		}
		interp.SetMatchContext(matchCtx)

		// Execute
		err := interp.Execute()
		_ = err
	})
}

// FuzzInterpreterMatchContext tests interpreter with various match contexts
func FuzzInterpreterMatchContext(f *testing.F) {
	// Seed corpus with rule and match data
	f.Add([]byte("rule test { strings: $a = \"test\" condition: #a > 0 }\x00test"))
	f.Add([]byte("rule test { strings: $a = \"test\" $b = \"test\" condition: #a == #b }\x00test test"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: @a[1] == 0 }\x00test"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: @a[1] < 100 }\x00" + strings.Repeat("x", 50) + "test"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: !a == 4 }\x00test"))
	f.Add([]byte("rule test { strings: $a = \"a\" $b = \"b\" $c = \"c\" condition: 2 of them }\x00a b"))
	f.Add([]byte("rule test { strings: $a = \"test\" $b = \"other\" condition: any of ($a, $b) }\x00test"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: $a in (0..100) }\x00" + strings.Repeat("x", 50) + "test"))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Match context interpreter panicked (fuzz input triggered crash): %v", r)
			}
		}()

		before, after, ok := bytes.Cut(data, []byte{0})
		if !ok {
			return
		}

		ruleBytes := before
		testData := after

		ruleStr := string(ruleBytes)

		l := lexer.New(ruleStr)
		p := parser.New(l)
		program, err := p.ParseRulesWithContext(context.Background())
		if err != nil || program == nil || len(program.Rules) == 0 {
			return
		}

		c := NewCompiler()
		compiledProgram, err := c.CompileSource(ruleStr)
		if err != nil || compiledProgram == nil {
			return
		}

		// Execute with various match contexts
		for _, rule := range compiledProgram.Rules {
			if len(rule.Bytecode) == 0 {
				continue
			}

			// Test with different data variations
			dataVariations := [][]byte{
				testData,
				[]byte(""),
				[]byte("test"),
				bytes.Repeat([]byte("x"), 100),
			}

			for _, data := range dataVariations {
				matchCtx := &MatchContext{
					Data:     data,
					Matches:  make(map[string][]Match),
					FileSize: int64(len(data)),
				}

				// Add some matches
				if len(rule.Strings) > 0 && len(data) > 0 {
					for strID := range rule.Strings {
						if textData, ok := rule.TextPatterns[strID]; ok {
							pattern := string(textData)
							if idx := bytes.Index(data, []byte(pattern)); idx >= 0 {
								matchCtx.AddMatch(Match{
									Pattern: strID,
									Offset:  int64(idx),
									Length:  len(pattern),
								})
							}
						}
					}
				}

				interp := NewInterpreter(rule.Bytecode)
				interp.SetCurrentRule(rule.Name)
				interp.SetCompiledRules(compiledProgram.Rules)
				interp.SetRuleResults(make(map[string]bool))
				interp.SetMatchContext(matchCtx)

				err := interp.Execute()
				_ = err
			}
		}
	})
}
