package compiler

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/parser"
)

const maxFuzzBytecodeSize = 4096

type interpreterFuzzSeed struct {
	name      string
	bytecode  []byte
	wantStack []Value
}

type fuzzSeedTest interface {
	Helper()
	Fatalf(format string, args ...any)
}

func buildInterpreterFuzzBytecode(
	tb fuzzSeedTest,
	emit func(*Emitter),
) []byte {
	tb.Helper()
	emitter := NewEmitter()
	emit(emitter)
	emitter.EmitHalt(1, 1)
	bytecode, err := emitter.GetBytecode()
	if err != nil {
		tb.Fatalf("building interpreter fuzz seed: %v", err)
	}
	return bytecode
}

func interpreterBytecodeSeeds(tb fuzzSeedTest) []interpreterFuzzSeed {
	tb.Helper()
	return []interpreterFuzzSeed{
		{
			name: "nop",
			bytecode: buildInterpreterFuzzBytecode(tb, func(emitter *Emitter) {
				emitter.EmitNop(1, 1)
			}),
		},
		{
			name: "undefined",
			bytecode: buildInterpreterFuzzBytecode(tb, func(emitter *Emitter) {
				emitter.EmitOpcode(OpPushU, 1, 1)
			}),
			wantStack: []Value{{Type: ValueTypeUndefined}},
		},
		{
			name: "push_8",
			bytecode: buildInterpreterFuzzBytecode(tb, func(emitter *Emitter) {
				emitter.EmitPush(1, 1, 1)
			}),
			wantStack: []Value{{Type: ValueTypeInt, IntVal: 1}},
		},
		{
			name: "push_16",
			bytecode: buildInterpreterFuzzBytecode(tb, func(emitter *Emitter) {
				emitter.EmitPush(256, 1, 1)
			}),
			wantStack: []Value{{Type: ValueTypeInt, IntVal: 256}},
		},
		{
			name: "push_32",
			bytecode: buildInterpreterFuzzBytecode(tb, func(emitter *Emitter) {
				emitter.EmitPush(65536, 1, 1)
			}),
			wantStack: []Value{{Type: ValueTypeInt, IntVal: 65536}},
		},
		{
			name: "push_64",
			bytecode: buildInterpreterFuzzBytecode(tb, func(emitter *Emitter) {
				emitter.EmitPush(1<<32, 1, 1)
			}),
			wantStack: []Value{{Type: ValueTypeInt, IntVal: 1 << 32}},
		},
		{
			name: "push_double",
			bytecode: buildInterpreterFuzzBytecode(tb, func(emitter *Emitter) {
				emitter.EmitPushDouble(1.5, 1, 1)
			}),
			wantStack: []Value{{Type: ValueTypeDouble, DoubleVal: 1.5}},
		},
		{
			name: "defined",
			bytecode: buildInterpreterFuzzBytecode(tb, func(emitter *Emitter) {
				emitter.EmitOpcode(OpPushU, 1, 1)
				emitter.EmitOpcode(OpDefined, 1, 1)
			}),
			wantStack: []Value{{Type: ValueTypeInt}},
		},
	}
}

func interpreterStackSeeds(tb fuzzSeedTest) []interpreterFuzzSeed {
	tb.Helper()
	return []interpreterFuzzSeed{
		{
			name: "logical_and",
			bytecode: buildInterpreterFuzzBytecode(tb, func(emitter *Emitter) {
				emitter.EmitPush(1, 1, 1)
				emitter.EmitPush(1, 1, 1)
				emitter.EmitOpcode(OpAnd, 1, 1)
			}),
			wantStack: []Value{{Type: ValueTypeInt, IntVal: 1}},
		},
		{
			name: "logical_or",
			bytecode: buildInterpreterFuzzBytecode(tb, func(emitter *Emitter) {
				emitter.EmitPush(1, 1, 1)
				emitter.EmitPush(0, 1, 1)
				emitter.EmitOpcode(OpOr, 1, 1)
			}),
			wantStack: []Value{{Type: ValueTypeInt, IntVal: 1}},
		},
		{
			name: "logical_not",
			bytecode: buildInterpreterFuzzBytecode(tb, func(emitter *Emitter) {
				emitter.EmitPush(1, 1, 1)
				emitter.EmitOpcode(OpNot, 1, 1)
			}),
			wantStack: []Value{{Type: ValueTypeInt}},
		},
		{
			name: "integer_add",
			bytecode: buildInterpreterFuzzBytecode(tb, func(emitter *Emitter) {
				emitter.EmitPush(10, 1, 1)
				emitter.EmitPush(20, 1, 1)
				emitter.EmitOpcode(OpIntAdd, 1, 1)
			}),
			wantStack: []Value{{Type: ValueTypeInt, IntVal: 30}},
		},
		{
			name: "integer_multiply",
			bytecode: buildInterpreterFuzzBytecode(tb, func(emitter *Emitter) {
				emitter.EmitPush(10, 1, 1)
				emitter.EmitPush(5, 1, 1)
				emitter.EmitOpcode(OpIntMul, 1, 1)
			}),
			wantStack: []Value{{Type: ValueTypeInt, IntVal: 50}},
		},
		{
			name: "shift_left",
			bytecode: buildInterpreterFuzzBytecode(tb, func(emitter *Emitter) {
				emitter.EmitPush(2, 1, 1)
				emitter.EmitPush(3, 1, 1)
				emitter.EmitOpcode(OpShl, 1, 1)
			}),
			wantStack: []Value{{Type: ValueTypeInt, IntVal: 16}},
		},
		{
			name: "many_pushes",
			bytecode: buildInterpreterFuzzBytecode(tb, func(emitter *Emitter) {
				for range 100 {
					emitter.EmitPush(1, 1, 1)
				}
			}),
			wantStack: []Value{{Type: ValueTypeInt, IntVal: 1}},
		},
	}
}

func interpreterMemorySeeds(tb fuzzSeedTest) []interpreterFuzzSeed {
	tb.Helper()
	memoryOperand := func(emitter *Emitter, opcode Opcode, slot uint64) {
		emitter.EmitOpcodeWithOperand(
			opcode,
			Operand{Type: OperandImmediate32, Value: slot},
			1,
			1,
		)
	}
	return []interpreterFuzzSeed{
		{
			name: "store_and_load",
			bytecode: buildInterpreterFuzzBytecode(tb, func(emitter *Emitter) {
				emitter.EmitPush(0x42, 1, 1)
				memoryOperand(emitter, OpPopM, 0)
				memoryOperand(emitter, OpPushM, 0)
			}),
			wantStack: []Value{{Type: ValueTypeInt, IntVal: 0x42}},
		},
		{
			name: "clear_and_load",
			bytecode: buildInterpreterFuzzBytecode(tb, func(emitter *Emitter) {
				memoryOperand(emitter, OpClearM, 255)
				memoryOperand(emitter, OpPushM, 255)
			}),
			wantStack: []Value{{Type: ValueTypeUndefined}},
		},
		{
			name: "increment_and_load",
			bytecode: buildInterpreterFuzzBytecode(tb, func(emitter *Emitter) {
				memoryOperand(emitter, OpIncrM, 1)
				memoryOperand(emitter, OpPushM, 1)
			}),
			wantStack: []Value{{Type: ValueTypeInt, IntVal: 2}},
		},
		{
			name: "load",
			bytecode: buildInterpreterFuzzBytecode(tb, func(emitter *Emitter) {
				memoryOperand(emitter, OpPushM, 42)
			}),
			wantStack: []Value{{Type: ValueTypeInt, IntVal: 42}},
		},
	}
}

func newBytecodeFuzzInterpreter(bytecode []byte) *Interpreter {
	interpreter := NewInterpreter(bytecode)
	interpreter.SetItersmax(1024)
	interpreter.ResetIterationCount()
	interpreter.SetCurrentRule("test")
	interpreter.SetCompiledRules([]*CompiledRule{})
	interpreter.SetRuleResults(make(map[string]bool))
	interpreter.SetMatchContext(&MatchContext{
		Data:     []byte("test"),
		Matches:  make(map[string][]Match),
		FileSize: 4,
	})
	return interpreter
}

func prefillFuzzMemory(interpreter *Interpreter) {
	for index := range interpreterMemorySlotCount {
		interpreter.memory[index] = Value{Type: ValueTypeInt, IntVal: int64(index)}
	}
}

func executeWithFuzzStackDepth(interpreter *Interpreter, stackSize int) error {
	interpreter.Reset()
	for index := range stackSize {
		interpreter.stack = append(
			interpreter.stack,
			Value{Type: ValueTypeInt, IntVal: int64(index)},
		)
	}
	return interpreter.executeMainLoop()
}

func TestInterpreterFuzzSeedsExecute(t *testing.T) {
	groups := []struct {
		name          string
		seeds         []interpreterFuzzSeed
		prefillMemory bool
	}{
		{name: "bytecode", seeds: interpreterBytecodeSeeds(t)},
		{name: "stack", seeds: interpreterStackSeeds(t)},
		{name: "memory", seeds: interpreterMemorySeeds(t), prefillMemory: true},
	}

	for _, group := range groups {
		t.Run(group.name, func(t *testing.T) {
			for _, seed := range group.seeds {
				t.Run(seed.name, func(t *testing.T) {
					interpreter := newBytecodeFuzzInterpreter(seed.bytecode)
					defer interpreter.Release()
					if group.prefillMemory {
						prefillFuzzMemory(interpreter)
					}
					if err := interpreter.Execute(); err != nil {
						t.Fatalf("Execute() error = %v", err)
					}
					if got := interpreter.GetStack(); !slices.Equal(got, seed.wantStack) {
						t.Fatalf("stack = %#v, want %#v", got, seed.wantStack)
					}
				})
			}
		})
	}

	t.Run("prefilled_stack", func(t *testing.T) {
		bytecode := buildInterpreterFuzzBytecode(t, func(emitter *Emitter) {
			emitter.EmitOpcode(OpPop, 1, 1)
		})
		interpreter := newBytecodeFuzzInterpreter(bytecode)
		defer interpreter.Release()
		if err := executeWithFuzzStackDepth(interpreter, 1); err != nil {
			t.Fatalf("executeWithFuzzStackDepth() error = %v", err)
		}
	})
}

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
	for _, seed := range interpreterBytecodeSeeds(f) {
		f.Add(seed.bytecode)
	}
	for _, seed := range interpreterStackSeeds(f) {
		f.Add(seed.bytecode)
	}
	f.Add([]byte{byte(OpPush64), 0}) // Truncated operand.
	f.Add([]byte{0xF0})              // Unassigned opcode.

	f.Fuzz(func(t *testing.T, bytecode []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Bytecode interpreter panicked (fuzz input triggered crash): %v", r)
			}
		}()

		if len(bytecode) == 0 || len(bytecode) > maxFuzzBytecodeSize {
			return
		}

		interp := newBytecodeFuzzInterpreter(bytecode)
		err := interp.Execute()
		_ = err
		interp.Release()

		// Exercise a bounded sample of prefixes so large mutations do not turn
		// one fuzz iteration into quadratic interpreter work.
		if len(bytecode) > 1 {
			truncationLimit := min(len(bytecode)-1, 64)
			for truncateLen := 1; truncateLen <= truncationLimit; truncateLen++ {
				truncatedBytecode := bytecode[:truncateLen]
				interp2 := newBytecodeFuzzInterpreter(truncatedBytecode)
				err2 := interp2.Execute()
				_ = err2
				interp2.Release()
			}
			if len(bytecode)-1 > truncationLimit {
				interp2 := newBytecodeFuzzInterpreter(bytecode[:len(bytecode)-1])
				err2 := interp2.Execute()
				_ = err2
				interp2.Release()
			}
		}
	})
}

// FuzzInterpreterStack tests interpreter stack behavior with various instruction sequences
func FuzzInterpreterStack(f *testing.F) {
	for _, seed := range interpreterStackSeeds(f) {
		f.Add(seed.bytecode)
	}

	f.Fuzz(func(t *testing.T, bytecode []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Stack interpreter panicked (fuzz input triggered crash): %v", r)
			}
		}()

		if len(bytecode) == 0 || len(bytecode) > maxFuzzBytecodeSize {
			return
		}

		interp := newBytecodeFuzzInterpreter(bytecode)
		err := interp.Execute()
		_ = err
		interp.Release()

		// Test with different stack depths
		if len(bytecode) < 1000 {
			for stackSize := 0; stackSize <= 100; stackSize += 10 {
				interp2 := newBytecodeFuzzInterpreter(bytecode)
				err2 := executeWithFuzzStackDepth(interp2, stackSize)
				_ = err2
				interp2.Release()
			}
		}
	})
}

// FuzzInterpreterMemory tests interpreter memory operations
func FuzzInterpreterMemory(f *testing.F) {
	for _, seed := range interpreterMemorySeeds(f) {
		f.Add(seed.bytecode)
	}

	f.Fuzz(func(t *testing.T, bytecode []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Memory interpreter panicked (fuzz input triggered crash): %v", r)
			}
		}()

		if len(bytecode) == 0 || len(bytecode) > maxFuzzBytecodeSize {
			return
		}

		interp := newBytecodeFuzzInterpreter(bytecode)
		prefillFuzzMemory(interp)
		err := interp.Execute()
		_ = err
		interp.Release()
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
