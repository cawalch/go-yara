package compiler

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func conditionAssertionRules(count int) string {
	var source strings.Builder
	for index := 0; index < count; index++ {
		fmt.Fprintf(&source, `rule r%d { strings: $a = "MZ" condition: uint16(0) == 0x5a4d and uint32(2) == 0x04030201 and filesize < 20MB and #a > 0 and $a at 0 } `, index)
	}
	return source.String()
}

func TestConditionOpcodeProfile(t *testing.T) {
	parsed, err := NewCompiler().compileParseWithContext(context.Background(), conditionAssertionRules(1))
	if err != nil {
		t.Fatal(err)
	}
	generator := newRuleCompiler()
	if _, err := generator.CompileRule(parsed.Rules[0]); err != nil {
		t.Fatal(err)
	}
	frequencies := map[string]int{}
	for _, instruction := range generator.emitter.GetInstructions() {
		frequencies[instruction.Opcode.String()]++
	}
	t.Logf("condition-heavy rule opcode frequencies: %v", frequencies)
}

func BenchmarkConditionAssertions(b *testing.B) {
	for _, fused := range []bool{false, true} {
		b.Run(fmt.Sprintf("fused=%t", fused), func(b *testing.B) {
			program := compileAssertionVariant(b, conditionAssertionRules(200), fused)
			for _, scenario := range []string{"pass", "header_reject", "size_reject"} {
				b.Run(scenario, func(b *testing.B) {
					scanner := program.NewScanner(WithoutMatches(), WithoutRuleResults())
					defer scanner.Close()
					data := []byte("MZ\x01\x02\x03\x04payload")
					if scenario == "header_reject" {
						data[0] = 'X'
					}
					b.ReportAllocs()
					for b.Loop() {
						var err error
						if scenario == "size_reject" {
							_, err = scanner.MatchingRulesInBlock(MemoryBlock{Data: data}, 30*1024*1024)
						} else {
							_, err = scanner.Scan(data)
						}
						if err != nil {
							b.Fatal(err)
						}
					}
				})
			}
		})
	}
}

// The unfused compiler remains the oracle for stack semantics, errors, and
// scanner results. Disable the derived header cache too for paired benchmarks.
func compileAssertionVariant(tb testing.TB, source string, fused bool) *CompiledProgram {
	tb.Helper()
	parsed, err := NewCompiler().compileParseWithContext(context.Background(), source)
	if err != nil {
		tb.Fatal(err)
	}
	generator := newRuleCompiler()
	generator.conditionCompiler.disableAssertions = !fused
	rules, err := generator.CompileProgram(parsed)
	if err != nil {
		tb.Fatal(err)
	}
	program := newCompiledProgram(rules)
	if err := program.Validate(); err != nil {
		tb.Fatal(err)
	}
	if !fused {
		program.sharedAssertions = nil
		for _, rule := range program.Rules {
			rule.headerCacheIndices = nil
		}
	}
	return program
}

func assertEquivalentAssertionScan(t *testing.T, pair [2]*CompiledProgram, data []byte) {
	t.Helper()
	for _, options := range [][]ScannerOption{nil, {WithFastScan()}, {WithoutMatches(), WithoutRuleResults()}, {WithReportedMatchesOnly()}} {
		var results [2]*ScanResult
		var failures [2]string
		for index, program := range pair {
			scanner := program.NewScanner(options...)
			result, err := scanner.Scan(data)
			scanner.Close()
			if err != nil {
				failures[index] = err.Error()
			}
			if result != nil {
				result.PrunedRules = nil
			}
			results[index] = result
		}
		if failures[0] != failures[1] || !reflect.DeepEqual(results[0], results[1]) {
			t.Fatalf("data %x: unfused=%#v (%s), fused=%#v (%s)", data, results[0], failures[0], results[1], failures[1])
		}
	}
	for index := range 2 {
		got, err := pair[index].MatchingRules(data)
		want, wantErr := pair[0].MatchingRules(data)
		if fmt.Sprint(err) != fmt.Sprint(wantErr) || !reflect.DeepEqual(got, want) {
			t.Fatalf("MatchingRules: %v/%v != %v/%v", got, err, want, wantErr)
		}
		matched, err := pair[index].Matches(data)
		wantMatch, wantErr := pair[0].Matches(data)
		if fmt.Sprint(err) != fmt.Sprint(wantErr) || matched != wantMatch {
			t.Fatalf("Matches: %v/%v != %v/%v", matched, err, wantMatch, wantErr)
		}
	}
}

func TestConditionAssertionsEquivalent(t *testing.T) {
	conditions := []string{
		`uint16(0) == 0x5a4d and $a`, `0x5a4d == uint16(0) and $a`,
		`uint32(2) == 0x04030201 and $a`, `uint32(0) == 0xffffffff and $a`,
		`(uint16(100) == 1 or $a) and filesize == 0`,
		`(uint32(0x7fffffffffffffff) == 1 or $a) and filesize == 0`,
		`uint16(-1) == 1 or $a`, `uint16(0) == -1 or $a`,
		`uint16(0) == 0x10000 or $a`, `uint16be(0) == 0x4d5a or $a`,
		`int16(0) == -1 or $a`, `uint16(filesize - 2) == 0x5a4d or $a`,
		`$a at 0`, `$a at 2`, `$a at -1`, `$a at 0x7fffffffffffffff`,
		`for any of them : ($ at 0 and # > 0)`,
		`filesize < 20MB and #a > 0 and $a at 0`,
		`(filesize == 0 or filesize > 4) and #a > 0`,
		`not (filesize == 0) and #a > 1`, `filesize < 2.5 and $a`,
		`filesize == 0 and (1 \ 0 == 0 or $a)`,
	}
	for _, op := range []string{"==", "!=", "<", "<=", ">", ">="} {
		for _, target := range []string{"filesize", "#a"} {
			conditions = append(conditions, target+" "+op+" 2 and $a", "2 "+op+" "+target+" and $a", target+" "+op+" -1 and $a", target+" "+op+" 0x7fffffffffffffff and $a")
		}
	}
	for _, condition := range conditions {
		t.Run(condition, func(t *testing.T) {
			source := `rule probe { strings: $a = "MZ" condition: ` + condition + ` }`
			pair := [2]*CompiledProgram{compileAssertionVariant(t, source, false), compileAssertionVariant(t, source, true)}
			for _, data := range [][]byte{nil, []byte("M"), []byte("MZ"), []byte("MZMZMZ"), []byte("xxMZ"), []byte("MZ\x01\x02\x03\x04"), {255, 255, 255, 255}} {
				assertEquivalentAssertionScan(t, pair, data)
			}
		})
	}
}

func TestSharedAssertionsResetAndIsolation(t *testing.T) {
	program := compileAssertionVariant(t, conditionAssertionRules(120), true)
	if len(program.sharedAssertions) != 3 {
		t.Fatalf("shared assertions=%d; want 3", len(program.sharedAssertions))
	}
	for worker := range 4 {
		t.Run(strconv.Itoa(worker), func(t *testing.T) {
			t.Parallel()
			scanner := program.NewScanner(WithReportedMatchesOnly())
			defer scanner.Close()
			for repeat := range 5 {
				for _, data := range [][]byte{[]byte("MZ\x01\x02\x03\x04"), []byte("none"), []byte("MZ\x01\x02\x03\x04"), nil} {
					result, err := scanner.Scan(data)
					if err != nil {
						t.Fatal(err)
					}
					want := 0
					if len(data) == 6 {
						want = 120
					}
					if len(result.MatchedRules) != want {
						t.Fatalf("repeat %d data %x matched %d, want %d", repeat, data, len(result.MatchedRules), want)
					}
				}
			}
		})
	}
}

func TestConditionAssertionsBlockOffsets(t *testing.T) {
	source := `rule r { strings: $a = "MZ" condition: uint16(100) == 0x5a4d and $a at 100 and #a == 1 and filesize == 102 }`
	for _, fused := range []bool{false, true} {
		program := compileAssertionVariant(t, source, fused)
		for _, options := range [][]ScannerOption{nil, {WithoutMatches(), WithoutRuleResults()}} {
			block := program.NewBlockScanner(options...)
			if err := block.Scan(100, []byte("MZ")); err != nil {
				t.Fatal(err)
			}
			result, err := block.Finish()
			block.Close()
			if err != nil || len(result.MatchedRules) != 1 {
				t.Fatalf("block result %v, %v", result, err)
			}
		}
		scanner := program.NewScanner()
		defer scanner.Close()
		for _, size := range []int64{102, 1 << 40, 102} {
			matched, err := scanner.MatchingRulesInBlock(MemoryBlock{Base: 100, Data: []byte("MZ")}, size)
			want := 0
			if size == 102 {
				want = 1
			}
			if err != nil || len(matched) != want {
				t.Fatalf("block size %d matched %v, %v", size, matched, err)
			}
		}
	}
}

func TestConditionAssertionsSerialization(t *testing.T) {
	for _, version := range []uint16{4, 5, 6, compiledProgramVersion} {
		source := conditionAssertionRules(2)
		if version == 5 || version == 6 {
			// A standalone string predicate retains the legacy stack-based fused form.
			source = strings.ReplaceAll(source, "$a at 0 }", "$a at 0 and $a }")
		}
		original := compileAssertionVariant(t, source, version != 4)
		if version < compiledProgramVersion && len(original.Rules[0].assertionProgram) != 0 {
			t.Fatal("legacy fixture contains a new assertion program")
		}
		encoded, err := original.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		binary.BigEndian.PutUint16(encoded[len(compiledProgramMagic):], version)
		loaded, err := UnmarshalCompiledProgram(encoded)
		if err != nil {
			t.Fatal(err)
		}
		reprepared := NewCompiledProgram(loaded.Rules)
		for _, program := range []*CompiledProgram{loaded, reprepared} {
			assertEquivalentAssertionScan(t, [2]*CompiledProgram{original, program}, []byte("MZ\x01\x02\x03\x04"))
		}
	}
}

func TestConditionAssertionsDoNotShareStrings(t *testing.T) {
	source := `rule a { strings: $a = "one" condition: #a == 1 and $a at 0 }
rule b { strings: $a = "two" condition: #a == 1 and $a at 0 }`
	pair := [2]*CompiledProgram{compileAssertionVariant(t, source, false), compileAssertionVariant(t, source, true)}
	if len(pair[1].sharedAssertions) != 0 {
		t.Fatal("rule-local string checks shared")
	}
	for _, data := range [][]byte{[]byte("one"), []byte("two"), []byte("one two"), nil} {
		assertEquivalentAssertionScan(t, pair, data)
	}
}

func TestConditionAssertionsMalformedOperands(t *testing.T) {
	for _, opcode := range []Opcode{OpAssertUint16Eq, OpAssertUint32Eq, OpAssertFilesize, OpAssertStringAt, OpAssertStringCount} {
		for _, operand := range [][]byte{nil, {0}, {0, 0, 0}, {255, 255, 255, 255}, {0, 0, 0, 0}} {
			interpreter := NewInterpreter(append([]byte{byte(opcode)}, operand...))
			interpreter.currentCompiledRule = &CompiledRule{assertions: []conditionAssertion{{Opcode: OpHalt}}}
			err := interpreter.Execute()
			var invalid *InterpreterError
			if !errors.As(err, &invalid) || invalid.Type != ErrorInvalidBytecode {
				t.Fatalf("opcode %v operand %x: %v", opcode, operand, err)
			}
		}
	}
}

func TestSharedAssertionsCacheHits(t *testing.T) {
	program := compileAssertionVariant(t, strings.ReplaceAll(conditionAssertionRules(120), " and $a at 0", ""), true)
	scanner := program.NewScanner()
	defer scanner.Close()
	ctx := &MatchContext{Data: []byte("MZ\x01\x02\x03\x04"), FileSize: 6}
	if !scanner.ruleConstraintsMatchContext(program.Rules[0], ctx, true) {
		t.Fatal("valid guards rejected")
	}
	for _, result := range scanner.assertionResults {
		if result != assertionTrue {
			t.Fatal("shared guard not evaluated")
		}
	}
	// Use a separate context with no readable bytes to prove the shared slots
	// supply the answers for every remaining rule without another input read.
	for _, rule := range program.Rules[1:] {
		ctx := &MatchContext{}
		ctx.FileSize = 1 << 40
		if !scanner.ruleConstraintsMatchContext(rule, ctx, true) {
			t.Fatal("shared guard recomputed")
		}
	}
	clear(scanner.assertionResults)
	if scanner.ruleConstraintsMatchContext(program.Rules[0], &MatchContext{}, true) {
		t.Fatal("reset cache retained a result")
	}
}

func FuzzConditionAssertionEquivalence(f *testing.F) {
	source := `rule first { strings: $a = "MZ" condition: (uint16(0) == 0xffff or $a) and filesize < 200 and #a <= 3 }
rule second { strings: $a = "MZ" condition: uint32(0) == 0xffffffff and filesize < 200 and $a at 4 }`
	pair := [2]*CompiledProgram{compileAssertionVariant(f, source, false), compileAssertionVariant(f, source, true)}
	for _, data := range [][]byte{nil, []byte("MZ"), []byte("MZMZ"), []byte("\xff\xff\xff\xffMZ")} {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1024 {
			t.Skip()
		}
		assertEquivalentAssertionScan(t, pair, data)
	})
}

func BenchmarkConditionDispatch(b *testing.B) {
	for _, fused := range []bool{false, true} {
		b.Run(fmt.Sprintf("fused=%t", fused), func(b *testing.B) {
			program := compileAssertionVariant(b, conditionAssertionRules(1), fused)
			scanner := program.NewScanner()
			defer scanner.Close()
			rule := program.Rules[0]
			_, err := scanner.Scan([]byte("MZ\x01\x02\x03\x04"))
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			for b.Loop() {
				scanner.prepareInterpreter(rule)
				if err := scanner.interp.Execute(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestConditionGuardsPreserveCallbacks(t *testing.T) {
	calls := 0
	module := Module{Name: "probe", Functions: map[string]ModuleFunction{
		"visit": {Signatures: []ModuleSignature{{}}, ReturnType: ModuleBoolean,
			Evaluate: func(ModuleContext, []ModuleValue) (ModuleValue, error) {
				calls++
				return BooleanValue(true), nil
			}},
	}}
	program, err := NewCompiler(WithModule(module)).CompileSource(`import "probe"
rule r { condition: filesize == 0 and probe.visit() }`)
	if err != nil {
		t.Fatal(err)
	}
	scanner := program.NewScanner(WithoutMatches(), WithoutRuleResults())
	defer scanner.Close()
	for repeat := range 2 {
		result, err := scanner.Scan([]byte("x"))
		if err != nil || len(result.MatchedRules) != 0 || calls != repeat+1 {
			t.Fatalf("scan %v, %v; callbacks=%d", result, err, calls)
		}
	}
}

func TestConditionGuardsBlockResultOptions(t *testing.T) {
	program := compileAssertionVariant(t, `rule size { strings: $a = "MZ" condition: filesize == 0 and $a }
rule header { condition: uint16(0) == 0x1234 }`, true)
	for _, omit := range []bool{false, true} {
		scanner := program.NewBlockScanner(WithoutRuleResults(), WithIncludeMatches(!omit))
		if err := scanner.Scan(0, []byte("MZ")); err != nil {
			t.Fatal(err)
		}
		result, err := scanner.Finish()
		scanner.Close()
		if err != nil || len(result.MatchedRules) != 0 || result.RuleResults != nil {
			t.Fatalf("result %v, %v", result, err)
		}
		if !omit && len(result.Matches["size"]["$a"]) != 1 {
			t.Fatal("filesize rejection hid requested matches")
		}
	}
}
