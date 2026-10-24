package compiler

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestAssertionProgramStackFree(t *testing.T) {
	program := compileAssertionVariant(t, `rule r { strings:$a="MZ" condition: uint16(0)==0x5a4d and (filesize<100 or #a>1) and not ($a at 2) }`, true)
	scanner := program.NewScanner()
	defer scanner.Close()
	rule := program.Rules[0]
	if len(rule.assertionProgram) == 0 {
		t.Fatal("no assertion program")
	}
	if _, err := scanner.Scan([]byte("MZ")); err != nil {
		t.Fatal(err)
	}
	scanner.interp.stack = nil
	scanner.prepareInterpreter(rule)
	if err := scanner.interp.Execute(); err != nil {
		t.Fatal(err)
	}
	if len(scanner.interp.stack) != 0 || cap(scanner.interp.stack) != 0 {
		t.Fatal("operand stack touched")
	}
	if !scanner.interp.ruleResultByIndex(0, "r") {
		t.Fatal("condition result lost")
	}
	if got := scanner.interp.GetStack(); len(got) != 1 || got[0].IntVal != 1 {
		t.Fatalf("debug result: %v", got)
	}
	if allocs := testing.AllocsPerRun(100, func() {
		scanner.prepareInterpreter(rule)
		if err := scanner.interp.Execute(); err != nil {
			panic(err)
		}
	}); allocs != 0 {
		t.Fatalf("allocations=%g", allocs)
	}
}

func TestExternalAssertionsEquivalent(t *testing.T) {
	for _, condition := range []string{
		`gate==1`, `filesize<0 and gate==1`, `gate>0 and filesize<10`, `1<gate or filesize==0`,
		`not (gate==1)`, `not (gate==1 or filesize>0)`,
		`gate=="yes" and filesize<10`, `"yes"!=gate or filesize==0`,
		`gate==1 and uint16(99)==0`, `gate==1 and (1 \ 0 == 0)`,
		`gate==1 and math.abs(-1)==1`,
	} {
		t.Run(condition, func(t *testing.T) {
			// The same compiler with assertion lowering disabled is the reference.
			source := `import "math" external gate rule r {condition:` + condition + `}`
			c := NewCompiler()
			parsed, err := c.compileParseWithContext(context.Background(), source)
			if err != nil {
				t.Fatal(err)
			}
			var programs [2]*CompiledProgram
			for index := range programs {
				generator, err := newRuleCompilerWithModules(defaultModules())
				if err != nil {
					t.Fatal(err)
				}
				generator.conditionCompiler.disableAssertions = index == 0
				rules, err := generator.CompileProgram(parsed)
				if err != nil {
					t.Fatal(err)
				}
				programs[index] = newCompiledProgram(rules)
			}
			for _, value := range []any{nil, false, true, 0, 1, 2, "yes", "no", 1.5} {
				values := map[string]any{}
				if value != nil {
					values["gate"] = value
				}
				var results [2]*ScanResult
				var failures [2]string
				for index, program := range programs {
					scanner := program.NewScanner(WithExternalVariables(values))
					results[index], err = scanner.Scan([]byte("x"))
					scanner.Close()
					if err != nil {
						failures[index] = err.Error()
					}
				}
				if failures[0] != failures[1] || !reflect.DeepEqual(results[0], results[1]) {
					t.Fatalf("value=%v reference=%+v/%s optimized=%+v/%s", value, results[0], failures[0], results[1], failures[1])
				}
			}
		})
	}
}

func TestSharedExternalGuards(t *testing.T) {
	var source strings.Builder
	source.WriteString(`external gate `)
	for index := 0; index < 120; index++ {
		fmt.Fprintf(&source, `rule r%d {condition: gate==1 and filesize<10} `, index)
	}
	program, err := NewCompiler().CompileSourceWithContext(context.Background(), source.String())
	if err != nil {
		t.Fatal(err)
	}
	if len(program.sharedAssertions) != 2 {
		t.Fatalf("shared predicates=%d", len(program.sharedAssertions))
	}
	encoded, err := program.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := UnmarshalCompiledProgram(encoded)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []*CompiledProgram{program, loaded} {
		scanner := p.NewScanner(WithoutMatches(), WithoutRuleResults())
		defer scanner.Close()
		for _, gate := range []int{1, 0, 1} {
			if err := scanner.SetExternalVariables(map[string]any{"gate": gate}); err != nil {
				t.Fatal(err)
			}
			result, err := scanner.Scan([]byte("x"))
			if err != nil {
				t.Fatal(err)
			}
			want := 0
			if gate == 1 {
				want = 120
			}
			if len(result.MatchedRules) != want {
				t.Fatalf("gate=%d matches=%d", gate, len(result.MatchedRules))
			}
			names, err := scanner.MatchingRulesInBlock(MemoryBlock{Base: 2, Data: []byte("x")}, 3)
			if err != nil || len(names) != want {
				t.Fatalf("block gate=%d matches=%d err=%v", gate, len(names), err)
			}
		}
	}
}

func TestAssertionProgramMalformed(t *testing.T) {
	for _, nodes := range [][]assertionInstruction{
		{{Op: OpAnd, Left: 0, Right: 0}},
		{{Op: OpNot, Left: -1}},
		{{Op: OpAssertFilesize, Assertion: 99}},
	} {
		rule := &CompiledRule{Bytecode: []byte{byte(OpEvalAssertions)}, assertionProgram: nodes}
		if err := rule.Validate(); err == nil {
			t.Fatal("invalid registers accepted")
		}
		interpreter := NewInterpreter(rule.Bytecode)
		interpreter.currentCompiledRule = rule
		if err := interpreter.Execute(); err == nil {
			t.Fatal("malformed program executed")
		}
	}
}

func TestExternalGuardsRejectBeforeInterpretation(t *testing.T) {
	program, err := NewCompiler().CompileSourceWithContext(context.Background(), `external gate rule r {condition:gate==1 and filesize<10}`)
	if err != nil {
		t.Fatal(err)
	}
	scanner := program.NewScanner(WithoutMatches(), WithoutRuleResults(), WithExternalVariables(map[string]any{"gate": 0}))
	defer scanner.Close()
	// An invalid instruction proves the rejection did not enter the interpreter.
	program.Rules[0].Bytecode = []byte{byte(OpAssertFilesize)}
	if _, err := scanner.Scan([]byte("x")); err != nil {
		t.Fatalf("false guard reached bytecode: %v", err)
	}
	if err := scanner.SetExternalVariables(map[string]any{"gate": 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := scanner.Scan([]byte("x")); err == nil {
		t.Fatal("true guard did not enter bytecode")
	}
}

func TestExternalGuardsPreserveCallbacks(t *testing.T) {
	calls := 0
	module := Module{Name: "probe", Functions: map[string]ModuleFunction{"visit": {
		Signatures: []ModuleSignature{{}}, ReturnType: ModuleBoolean,
		Evaluate: func(ModuleContext, []ModuleValue) (ModuleValue, error) { calls++; return BooleanValue(true), nil },
	}}}
	program, err := NewCompiler(WithModule(module)).CompileSourceWithContext(context.Background(), `import "probe" external gate rule r {condition:gate==1 and probe.visit()}`)
	if err != nil {
		t.Fatal(err)
	}
	scanner := program.NewScanner(WithoutMatches(), WithExternalVariables(map[string]any{"gate": 0}))
	defer scanner.Close()
	if yes, err := scanner.Matches(nil); err != nil || yes || calls != 1 {
		t.Fatalf("callback changed: match=%t err=%v calls=%d", yes, err, calls)
	}
}

func TestExternalGuardCacheScope(t *testing.T) {
	program, err := NewCompiler().CompileSourceWithContext(context.Background(), `external gate rule r {condition:gate==1}`)
	if err != nil {
		t.Fatal(err)
	}
	scanner := program.NewScanner(WithExternalVariables(map[string]any{"gate": 1}))
	defer scanner.Close()
	ctx := &MatchContext{assertionResults: scanner.assertionResults, externalValues: scanner.externalValues}
	assertion := &program.sharedAssertions[0]
	for range 120 {
		if got := cachedInputAssertion(assertion, ctx, 0); got != assertionTrue {
			t.Fatal(got)
		}
	}
	ctx.externalValues = map[string]externalValue{"gate": {valueType: ValueTypeInt, intVal: 0}}
	if got := cachedInputAssertion(assertion, ctx, 0); got != assertionTrue {
		t.Fatal("shared result was recomputed")
	}
	clear(ctx.assertionResults)
	if got := cachedInputAssertion(assertion, ctx, 0); got != assertionFalse {
		t.Fatal("next scan retained old result")
	}
}

func FuzzExternalAssertionEquivalence(f *testing.F) {
	source := `external gate rule r {strings:$a="MZ" condition: (gate>3 and #a>0) or not (gate==0 or filesize>12)}`
	var pair [2]*CompiledProgram
	for index := range pair {
		parsed, err := NewCompiler().compileParseWithContext(context.Background(), source)
		if err != nil {
			f.Fatal(err)
		}
		generator := newRuleCompiler()
		generator.conditionCompiler.disableAssertions = index == 0
		rules, err := generator.CompileProgram(parsed)
		if err != nil {
			f.Fatal(err)
		}
		pair[index] = newCompiledProgram(rules)
	}
	f.Add([]byte("MZ"), int64(4))
	f.Add([]byte("x"), int64(-1))
	f.Fuzz(func(t *testing.T, data []byte, gate int64) {
		if len(data) > 1024 {
			t.Skip()
		}
		for _, p := range pair {
			if err := p.SetExternalVariables(map[string]any{"gate": gate}); err != nil {
				t.Fatal(err)
			}
		}
		assertEquivalentAssertionScan(t, pair, data)
	})
}

func TestExternalGuardPreservesMatches(t *testing.T) {
	program, err := NewCompiler().CompileSourceWithContext(context.Background(), `external gate rule r {strings:$a="MZ" condition:gate==1 and #a>0}`)
	if err != nil {
		t.Fatal(err)
	}
	scanner := program.NewScanner(WithExternalVariables(map[string]any{"gate": 0}))
	defer scanner.Close()
	result, err := scanner.Scan([]byte("MZ"))
	if err != nil || result == nil {
		t.Fatal(err)
	}
	if len(result.MatchedRules) != 0 || len(result.Matches["r"]["$a"]) != 1 {
		t.Fatalf("default match reporting changed: %+v", result)
	}
}
