package compiler

import "testing"

func TestInterpreterPoolReset(t *testing.T) {
	program, err := NewCompiler().CompileSource(`rule loop { condition: for all i in (1..3) : (i > 0) }`)
	if err != nil {
		t.Fatal(err)
	}
	interp := NewInterpreter(nil)
	defer interp.Release()
	interp.SetCompiledRules(program.Rules)
	interp.SetCurrentRule("loop")
	interp.SetItersmax(1)
	if err := interp.Execute(); err == nil {
		t.Fatal("expected iteration limit")
	}
	borrowedResults := map[string]bool{"keep": true}
	borrowedContext := &MatchContext{Data: []byte("keep")}
	interp.SetRuleResults(borrowedResults)
	interp.SetMatchContext(borrowedContext)
	interp.PreserveRuleResults = true
	interp.stringArena = []string{"retained"}
	interp.iterators = []Iterator{{TextStrings: []string{"retained"}}}
	interp.stringArena = interp.stringArena[:0]
	interp.iterators = interp.iterators[:0]
	interp.regexCache["retained"] = compiledRegex{code: []byte{1}}

	// Exercise the release invariant directly; sync.Pool reuse is not guaranteed.
	interp.resetForPool()
	if interp.currentCompiledRule != nil || interp.ruleMap != nil || interp.matchContext != nil ||
		interp.ruleResults != nil || interp.PreserveRuleResults || len(interp.regexCache) != 0 {
		t.Fatal("interpreter retained execution state")
	}
	if interp.stringArena[:1][0] != "" || interp.iterators[:1][0].TextStrings != nil {
		t.Fatal("scratch storage retained references")
	}
	if !borrowedResults["keep"] || string(borrowedContext.Data) != "keep" {
		t.Fatal("reset modified borrowed state")
	}
	interp.SetCompiledRules(program.Rules)
	interp.SetCurrentRule("loop")
	if err := interp.Execute(); err != nil {
		t.Fatalf("fresh execution inherited state: %v", err)
	}
	if !interp.GetRuleResults()["loop"] {
		t.Fatal("fresh execution did not match")
	}
}

func TestBlockScannerLifecycle(t *testing.T) {
	program, err := NewCompiler().CompileSource(`rule test { strings: $a = "data" condition: $a }`)
	if err != nil {
		t.Fatal(err)
	}
	scanner := program.NewBlockScanner()
	defer scanner.Close()
	for range 2 {
		if err := scanner.Scan(0, []byte("data")); err != nil {
			t.Fatal(err)
		}
		result, err := scanner.Finish()
		if err != nil || len(result.MatchedRules) != 1 {
			t.Fatalf("Finish() = %v, %v", result, err)
		}
		scanner.Reset()
		if len(scanner.matches) != 0 || scanner.blocks[:cap(scanner.blocks)][0].Data != nil ||
			scanner.scanner.matchCtx.Data != nil || scanner.scanner.matchCtx.Blocks != nil {
			t.Fatal("Reset retained input or matches")
		}
	}
	if err := scanner.Scan(0, []byte("data")); err != nil {
		t.Fatal(err)
	}
	scanner.Close()
	if scanner.blocks != nil || scanner.matches != nil || scanner.program != nil {
		t.Fatal("Close retained scan state")
	}
	if err := scanner.Scan(0, nil); err == nil {
		t.Fatal("closed block scanner accepted input")
	}
}

func TestScannerClose(t *testing.T) {
	program, err := NewCompiler().CompileSource(`rule test { condition: true }`)
	if err != nil {
		t.Fatal(err)
	}
	scanner := program.NewScanner()
	scanner.Close()
	scanner.Close()
	if matched, err := scanner.Matches(nil); err != nil || matched {
		t.Fatalf("closed scanner Matches() = %v, %v", matched, err)
	}
	if scanner.program != nil || scanner.interp != nil || scanner.matchCtx != nil {
		t.Fatal("Close retained scan resources")
	}
}

func TestMatchContextPoolReset(t *testing.T) {
	ctx := &MatchContext{Data: []byte("data"), maxMatchesPerPattern: 1}
	ctx.AddMatch(Match{Pattern: "$a", MatchedData: ctx.Data})
	ctx.Reset(nil)
	ctx.AddMatch(Match{Pattern: "$b", MatchedData: []byte("other")})
	ctx.AddMatch(Match{Pattern: "$c", Length: 1})
	ctx.Reset(nil)
	ctx.AddMatch(Match{Pattern: "$d", Length: 1})
	ctx.resetForPool()
	if len(ctx.Matches)+len(ctx.spans)+len(ctx.spanBuffers) != 0 ||
		ctx.Data != nil || ctx.maxMatchesPerPattern != 0 {
		t.Fatal("match context retained previous scan state")
	}
}

func TestStandaloneRuntimeRelease(t *testing.T) {
	program, err := NewCompiler().CompileSource(`rule greeting { strings: $a = "hello" condition: $a }`)
	if err != nil {
		t.Fatal(err)
	}
	rule := program.Rules[0]
	const input = "hello"
	firstCtx := BuildMatchContext(rule, []byte(input))
	firstInterp := NewInterpreter(rule.Bytecode)
	firstCtx.Release()
	firstInterp.Release()

	ctx := BuildMatchContext(rule, []byte(input))
	t.Cleanup(ctx.Release)
	secondCtx := BuildMatchContext(rule, []byte("other"))
	t.Cleanup(secondCtx.Release)
	interp := NewInterpreter(rule.Bytecode)
	t.Cleanup(interp.Release)
	secondInterp := NewInterpreter(rule.Bytecode)
	t.Cleanup(secondInterp.Release)
	interp.SetCompiledRules(program.Rules)
	interp.SetCurrentRule(rule.Name)
	interp.SetMatchContext(ctx)
	firstCtx.Release()
	firstInterp.Release()

	if ctx == secondCtx || string(ctx.Data) != input || len(ctx.Matches["$a"]) != 1 || len(secondCtx.Matches) != 0 {
		t.Fatal("standalone match contexts lost independent results")
	}
	if interp == secondInterp {
		t.Fatal("standalone interpreters have the same identity")
	}
	if err := interp.Execute(); err != nil || !interp.GetRuleResults()[rule.Name] {
		t.Fatalf("standalone interpreter lost its prepared state: %v", err)
	}
}

func TestInterpreterReleaseOfValueCopy(t *testing.T) {
	for _, setup := range []struct {
		name string
		new  func() *Interpreter
	}{
		{"constructor", func() *Interpreter { return NewInterpreter(nil) }},
		{"zero value", func() *Interpreter { return &Interpreter{} }},
	} {
		t.Run(setup.name, func(t *testing.T) {
			const slot = 2
			owner := setup.new()
			defer owner.Release()
			owner.SetMemoryString(slot, "owner")
			copyBeforeRelease, copyAfterRelease := *owner, *owner
			copyBeforeRelease.Release()
			if value := owner.GetMemoryAt(slot); owner.GetString(value) != "owner" {
				t.Fatal("releasing a value copy changed the owner's memory")
			}
			owner.Release()

			next := NewInterpreter(nil)
			defer next.Release()
			next.SetMemoryString(slot, "next")
			copyAfterRelease.Release()
			if value := next.GetMemoryAt(slot); next.GetString(value) != "next" {
				t.Fatal("releasing a value copy changed a later owner's memory")
			}
		})
	}
}

func TestMatchContextReleaseOfValueCopy(t *testing.T) {
	program, err := NewCompiler().CompileSource(`rule greeting { strings: $a = /h[a-z]+o/ condition: $a }`)
	if err != nil {
		t.Fatal(err)
	}
	rule := program.Rules[0]
	assertMatch := func(ctx *MatchContext, offset int64) {
		t.Helper()
		if got := ctx.Matches["$a"]; len(got) != 1 || got[0].Offset != offset || got[0].Length != 5 {
			t.Fatalf("matches = %v, want one five-byte match at %d", got, offset)
		}
	}
	owner := &MatchContext{}
	defer owner.Release()
	PopulateMatchContext(owner, rule, []byte("hello"))
	copyBeforeRelease, copyAfterRelease := *owner, *owner
	copyBeforeRelease.Release()
	assertMatch(owner, 0)
	PopulateMatchContext(owner, rule, []byte(" hello"))
	assertMatch(owner, 1)
	owner.Release()

	next := BuildMatchContext(rule, []byte("  hello"))
	defer next.Release()
	copyAfterRelease.Release()
	assertMatch(next, 2)
	PopulateMatchContext(next, rule, []byte("   hello"))
	assertMatch(next, 3)
}

func TestScannerMemoryScope(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
external lower
rule loop { condition: for all j in (1..3) : (j >= lower) }
rule next { condition: loop }
`)
	if err != nil {
		t.Fatal(err)
	}
	scanner := program.NewScanner(WithExternalVariables(map[string]any{"lower": 1}))
	defer scanner.Close()
	assertClean := func() {
		t.Helper()
		for slot, value := range scanner.interp.GetMemory() {
			if value != (Value{Type: ValueTypeUndefined}) {
				t.Fatalf("memory slot %d retained %+v", slot, value)
			}
		}
	}
	scanner.prepareInterpreter(program.Rules[0])
	if got := scanner.interp.GetMemoryAt(program.Rules[0].ExternalSlots["lower"]); got.Type != ValueTypeInt || got.IntVal != 1 {
		t.Fatalf("external slot = %+v, want 1", got)
	}
	const scratchSlot = interpreterMemorySlotCount - 2
	scanner.interp.SetMemoryString(scratchSlot, "scratch")
	scanner.prepareInterpreter(program.Rules[1])
	if got := scanner.interp.GetMemoryAt(scratchSlot); got.Type != ValueTypeUndefined {
		t.Fatalf("scratch slot = %+v, want undefined", got)
	}
	for range 2 {
		matches, err := scanner.MatchingRules(nil)
		if err != nil || len(matches) != 2 {
			t.Fatalf("MatchingRules = (%+v, %v), want loop and next", matches, err)
		}
		assertClean()
	}
}
