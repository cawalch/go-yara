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
	interp.debugMode = true
	interp.stringArena = []string{"retained"}
	interp.iterators = []Iterator{{TextStrings: []string{"retained"}}}
	interp.stringArena = interp.stringArena[:0]
	interp.iterators = interp.iterators[:0]
	interp.regexCache["retained"] = compiledRegex{code: []byte{1}}

	// Exercise the release invariant directly; sync.Pool reuse is not guaranteed.
	interp.resetForPool()
	if interp.currentCompiledRule != nil || interp.ruleMap != nil || interp.matchContext != nil ||
		interp.ruleResults != nil || interp.PreserveRuleResults || interp.debugMode || len(interp.regexCache) != 0 {
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
	ctx.compact = true
	ctx.AddMatch(Match{Pattern: "$c", Length: 1})
	ctx.Reset(nil)
	ctx.AddMatch(Match{Pattern: "$d", Length: 1})
	ctx.resetForPool()
	if len(ctx.Matches)+len(ctx.matchBuffers)+len(ctx.spans)+len(ctx.spanBuffers) != 0 ||
		ctx.Data != nil || ctx.compact || ctx.maxMatchesPerPattern != 0 {
		t.Fatal("match context retained previous scan state")
	}
}
