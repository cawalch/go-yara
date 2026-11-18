package compiler

import (
	"bytes"
	"context"
	"reflect"
	"slices"
	"sync"
	"testing"

	"github.com/cawalch/go-yara/regex"
)

// deferredPatternSet covers the trie-construction branches whose replay must
// stay faithful between eager and deferred materialization: shared prefixes,
// duplicate patterns, a pattern that is a proper prefix of another (terminal
// state with continuation), nocase dual transitions shared with a
// case-sensitive string, an inner-suffix failure output, an empty pattern,
// and a standalone literal.
var deferredPatternSet = []struct {
	id    string
	data  string
	flags regex.Flags
}{
	{"$a", "hello", 0},
	{"$b", "hello", 0}, // duplicate terminal output
	{"$c", "he", 0},    // proper prefix of $a: terminal state with continuation
	{"$d", "world", regex.FlagsNoCase},
	{"$e", "wo", 0}, // shares prefix bytes with the nocase $d
	{"$f", "ll", 0}, // inner suffix of $a via failure links
	{"$g", "", 0},   // empty pattern: output on the root state
	{"$h", "xyz", 0},
}

func buildEagerAutomaton(tb testing.TB) *acAutomaton {
	tb.Helper()
	ac := newacAutomaton()
	for _, p := range deferredPatternSet {
		if err := ac.AddStringWithFlags(p.id, []byte(p.data), false, false, p.flags); err != nil {
			tb.Fatalf("AddStringWithFlags(%q): %v", p.id, err)
		}
	}
	if err := ac.Compile(); err != nil {
		tb.Fatalf("eager Compile(): %v", err)
	}
	return ac
}

func buildUncompiledDeferredAutomaton(tb testing.TB) *acAutomaton {
	tb.Helper()
	ac := newDeferredAutomaton(len(deferredPatternSet))
	for _, p := range deferredPatternSet {
		if err := ac.AddStringWithFlags(p.id, []byte(p.data), false, false, p.flags); err != nil {
			tb.Fatalf("AddStringWithFlags(%q): %v", p.id, err)
		}
	}
	return ac
}

var deferredScanInputs = [][]byte{
	{},
	[]byte("no hits here"),
	bytes.Repeat([]byte("l"), 32),
	[]byte("hello world"),
	[]byte("HEllO WORld wo he ll xyz"),
	bytes.Repeat([]byte("x"), 512),
	[]byte("hell"),
}

// TestDeferredAutomatonMatchesEagerConstruction pins lazy materialization to
// the eager build: identical flat tables, output ranges, root lanes, and match
// output across both scan entry points.
func TestDeferredAutomatonMatchesEagerConstruction(t *testing.T) {
	eager := buildEagerAutomaton(t)
	deferred := buildUncompiledDeferredAutomaton(t)

	if err := deferred.Compile(); err != nil {
		t.Fatalf("deferred Compile(): %v", err)
	}

	if !reflect.DeepEqual(eager.outputs, deferred.outputs) {
		t.Fatalf("outputs diverge:\neager:   %v\ndeferred: %v", eager.outputs, deferred.outputs)
	}
	if !reflect.DeepEqual(eager.transitions16, deferred.transitions16) {
		t.Fatal("16-bit transition tables diverge")
	}
	if !reflect.DeepEqual(eager.outputRanges, deferred.outputRanges) {
		t.Fatal("output ranges diverge")
	}
	if !reflect.DeepEqual(eager.hasOutput, deferred.hasOutput) {
		t.Fatal("hasOutput flags diverge")
	}
	if !reflect.DeepEqual(eager.rootLanes, deferred.rootLanes) {
		t.Fatal("root lanes diverge")
	}
	if eager.states != nil || deferred.states != nil {
		t.Fatal("Compile retained construction states")
	}
	if deferred.GetStateCount() != eager.GetStateCount() {
		t.Fatalf("state counts diverge: %d vs %d", deferred.GetStateCount(), eager.GetStateCount())
	}
	if (deferred.teddy == nil) != (eager.teddy == nil) {
		t.Fatal("teddy prefilter presence diverges")
	}

	for _, data := range deferredScanInputs {
		want := slices.Collect(eager.SearchIter(data))
		got := slices.Collect(deferred.SearchIter(data))
		if !slices.Equal(got, want) {
			t.Fatalf("SearchIter(%q) diverge:\ngot:  %+v\nwant: %+v", data, got, want)
		}
		gotCancel := collectSearchWithCancel(t, deferred, data)
		if !slices.Equal(gotCancel, want) {
			t.Fatalf("SearchWithCancel(%q) diverge:\ngot:  %+v\nwant: %+v", data, gotCancel, want)
		}
	}

	// A deferred clone must stay usable for searching without rebuilding.
	clone := deferred.Clone()
	if !slices.Equal(slices.Collect(clone.SearchIter([]byte("hello"))), slices.Collect(eager.SearchIter([]byte("hello")))) {
		t.Fatal("deferred Clone() diverges from eager matches")
	}
}

// TestDeferredAutomatonSearchBuildsLazily verifies the scan-time path: an
// unbuilt deferred automaton materializes on the first Search and reports no
// pattern metadata side effects in the meantime.
func TestDeferredAutomatonSearchBuildsLazily(t *testing.T) {
	deferred := buildUncompiledDeferredAutomaton(t)

	if deferred.compiled {
		t.Fatal("deferred automaton compiled before first search")
	}
	if deferred.states != nil {
		t.Fatal("deferred automaton allocated trie states before first search")
	}
	if len(deferred.strings) != len(deferredPatternSet) {
		t.Fatalf("deferred metadata strings = %d, want %d", len(deferred.strings), len(deferredPatternSet))
	}
	if err := deferred.Validate(); err != nil {
		t.Fatalf("unbuilt deferred automaton invalid: %v", err)
	}
	if got := deferred.GetStateCount(); got == 0 {
		t.Fatal("unbuilt deferred automaton reports no state estimate")
	}

	data := []byte("hello world")
	want := slices.Collect(buildEagerAutomaton(t).SearchIter(data))
	got := slices.Collect(deferred.SearchIter(data))
	if !slices.Equal(got, want) {
		t.Fatalf("first search diverges:\ngot:  %+v\nwant: %+v", got, want)
	}
	if !deferred.compiled || deferred.states != nil {
		t.Fatal("first search did not materialize and release the trie")
	}

	// Repeated searches reuse the built tables.
	got = slices.Collect(deferred.SearchIter(data))
	if !slices.Equal(got, want) {
		t.Fatal("second search diverges")
	}
}

// TestDeferredAutomatonCompileIsIdempotent checks that an explicit Compile
// after a search-triggered build neither rebuilds nor errors.
func TestDeferredAutomatonCompileIsIdempotent(t *testing.T) {
	deferred := buildUncompiledDeferredAutomaton(t)
	if err := deferred.Compile(); err != nil {
		t.Fatalf("first Compile(): %v", err)
	}
	first := slices.Collect(deferred.SearchIter([]byte("xyz")))
	if err := deferred.Compile(); err != nil {
		t.Fatalf("second Compile(): %v", err)
	}
	second := slices.Collect(deferred.SearchIter([]byte("xyz")))
	if !slices.Equal(first, second) {
		t.Fatal("second Compile() changed matches")
	}
}

// TestDeferredAutomatonConcurrentBuild races concurrent scanners against the
// first local search; the sync.Once build must be executed exactly once and
// every observer must see the same matches.
func TestDeferredAutomatonConcurrentBuild(t *testing.T) {
	deferred := buildUncompiledDeferredAutomaton(t)
	eager := buildEagerAutomaton(t)
	data := []byte("HEllO WORld wo he ll xyz")
	want := slices.Collect(eager.SearchIter(data))
	if len(want) == 0 {
		t.Fatal("control automaton produced no matches")
	}

	const workers = 8
	results := make([][]acMatch, workers)
	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = slices.Collect(deferred.SearchIter(data))
		}()
	}
	wg.Wait()

	for i, got := range results {
		if !slices.Equal(got, want) {
			t.Fatalf("worker %d diverges:\ngot:  %+v\nwant: %+v", i, got, want)
		}
	}
	if !deferred.compiled {
		t.Fatal("concurrent searches left the automaton unbuilt")
	}
}

// TestDeferredAutomatonResetKeepsDeferring resets a built deferred automaton
// and reuses it for a fresh pattern set.
func TestDeferredAutomatonResetKeepsDeferring(t *testing.T) {
	deferred := buildUncompiledDeferredAutomaton(t)
	if err := deferred.Compile(); err != nil {
		t.Fatalf("Compile(): %v", err)
	}
	deferred.Reset()
	if !deferred.deferred || deferred.compiled || deferred.states != nil {
		t.Fatal("Reset() dropped deferred construction mode")
	}
	if deferred.GetStateCount() != 1 {
		t.Fatalf("GetStateCount() after Reset = %d, want 1", deferred.GetStateCount())
	}
	if err := deferred.AddStringWithFlags("$solo", []byte("solo"), false, false, 0); err != nil {
		t.Fatalf("AddString after Reset: %v", err)
	}
	got := slices.Collect(deferred.SearchIter([]byte("xx solo xx")))
	if len(got) != 1 || got[0].StringID != "$solo" {
		t.Fatalf("post-reset search = %+v, want one $solo match", got)
	}
}

// TestCompileReleasesConstructionStates pins the retained-memory contract:
// after Compile the 1 KiB-per-state construction rows are gone, every scan
// structure survives, and the memory estimate halves.
func TestCompileReleasesConstructionStates(t *testing.T) {
	ac := newacAutomaton()
	for _, p := range deferredPatternSet {
		if err := ac.AddStringWithFlags(p.id, []byte(p.data), false, false, p.flags); err != nil {
			t.Fatalf("AddStringWithFlags(%q): %v", p.id, err)
		}
	}
	stateCount := ac.GetStateCount()
	if stateCount < 9 {
		t.Fatalf("test pattern set built only %d states", stateCount)
	}
	preCompile := ac.EstimateMemoryUsage()

	if err := ac.Compile(); err != nil {
		t.Fatalf("Compile(): %v", err)
	}
	if ac.states != nil {
		t.Fatal("Compile retained construction states")
	}
	if ac.GetStateCount() != stateCount {
		t.Fatalf("GetStateCount() = %d, want %d", ac.GetStateCount(), stateCount)
	}
	if len(ac.transitions16) != stateCount || len(ac.outputRanges) != stateCount || len(ac.hasOutput) != stateCount {
		t.Fatalf(
			"retained structures disagree with state count: tables=%d ranges=%d flags=%d, want %d",
			len(ac.transitions16), len(ac.outputRanges), len(ac.hasOutput), stateCount,
		)
	}
	if err := ac.Validate(); err != nil {
		t.Fatalf("released automaton invalid: %v", err)
	}
	postCompile := ac.EstimateMemoryUsage()
	if postCompile >= preCompile {
		t.Fatalf("estimate did not drop across release: %d -> %d", preCompile, postCompile)
	}
	// 16-bit rows retain 512 B/state plus 8 B output ranges and 1 B flags;
	// the released construction rows cost 1,036 B/state.
	if postCompile*100 >= preCompile*55 {
		t.Fatalf("retained estimate %d not below 55%% of %d", postCompile, preCompile)
	}
}

// TestRootDensityHelpersAcrossWidths drives rootIsDense/rootIsDense16
// through every retained table layout.
func TestRootDensityHelpersAcrossWidths(t *testing.T) {
	dense := bytes.Repeat([]byte("a"), 64)
	sparse := []byte("zzzz")
	ac := &acAutomaton{
		transitions16: []([256]uint16){{}},
	}
	ac.transitions16[0]['a'] = 1
	if !ac.rootIsDense16(dense) || !ac.rootIsDense(dense) {
		t.Fatal("16-bit root row reported sparse for dense input")
	}
	if ac.rootIsDense16(sparse) || ac.rootIsDense(sparse) {
		t.Fatal("16-bit root row reported dense for sparse input")
	}

	wide := &acAutomaton{
		transitions32: []([256]int32){{}},
	}
	wide.transitions32[0]['a'] = 1
	if !wide.rootIsDense(dense) {
		t.Fatal("32-bit root row reported sparse for dense input")
	}
	if wide.rootIsDense(sparse) {
		t.Fatal("32-bit root row reported dense for sparse input")
	}

	raw := &acAutomaton{states: []acState{{}}}
	raw.states[0].transitions['a'] = 1
	if !raw.rootIsDense(dense) || raw.rootIsDense(sparse) {
		t.Fatal("construction-state root row not honored")
	}

	empty := &acAutomaton{}
	if empty.rootIsDense(dense) || empty.rootIsDense16(dense) {
		t.Fatal("empty automaton reported a dense root")
	}
}

const deferredProgramSource = `
rule deferred_text {
	strings:
		$needle = "NEEDLE_TOKEN"
		$alt = "FALLBACK_TOKEN"
	condition:
		any of them
}
`

// TestPerRuleAutomatonStaysDeferredUntilLocalScan proves the compile and
// shared-scan paths never materialize per-rule tables; only a local
// match-context search does.
func TestPerRuleAutomatonStaysDeferredUntilLocalScan(t *testing.T) {
	program, err := NewCompiler().CompileSource(deferredProgramSource)
	if err != nil {
		t.Fatalf("CompileSource(): %v", err)
	}
	rule, ok := program.GetRuleByName("deferred_text")
	if !ok {
		t.Fatal("rule not found")
	}
	if rule.automaton == nil {
		t.Fatal("text rule has no automaton")
	}
	if rule.automaton.compiled || rule.automaton.states != nil {
		t.Fatal("CompileSource eagerly built the per-rule automaton")
	}

	data := []byte("xx NEEDLE_TOKEN yy")
	result, err := program.Scan(data)
	if err != nil {
		t.Fatalf("Scan(): %v", err)
	}
	if !result.RuleResults["deferred_text"] {
		t.Fatal("scan did not match")
	}
	if rule.automaton.compiled {
		t.Fatal("shared-automaton scan built the per-rule automaton")
	}

	ctx := BuildMatchContext(rule, data)
	matches := ctx.Matches["$needle"]
	if len(matches) != 1 || matches[0].Offset != 3 {
		t.Fatalf("local match context = %+v, want one $needle at offset 3", matches)
	}
	if !rule.automaton.compiled || rule.automaton.states != nil {
		t.Fatal("local match-context search did not build the per-rule automaton")
	}
}

// TestUnmarshalDefersRuleAutomatons pins the deserialization contract: a
// loaded program carries deferred per-rule automatons that scan identically
// and build only on local searches.
func TestUnmarshalDefersRuleAutomatons(t *testing.T) {
	compiled, err := NewCompiler().CompileSource(deferredProgramSource)
	if err != nil {
		t.Fatalf("CompileSource(): %v", err)
	}
	marshaled, err := compiled.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(): %v", err)
	}
	loaded, err := UnmarshalCompiledProgram(marshaled)
	if err != nil {
		t.Fatalf("UnmarshalCompiledProgram(): %v", err)
	}
	rule, ok := loaded.GetRuleByName("deferred_text")
	if !ok || rule.automaton == nil {
		t.Fatal("loaded rule or automaton missing")
	}
	if rule.automaton.compiled || rule.automaton.states != nil {
		t.Fatal("UnmarshalCompiledProgram eagerly built per-rule transition tables")
	}

	data := []byte("yy FALLBACK_TOKEN xx")
	loadedResult, err := loaded.Scan(data)
	if err != nil {
		t.Fatalf("loaded Scan(): %v", err)
	}
	compiledResult, err := compiled.Scan(data)
	if err != nil {
		t.Fatalf("compiled Scan(): %v", err)
	}
	if !loadedResult.RuleResults["deferred_text"] || !compiledResult.RuleResults["deferred_text"] {
		t.Fatalf("scan mismatch: loaded=%v compiled=%v", loadedResult.RuleResults, compiledResult.RuleResults)
	}

	ctx := BuildMatchContext(rule, data)
	if matches := ctx.Matches["$alt"]; len(matches) != 1 || matches[0].Offset != 3 {
		t.Fatalf("loaded local matches = %+v, want one $alt at offset 3", matches)
	}
	if !rule.automaton.compiled {
		t.Fatal("local search on loaded program did not build the automaton")
	}
}

// TestCloneDeferredAutomatonUnbuilt covers cloning before the first search:
// the clone stays deferred, owns its pattern buffers, and builds independently.
func TestCloneDeferredAutomatonUnbuilt(t *testing.T) {
	deferred := buildUncompiledDeferredAutomaton(t)

	// Buffer ownership: mutating a clone's metadata must not touch the source.
	ownershipClone := deferred.Clone()
	if !ownershipClone.deferred || ownershipClone.compiled {
		t.Fatal("clone of an unbuilt deferred automaton is not deferred")
	}
	if len(ownershipClone.strings) != len(deferredPatternSet) {
		t.Fatalf("clone strings = %d, want %d", len(ownershipClone.strings), len(deferredPatternSet))
	}
	ownershipClone.strings[0].Data[0] = 'X'
	if string(deferred.strings[0].Data) != "hello" {
		t.Fatal("clone shares pattern buffers with the original")
	}

	// Search fidelity: a pristine clone builds its own tables and matches the
	// eager reference exactly.
	searchClone := deferred.Clone()
	eager := buildEagerAutomaton(t)
	data := []byte("hello world")
	want := slices.Collect(eager.SearchIter(data))
	if got := slices.Collect(searchClone.SearchIter(data)); !slices.Equal(got, want) {
		t.Fatalf("cloned deferred search diverges:\ngot:  %+v\nwant: %+v", got, want)
	}
	if !searchClone.compiled {
		t.Fatal("clone search did not materialize the trie")
	}
	if deferred.compiled {
		t.Fatal("clone build leaked into the source automaton")
	}

	// Cloning an already-compiled deferred automaton must not re-run buildDeferred.
	compiledClone := searchClone.Clone()
	if got := slices.Collect(compiledClone.SearchIter(data)); !slices.Equal(got, want) {
		t.Fatalf("compiled clone search diverges:\ngot:  %+v\nwant: %+v", got, want)
	}
}

// TestStreamedScanKeepsPerRuleAutomatonDeferred verifies that streaming scans
// route through the program's shared automaton and leave per-rule automatons
// unbuilt.
func TestStreamedScanBuildsPerRuleAutomaton(t *testing.T) {
	program, err := NewCompiler().CompileSource(deferredProgramSource)
	if err != nil {
		t.Fatalf("CompileSource(): %v", err)
	}
	rule, ok := program.GetRuleByName("deferred_text")
	if !ok {
		t.Fatal("rule not found")
	}
	data := []byte("zz NEEDLE_TOKEN zz")

	scanner := NewScanner(program, WithStreamChunkSize(8))
	result, err := scanner.ScanReaderWithContext(context.Background(), bytes.NewReader(data))
	if err != nil {
		t.Fatalf("ScanReaderWithContext(): %v", err)
	}
	if len(result.MatchedRules) == 0 {
		t.Fatal("streaming scan did not match")
	}
	if rule.automaton.compiled {
		t.Fatal("streaming scan unnecessarily compiled the per-rule automaton")
	}
	if rule.automaton.states != nil {
		t.Fatal("streaming scan allocated construction states")
	}
}
