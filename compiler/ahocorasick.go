package compiler

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"sync"

	"github.com/cawalch/go-yara/regex"
)

// acState represents a state in the Aho-Corasick automaton
// Using struct-of-arrays layout for better cache locality
type acState struct {
	// Transition table (256 possible byte values)
	transitions [256]int32 // -1 means no transition, >=0 is state index
	// Failure link
	failure int32
	// Output information
	outputStart int32
	outputEnd   int32
}

// acTrieState is a compact construction state used during sparse trie building.
type acTrieState struct {
	firstEdge      int32
	ownOutputStart int32
	ownOutputEnd   int32
}

// acTrieEdge is a labeled directed edge in a state's adjacency list.
type acTrieEdge struct {
	next int32
	to   int32
	b    byte
}

// acAutomaton represents the high-performance Aho-Corasick automaton
type acAutomaton struct {
	// Trie construction states (1 KiB each). Retained for compatibility with
	// direct ac.states manipulation in whitebox tests; standard construction
	// uses the compact sparse trie fields below and releases them on Compile.
	states []acState

	trieStates  []acTrieState
	trieEdges   []acTrieEdge
	trieRoot    *[256]int32
	trieOutputs []int32

	// Output storage (flattened)
	outputs []int32

	// String information
	strings []acStringInfo

	// Explicit bytes reachable from the root before failure links are built.
	// Small sets can use SIMD-optimized byte search to skip root misses.
	rootBytes []byte
	rootLanes []rootLane
	teddy     teddyPrefilter
	teddyGate *corpusTeddyPrefilter

	// Flattened transition table. If len(states) <= 65536, transitions16 is populated
	// and transitions32 is nil. If len(states) > 65536, transitions32 is populated.
	transitions16 [][256]uint16
	transitions32 [][256]int32

	// Byte-equivalence-class compressed transition tables when classShift > 0.
	// classRoot retains the expanded 256-entry root row so root misses need no
	// class indirection.
	classMap    [256]byte
	classShift  uint8
	classCount  int
	classRoot16 *[256]uint16
	classRoot32 *[256]int32
	flatClass16 []uint16
	flatClass32 []int32

	// hasOutput indicates whether a state has any outputs. 1 byte per state.
	hasOutput []bool

	// outputRanges retains each state's [start, end) window into outputs after
	// the construction states are released (8 bytes per state).
	outputRanges [][2]int32

	// stateCount preserves len(states) across the release; stateHint carries
	// the construction-time capacity estimate for deferred automatons that
	// have not built their trie yet.
	stateCount int
	stateHint  int

	// Compilation state
	compiledOnce  sync.Once
	compiled      bool
	compactStates bool

	// deferred marks per-rule automatons whose trie and transition tables are
	// materialized lazily on the first local search. compiledOnce guards that
	// construction so concurrent scanners sharing a program build it once.
	deferred bool
	// buildMu lets diagnostics inspect the tables without starting a deferred build.
	buildMu  sync.Mutex
	buildErr error

	// Exported metadata retained for compatibility with existing callers.
	StringCount int

	// patternBytes tracks stored pattern payload. Trie construction amplifies
	// each byte into construction states and edges, so both per-pattern and
	// total storage are bounded for untrusted compiled artifacts.
	patternBytes int
}

const (
	maxAutomatonPatternLength = 1 << 20
	maxAutomatonPatternBytes  = 16 << 20
)

// newacAutomaton creates a new Aho-Corasick automaton with compact initial capacity.
func newacAutomaton() *acAutomaton {
	return newacAutomatonWithCapacity(1, 8, 16)
}

// newacAutomatonWithCapacity creates a new Aho-Corasick automaton with pre-allocated capacities.
func newacAutomatonWithCapacity(stateCap, stringCap, outputCap int) *acAutomaton {
	if stateCap < 1 {
		stateCap = 1
	}
	var root [256]int32
	for i := range root {
		root[i] = -1
	}
	trieStates := make([]acTrieState, 1, stateCap)
	trieStates[0] = acTrieState{firstEdge: -1}

	if outputCap < 16 {
		outputCap = 16
	}
	if stringCap < 8 {
		stringCap = 8
	}

	return &acAutomaton{
		trieStates:  trieStates,
		trieEdges:   make([]acTrieEdge, 0, max(stateCap-1, 8)),
		trieRoot:    &root,
		trieOutputs: make([]int32, 0, outputCap),
		strings:     make([]acStringInfo, 0, stringCap),
		compiled:    false,
		StringCount: 0,
	}
}

// newDeferredAutomaton creates a per-rule automaton that stores pattern
// metadata eagerly but defers all trie construction, failure-link closure,
// and flat-table allocation until the first local search. Normal scans run
// through the program's shared automaton, so deferred per-rule tables are
// typically never built at all.
func newDeferredAutomaton(stringCap int) *acAutomaton {
	if stringCap < 8 {
		stringCap = 8
	}
	return &acAutomaton{
		outputs:   make([]int32, 0, max(16, stringCap)),
		strings:   make([]acStringInfo, 0, stringCap),
		deferred:  true,
		compiled:  false,
		stateHint: 1,
	}
}

// AddString adds a string pattern to the automaton
//
//nolint:revive // argument-limit: API surface
func (ac *acAutomaton) AddString(identifier string, data []byte, isHex, isRegex bool) error {
	config := stringConfig{
		Identifier: identifier,
		Data:       data,
		IsHex:      isHex,
		IsRegex:    isRegex,
		Flags:      0, // Default flags
	}
	return ac.addStringToAutomaton(config)
}

// addStringToAutomaton implements the core string addition logic
func (ac *acAutomaton) addStringToAutomaton(config stringConfig) error {
	if ac.compiled {
		return errors.New("cannot add strings to compiled automaton")
	}

	// Own the pattern bytes exactly once; the trie, if constructed, works
	// from this stored copy.
	patternLength := len(config.Data)
	if patternLength > maxAutomatonPatternLength ||
		ac.patternBytes > maxAutomatonPatternBytes-patternLength {
		return errors.New("automaton pattern storage limit exceeded")
	}
	ac.patternBytes += patternLength
	patternData := make([]byte, patternLength)
	copy(patternData, config.Data)
	stringInfo := acStringInfo{
		Identifier: config.Identifier,
		Length:     patternLength,
		IsHex:      config.IsHex,
		IsRegex:    config.IsRegex,
		Data:       patternData,
		Flags:      config.Flags,
	}

	// Add string to collection
	ac.strings = append(ac.strings, stringInfo)
	ac.StringCount = len(ac.strings)
	stringIndex := mustACIndex(len(ac.strings) - 1)

	// Deferred automatons retain pattern metadata only; the trie is built by
	// buildDeferred on the first local search.
	if ac.deferred {
		return nil
	}
	ac.insertPatternEdges(config, stringIndex)
	return nil
}

// insertPatternEdges walks a pattern from the root, creating or reusing trie
// states, and registers the pattern's output on the terminal state. It runs
// before failure links are built, for both eager and deferred construction.
func (ac *acAutomaton) insertPatternEdges(config stringConfig, stringIndex int32) {
	if ac.trieRoot == nil {
		// Fallback for legacy ac.states mutations in whitebox tests.
		ac.insertPatternEdgesDense(config, stringIndex)
		return
	}
	ac.insertPatternEdgesFrom(0, config, stringIndex)
}

func (ac *acAutomaton) lookupSparseVariants(currentState int32, variants [2]byte, n int) (int32, int32) {
	if currentState == 0 {
		t0 := ac.trieRoot[variants[0]]
		t1 := int32(-1)
		if n == 2 {
			t1 = ac.trieRoot[variants[1]]
		}
		return t0, t1
	}
	t0, t1 := int32(-1), int32(-1)
	v0 := variants[0]
	for e := ac.trieStates[currentState].firstEdge; e != -1; e = ac.trieEdges[e].next {
		eb := ac.trieEdges[e].b
		if eb == v0 {
			t0 = ac.trieEdges[e].to
		} else if n == 2 && eb == variants[1] {
			t1 = ac.trieEdges[e].to
		}
	}
	return t0, t1
}

func (ac *acAutomaton) insertPatternEdgesFrom(currentState int32, config stringConfig, stringIndex int32) {
	noCase := config.Flags&regex.FlagsNoCase != 0
	for idx, b := range config.Data {
		var variants [2]byte
		n := 1
		variants[0] = b
		if noCase {
			if flipped := flipASCIICase(b); flipped != b {
				variants[1] = flipped
				n = 2
			}
		}

		t0, t1 := ac.lookupSparseVariants(currentState, variants, n)

		// When both ASCII cases already lead to distinct states (from prior
		// case-sensitive patterns), insert the remaining suffix down both
		// branches so neither case drops this nocase pattern.
		if n == 2 && t0 != -1 && t1 != -1 && t0 != t1 {
			branch := config
			branch.Data = config.Data[idx+1:]
			ac.insertPatternEdgesFrom(t1, branch, stringIndex)
			currentState = t0
			continue
		}

		nextState := t0
		if nextState == -1 {
			nextState = t1
		}
		if nextState == -1 {
			nextState = mustACIndex(len(ac.trieStates))
			ac.trieStates = append(ac.trieStates, acTrieState{firstEdge: -1})
		}

		ac.bindSparseVariants(currentState, nextState, variants[:n])
		currentState = nextState
	}

	st := &ac.trieStates[currentState]
	ac.trieOutputs = appendACOutput(ac.trieOutputs, &st.ownOutputStart, &st.ownOutputEnd, stringIndex)
}

func (ac *acAutomaton) bindSparseVariants(state, nextState int32, variants []byte) {
	if state == 0 {
		for _, b := range variants {
			if ac.trieRoot[b] == -1 {
				ac.trieRoot[b] = nextState
			}
		}
		return
	}
	for _, b := range variants {
		ac.addSparseEdge(state, b, nextState)
	}
}

//nolint:revive // argument-limit: internal output-range helper
func appendACOutput(outputs []int32, start, end *int32, stringIndex int32) []int32 {
	existingStart, existingEnd := *start, *end
	switch {
	case existingStart == existingEnd:
		*start = mustACIndex(len(outputs))
	case int(existingEnd) != len(outputs):
		*start = mustACIndex(len(outputs))
		outputs = append(outputs, outputs[existingStart:existingEnd]...)
	}
	outputs = append(outputs, stringIndex)
	*end = mustACIndex(len(outputs))
	return outputs
}

func (ac *acAutomaton) addSparseEdge(state int32, b byte, nextState int32) {
	for e := ac.trieStates[state].firstEdge; e != -1; e = ac.trieEdges[e].next {
		if ac.trieEdges[e].b == b {
			return
		}
	}
	edgeIdx := mustACIndex(len(ac.trieEdges))
	ac.trieEdges = append(ac.trieEdges, acTrieEdge{
		next: ac.trieStates[state].firstEdge,
		to:   nextState,
		b:    b,
	})
	ac.trieStates[state].firstEdge = edgeIdx
}

func (ac *acAutomaton) insertPatternEdgesDense(config stringConfig, stringIndex int32) {
	ac.insertPatternEdgesDenseFrom(0, config, stringIndex)
}

func (ac *acAutomaton) insertPatternEdgesDenseFrom(currentState int32, config stringConfig, stringIndex int32) {
	noCase := config.Flags&regex.FlagsNoCase != 0
	for idx, b := range config.Data {
		// For nocase strings the pattern is already lowercased; register both
		// ASCII cases of each alphabetic byte so the shared automaton fires on
		// any case. Case-sensitive strings keep a single transition. Because
		// trie states are shared, a case-sensitive string can end up reachable
		// via a nocase string's dual transitions; PopulateMatchContext re-verifies
		// the matched bytes (case-sensitively for case-sensitive strings) to
		// reject those false candidates.
		var variants [2]byte
		n := 1
		variants[0] = b
		if noCase {
			if flipped := flipASCIICase(b); flipped != b {
				variants[1] = flipped
				n = 2
			}
		}

		t0 := ac.states[currentState].transitions[variants[0]]
		t1 := int32(-1)
		if n == 2 {
			t1 = ac.states[currentState].transitions[variants[1]]
		}
		if n == 2 && t0 != -1 && t1 != -1 && t0 != t1 {
			branch := config
			branch.Data = config.Data[idx+1:]
			ac.insertPatternEdgesDenseFrom(t1, branch, stringIndex)
			currentState = t0
			continue
		}

		nextState := t0
		if nextState == -1 {
			nextState = t1
		}
		if nextState == -1 {
			// Create new state
			newState := acState{
				transitions: [256]int32{},
				failure:     -1,
				outputStart: 0,
				outputEnd:   0,
			}
			for i := range newState.transitions {
				newState.transitions[i] = -1
			}
			// Dense rows exceed 1 KiB each. Above 32 MiB, double capacity
			// to avoid repeated copies at the slice runtime's smaller growth
			// factor. Compile releases the unused capacity.
			if len(ac.states) == cap(ac.states) && len(ac.states) >= 32768 {
				states := make([]acState, len(ac.states), len(ac.states)*2)
				copy(states, ac.states)
				ac.states = states
				ac.compactStates = true
			}
			ac.states = append(ac.states, newState)
			nextState = mustACIndex(len(ac.states) - 1)
		}
		// Point every variant at the resolved state (skip those already bound).
		for k := 0; k < n; k++ {
			if ac.states[currentState].transitions[variants[k]] == -1 {
				ac.states[currentState].transitions[variants[k]] = nextState
			}
		}
		currentState = nextState
	}

	// Add output for the final state. Multiple patterns can share the same
	// terminal state (for example, identical strings in different rules).
	// Preserve the existing range by copying it to a new contiguous range.
	st := &ac.states[currentState]
	ac.outputs = appendACOutput(ac.outputs, &st.outputStart, &st.outputEnd, stringIndex)
}

// Compile compiles the optimized automaton. For deferred automatons it is
// idempotent: it materializes the trie and tables immediately if a search has
// not already done so.
func (ac *acAutomaton) Compile() error {
	if ac.deferred {
		ac.ensureCompiled()
		return ac.buildErr
	}
	var compileErr error
	ac.compiledOnce.Do(func() {
		if ac.compiled {
			compileErr = errors.New("already compiled")
			return
		}
		if ac.trieRoot != nil {
			if err := ac.compileSparseTrie(); err != nil {
				compileErr = err
				return
			}
		} else {
			if err := ac.compileDense(); err != nil {
				compileErr = err
				return
			}
		}
		filter := newTeddyPrefilter(ac.strings)
		if gate, ok := filter.(*corpusTeddyPrefilter); ok {
			ac.teddyGate = gate
			ac.teddy = gate.teddyPrefilter
		} else {
			ac.teddy = filter
		}
		ac.compiled = true
	})

	return compileErr
}

// ensureCompiled materializes a deferred automaton's trie and transition
// tables before a search. sync.Once makes the build safe for concurrent
// scanners sharing one compiled program: the completed fast path is a single
// atomic load, and a build failure leaves the automaton uncompiled so
// searches yield no matches rather than fail the scan. ac.compiled is only
// read after the Once, which supplies the necessary happens-before edge.
func (ac *acAutomaton) ensureCompiled() {
	if !ac.deferred {
		return
	}
	ac.compiledOnce.Do(ac.buildDeferred)
}

// buildDeferred constructs the trie from the stored pattern metadata and then
// runs the same compile pipeline as the eager path. It always executes inside
// compiledOnce, mirroring the original AddString insertion order so the resulting
// automaton is identical to an eagerly built one.
func (ac *acAutomaton) buildDeferred() {
	ac.buildMu.Lock()
	defer ac.buildMu.Unlock()

	// Trie states are bounded by the total pattern length (plus the root).
	capacity := 1
	totalOutputs := 0
	for _, info := range ac.strings {
		capacity += len(info.Data)
		totalOutputs++
	}
	capacity = max(capacity, ac.stateHint)
	trieStates := make([]acTrieState, 1, capacity)
	trieStates[0] = acTrieState{firstEdge: -1}
	trieRoot := new([256]int32)
	for i := range trieRoot {
		trieRoot[i] = -1
	}
	ac.trieStates = trieStates
	ac.trieEdges = make([]acTrieEdge, 0, max(capacity-1, 0))
	ac.trieRoot = trieRoot
	ac.trieOutputs = make([]int32, 0, totalOutputs)
	ac.compactStates = false

	for i := range ac.strings {
		info := ac.strings[i]
		ac.insertPatternEdges(stringConfig{
			Identifier: info.Identifier,
			Data:       info.Data,
			IsHex:      info.IsHex,
			IsRegex:    info.IsRegex,
			Flags:      info.Flags,
		}, mustACIndex(i))
	}

	if err := ac.compileSparseTrie(); err != nil {
		ac.buildErr = err
		return
	}
	filter := newTeddyPrefilter(ac.strings)
	if gate, ok := filter.(*corpusTeddyPrefilter); ok {
		ac.teddyGate = gate
		ac.teddy = gate.teddyPrefilter
	} else {
		ac.teddy = filter
	}
	ac.compiled = true
}

func (ac *acAutomaton) compileDense() error {
	// Compact doubled construction buffers before allocating the flat scan
	// table. Keep small buffers reusable without another allocation.
	if ac.compactStates && cap(ac.states) > len(ac.states) {
		states := make([]acState, len(ac.states))
		copy(states, ac.states)
		ac.states = states
	}
	ac.compactStates = false
	ac.collectRootBytes()

	if err := ac.buildFailureLinks(); err != nil {
		return fmt.Errorf("building failure links: %w", err)
	}
	ac.closeTransitions()
	ac.buildFlatTransitions()
	return nil
}

func (ac *acAutomaton) collectRootBytes() {
	if ac.trieRoot != nil {
		ac.collectRootBytesFromRow(ac.trieRoot)
		return
	}
	ac.collectRootBytesFromRow(&ac.states[0].transitions)
}

func (ac *acAutomaton) collectRootBytesFromRow(root *[256]int32) {
	ac.rootBytes = ac.rootBytes[:0]
	ac.rootLanes = ac.rootLanes[:0]
	for byteVal, nextState := range root {
		if nextState != -1 {
			ac.rootBytes = append(ac.rootBytes, byte(byteVal))
		}
	}
	var visited [256]bool
	for _, b := range ac.rootBytes {
		if visited[b] {
			continue
		}
		visited[b] = true
		other := flipASCIICase(b)
		if other != b && root[other] != -1 {
			visited[other] = true
			ac.rootLanes = append(ac.rootLanes, rootLane{value: toLowerTable[b], isFold: true})
		} else {
			ac.rootLanes = append(ac.rootLanes, rootLane{value: b, isFold: false})
		}
	}
}

func (ac *acAutomaton) failureState(current int32, byteVal byte) int32 {
	failure := ac.states[current].failure
	for failure != -1 && ac.states[failure].transitions[byteVal] == -1 {
		failure = ac.states[failure].failure
	}
	if failure != -1 {
		return ac.states[failure].transitions[byteVal]
	}
	return 0
}

// mergeFailureOutput merges output from the failure state to the current state.
func (ac *acAutomaton) mergeFailureOutput(state int32) {
	failState := ac.states[ac.states[state].failure]
	if failState.outputStart != failState.outputEnd {
		// Copy both ranges into a new contiguous range. Output ranges for other
		// states may have been appended between this state's original range and
		// the current end of the flat output storage.
		stateOutput := slices.Clone(ac.outputs[ac.states[state].outputStart:ac.states[state].outputEnd])
		failOutput := ac.outputs[failState.outputStart:failState.outputEnd]
		ac.states[state].outputStart = mustACIndex(len(ac.outputs))
		ac.outputs = append(ac.outputs, stateOutput...)
		ac.outputs = append(ac.outputs, failOutput...)
		ac.states[state].outputEnd = mustACIndex(len(ac.outputs))
	}
}

func mustACIndex(value int) int32 {
	if value < 0 || value > math.MaxInt32 {
		panic("Aho-Corasick index exceeds int32 capacity")
	}
	return int32(value)
}

// compileSparseTrie builds failure links, merges outputs, and emits the closed
// flat or byte-equivalence-class transition table directly from the sparse
// trie representation in a single BFS pass, then releases the trie buffers.
func (ac *acAutomaton) compileSparseTrie() error {
	numStates := len(ac.trieStates)
	if numStates == 0 || ac.trieRoot == nil {
		return errors.New("no states in automaton")
	}

	ac.collectRootBytesFromRow(ac.trieRoot)
	var classMap, classRep [256]byte
	numClasses := 256
	if numStates > 16384 {
		classMap, classRep, numClasses = computeByteClassesSparse(ac.trieStates, ac.trieEdges, ac.trieRoot)
	}

	b := &sparseBuildState{
		ac:              ac,
		numStates:       numStates,
		hasOutput:       make([]bool, numStates),
		outputRanges:    make([][2]int32, numStates),
		retainedOutputs: make([]int32, 0, len(ac.trieOutputs)),
	}

	ac.transitions16 = nil
	ac.transitions32 = nil
	ac.flatClass16 = nil
	ac.flatClass32 = nil
	ac.classRoot16 = nil
	ac.classRoot32 = nil
	ac.classShift = 0
	ac.classCount = 0

	ac.emitSparseTables(b, classMap, classRep, numClasses)

	ac.outputs = b.retainedOutputs
	ac.hasOutput = b.hasOutput
	ac.outputRanges = b.outputRanges
	ac.stateCount = b.numStates
	ac.trieStates = nil
	ac.trieEdges = nil
	ac.trieRoot = nil
	ac.trieOutputs = nil
	return nil
}

type sparseBuildState struct {
	ac              *acAutomaton
	numStates       int
	hasOutput       []bool
	outputRanges    [][2]int32
	retainedOutputs []int32
}

type sparseClassSpec struct {
	numClasses int
	stride     int
	classMap   [256]byte
	classRep   [256]byte
}

type acCloneKey struct {
	orig int32
	fail int32
}

func maxTableStates[S ~uint16 | ~int32]() int {
	if ^S(0) > 0 {
		return math.MaxUint16 + 1
	}
	return math.MaxInt32
}

func (b *sparseBuildState) resetOutputs(origNumStates int) {
	b.numStates = origNumStates
	b.hasOutput = b.hasOutput[:origNumStates]
	clear(b.hasOutput)
	b.outputRanges = b.outputRanges[:origNumStates]
	clear(b.outputRanges)
	b.retainedOutputs = b.retainedOutputs[:0]
}

type sparseConflictState[S ~uint16 | ~int32] struct {
	b          *sparseBuildState
	trieStates []acTrieState
	failures   []int32
	seen       []bool
	queue      []int32
	table      [][256]S
	flat       []S
	clones     map[acCloneKey]int32
	stride     int
	maxStates  int
}

//go:noinline
func handleSparseFlatConflict[S ~uint16 | ~int32](
	s *sparseConflictState[S],
	edge acTrieEdge,
	targetFail int32,
) (int32, bool) {
	key := acCloneKey{orig: edge.to, fail: targetFail}
	if existing, exists := s.clones[key]; exists {
		return existing, true
	}
	if len(s.failures) >= s.maxStates {
		return 0, false
	}
	cloneIdx := mustACIndex(len(s.failures))
	if s.clones == nil {
		s.clones = make(map[acCloneKey]int32)
	}
	s.clones[key] = cloneIdx
	s.trieStates = append(s.trieStates, s.trieStates[edge.to])
	s.failures = slices.Grow(s.failures, 1)
	s.failures = s.failures[:len(s.failures)+1]
	s.failures[cloneIdx] = targetFail
	s.seen = slices.Grow(s.seen, 1)
	s.seen = s.seen[:len(s.seen)+1]
	s.seen[cloneIdx] = true
	s.b.appendClonedOutput()
	if s.stride > 0 {
		s.flat = slices.Grow(s.flat, s.stride)
		s.flat = s.flat[:len(s.flat)+s.stride]
	} else {
		s.table = slices.Grow(s.table, 1)
		s.table = s.table[:len(s.table)+1]
	}
	s.queue = append(s.queue, cloneIdx)
	return cloneIdx, true
}

func (b *sparseBuildState) appendClonedOutput() {
	b.hasOutput = append(b.hasOutput, false)
	b.outputRanges = append(b.outputRanges, [2]int32{})
}

//nolint:revive // argument-limit: internal builder helper
func (ac *acAutomaton) emitSparseTables(b *sparseBuildState, classMap [256]byte, classRep [256]byte, numClasses int) {
	origNumStates := b.numStates
	if numClasses > 128 || origNumStates <= 16384 {
		if origNumStates <= 65536 {
			if table16, ok := buildSparseFlatTable[uint16](b); ok {
				ac.transitions16 = table16
				return
			}
			b.resetOutputs(origNumStates)
		}
		ac.transitions32, _ = buildSparseFlatTable[int32](b)
		return
	}
	stride := 1
	var shift uint8
	for stride < numClasses {
		stride <<= 1
		shift++
	}
	ac.classMap = classMap
	ac.classShift = shift
	ac.classCount = numClasses
	spec := sparseClassSpec{
		numClasses: numClasses,
		stride:     stride,
		classMap:   classMap,
		classRep:   classRep,
	}
	if origNumStates <= 65536 {
		if flat16, root16, ok := buildSparseClassTable[uint16](b, spec); ok {
			ac.flatClass16, ac.classRoot16 = flat16, root16
			return
		}
		b.resetOutputs(origNumStates)
	}
	ac.flatClass32, ac.classRoot32, _ = buildSparseClassTable[int32](b, spec)
}

func (ac *acAutomaton) hasNoCasePattern() bool {
	for i := range ac.strings {
		if ac.strings[i].Flags&regex.FlagsNoCase != 0 {
			return true
		}
	}
	return false
}

func buildSparseClassTable[S ~uint16 | ~int32](b *sparseBuildState, spec sparseClassSpec) ([]S, *[256]S, bool) {
	ac := b.ac
	origNumStates := b.numStates
	flat := make([]S, origNumStates*spec.stride)
	rootRow := new([256]S)
	for byteVal := range 256 {
		target := max(ac.trieRoot[byteVal], 0)
		//checkednarrow:ignore target is in [0, origNumStates) and S is uint16 only when origNumStates <= 65536
		rootRow[byteVal] = S(target)
	}
	for c := 0; c < spec.numClasses; c++ {
		target := max(ac.trieRoot[spec.classRep[c]], 0)
		//checkednarrow:ignore target is in [0, origNumStates) and S is uint16 only when origNumStates <= 65536
		flat[c] = S(target)
	}

	failures := make([]int32, origNumStates)
	failures[0] = -1
	queue := make([]int32, 0, origNumStates)
	seen := make([]bool, origNumStates)
	seen[0] = true

	b.initRootOutput()

	for _, nextState := range ac.trieRoot {
		if nextState != -1 && !seen[nextState] {
			seen[nextState] = true
			failures[nextState] = 0
			queue = append(queue, nextState)
		}
	}

	if !ac.hasNoCasePattern() {
		fillSparseClassTree(b, spec, flat, failures, seen, queue)
		return flat, rootRow, true
	}
	flat, finalStates, ok := fillSparseClassDAG(b, spec, flat, failures, seen, queue)
	if !ok {
		return nil, nil, false
	}
	b.numStates = finalStates
	return flat, rootRow, true
}

//nolint:revive // argument-limit: internal BFS kernel keeps slices unescaped
func fillSparseClassTree[S ~uint16 | ~int32](
	b *sparseBuildState,
	spec sparseClassSpec,
	flat []S,
	failures []int32,
	seen []bool,
	queue []int32,
) {
	ac := b.ac
	trieStates := ac.trieStates
	for head := 0; head < len(queue); head++ {
		cur := queue[head]
		fail := failures[cur]
		st := trieStates[cur]

		b.mergeNodeOutputs(cur, fail, st)

		curOff := int(cur) * spec.stride
		failOff := int(fail) * spec.stride
		copy(flat[curOff:curOff+spec.numClasses], flat[failOff:failOff+spec.numClasses])

		for e := st.firstEdge; e != -1; e = ac.trieEdges[e].next {
			edge := ac.trieEdges[e]
			next := edge.to
			cls := int(spec.classMap[edge.b])
			failures[next] = int32(flat[failOff+cls])
			//checkednarrow:ignore next is in [0, origNumStates) and S is uint16 only when origNumStates <= 65536
			flat[curOff+cls] = S(next)
			if !seen[next] {
				seen[next] = true
				queue = append(queue, next)
			}
		}
	}
}

//nolint:revive // argument-limit: internal BFS kernel keeps slices unescaped
func fillSparseClassDAG[S ~uint16 | ~int32](
	b *sparseBuildState,
	spec sparseClassSpec,
	flat []S,
	failures []int32,
	seen []bool,
	queue []int32,
) ([]S, int, bool) {
	ac := b.ac
	maxStates := maxTableStates[S]()
	trieStates := ac.trieStates
	var conflict *sparseConflictState[S]
	for head := 0; head < len(queue); head++ {
		cur := queue[head]
		fail := failures[cur]
		st := trieStates[cur]

		b.mergeNodeOutputs(cur, fail, st)

		curOff := int(cur) * spec.stride
		failOff := int(fail) * spec.stride
		copy(flat[curOff:curOff+spec.numClasses], flat[failOff:failOff+spec.numClasses])

		for e := st.firstEdge; e != -1; e = ac.trieEdges[e].next {
			edge := ac.trieEdges[e]
			next := edge.to
			cls := int(spec.classMap[edge.b])
			targetFail := int32(flat[failOff+cls])
			if !seen[next] {
				seen[next] = true
				failures[next] = targetFail
				queue = append(queue, next)
				//checkednarrow:ignore next is in [0, maxStates) and S is uint16 only when maxStates <= 65536
				flat[curOff+cls] = S(next)
				continue
			}
			if failures[next] != targetFail {
				if conflict == nil {
					conflict = &sparseConflictState[S]{
						b:          b,
						trieStates: trieStates,
						failures:   failures,
						seen:       seen,
						queue:      queue,
						flat:       flat,
						stride:     spec.stride,
						maxStates:  maxStates,
					}
				} else {
					conflict.queue = queue
				}
				var ok bool
				next, ok = handleSparseFlatConflict(conflict, edge, targetFail)
				if !ok {
					return nil, 0, false
				}
				trieStates, failures, seen, queue, flat = conflict.trieStates, conflict.failures, conflict.seen, conflict.queue, conflict.flat
			}
			//checkednarrow:ignore next is in [0, maxStates) and S is uint16 only when maxStates <= 65536
			flat[curOff+cls] = S(next)
		}
	}
	return flat, len(failures), true
}

func buildSparseFlatTable[S ~uint16 | ~int32](b *sparseBuildState) ([][256]S, bool) {
	ac := b.ac
	origNumStates := b.numStates
	table := make([][256]S, origNumStates)
	for byteVal := range 256 {
		target := max(ac.trieRoot[byteVal], 0)
		//checkednarrow:ignore target is in [0, origNumStates) and S is uint16 only when origNumStates <= 65536
		table[0][byteVal] = S(target)
	}

	failures := make([]int32, origNumStates)
	failures[0] = -1
	queue := make([]int32, 0, origNumStates)
	seen := make([]bool, origNumStates)
	seen[0] = true

	b.initRootOutput()

	for _, nextState := range ac.trieRoot {
		if nextState != -1 && !seen[nextState] {
			seen[nextState] = true
			failures[nextState] = 0
			queue = append(queue, nextState)
		}
	}

	if !ac.hasNoCasePattern() {
		fillSparseFlatTree(b, table, failures, seen, queue)
		return table, true
	}
	table, finalStates, ok := fillSparseFlatDAG(b, table, failures, seen, queue)
	if !ok {
		return nil, false
	}
	b.numStates = finalStates
	return table, true
}

//nolint:revive // argument-limit: internal BFS kernel keeps slices unescaped
func fillSparseFlatTree[S ~uint16 | ~int32](
	b *sparseBuildState,
	table [][256]S,
	failures []int32,
	seen []bool,
	queue []int32,
) {
	ac := b.ac
	trieStates := ac.trieStates
	for head := 0; head < len(queue); head++ {
		cur := queue[head]
		fail := failures[cur]
		st := trieStates[cur]

		b.mergeNodeOutputs(cur, fail, st)

		table[cur] = table[fail]
		for e := st.firstEdge; e != -1; e = ac.trieEdges[e].next {
			edge := ac.trieEdges[e]
			next := edge.to
			failures[next] = int32(table[fail][edge.b])
			//checkednarrow:ignore next is in [0, origNumStates) and S is uint16 only when origNumStates <= 65536
			table[cur][edge.b] = S(next)
			if !seen[next] {
				seen[next] = true
				queue = append(queue, next)
			}
		}
	}
}

//nolint:revive // argument-limit: internal BFS kernel keeps slices unescaped
func fillSparseFlatDAG[S ~uint16 | ~int32](
	b *sparseBuildState,
	table [][256]S,
	failures []int32,
	seen []bool,
	queue []int32,
) ([][256]S, int, bool) {
	ac := b.ac
	maxStates := maxTableStates[S]()
	trieStates := ac.trieStates
	var conflict *sparseConflictState[S]
	for head := 0; head < len(queue); head++ {
		cur := queue[head]
		fail := failures[cur]
		st := trieStates[cur]

		b.mergeNodeOutputs(cur, fail, st)

		table[cur] = table[fail]
		for e := st.firstEdge; e != -1; e = ac.trieEdges[e].next {
			edge := ac.trieEdges[e]
			next := edge.to
			targetFail := int32(table[fail][edge.b])
			if !seen[next] {
				seen[next] = true
				failures[next] = targetFail
				queue = append(queue, next)
				//checkednarrow:ignore next is in [0, maxStates) and S is uint16 only when maxStates <= 65536
				table[cur][edge.b] = S(next)
				continue
			}
			if failures[next] != targetFail {
				if conflict == nil {
					conflict = &sparseConflictState[S]{
						b:          b,
						trieStates: trieStates,
						failures:   failures,
						seen:       seen,
						queue:      queue,
						table:      table,
						maxStates:  maxStates,
					}
				} else {
					conflict.queue = queue
				}
				var ok bool
				next, ok = handleSparseFlatConflict(conflict, edge, targetFail)
				if !ok {
					return nil, 0, false
				}
				trieStates, failures, seen, queue, table = conflict.trieStates, conflict.failures, conflict.seen, conflict.queue, conflict.table
			}
			//checkednarrow:ignore next is in [0, maxStates) and S is uint16 only when maxStates <= 65536
			table[cur][edge.b] = S(next)
		}
	}
	return table, len(failures), true
}

func (b *sparseBuildState) initRootOutput() {
	st0 := b.ac.trieStates[0]
	if st0.ownOutputEnd > st0.ownOutputStart {
		b.retainedOutputs = append(b.retainedOutputs, b.ac.trieOutputs[st0.ownOutputStart:st0.ownOutputEnd]...)
		b.outputRanges[0] = [2]int32{0, mustACIndex(len(b.retainedOutputs))}
		b.hasOutput[0] = true
	}
}

func (b *sparseBuildState) mergeNodeOutputs(cur, fail int32, st acTrieState) {
	failRange := b.outputRanges[fail]
	if st.ownOutputEnd == st.ownOutputStart {
		b.outputRanges[cur] = failRange
		b.hasOutput[cur] = b.hasOutput[fail]
		return
	}
	start := mustACIndex(len(b.retainedOutputs))
	b.retainedOutputs = append(b.retainedOutputs, b.ac.trieOutputs[st.ownOutputStart:st.ownOutputEnd]...)
	if failRange[1] > failRange[0] {
		b.retainedOutputs = append(b.retainedOutputs, b.retainedOutputs[failRange[0]:failRange[1]]...)
	}
	b.outputRanges[cur] = [2]int32{start, mustACIndex(len(b.retainedOutputs))}
	b.hasOutput[cur] = true
}

// computeByteClassesSparse partitions the 256 byte values into equivalence
// classes where two bytes share a class iff they have identical goto edges out
// of every trie state. If more than 128 classes are needed, it returns 256 to
// fall back to uncompressed 256-entry rows.
func computeByteClassesSparse(trieStates []acTrieState, trieEdges []acTrieEdge, trieRoot *[256]int32) (classMap [256]byte, classRep [256]byte, numClasses int) {
	var used [256]bool
	var hashes [256]uint64
	var counts [256]int32

	for b := range 256 {
		if target := trieRoot[b]; target != -1 {
			used[b] = true
			hashes[b] ^= mixAC64(0, uint64(target))
			counts[b]++
		}
	}
	for s, st := range trieStates {
		for e := st.firstEdge; e != -1; e = trieEdges[e].next {
			edge := trieEdges[e]
			used[edge.b] = true
			hashes[edge.b] ^= mixAC64(uint64(s+1), uint64(edge.to))
			counts[edge.b]++
		}
	}

	unusedClass := -1
	for b := range 256 {
		if !used[b] {
			if unusedClass == -1 {
				if numClasses >= 128 {
					return classMap, classRep, 256
				}
				unusedClass = numClasses
				classRep[unusedClass] = byte(b)
				numClasses++
			}
			//checkednarrow:ignore unusedClass is in [0, 128)
			classMap[b] = byte(unusedClass)
			continue
		}

		matched := -1
		h := hashes[b]
		c := counts[b]
		for cls := 0; cls < numClasses; cls++ {
			if cls == unusedClass {
				continue
			}
			rep := classRep[cls]
			if hashes[rep] == h && counts[rep] == c && bytesHaveSameEdgesSparse(rep, byte(b), trieStates, trieEdges, trieRoot) {
				matched = cls
				break
			}
		}
		if matched >= 0 {
			//checkednarrow:ignore matched is in [0, numClasses) and numClasses <= 128
			classMap[b] = byte(matched)
			continue
		}
		if numClasses >= 128 {
			return classMap, classRep, 256
		}
		//checkednarrow:ignore numClasses is in [0, 128)
		classMap[b] = byte(numClasses)
		classRep[numClasses] = byte(b)
		numClasses++
	}
	return classMap, classRep, numClasses
}

//nolint:revive // argument-limit: internal byte-equivalence check
func bytesHaveSameEdgesSparse(a, b byte, trieStates []acTrieState, trieEdges []acTrieEdge, trieRoot *[256]int32) bool {
	if trieRoot[a] != trieRoot[b] {
		return false
	}
	for s := range trieStates {
		toA := int32(-1)
		toB := int32(-1)
		for e := trieStates[s].firstEdge; e != -1; e = trieEdges[e].next {
			edge := trieEdges[e]
			switch edge.b {
			case a:
				toA = edge.to
			case b:
				toB = edge.to
			}
		}
		if toA != toB {
			return false
		}
	}
	return true
}

func mixAC64(a, b uint64) uint64 {
	x := a*0x9e3779b97f4a7c15 ^ b*0xbf58476d1ce4e5b9
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9
	x = (x ^ (x >> 27)) * 0x94d049bb133111eb
	return x ^ (x >> 31)
}

type denseFailureCloner struct {
	ac     *acAutomaton
	queue  []int32
	seen   []bool
	clones map[acCloneKey]int32
}

func (c *denseFailureCloner) resolve(nextState, targetFail int32) int32 {
	if !c.seen[nextState] {
		c.seen[nextState] = true
		c.ac.states[nextState].failure = targetFail
		c.queue = append(c.queue, nextState)
		return nextState
	}
	if c.ac.states[nextState].failure == targetFail {
		return nextState
	}
	key := acCloneKey{orig: nextState, fail: targetFail}
	if cloneIdx, exists := c.clones[key]; exists {
		return cloneIdx
	}
	cloneIdx := mustACIndex(len(c.ac.states))
	if c.clones == nil {
		c.clones = make(map[acCloneKey]int32)
	}
	c.clones[key] = cloneIdx
	if len(c.ac.states) == cap(c.ac.states) && len(c.ac.states) >= 32768 {
		states := make([]acState, len(c.ac.states), len(c.ac.states)*2)
		copy(states, c.ac.states)
		c.ac.states = states
		c.ac.compactStates = true
	}
	clone := c.ac.states[nextState]
	clone.failure = targetFail
	c.ac.states = append(c.ac.states, clone)
	c.seen = slices.Grow(c.seen, 1)
	c.seen = c.seen[:len(c.seen)+1]
	c.seen[cloneIdx] = true
	c.queue = append(c.queue, cloneIdx)
	return cloneIdx
}

// buildFailureLinks builds failure links for the optimized automaton
func (ac *acAutomaton) buildFailureLinks() error {
	if len(ac.states) == 0 {
		return errors.New("no states in automaton")
	}

	cloner := denseFailureCloner{
		ac:    ac,
		queue: make([]int32, 0, len(ac.states)),
		seen:  make([]bool, len(ac.states)),
	}
	cloner.seen[0] = true
	for _, nextState := range &ac.states[0].transitions {
		if nextState != -1 && !cloner.seen[nextState] {
			cloner.seen[nextState] = true
			ac.states[nextState].failure = 0
			cloner.queue = append(cloner.queue, nextState)
		}
	}

	for head := 0; head < len(cloner.queue); head++ {
		current := cloner.queue[head]
		ac.mergeFailureOutput(current)
		for byteVal := range 256 {
			nextState := ac.states[current].transitions[byteVal]
			if nextState == -1 {
				continue
			}
			targetFail := ac.failureState(current, byte(byteVal))
			if resolved := cloner.resolve(nextState, targetFail); resolved != nextState {
				ac.states[current].transitions[byteVal] = resolved
			}
		}
	}

	return nil
}

// closeTransitions converts the goto table from the sparse Aho-Corasick form,
// where a missing edge is -1 and the scan follows failure links at run time, to
// the full deterministic form, where every (state, byte) pair has an explicit
// target.
//
// The scan is the whole cost on large inputs — on a 16KB event it was 99% of
// Matches(), split between the SearchIter loop and findNextState's failure
// walk — so paying once at compile time to make the per-byte step a single
// indexed load is a large win. This costs no extra memory: acState.transitions
// is already a dense [256]int32.
//
// Must run after buildFailureLinks, and after collectRootBytes, which
// distinguishes real root edges by their -1 absence.
func (ac *acAutomaton) closeTransitions() {
	// Breadth-first from the root so a state's failure target, which is always
	// strictly shallower, is closed before the state itself.
	//
	// The seen guard is required, not defensive: case-insensitive strings point
	// several byte values at the same next state, so a state is reachable more
	// than once and an unguarded walk re-enqueues it without bound.
	queue := make([]int32, 0, len(ac.states))
	seen := make([]bool, len(ac.states))
	seen[0] = true
	for b := range ac.states[0].transitions {
		next := ac.states[0].transitions[b]
		if next == -1 {
			// A miss at the root restarts the scan at the root.
			ac.states[0].transitions[b] = 0
			continue
		}
		if !seen[next] {
			seen[next] = true
			queue = append(queue, next)
		}
	}
	for head := 0; head < len(queue); head++ {
		state := queue[head]
		failure := max(ac.states[state].failure, 0)
		for b := range ac.states[state].transitions {
			next := ac.states[state].transitions[b]
			if next == -1 {
				ac.states[state].transitions[b] = ac.states[failure].transitions[b]
				continue
			}
			if !seen[next] {
				seen[next] = true
				queue = append(queue, next)
			}
		}
	}
}

// buildFlatTransitions allocates the flat scan table, extracts the per-state
// output ranges, and releases the construction states. After this call the
// flat table, outputRanges, and hasOutput are authoritative: releasing the
// 1,036-byte construction states cuts retained automaton memory by roughly
// two thirds for 16-bit tables (1,548 -> 521 bytes per state) while the
// search kernels keep their single indexed load per byte.
func (ac *acAutomaton) buildFlatTransitions() {
	numStates := len(ac.states)
	if numStates == 0 {
		return
	}
	ac.hasOutput = make([]bool, numStates)
	ac.outputRanges = make([][2]int32, numStates)
	for i := range ac.states {
		start, end := ac.states[i].outputStart, ac.states[i].outputEnd
		if start != end {
			ac.hasOutput[i] = true
		}
		ac.outputRanges[i] = [2]int32{start, end}
	}

	if numStates <= 65536 {
		flat := make([][256]uint16, numStates)
		for s := range ac.states {
			transitions := &ac.states[s].transitions
			row := &flat[s]
			for b := range 256 {
				row[b] = uint16(transitions[b]) //checkednarrow:ignore guarded by numStates <= 65536
			}
		}
		ac.transitions16 = flat
	} else {
		flat := make([][256]int32, numStates)
		for s := range ac.states {
			flat[s] = ac.states[s].transitions
		}
		ac.transitions32 = flat
	}

	ac.stateCount = numStates
	ac.states = nil
}

// AddStringWithFlags adds a string and records regex VM flags alongside metadata
//
//nolint:revive // argument-limit: API surface
func (ac *acAutomaton) AddStringWithFlags(
	identifier string,
	data []byte,
	isHex, isRegex bool,
	flags regex.Flags,
) error {
	config := stringConfig{
		Identifier: identifier,
		Data:       data,
		IsHex:      isHex,
		IsRegex:    isRegex,
		Flags:      flags,
	}
	return ac.addStringToAutomaton(config)
}

// ReserveStrings ensures capacity for at least n string infos to avoid slice growth
func (ac *acAutomaton) ReserveStrings(n int) {
	if n > 0 && cap(ac.strings) < n {
		ac.strings = slices.Grow(ac.strings, n-len(ac.strings))
	}
}

// ReserveStates ensures capacity for at least n states to avoid slice growth.
// Deferred automatons only record the estimate; their states are allocated
// when the trie is materialized.
func (ac *acAutomaton) ReserveStates(n int) {
	if ac.deferred {
		if n > ac.stateHint {
			ac.stateHint = n
		}
		return
	}
	if ac.trieRoot != nil {
		if n > 0 && cap(ac.trieStates) < n {
			ac.trieStates = slices.Grow(ac.trieStates, n-len(ac.trieStates))
		}
		return
	}
	if n > 0 && cap(ac.states) < n {
		ac.states = slices.Grow(ac.states, n-len(ac.states))
	}
}

// BuildFailureLinks builds the failure links for the automaton
func (ac *acAutomaton) BuildFailureLinks() error {
	return ac.buildFailureLinks()
}

// Validate checks if the automaton is correctly constructed
func (ac *acAutomaton) Validate() error {
	if ac.deferred {
		ac.buildMu.Lock()
		defer ac.buildMu.Unlock()
		if ac.buildErr != nil {
			return ac.buildErr
		}
	}
	hasFlatTable := len(ac.transitions16) > 0 || len(ac.transitions32) > 0 ||
		len(ac.flatClass16) > 0 || len(ac.flatClass32) > 0
	hasConstructionStates := len(ac.states) > 0 || len(ac.trieStates) > 0
	// Deferred automatons hold pattern metadata before their first local
	// search; released construction states are equally valid once a flat
	// table exists.
	if !hasConstructionStates && !hasFlatTable && !ac.deferred {
		return errors.New("automaton has no states")
	}

	if (hasConstructionStates || hasFlatTable) && len(ac.strings) == 0 && ac.compiled {
		return errors.New("inconsistent automaton state")
	}

	return nil
}

// Clone creates a copy of the automaton
func (ac *acAutomaton) Clone() *acAutomaton {
	if ac.deferred {
		ac.buildMu.Lock()
		defer ac.buildMu.Unlock()
	}
	internalStrings := cloneacStringInfos(ac.strings)
	var trieRootCopy *[256]int32
	if ac.trieRoot != nil {
		trieRootCopy = new([256]int32)
		*trieRootCopy = *ac.trieRoot
	}
	var classRoot16Copy *[256]uint16
	if ac.classRoot16 != nil {
		classRoot16Copy = new([256]uint16)
		*classRoot16Copy = *ac.classRoot16
	}
	var classRoot32Copy *[256]int32
	if ac.classRoot32 != nil {
		classRoot32Copy = new([256]int32)
		*classRoot32Copy = *ac.classRoot32
	}
	newAC := &acAutomaton{
		states:        slices.Clone(ac.states),
		trieStates:    slices.Clone(ac.trieStates),
		trieEdges:     slices.Clone(ac.trieEdges),
		trieRoot:      trieRootCopy,
		trieOutputs:   slices.Clone(ac.trieOutputs),
		outputs:       slices.Clone(ac.outputs),
		strings:       internalStrings,
		rootBytes:     slices.Clone(ac.rootBytes),
		rootLanes:     slices.Clone(ac.rootLanes),
		teddy:         ac.teddy,
		teddyGate:     ac.teddyGate,
		transitions16: slices.Clone(ac.transitions16),
		transitions32: slices.Clone(ac.transitions32),
		classMap:      ac.classMap,
		classShift:    ac.classShift,
		classCount:    ac.classCount,
		classRoot16:   classRoot16Copy,
		classRoot32:   classRoot32Copy,
		flatClass16:   slices.Clone(ac.flatClass16),
		flatClass32:   slices.Clone(ac.flatClass32),
		hasOutput:     slices.Clone(ac.hasOutput),
		outputRanges:  slices.Clone(ac.outputRanges),
		stateCount:    ac.stateCount,
		stateHint:     ac.stateHint,
		deferred:      ac.deferred,
		compiled:      ac.compiled,
		StringCount:   len(internalStrings),
	}
	if ac.compiled {
		newAC.compiledOnce.Do(func() {})
	}

	return newAC
}

func cloneacStringInfos(in []acStringInfo) []acStringInfo {
	out := slices.Clone(in)
	for index := range out {
		out[index].Data = slices.Clone(out[index].Data)
	}
	return out
}

// acMatch represents a pattern match found by the automaton
type acMatch struct {
	StringIndex int    // Index of the matched string
	StringID    string // Identifier of the matched string
	Backtrack   int    // Backtrack distance
}

// acStringInfo contains information about a registered string pattern
type acStringInfo struct {
	Data       []byte
	Identifier string
	Length     int
	Flags      regex.Flags
	IsHex      bool
	IsRegex    bool
}

type stringConfig struct {
	Identifier string
	Data       []byte
	IsHex      bool
	IsRegex    bool
	Flags      regex.Flags
}

// GetStateCount returns the number of states in the automaton. Construction
// states are released after Compile, so the count is served from stateCount;
// deferred automatons that have not built a trie yet report their estimate.
func (ac *acAutomaton) GetStateCount() int {
	if ac.deferred {
		ac.buildMu.Lock()
		defer ac.buildMu.Unlock()
	}
	if len(ac.trieStates) > 0 {
		return len(ac.trieStates)
	}
	if len(ac.states) > 0 {
		return len(ac.states)
	}
	if ac.stateCount > 0 {
		return ac.stateCount
	}
	return ac.stateHint
}

// GetStringCount returns the number of strings in the automaton
func (ac *acAutomaton) GetStringCount() int {
	return len(ac.strings)
}

// GetStrings returns an owned snapshot of all string information.
func (ac *acAutomaton) GetStrings() []acStringInfo {
	return cloneacStringInfos(ac.strings)
}

// GetPatternData returns owned pattern data keyed by string identifier.
func (ac *acAutomaton) GetPatternData() map[string][]byte {
	// Pre-allocate map with known capacity for better performance
	result := make(map[string][]byte, len(ac.strings))
	for _, strInfo := range ac.strings {
		result[strInfo.Identifier] = slices.Clone(strInfo.Data)
	}
	return result
}

// EstimateMemoryUsage returns a deterministic heuristic byte estimate for the automaton.
// It is intended for relative sizing and diagnostics, not exact Go heap accounting.
// Released construction states contribute nothing; the retained flat table,
// output ranges, and outputs are what scans actually read.
func (ac *acAutomaton) EstimateMemoryUsage() int {
	if ac.deferred {
		ac.buildMu.Lock()
		defer ac.buildMu.Unlock()
	}
	stateMemory := len(ac.states) * (256*4 + 8) // transitions + failure + output indices
	stateMemory += len(ac.trieStates)*12 + len(ac.trieEdges)*12
	if ac.trieRoot != nil {
		stateMemory += 256 * 4
	}
	switch {
	case len(ac.flatClass16) > 0:
		stateMemory += len(ac.flatClass16)*2 + 256*2
	case len(ac.flatClass32) > 0:
		stateMemory += len(ac.flatClass32)*4 + 256*4
	case len(ac.transitions16) > 0:
		stateMemory += len(ac.transitions16) * 256 * 2
	case len(ac.transitions32) > 0:
		stateMemory += len(ac.transitions32) * 256 * 4
	}
	stateMemory += len(ac.hasOutput)
	stateMemory += len(ac.outputRanges) * 8
	outputMemory := (len(ac.outputs) + len(ac.trieOutputs)) * 4
	stringMemory := len(ac.strings) * 64 // Approximate

	return stateMemory + outputMemory + stringMemory
}

// Reset clears the automaton for reuse
func (ac *acAutomaton) Reset() {
	ac.compactStates = false
	// Restore the root state. Compile releases the construction slice, so a
	// compiled automaton starts from a fresh allocation; a deferred automaton
	// keeps deferring (no trie states) after reset.
	switch {
	case ac.deferred:
		ac.states = nil
		ac.trieStates = nil
		ac.trieEdges = nil
		ac.trieRoot = nil
		ac.trieOutputs = nil
	case ac.states != nil && ac.trieRoot == nil:
		ac.states = ac.states[:1] // Keep root state
		for i := range ac.states[0].transitions {
			ac.states[0].transitions[i] = -1
		}
		ac.states[0].failure = -1
		ac.states[0].outputStart = 0
		ac.states[0].outputEnd = 0
	default:
		ac.states = nil
		if len(ac.trieStates) == 0 {
			ac.trieStates = make([]acTrieState, 1)
		} else {
			ac.trieStates = ac.trieStates[:1]
		}
		ac.trieStates[0] = acTrieState{firstEdge: -1}
		ac.trieEdges = ac.trieEdges[:0]
		ac.trieOutputs = ac.trieOutputs[:0]
		if ac.trieRoot == nil {
			ac.trieRoot = new([256]int32)
		}
		for i := range ac.trieRoot {
			ac.trieRoot[i] = -1
		}
	}

	// Clear outputs and strings
	ac.outputs = ac.outputs[:0]
	ac.strings = ac.strings[:0]
	ac.rootBytes = ac.rootBytes[:0]
	ac.rootLanes = ac.rootLanes[:0]
	ac.teddy = nil
	ac.teddyGate = nil
	ac.StringCount = 0
	ac.transitions16 = nil
	ac.transitions32 = nil
	ac.classMap = [256]byte{}
	ac.classShift = 0
	ac.classCount = 0
	ac.classRoot16 = nil
	ac.classRoot32 = nil
	ac.flatClass16 = nil
	ac.flatClass32 = nil
	ac.hasOutput = nil
	ac.outputRanges = nil
	ac.stateCount = 0
	ac.stateHint = 1

	// Reset compilation state
	ac.compiledOnce = sync.Once{}
	ac.compiled = false
	ac.buildErr = nil
}

// flipASCIICase returns the opposite-ASCII-case equivalent of b for letters,
// and b unchanged otherwise. Used to register dual trie transitions for
// nocase strings (whose pattern bytes are already lowercased).
func flipASCIICase(b byte) byte {
	switch {
	case b >= 'a' && b <= 'z':
		return b - 32
	case b >= 'A' && b <= 'Z':
		return b + 32
	default:
		return b
	}
}
