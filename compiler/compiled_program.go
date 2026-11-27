package compiler

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/cawalch/go-yara/internal/wordmatch"
)

// sharedAutomatonEntry maps a shared automaton entry to its exact verifier.
type sharedAutomatonEntry struct {
	combined   *combinedRegexNFA
	fanout     []sharedAutomatonEntry
	hexDisc    *hexFanoutDiscriminator
	RuleIndex  int // index into CompiledProgram.Rules
	StringIdx  int // index into CompiledRule.IndexToStringID
	AtomOffset int
	// AtomMaxOffset is the maximum number of bytes before a regex atom. It is
	// -1 for an atom after an unbounded prefix and equals AtomOffset for
	// fixed-offset regex and hex atoms.
	AtomMaxOffset   int
	CacheIndex      int
	Kind            StringKind
	alternativeAtom bool
	forceShared     bool
	IsWide          bool
	canTriggerRule  bool
	singleRuleCache bool
	hasFullword     bool
}

// CompiledProgram represents an immutable, thread-safe collection of compiled YARA rules.
// It encapsulates prefilter lookup tables, bytecode instruction sequences, and shared
// automata. A CompiledProgram is safe for concurrent access across multiple goroutines.
//
// Performance note: Convenience scanning methods directly on CompiledProgram (such as Scan,
// Matches, and MatchingRules) borrow reusable scanners from an internal sync.Pool, achieving
// zero heap allocations on repeated scans with default options. When custom scanning options
// (such as tag filters, match limits, hooks, or fast-scan flags) are required, instantiate an
// explicit Scanner via NewScanner.
type CompiledProgram struct {
	moduleSchemas   map[string]*ModuleSchema
	nativePCAP      bool
	Rules           []*CompiledRule
	sharedAutomaton *acAutomaton
	Stats           map[string]any
	externalValues  *atomic.Pointer[map[string]externalValue]

	// Lookup table: shared automaton entry -> exact text/regex/hex verifier.
	// Built once at compile time, used by extractGlobalMatches for O(1) routing.
	sharedLookup []sharedAutomatonEntry

	// Number of compile-time integer slots used to cache regex/hex matches.
	nonTextCacheSize int
	sharedAssertions []conditionAssertion
	// sharedNonTextCaches marks cache slots whose mandatory atom cover is fully
	// represented in sharedAutomaton.
	sharedNonTextCaches []bool
	// sharedNonTextCacheRules routes one verified cache slot to every rule that
	// references the deduplicated pattern.
	sharedNonTextCacheRules [][]int
	fixedRegexScan          *fixedRegexDispatch
	dependencies            map[string][]string
	preparationErr          error
	compactPrefilter        *compactPrefilter
	booleanRouting          func() *wordmatch.RoutedProgram

	// Streaming support
	streamingProcessor             *StreamingProcessor
	sharedHasTextOrAlternative     bool
	allRulesUseSharedPatterns      bool
	hasHeaderOrMandatoryAssertions bool
	enableStreaming                bool

	scannerPool *sync.Pool
}

// NewCompiledProgram prepares compiled rules for scanning. Preparation errors
// are returned by Validate and scan methods. The returned program owns its
// rule structs, assertions, required and forbidden string lists, regex map,
// hex map and pattern structs, and derived caches. It borrows the remaining
// rule data, which callers must treat as immutable.
func NewCompiledProgram(rules []*CompiledRule) *CompiledProgram {
	owned := make([]*CompiledRule, len(rules))
	for index, rule := range rules {
		if rule == nil {
			continue
		}
		copyRule := *rule
		copyRule.assertions = slices.Clone(rule.assertions)
		copyRule.requiredStrings = slices.Clone(rule.requiredStrings)
		copyRule.forbiddenStrings = slices.Clone(rule.forbiddenStrings)
		copyRule.RegexPatterns = maps.Clone(rule.RegexPatterns)
		copyRule.HexPatterns = make(map[string]*HexPattern, len(rule.HexPatterns))
		for id, pattern := range rule.HexPatterns {
			if pattern != nil {
				copyPattern := *pattern
				copyRule.HexPatterns[id] = &copyPattern
			}
		}
		owned[index] = &copyRule
	}
	return newCompiledProgramWithCacheValidation(owned, true)
}

func newCompiledProgram(rules []*CompiledRule) *CompiledProgram {
	return newCompiledProgramWithCacheValidation(rules, false)
}

func newCompiledProgramWithCacheValidation(rules []*CompiledRule, validateCacheKeys bool) *CompiledProgram {
	program := &CompiledProgram{
		Rules:          rules,
		Stats:          make(map[string]any),
		externalValues: new(atomic.Pointer[map[string]externalValue]),
	}
	program.scannerPool = &sync.Pool{
		New: func() any {
			return NewScanner(program)
		},
	}
	program.preparationErr = program.prepare(validateCacheKeys)
	return program
}

func (cp *CompiledProgram) loadExternalValues() map[string]externalValue {
	if cp == nil || cp.externalValues == nil {
		return nil
	}
	if extPtr := cp.externalValues.Load(); extPtr != nil {
		return *extPtr
	}
	return nil
}

func (cp *CompiledProgram) acquireScanner() *Scanner {
	if cp == nil || cp.scannerPool == nil {
		return NewScanner(cp)
	}
	s, ok := cp.scannerPool.Get().(*Scanner)
	if !ok || s == nil {
		return NewScanner(cp)
	}
	if ext := cp.loadExternalValues(); len(ext) > 0 {
		s.externalValues = maps.Clone(ext)
	} else {
		s.externalValues = nil
	}
	return s
}

func (cp *CompiledProgram) releaseScanner(s *Scanner) {
	if cp == nil || cp.scannerPool == nil || s == nil {
		return
	}
	if s.matchCtx != nil {
		s.matchCtx.Data = nil
	}
	s.moduleCache.reset()
	s.blockContext[0].Data = nil
	s.skipUnmatchedNonText = false
	cp.scannerPool.Put(s)
}

func (cp *CompiledProgram) prepare(validateCacheKeys bool) error {
	if err := cp.Validate(); err != nil {
		return err
	}
	cp.moduleSchemas = map[string]*ModuleSchema{}
	cp.dependencies = make(map[string][]string, len(cp.Rules))
	names := make(map[string]bool, len(cp.Rules))
	for index, rule := range cp.Rules {
		if rule.Name == "" {
			return fmt.Errorf("rule %d has empty rule name", index)
		}
		if names[rule.Name] {
			return fmt.Errorf("duplicate rule name %q", rule.Name)
		}
		if rule.Index != index {
			return fmt.Errorf("rule %q index %d does not match position %d", rule.Name, rule.Index, index)
		}
		names[rule.Name] = true
		for name, schema := range rule.moduleSchemas {
			if prior := cp.moduleSchemas[name]; prior != nil && prior != schema && !reflect.DeepEqual(prior, schema) {
				return fmt.Errorf("conflicting schema for module %q", name)
			}
			cp.moduleSchemas[name] = schema
		}
		for _, pattern := range rule.HexPatterns {
			if pattern != nil {
				pattern.scanMetadata = prepareHexScanMetadata(pattern)
			}
		}
		rule.BuildStringIndex()
		if len(rule.HeaderConstraints) > 0 || len(rule.mandatoryAssertions) > 0 {
			cp.hasHeaderOrMandatoryAssertions = true
		}
		if rule.dependencies != nil {
			cp.dependencies[rule.Name] = slices.Clone(rule.dependencies)
			slices.Sort(cp.dependencies[rule.Name])
		}
	}
	// Schemas agree across rules. Compare the built-in schema once, including
	// when deserialization has reconstructed it at a different address.
	nativePE := isNativePESchema(cp.moduleSchemas["pe"])
	schema := cp.moduleSchemas["pcap"]
	cp.nativePCAP = nativePCAPSchema(schema)
	for _, rule := range cp.Rules {
		rule.nativePE = nativePE && rule.moduleSchemas["pe"] != nil
		rule.nativePCAP = cp.nativePCAP && rule.moduleSchemas["pcap"] != nil
	}
	cp.assignSharedAssertions()
	var err error
	cp.nonTextCacheSize, err = assignNonTextCacheIndices(cp.Rules, validateCacheKeys)
	if err != nil {
		return err
	}
	cp.fixedRegexScan = buildFixedRegexDispatch(cp.Rules)
	cp.sharedAutomaton, cp.sharedLookup, err = buildSharedPatternAutomaton(cp.Rules)
	if err != nil {
		return err
	}
	cp.sharedNonTextCaches = sharedNonTextCacheCoverage(cp.nonTextCacheSize, cp.sharedLookup)
	cp.allRulesUseSharedPatterns = true
	for _, rule := range cp.Rules {
		if len(rule.DeadStrings) > 0 || !cp.ruleAllStringsInSharedPrefilter(rule) {
			cp.allRulesUseSharedPatterns = false
			break
		}
	}
	markSharedLookupCandidateTriggers(cp.Rules, cp.sharedLookup, cp.sharedNonTextCaches)
	cp.sharedNonTextCacheRules = sharedNonTextCacheRuleLookup(cp.Rules, cp.sharedNonTextCaches)
	cp.prepareCombinedRegex()
	buildHexFanoutDiscriminators(cp.Rules, cp.sharedLookup)
	cp.compactPrefilter = cp.buildCompactPrefilter()
	cp.booleanRouting = sync.OnceValue(cp.buildBooleanRouting)
	for _, entry := range cp.sharedLookup {
		if entry.Kind == StringKindText || entry.alternativeAtom || entry.forceShared {
			cp.sharedHasTextOrAlternative = true
			break
		}
	}
	return nil
}

// RuleDependencies returns the direct rule references made by name. The
// returned slice is sorted and independent of the program's internal state.
func (cp *CompiledProgram) RuleDependencies(name string) []string {
	return slices.Clone(cp.dependencies[name])
}

// RuleDependents returns the rules that directly reference name. The returned
// slice is sorted and independent of the program's internal state.
func (cp *CompiledProgram) RuleDependents(name string) []string {
	dependents := make([]string, 0)
	for rule, dependencies := range cp.dependencies {
		if slices.Contains(dependencies, name) {
			dependents = append(dependents, rule)
		}
	}
	slices.Sort(dependents)
	return dependents
}

// DependencyGraph returns all direct rule-to-rule dependencies.
func (cp *CompiledProgram) DependencyGraph() map[string][]string {
	graph := make(map[string][]string, len(cp.dependencies))
	for rule, dependencies := range cp.dependencies {
		graph[rule] = slices.Clone(dependencies)
	}
	return graph
}

// SetExternalVariables replaces runtime values for declared external variables.
func (cp *CompiledProgram) SetExternalVariables(vars map[string]any) error {
	values, err := normalizeExternalVariables(cp, vars)
	if err != nil {
		return err
	}
	if cp.externalValues == nil {
		cp.externalValues = new(atomic.Pointer[map[string]externalValue])
	}
	if len(values) == 0 {
		cp.externalValues.Store(nil)
	} else {
		cp.externalValues.Store(&values)
	}
	return nil
}

// SetsharedAutomaton returns an error because the shared automaton and its
// routing tables are built together when the program is created.
//
// Deprecated: Create a new compiled program to change its rules and automaton.
func (*CompiledProgram) SetsharedAutomaton(*acAutomaton) error {
	return errors.New("cannot replace a compiled program's shared automaton")
}

// GetRuleCount returns the number of compiled rules
func (cp *CompiledProgram) GetRuleCount() int {
	return len(cp.Rules)
}

// GetStringCount returns the total number of strings across all rules
func (cp *CompiledProgram) GetStringCount() int {
	total := 0
	for _, rule := range cp.Rules {
		total += rule.GetStringCount()
	}
	return total
}

// GetTotalBytecodeSize returns the total size of all bytecode
func (cp *CompiledProgram) GetTotalBytecodeSize() int {
	total := 0
	for _, rule := range cp.Rules {
		total += len(rule.Bytecode)
	}
	return total
}

// GetTotalMemoryUsage returns the sum of each rule's heuristic memory estimate.
// It is intended for relative sizing and diagnostics, not exact Go heap
// accounting for the compiled program.
func (cp *CompiledProgram) GetTotalMemoryUsage() int {
	total := 0
	for _, rule := range cp.Rules {
		total += rule.GetMemoryUsage()
	}
	return total
}

// Validate validates all compiled rules
func (cp *CompiledProgram) Validate() error {
	if cp.preparationErr != nil {
		return cp.preparationErr
	}
	for i, rule := range cp.Rules {
		if rule == nil {
			return fmt.Errorf("rule %d is nil", i)
		}
		if err := rule.Validate(); err != nil {
			return fmt.Errorf("validating rule %d (%s): %w", i, rule.Name, err)
		}
	}
	return validateProgramBytecodeRuleRefs(cp)
}

// GetRuleByName finds a rule by name. The returned pointer is borrowed from the
// compiled program and should be treated as immutable while scanners use it.
func (cp *CompiledProgram) GetRuleByName(name string) (*CompiledRule, bool) {
	for _, rule := range cp.Rules {
		if rule.Name == name {
			return rule, true
		}
	}
	return nil, false
}

func (cp *CompiledProgram) totalInstructionCount() int {
	total := 0
	for _, rule := range cp.Rules {
		if count, ok := rule.Stats["instruction_count"].(int); ok {
			total += count
		}
	}
	return total
}

// streamingMu guards program streaming configuration and publication of the
// latest progress pointer. Programs may be shallow-copied or initialized
// without a constructor, so the lock lives outside the program. It is held
// only for configuration, scan setup, and progress snapshots.
var streamingMu sync.Mutex

// EnableStreaming enables or disables pattern-only streaming for future scans.
func (cp *CompiledProgram) EnableStreaming(enable bool) {
	streamingMu.Lock()
	defer streamingMu.Unlock()
	cp.enableStreaming = enable
	if enable && cp.streamingProcessor == nil {
		cp.streamingProcessor = NewStreamingProcessor(cp)
	}
}

// IsStreamingEnabled reports whether streaming is enabled for future scans.
func (cp *CompiledProgram) IsStreamingEnabled() bool {
	streamingMu.Lock()
	defer streamingMu.Unlock()
	return cp.enableStreaming
}

// SetStreamingChunkSize sets the chunk size for future scans after the first
// call to EnableStreaming(true).
func (cp *CompiledProgram) SetStreamingChunkSize(chunkSize int) {
	streamingMu.Lock()
	defer streamingMu.Unlock()
	if cp.streamingProcessor != nil {
		cp.streamingProcessor.SetChunkSize(chunkSize)
	}
}

// EnableStreamingEarlyTermination sets whether future scans stop after the
// first matching chunk, after the first call to EnableStreaming(true).
func (cp *CompiledProgram) EnableStreamingEarlyTermination(enable bool) {
	streamingMu.Lock()
	defer streamingMu.Unlock()
	if cp.streamingProcessor != nil {
		cp.streamingProcessor.EnableEarlyTermination(enable)
	}
}

// ProcessFileStreaming returns text-pattern matches from a file using chunked
// streaming. Concurrent calls use independent scan state and the configuration
// in effect when each call starts. Use ScanFile for full rule evaluation.
func (cp *CompiledProgram) ProcessFileStreaming(ctx context.Context, filename string) ([]StreamingMatch, error) {
	scan, err := cp.startStreamingScan()
	if err != nil {
		return nil, err
	}
	return scan.ProcessFile(ctx, filename)
}

// ProcessBytesStreaming returns text-pattern matches from byte data using
// chunked streaming. Concurrent calls use independent scan state and the
// configuration in effect when each call starts. Use Scan for full rule
// evaluation.
func (cp *CompiledProgram) ProcessBytesStreaming(ctx context.Context, data []byte) ([]StreamingMatch, error) {
	scan, err := cp.startStreamingScan()
	if err != nil {
		return nil, err
	}
	return scan.ProcessBytes(ctx, data)
}

func (cp *CompiledProgram) startStreamingScan() (StreamingProcessor, error) {
	streamingMu.Lock()
	defer streamingMu.Unlock()
	if !cp.enableStreaming {
		return StreamingProcessor{}, errors.New("streaming is not enabled")
	}

	scan := *cp.streamingProcessor
	scan.progress = &streamingProgress{}
	cp.streamingProcessor.progress = scan.progress
	return scan, nil
}

// GetStreamingProgress returns progress for the most recently started scan,
// even if an earlier scan is still running.
func (cp *CompiledProgram) GetStreamingProgress() (processed, total int64, percent float64, matches int) {
	streamingMu.Lock()
	defer streamingMu.Unlock()
	if cp.streamingProcessor != nil {
		return cp.streamingProcessor.GetProgress()
	}
	return 0, 0, 0, 0
}
