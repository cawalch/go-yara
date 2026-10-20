package compiler

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"

	"github.com/cawalch/go-yara/internal/wordmatch"
)

// sharedAutomatonEntry maps a shared automaton entry to its exact verifier.
type sharedAutomatonEntry struct {
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
	Rules           []*CompiledRule
	sharedAutomaton *acAutomaton
	Stats           map[string]any
	externalValues  map[string]externalValue

	// Lookup table: shared automaton entry -> exact text/regex/hex verifier.
	// Built once at compile time, used by extractGlobalMatches for O(1) routing.
	sharedLookup []sharedAutomatonEntry

	// Number of compile-time integer slots used to cache regex/hex matches.
	nonTextCacheSize int
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
	streamingProcessor         *StreamingProcessor
	sharedHasTextOrAlternative bool
	enableStreaming            bool

	scannerPool *sync.Pool
}

// NewCompiledProgram prepares compiled rules for scanning. Preparation errors
// are returned by Validate and scan methods. Input rules remain borrowed and
// immutable; derived per-program caches are owned by the returned program.
func NewCompiledProgram(rules []*CompiledRule) *CompiledProgram {
	owned := make([]*CompiledRule, len(rules))
	for index, rule := range rules {
		if rule == nil {
			continue
		}
		copyRule := *rule
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
	return newCompiledProgram(owned)
}

func newCompiledProgram(rules []*CompiledRule) *CompiledProgram {
	program := &CompiledProgram{Rules: rules, Stats: make(map[string]any)}
	program.scannerPool = &sync.Pool{
		New: func() any {
			return NewScanner(program)
		},
	}
	program.preparationErr = program.prepare()
	return program
}

func (cp *CompiledProgram) acquireScanner() *Scanner {
	if cp == nil || cp.scannerPool == nil {
		return NewScanner(cp)
	}
	if s, ok := cp.scannerPool.Get().(*Scanner); ok && s != nil {
		if len(cp.externalValues) > 0 {
			s.externalValues = maps.Clone(cp.externalValues)
		} else {
			s.externalValues = nil
		}
		return s
	}
	return NewScanner(cp)
}

func (cp *CompiledProgram) releaseScanner(s *Scanner) {
	if cp == nil || cp.scannerPool == nil || s == nil {
		return
	}
	if s.matchCtx != nil {
		s.matchCtx.Data = nil
	}
	s.blockContext[0].Data = nil
	s.skipUnmatchedNonText = false
	cp.scannerPool.Put(s)
}

func (cp *CompiledProgram) prepare() error {
	if err := cp.Validate(); err != nil {
		return err
	}
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
		rule.BuildStringIndex()
		if rule.dependencies != nil {
			cp.dependencies[rule.Name] = slices.Clone(rule.dependencies)
			slices.Sort(cp.dependencies[rule.Name])
		}
	}
	cp.nonTextCacheSize = assignNonTextCacheIndices(cp.Rules)
	cp.fixedRegexScan = buildFixedRegexDispatch(cp.Rules)
	var err error
	cp.sharedAutomaton, cp.sharedLookup, err = buildSharedPatternAutomaton(cp.Rules)
	if err != nil {
		return err
	}
	cp.sharedNonTextCaches = sharedNonTextCacheCoverage(cp.nonTextCacheSize, cp.sharedLookup)
	markSharedLookupCandidateTriggers(cp.Rules, cp.sharedLookup, cp.sharedNonTextCaches)
	cp.sharedNonTextCacheRules = sharedNonTextCacheRuleLookup(cp.Rules, cp.sharedNonTextCaches)
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
	cp.externalValues = values
	return nil
}

// SetsharedAutomaton attaches the global multi-rule search tree to the compiled program
func (cp *CompiledProgram) SetsharedAutomaton(automaton *acAutomaton) {
	cp.sharedAutomaton = automaton
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
	return nil
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

// Streaming methods for CompiledProgram.
//
// Streaming reports exact text-pattern matches only. It does not report regex
// or hex matches and does not evaluate rule condition bytecode. Use Scan,
// ScanReader, or ScanFile for full rule evaluation.

// EnableStreaming enables or disables pattern-only streaming for large files.
func (cp *CompiledProgram) EnableStreaming(enable bool) {
	cp.enableStreaming = enable
	if enable && cp.streamingProcessor == nil {
		cp.streamingProcessor = NewStreamingProcessor(cp)
	}
}

// IsStreamingEnabled returns true if streaming is enabled
func (cp *CompiledProgram) IsStreamingEnabled() bool {
	return cp.enableStreaming
}

// SetStreamingChunkSize sets the chunk size for streaming processing
func (cp *CompiledProgram) SetStreamingChunkSize(chunkSize int) {
	if cp.streamingProcessor != nil {
		cp.streamingProcessor.SetChunkSize(chunkSize)
	}
}

// EnableStreamingEarlyTermination enables or disables early termination in streaming
func (cp *CompiledProgram) EnableStreamingEarlyTermination(enable bool) {
	if cp.streamingProcessor != nil {
		cp.streamingProcessor.EnableEarlyTermination(enable)
	}
}

// ProcessFileStreaming returns text-pattern matches from a file using chunked streaming.
func (cp *CompiledProgram) ProcessFileStreaming(ctx context.Context, filename string) ([]StreamingMatch, error) {
	if !cp.enableStreaming {
		return nil, errors.New("streaming is not enabled")
	}

	if cp.streamingProcessor == nil {
		cp.streamingProcessor = NewStreamingProcessor(cp)
	}

	return cp.streamingProcessor.ProcessFile(ctx, filename)
}

// ProcessBytesStreaming returns text-pattern matches from byte data using chunked streaming.
func (cp *CompiledProgram) ProcessBytesStreaming(ctx context.Context, data []byte) ([]StreamingMatch, error) {
	if !cp.enableStreaming {
		return nil, errors.New("streaming is not enabled")
	}

	if cp.streamingProcessor == nil {
		cp.streamingProcessor = NewStreamingProcessor(cp)
	}

	return cp.streamingProcessor.ProcessBytes(ctx, data)
}

// GetStreamingProgress returns progress information for streaming operations
func (cp *CompiledProgram) GetStreamingProgress() (processed, total int64, percent float64, matches int) {
	if cp.streamingProcessor != nil {
		return cp.streamingProcessor.GetProgress()
	}
	return 0, 0, 0, 0
}
