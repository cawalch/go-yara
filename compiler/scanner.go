package compiler

import (
	"context"
	"fmt"
	"io"
	"maps"
	"math"
	"os"
	"slices"

	"github.com/cawalch/go-yara/regex"
)

// Scanner provides a reusable, allocation-efficient YARA scanning engine.
//
// A Scanner is safe to reuse across multiple Scan calls but is NOT safe for
// concurrent use. Use one Scanner per goroutine.
type Scanner struct {
	program     *CompiledProgram
	interp      *Interpreter    // reused across calls
	matchCtx    *MatchContext   // reused across calls
	ruleResults map[string]bool // reused across calls
	tagsFilter  map[string]bool // non-empty means: only scan rules with these tags
	itersmax    int             // max for-loop iterations (0 = unlimited)

	matchDataMax        int
	matchContextBefore  int
	matchContextAfter   int
	matchContextEnabled bool

	externalValues      map[string]externalValue
	externalErr         error
	nonTextCache        nonTextMatchCache
	regexByteSetCache   regexByteSetCandidateCache
	reportedMatchesOnly bool
	fastScan            bool
	evidenceMax         int

	// Candidate offsets grouped by SharedLookup index and retained across scans.
	prefilterCandidates [][]int
	// Non-empty candidate slots from the previous scan. Keeping this sparse list
	// avoids clearing every shared-lookup slot for each small event.
	touchedPrefilterCandidates []int
	// Shared text matches grouped by rule index and retained across scans.
	globalMatches [][]globalMatchEntry
	// Non-empty rule slots from the previous scan. High-cardinality rulesets
	// commonly touch no rules for an event, so a full rules-sized reset is waste.
	touchedGlobalMatches []int
	// Fast-scan candidate keys retained across scans.
	fastSeen map[uint64]bool

	// allEvaluatedRulesRequireSharedPatterns proves that every rule this scanner
	// can evaluate is false when the shared automaton's complete text and
	// non-text covers produce no exact matches.
	allEvaluatedRulesRequireSharedPatterns bool
	sharedNonTextMatched                   bool
	alwaysEvaluateSharedRules              []int
	evaluatedGlobalRules                   []int
	// Candidate rule indices are deduplicated and sorted before sparse exact
	// condition evaluation.
	candidateRuleIndices []int
	candidateRuleSeen    []bool

	// Test-only escape hatch used by parity coverage.
	prefilterDisabled bool
}

// ScanResult represents the result of scanning data against compiled rules.
type ScanResult struct {
	MatchedRules []RuleMatch
	// PrunedRules lists rules rejected by mandatory fixed-offset header
	// constraints before pattern matching.
	PrunedRules []string

	// RuleResults contains the boolean condition result for every evaluated rule.
	RuleResults map[string]bool

	// Matches contains per-rule pattern matches, keyed by rule name and string identifier.
	Matches map[string]map[string][]Match

	// Evidence contains candidate tuples keyed first by rule, then declaration.
	Evidence map[string]map[string][]EvidenceFinding
}

// RuleMatch represents a single rule match with details.
type RuleMatch struct {
	Rule     string
	Tags     []string           // Rule tags
	Meta     map[string]any     // Rule metadata
	Matches  map[string][]Match // pattern -> matches (string-keyed for public API)
	Evidence map[string][]EvidenceFinding
}

// ScannerOption configures a Scanner.
type ScannerOption func(*Scanner)

// WithTagsFilter restricts scanning to rules that have at least one of the given tags.
// Global rules are always evaluated regardless of tags.
func WithTagsFilter(tags []string) ScannerOption {
	filter := make(map[string]bool, len(tags))
	for _, t := range tags {
		filter[t] = true
	}
	return func(s *Scanner) {
		s.tagsFilter = filter
	}
}

// WithItersmax sets a limit on the total number of for-loop iterations.
// A value of 0 means unlimited. Corresponds to YARA's ITERSMAX compile-time constant.
func WithItersmax(limit int) ScannerOption {
	return func(scanner *Scanner) {
		scanner.itersmax = limit
	}
}

// WithMatchData includes up to maxBytes of matched data in each reported match.
// Non-positive values disable matched data evidence.
func WithMatchData(maxBytes int) ScannerOption {
	if maxBytes < 0 {
		maxBytes = 0
	}
	return func(scanner *Scanner) {
		scanner.matchDataMax = maxBytes
	}
}

// WithEvidence enables capture extraction and correlation, copying at most
// maxCaptureBytes per capture. Non-positive values disable evidence.
func WithEvidence(maxCaptureBytes int) ScannerOption {
	if maxCaptureBytes < 0 {
		maxCaptureBytes = 0
	}
	return func(scanner *Scanner) {
		scanner.evidenceMax = maxCaptureBytes
	}
}

// WithMatchContext includes byte context before and after each reported match.
// Negative values are treated as zero.
func WithMatchContext(beforeBytes, afterBytes int) ScannerOption {
	if beforeBytes < 0 {
		beforeBytes = 0
	}
	if afterBytes < 0 {
		afterBytes = 0
	}
	return func(scanner *Scanner) {
		scanner.matchContextBefore = beforeBytes
		scanner.matchContextAfter = afterBytes
		scanner.matchContextEnabled = true
	}
}

// WithReportedMatchesOnly restricts ScanResult.Matches to public rules that
// matched. RuleResults remains unchanged. This avoids materializing matches for
// private and non-matching rules when scanning match-dense inputs.
func WithReportedMatchesOnly() ScannerOption {
	return func(scanner *Scanner) {
		scanner.reportedMatchesOnly = true
	}
}

// WithFastScan retains only the first occurrence of each pattern for rules
// whose conditions only test pattern presence. Rules that inspect counts,
// offsets, lengths, or constrained ranges automatically retain all matches so
// their condition result remains exact.
func WithFastScan() ScannerOption {
	return func(scanner *Scanner) {
		scanner.fastScan = true
	}
}

// WithExternalVariables provides runtime values for declared external variables.
//
// Invalid variable names or unsupported values are reported by Scan.
func WithExternalVariables(vars map[string]any) ScannerOption {
	return func(scanner *Scanner) {
		if err := scanner.SetExternalVariables(vars); err != nil {
			scanner.externalErr = err
		}
	}
}

// NewScanner creates a new Scanner for the given compiled program.
func NewScanner(program *CompiledProgram, opts ...ScannerOption) *Scanner {
	interp := acquireScannerInterpreter()
	if program != nil {
		// CompiledProgram owns this slice for the scanner's lifetime, so avoid
		// the public API's defensive copy on scanner construction.
		interp.setCompiledRules(program.Rules)
	}

	ctx := matchContextPool.Get().(*MatchContext)
	ctx.compact = true

	s := &Scanner{
		program:     program,
		interp:      interp,
		matchCtx:    ctx,
		ruleResults: make(map[string]bool),
	}
	if program != nil {
		s.externalValues = cloneExternalValues(program.externalValues)
	}
	for _, opt := range opts {
		opt(s)
	}
	s.allEvaluatedRulesRequireSharedPatterns = s.computeAllEvaluatedRulesRequireSharedPatterns()
	return s
}

func (s *Scanner) computeAllEvaluatedRulesRequireSharedPatterns() bool {
	if s == nil || s.program == nil {
		return false
	}
	for _, rule := range s.program.Rules {
		if !rule.IsGlobal && !s.hasMatchingTag(rule) {
			continue
		}
		if rule.IsGlobal {
			s.evaluatedGlobalRules = append(s.evaluatedGlobalRules, rule.Index)
		}
		if !s.ruleHasCompleteSharedPrefilter(rule) {
			s.alwaysEvaluateSharedRules = append(s.alwaysEvaluateSharedRules, rule.Index)
		}
	}
	return len(s.alwaysEvaluateSharedRules) == 0
}

func (s *Scanner) ruleHasCompleteSharedPrefilter(rule *CompiledRule) bool {
	if !rule.RequiresStringMatch || len(rule.prefilterStrings) == 0 {
		return false
	}
	for _, info := range rule.prefilterStrings {
		switch info.class {
		case prefilterStringText:
		case prefilterStringNonText:
			if info.cacheIndex < 0 || info.cacheIndex >= len(s.program.sharedNonTextCaches) ||
				!s.program.sharedNonTextCaches[info.cacheIndex] {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func (s *Scanner) getNonTextMatches(
	cache *nonTextMatchCache,
	index int,
	useSharedAutomaton bool,
) ([]matchSpan, bool) {
	if matches, ready := cache.get(index); ready {
		return matches, true
	}
	if useSharedAutomaton && index >= 0 && index < len(s.program.sharedNonTextCaches) &&
		s.program.sharedNonTextCaches[index] {
		return nil, true
	}
	return nil, false
}

func (s *Scanner) resetCandidateRules(size int) {
	if cap(s.candidateRuleSeen) < size {
		s.candidateRuleSeen = make([]bool, size)
	} else {
		for _, index := range s.candidateRuleIndices {
			if index >= 0 && index < len(s.candidateRuleSeen) {
				s.candidateRuleSeen[index] = false
			}
		}
		s.candidateRuleSeen = s.candidateRuleSeen[:size]
	}
	s.candidateRuleIndices = s.candidateRuleIndices[:0]
	for _, index := range s.alwaysEvaluateSharedRules {
		s.markCandidateRule(index)
	}
}

func (s *Scanner) markCandidateRule(index int) {
	if index < 0 || index >= len(s.candidateRuleSeen) || s.candidateRuleSeen[index] {
		return
	}
	s.candidateRuleSeen[index] = true
	s.candidateRuleIndices = append(s.candidateRuleIndices, index)
}

func (s *Scanner) markNonTextCacheRules(cacheIndex int) {
	if cacheIndex < 0 || cacheIndex >= len(s.program.sharedNonTextCacheRules) {
		return
	}
	for _, ruleIndex := range s.program.sharedNonTextCacheRules[cacheIndex] {
		s.markCandidateRule(ruleIndex)
	}
}

func acquireScannerInterpreter() *Interpreter {
	interp := interpreterPool.Get().(*Interpreter)
	interp.bytecode = nil
	interp.ip = 0
	interp.stack = interp.stack[:0]
	for idx := range interp.memory {
		interp.memory[idx] = Value{}
	}
	interp.iterators = interp.iterators[:0]
	interp.stopped = false
	interp.result = nil
	interp.matchContext = nil
	interp.ruleResults = nil
	interp.currentRule = ""
	interp.currentCompiledRule = nil
	interp.compiledRules = nil
	interp.stringLiterals = nil
	interp.stringSets = nil
	interp.allStrings = nil
	interp.anonymousStrings = nil
	interp.stringArena = interp.stringArena[:0]
	if interp.regexCache == nil {
		interp.regexCache = make(map[string]compiledRegex)
	}
	interp.PreserveRuleResults = true
	return interp
}

// Close releases resources held by the Scanner.
func (s *Scanner) Close() {
	if s.interp != nil {
		s.interp.PreserveRuleResults = false
		s.interp.Release()
		s.interp = nil
	}
	if s.matchCtx != nil {
		s.matchCtx.Release()
		s.matchCtx = nil
	}
}

// NewScanner creates a Scanner for this compiled program.
func (cp *CompiledProgram) NewScanner(opts ...ScannerOption) *Scanner {
	return NewScanner(cp, opts...)
}

// Scan evaluates all rules in this compiled program against data.
func (cp *CompiledProgram) Scan(data []byte) (*ScanResult, error) {
	return cp.ScanWithContext(context.Background(), data)
}

// ScanWithContext evaluates all rules in this compiled program against data.
func (cp *CompiledProgram) ScanWithContext(ctx context.Context, data []byte) (*ScanResult, error) {
	scanner := NewScanner(cp)
	defer scanner.Close()
	return scanner.ScanWithContext(ctx, data)
}

// Matches reports whether this compiled program has at least one public rule
// match. Reuse a Scanner and call Scanner.Matches for the allocation-free
// prefilter reject path.
func (cp *CompiledProgram) Matches(data []byte) (bool, error) {
	return cp.MatchesWithContext(context.Background(), data)
}

// MatchesWithContext reports whether this compiled program has at least one
// public rule match.
func (cp *CompiledProgram) MatchesWithContext(ctx context.Context, data []byte) (bool, error) {
	scanner := NewScanner(cp)
	defer scanner.Close()
	return scanner.MatchesWithContext(ctx, data)
}

// ScanReader reads from r and evaluates all rules in this compiled program.
func (cp *CompiledProgram) ScanReader(r io.Reader) (*ScanResult, error) {
	return cp.ScanReaderWithContext(context.Background(), r)
}

// ScanReaderWithContext reads from r and evaluates all rules in this compiled program.
func (cp *CompiledProgram) ScanReaderWithContext(ctx context.Context, r io.Reader) (*ScanResult, error) {
	scanner := NewScanner(cp)
	defer scanner.Close()
	return scanner.ScanReaderWithContext(ctx, r)
}

// ScanFile reads filename and evaluates all rules in this compiled program.
func (cp *CompiledProgram) ScanFile(filename string) (*ScanResult, error) {
	return cp.ScanFileWithContext(context.Background(), filename)
}

// ScanFileWithContext reads filename and evaluates all rules in this compiled program.
func (cp *CompiledProgram) ScanFileWithContext(ctx context.Context, filename string) (*ScanResult, error) {
	scanner := NewScanner(cp)
	defer scanner.Close()
	return scanner.ScanFileWithContext(ctx, filename)
}

// globalMatchEntry is a match routed by integer indices from the shared automaton.
type globalMatchEntry struct {
	strID    string // string identifier (e.g. "$a")
	span     matchSpan
	isWide   bool   // whether this concrete automaton pattern is wide-encoded
	isNocase bool   // whether the originating string is nocase
	pattern  []byte // stored automaton pattern bytes for re-verification
}

type nonTextMatchCache struct {
	matches [][]matchSpan
	ready   []bool
	touched []int
}

func (cache *nonTextMatchCache) reset(size int) {
	if cap(cache.matches) < size || cap(cache.ready) < size {
		cache.matches = make([][]matchSpan, size)
		cache.ready = make([]bool, size)
		cache.touched = cache.touched[:0]
		return
	}
	for _, index := range cache.touched {
		if index >= 0 && index < len(cache.matches) {
			cache.matches[index] = cache.matches[index][:0]
		}
		if index >= 0 && index < len(cache.ready) {
			cache.ready[index] = false
		}
	}
	cache.matches = cache.matches[:size]
	cache.ready = cache.ready[:size]
	cache.touched = cache.touched[:0]
}

func (cache *nonTextMatchCache) get(index int) ([]matchSpan, bool) {
	if index < 0 || index >= len(cache.ready) || !cache.ready[index] {
		return nil, false
	}
	return cache.matches[index], true
}

func (cache *nonTextMatchCache) set(index int, matches []matchSpan) {
	if index < 0 || index >= len(cache.ready) {
		return
	}
	if !cache.ready[index] {
		cache.touched = append(cache.touched, index)
	}
	cache.matches[index] = matches
	cache.ready[index] = true
}

// hasMatchingTag returns true if the rule has at least one tag in the filter.
func (s *Scanner) hasMatchingTag(rule *CompiledRule) bool {
	if len(s.tagsFilter) == 0 {
		return true
	}
	for _, tag := range rule.Tags {
		if s.tagsFilter[tag] {
			return true
		}
	}
	return false
}

// Scan scans the provided byte slice against the compiled rules.
func (s *Scanner) Scan(data []byte) (*ScanResult, error) {
	return s.ScanWithContext(context.Background(), data)
}

// ScanWithContext scans the provided byte slice against the compiled rules.
func (s *Scanner) ScanWithContext(ctx context.Context, data []byte) (*ScanResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ruleCount := 0
	if s != nil && s.program != nil {
		ruleCount = len(s.program.Rules)
	}
	result := &ScanResult{
		MatchedRules: make([]RuleMatch, 0),
		PrunedRules:  make([]string, 0),
		RuleResults:  make(map[string]bool, ruleCount),
	}
	if s == nil || !s.reportedMatchesOnly {
		result.Matches = make(map[string]map[string][]Match)
	}
	if s == nil || s.program == nil {
		return result, nil
	}
	if s.externalErr != nil {
		return nil, s.externalErr
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	useSharedAutomaton, err := s.preparePatternScan(ctx, data)
	if err != nil {
		return nil, err
	}
	scanInput := ruleScanInput{data: data, useSharedAutomaton: useSharedAutomaton}

	clear(s.ruleResults)
	if !s.prefilterDisabled && s.allEvaluatedRulesPrefilterRejected(data, useSharedAutomaton) {
		for _, rule := range s.program.Rules {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if !rule.IsGlobal && !s.hasMatchingTag(rule) {
				continue
			}
			result.RuleResults[rule.Name] = false
			if !ruleHeaderConstraintsMatch(rule, data) {
				result.PrunedRules = append(result.PrunedRules, rule.Name)
			}
		}
		return result, nil
	}

	// YARA spec: global rules are evaluated first and ALL must match
	// before non-global rules are evaluated.
	// Private rules are never reported in MatchedRules.
	// Tag filtering: only evaluate rules with matching tags (global rules always evaluated).
	//
	// Two-pass approach:
	// 1. Evaluate all rules to populate match context and rule results.
	// 2. Build MatchedRules, skipping non-global rules if any global rule failed.

	// Pass 1: evaluate every rule
	s.interp.ResetIterationCount()
	for _, rule := range s.program.Rules {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// Global rules are always evaluated; others only if they match the tag filter.
		if !rule.IsGlobal && !s.hasMatchingTag(rule) {
			continue
		}
		evaluation, err := s.evaluateRuleCondition(ctx, rule, scanInput)
		if err != nil {
			return nil, err
		}
		if evaluation.pruned {
			result.PrunedRules = append(result.PrunedRules, rule.Name)
			result.RuleResults[rule.Name] = false
			continue
		}

		// The default preserves the historical all-evaluated-rules result shape.
		// The opt-in compact result mode materializes only matching public rules.
		materialize := !s.reportedMatchesOnly || evaluation.matched && !rule.IsPrivate
		if materialize && len(s.matchCtx.spans) > 0 {
			ruleMatches := materializeMatches(s.matchCtx.spans)
			ruleMatches = filterPrivateStrings(rule, ruleMatches)
			if err := s.populateMatchEvidence(ctx, data, ruleMatches); err != nil {
				return nil, err
			}
			if result.Matches == nil {
				result.Matches = make(map[string]map[string][]Match)
			}
			result.Matches[rule.Name] = ruleMatches
		}
		result.RuleResults[rule.Name] = evaluation.matched
	}

	// Check if all global rules matched
	allGlobalMatched := true
	for _, rule := range s.program.Rules {
		if rule.IsGlobal && !result.RuleResults[rule.Name] {
			allGlobalMatched = false
			break
		}
	}

	// Pass 2: build MatchedRules
	for _, rule := range s.program.Rules {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// Skip non-global rules if not all global rules matched
		if !rule.IsGlobal && !allGlobalMatched {
			if s.reportedMatchesOnly {
				delete(result.Matches, rule.Name)
			}
			continue
		}
		// Skip rules not matching the tag filter
		if !s.hasMatchingTag(rule) {
			if s.reportedMatchesOnly {
				delete(result.Matches, rule.Name)
			}
			continue
		}
		// Private rules are not reported in results
		if rule.IsPrivate {
			continue
		}
		// Evidence extraction is deliberately colocated with final public-rule
		// reporting so private or globally filtered matches cannot expose bytes.
		//nolint:nestif // the nested gates mirror that security-sensitive result boundary
		if result.RuleResults[rule.Name] {
			matches := result.Matches[rule.Name]
			// Filter out private strings from the report
			publicMatches := filterPrivateStrings(rule, matches)
			var evidence map[string][]EvidenceFinding
			if s.evidenceMax > 0 {
				var err error
				evidence, err = s.populateRuleEvidence(ctx, rule, publicMatches, func(match Match) (captureInput, bool) {
					if match.Offset < 0 || match.Length < 0 || match.Offset > int64(len(data)) {
						return captureInput{}, false
					}
					end := match.Offset + int64(match.Length)
					if end < match.Offset || end > int64(len(data)) {
						return captureInput{}, false
					}
					return captureInput{data: data, start: int(match.Offset), end: int(end)}, true
				})
				if err != nil {
					return nil, err
				}
			}
			if result.Matches == nil {
				result.Matches = make(map[string]map[string][]Match)
			}
			result.Matches[rule.Name] = publicMatches
			if len(evidence) != 0 {
				if result.Evidence == nil {
					result.Evidence = make(map[string]map[string][]EvidenceFinding)
				}
				result.Evidence[rule.Name] = evidence
			}
			result.MatchedRules = append(result.MatchedRules, newPublicRuleMatch(rule, publicMatches, evidence))
		}
	}

	clear(s.ruleResults)
	return result, nil
}

func newPublicRuleMatch(
	rule *CompiledRule,
	matches map[string][]Match,
	evidence map[string][]EvidenceFinding,
) RuleMatch {
	return RuleMatch{
		Rule:     rule.Name,
		Tags:     slices.Clone(rule.Tags),
		Meta:     maps.Clone(rule.Meta),
		Matches:  matches,
		Evidence: evidence,
	}
}

// Matches reports whether at least one public rule matches data. A reusable
// scanner can reject clean inputs without allocating once its internal buffers
// have been warmed.
func (s *Scanner) Matches(data []byte) (bool, error) {
	return s.MatchesWithContext(context.Background(), data)
}

// MatchesWithContext reports whether at least one public rule matches data.
func (s *Scanner) MatchesWithContext(ctx context.Context, data []byte) (bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if s == nil || s.program == nil {
		return false, nil
	}
	if s.externalErr != nil {
		return false, s.externalErr
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}

	useSharedAutomaton, err := s.preparePatternScan(ctx, data)
	if err != nil {
		return false, err
	}
	scanInput := ruleScanInput{data: data, useSharedAutomaton: useSharedAutomaton}
	clear(s.ruleResults)
	if !s.prefilterDisabled && useSharedAutomaton {
		if len(s.candidateRuleIndices) == 0 {
			return false, nil
		}
		return s.matchesSharedCandidates(ctx, scanInput)
	}
	if !s.prefilterDisabled && s.allEvaluatedRulesPrefilterRejected(data, useSharedAutomaton) {
		return false, nil
	}

	allGlobalMatched := true
	matchedPublicGlobal := false
	matchedPublicNonGlobal := false
	s.interp.ResetIterationCount()
	for _, rule := range s.program.Rules {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if !rule.IsGlobal && !s.hasMatchingTag(rule) {
			continue
		}

		evaluation, err := s.evaluateRuleCondition(ctx, rule, scanInput)
		if err != nil {
			return false, err
		}

		if rule.IsGlobal && !evaluation.matched {
			allGlobalMatched = false
		}
		if rule.IsPrivate || !s.hasMatchingTag(rule) || !evaluation.matched {
			continue
		}
		if rule.IsGlobal {
			matchedPublicGlobal = true
		} else {
			matchedPublicNonGlobal = true
		}
	}
	clear(s.ruleResults)
	return matchedPublicGlobal || allGlobalMatched && matchedPublicNonGlobal, nil
}

func (s *Scanner) matchesSharedCandidates(ctx context.Context, scanInput ruleScanInput) (bool, error) {
	slices.Sort(s.candidateRuleIndices)
	allGlobalMatched := true
	for _, ruleIndex := range s.evaluatedGlobalRules {
		if !s.candidateRuleSeen[ruleIndex] {
			allGlobalMatched = false
			break
		}
	}

	matchedPublicGlobal := false
	matchedPublicNonGlobal := false
	s.interp.ResetIterationCount()
	for _, ruleIndex := range s.candidateRuleIndices {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if ruleIndex < 0 || ruleIndex >= len(s.program.Rules) {
			continue
		}
		rule := s.program.Rules[ruleIndex]
		if !rule.IsGlobal && !s.hasMatchingTag(rule) {
			continue
		}

		evaluation, err := s.evaluateRuleCondition(ctx, rule, scanInput)
		if err != nil {
			return false, err
		}
		if rule.IsGlobal && !evaluation.matched {
			allGlobalMatched = false
		}
		if rule.IsPrivate || !s.hasMatchingTag(rule) || !evaluation.matched {
			continue
		}
		if rule.IsGlobal {
			matchedPublicGlobal = true
		} else {
			matchedPublicNonGlobal = true
		}
	}
	clear(s.ruleResults)
	return matchedPublicGlobal || allGlobalMatched && matchedPublicNonGlobal, nil
}

// ScanReader reads from the reader and scans the data.
func (s *Scanner) ScanReader(r io.Reader) (*ScanResult, error) {
	return s.ScanReaderWithContext(context.Background(), r)
}

// ScanReaderWithContext reads from the reader and scans the data.
func (s *Scanner) ScanReaderWithContext(ctx context.Context, r io.Reader) (*ScanResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s.ScanWithContext(ctx, data)
}

// ScanFile scans the given file.
func (s *Scanner) ScanFile(filename string) (*ScanResult, error) {
	return s.ScanFileWithContext(context.Background(), filename)
}

// ScanFileWithContext scans the given file.
func (s *Scanner) ScanFileWithContext(ctx context.Context, filename string) (*ScanResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filename) // #nosec G304 - caller intentionally scans this path
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s.ScanWithContext(ctx, data)
}

// extractGlobalMatchesInt uses the SharedLookup table for O(1) integer routing
// instead of parsing colon-delimited string IDs.
func (s *Scanner) extractGlobalMatchesInt(
	ctx context.Context,
	data []byte,
) error {
	lookup := s.program.SharedLookup
	rules := s.program.Rules
	globalByRule := s.globalMatches
	fastSeen := s.fastSeen
	if s.fastScan {
		if fastSeen == nil {
			fastSeen = make(map[uint64]bool)
			s.fastSeen = fastSeen
		} else {
			clear(fastSeen)
		}
	}
	// Keep the non-cancellable iterator as a distinct branch: routing an
	// iterator through an interface adds two allocations to clean Matches calls.
	//nolint:nestif // duplicated hot paths preserve the zero-allocation default
	if ctx.Done() == nil {
		for match := range s.program.SharedAutomaton.SearchIter(data) {
			if match.StringIndex < 0 || match.StringIndex >= len(lookup) {
				continue
			}

			entry := lookup[match.StringIndex]
			if entry.Kind == StringKindRegex || entry.Kind == StringKindHex {
				if len(s.prefilterCandidates[match.StringIndex]) == 0 {
					s.touchedPrefilterCandidates = append(s.touchedPrefilterCandidates, match.StringIndex)
				}
				s.prefilterCandidates[match.StringIndex] = append(
					s.prefilterCandidates[match.StringIndex],
					match.Backtrack,
				)
				continue
			}
			if entry.RuleIndex < 0 || entry.RuleIndex >= len(rules) {
				continue
			}

			rule := rules[entry.RuleIndex]
			if entry.StringIdx < 0 || entry.StringIdx >= len(rule.IndexToStringID) {
				continue
			}

			info := s.program.SharedAutomaton.strings[match.StringIndex]
			strID := rule.IndexToStringID[entry.StringIdx]
			globalEntry := globalMatchEntry{
				strID:    strID,
				span:     matchSpan{Offset: int64(match.Backtrack), Length: info.Length},
				isWide:   (info.Flags & regex.FlagsWide) != 0,
				isNocase: (info.Flags & regex.FlagsNoCase) != 0,
				pattern:  info.Data,
			}
			if s.fastScan && rule.FastScanSafe {
				key, ok := packFastScanKey(entry.RuleIndex, entry.StringIdx)
				if !ok {
					continue
				}
				if fastSeen[key] {
					continue
				}
				candidate := Match{
					Pattern: strID,
					Offset:  globalEntry.span.Offset,
					Length:  globalEntry.span.Length,
				}
				if !verifyTextMatch(data, candidate, globalEntry.pattern, globalEntry.isNocase) ||
					!matchPassesModifiers(data, candidate, rule.StringModifiers[strID], globalEntry.isWide) {
					continue
				}
				fastSeen[key] = true
			}
			if len(globalByRule[entry.RuleIndex]) == 0 {
				s.touchedGlobalMatches = append(s.touchedGlobalMatches, entry.RuleIndex)
			}
			globalByRule[entry.RuleIndex] = append(globalByRule[entry.RuleIndex], globalEntry)
			s.markCandidateRule(entry.RuleIndex)
		}
	} else {
		for match := range s.program.SharedAutomaton.searchIterWithCancel(data, ctx.Done()) {
			if match.StringIndex < 0 || match.StringIndex >= len(lookup) {
				continue
			}

			entry := lookup[match.StringIndex]
			if entry.Kind == StringKindRegex || entry.Kind == StringKindHex {
				if len(s.prefilterCandidates[match.StringIndex]) == 0 {
					s.touchedPrefilterCandidates = append(s.touchedPrefilterCandidates, match.StringIndex)
				}
				s.prefilterCandidates[match.StringIndex] = append(
					s.prefilterCandidates[match.StringIndex],
					match.Backtrack,
				)
				continue
			}
			if entry.RuleIndex < 0 || entry.RuleIndex >= len(rules) {
				continue
			}

			rule := rules[entry.RuleIndex]
			if entry.StringIdx < 0 || entry.StringIdx >= len(rule.IndexToStringID) {
				continue
			}

			info := s.program.SharedAutomaton.strings[match.StringIndex]
			strID := rule.IndexToStringID[entry.StringIdx]
			globalEntry := globalMatchEntry{
				strID:    strID,
				span:     matchSpan{Offset: int64(match.Backtrack), Length: info.Length},
				isWide:   (info.Flags & regex.FlagsWide) != 0,
				isNocase: (info.Flags & regex.FlagsNoCase) != 0,
				pattern:  info.Data,
			}
			if s.fastScan && rule.FastScanSafe {
				key, ok := packFastScanKey(entry.RuleIndex, entry.StringIdx)
				if !ok {
					continue
				}
				if fastSeen[key] {
					continue
				}
				candidate := Match{
					Pattern: strID,
					Offset:  globalEntry.span.Offset,
					Length:  globalEntry.span.Length,
				}
				if !verifyTextMatch(data, candidate, globalEntry.pattern, globalEntry.isNocase) ||
					!matchPassesModifiers(data, candidate, rule.StringModifiers[strID], globalEntry.isWide) {
					continue
				}
				fastSeen[key] = true
			}
			if len(globalByRule[entry.RuleIndex]) == 0 {
				s.touchedGlobalMatches = append(s.touchedGlobalMatches, entry.RuleIndex)
			}
			globalByRule[entry.RuleIndex] = append(globalByRule[entry.RuleIndex], globalEntry)
			s.markCandidateRule(entry.RuleIndex)
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.populateNonTextPrefilterCache(ctx, data, &s.nonTextCache)
}

// addStaticMatchesInt adds matches routed by integer indices to the match context.
//
//nolint:revive // hot path keeps prepared match state explicit
func (s *Scanner) addStaticMatchesInt(
	ctx context.Context,
	rule *CompiledRule,
	data []byte,
	entries []globalMatchEntry,
) error {
	done := ctx.Done()
	for index, e := range entries {
		if scanCanceledAt(done, index) {
			return ctx.Err()
		}
		if s.matchCtx.maxMatchesPerPattern > 0 && s.matchCtx.matchCount(e.strID) > 0 {
			continue
		}
		m := Match{Pattern: e.strID, Offset: e.span.Offset, Length: e.span.Length}
		// Re-verify the candidate bytes against the stored pattern. The shared
		// automaton registers both ASCII cases for nocase strings, so a
		// case-sensitive string whose output state lies on a nocase path could
		// fire on the wrong case; reject those false candidates here.
		if !verifyTextMatch(data, m, e.pattern, e.isNocase) {
			continue
		}
		modifiers := rule.StringModifiers[m.Pattern]
		if matchPassesModifiers(data, m, modifiers, e.isWide) {
			s.matchCtx.AddMatch(m)
		}
	}
	return ctx.Err()
}

func packFastScanKey(ruleIndex, stringIndex int) (uint64, bool) {
	if ruleIndex < 0 || stringIndex < 0 ||
		uint64(ruleIndex) > math.MaxUint32 || uint64(stringIndex) > math.MaxUint32 {
		return 0, false
	}
	key := uint64(ruleIndex)<<32 | uint64(stringIndex)
	return key, true
}

func (s *Scanner) addLocalTextMatches(ctx context.Context, rule *CompiledRule, data []byte) error {
	if rule == nil || rule.Automaton == nil || len(data) == 0 {
		return ctx.Err()
	}
	//nolint:nestif // separate iterator branches preserve zero-allocation Scan
	if s.matchCtx.maxMatchesPerPattern <= 0 {
		if ctx.Done() == nil {
			for match := range rule.Automaton.SearchIter(data) {
				acceptAutomatonMatch(s.matchCtx, rule, data, match)
			}
		} else {
			for match := range rule.Automaton.searchIterWithCancel(data, ctx.Done()) {
				acceptAutomatonMatch(s.matchCtx, rule, data, match)
			}
		}
		return ctx.Err()
	}

	matched := make(map[string]bool, len(rule.TextPatterns))
	//nolint:nestif // separate iterator branches preserve zero-allocation Scan
	if ctx.Done() == nil {
		for match := range rule.Automaton.SearchIter(data) {
			if matched[match.StringID] {
				continue
			}
			if acceptAutomatonMatch(s.matchCtx, rule, data, match) {
				matched[match.StringID] = true
				if len(matched) == len(rule.TextPatterns) {
					break
				}
			}
		}
	} else {
		for match := range rule.Automaton.searchIterWithCancel(data, ctx.Done()) {
			if matched[match.StringID] {
				continue
			}
			if acceptAutomatonMatch(s.matchCtx, rule, data, match) {
				matched[match.StringID] = true
				if len(matched) == len(rule.TextPatterns) {
					break
				}
			}
		}
	}
	return ctx.Err()
}

func (s *Scanner) populateFixedRegexCache(
	ctx context.Context,
	data []byte,
	cache *nonTextMatchCache,
) error {
	dispatch := s.program.fixedRegexScan
	if dispatch == nil || len(data) == 0 || !shouldUseFixedRegexDispatch(data, dispatch) {
		return ctx.Err()
	}
	done := ctx.Done()
	for position, value := range data {
		if scanCanceledAt(done, position) {
			return ctx.Err()
		}
		for _, entryIndex := range dispatch.buckets[value] {
			entry := dispatch.entries[entryIndex]
			if entry.wide && (position+1 >= len(data) || data[position+1] != 0) {
				continue
			}
			start := position - entry.atomOffset
			if start < 0 {
				continue
			}
			flags := entry.pattern.Flags &^ regex.FlagsWide
			if entry.wide {
				flags |= regex.FlagsWide
			}
			matched, startOffset, endOffset := execRegexMatchAt(nil, entry.pattern, data, flags, entry.wide, start)
			if !matched {
				continue
			}
			absoluteStart := start + startOffset
			absoluteEnd := start + endOffset
			if absoluteEnd < absoluteStart {
				continue
			}
			match := Match{Offset: int64(absoluteStart), Length: absoluteEnd - absoluteStart}
			if matchPassesModifiers(data, match, entry.modifiers, entry.wide) {
				cache.matches[entry.cacheIndex] = append(cache.matches[entry.cacheIndex], matchSpan{
					Offset: match.Offset,
					Length: match.Length,
				})
			}
		}
	}
	for _, order := range dispatch.cacheOrder {
		matches := cache.matches[order.cacheIndex]
		slices.SortStableFunc(matches, func(left, right matchSpan) int {
			leftWide := left.Length == order.wideLength
			rightWide := right.Length == order.wideLength
			switch {
			case leftWide == rightWide:
				return 0
			case leftWide:
				return -1
			default:
				return 1
			}
		})
	}
	for _, cacheIndex := range dispatch.cacheIndices {
		cache.set(cacheIndex, cache.matches[cacheIndex])
	}
	return ctx.Err()
}

func shouldUseSharedPatternAutomaton(data []byte, program *CompiledProgram) bool {
	if program == nil || program.SharedAutomaton == nil || len(program.SharedLookup) == 0 {
		return false
	}
	// Text strings rely on the shared automaton, and large non-text sets have
	// already crossed the compile-time threshold where one pass wins broadly.
	if len(program.SharedLookup) >= minSharedNonTextEntries {
		return true
	}
	for _, entry := range program.SharedLookup {
		if entry.Kind == StringKindText || entry.alternativeAtom || entry.forceShared {
			return true
		}
	}

	// Small non-text automata are profitable when their root bytes are sparse
	// in the input. Candidate-dense roots make the AC state machine more
	// expensive than independent SIMD literal searches, so sample the input.
	//
	// The independent path performs one search per entry, while the sparse-root
	// automaton performs one search per distinct root byte. Scale the tolerated
	// root density by that entries-per-root reuse ratio. This retains the old
	// one-hit-per-32-bytes crossover when every entry has its own root, while
	// avoiding repeated full-input scans when many entries share a root.
	if len(data) == 0 || len(program.SharedAutomaton.rootBytes) == 0 {
		return false
	}
	const (
		sampleBlocks     = 8
		sampleBlockSize  = 32
		rootDensityScale = 32
	)
	samples := 0
	rootHits := 0
	rootTransitions := &program.SharedAutomaton.states[0].transitions
	sampleAt := func(position int) {
		// A compiled automaton's goto table is closed over failure links, so an
		// absent root edge reads back as 0 rather than -1. No real transition can
		// target the root, so 0 is the "no root edge" test. Comparing against -1
		// here would count every byte as a root hit and stop the shared automaton
		// from ever being selected.
		if rootTransitions[data[position]] != 0 {
			rootHits++
		}
		samples++
	}
	if len(data) <= sampleBlocks*sampleBlockSize {
		for position := range data {
			sampleAt(position)
		}
	} else {
		maxStart := len(data) - sampleBlockSize
		for block := range sampleBlocks {
			start := block * maxStart / (sampleBlocks - 1)
			for position := start; position < start+sampleBlockSize; position++ {
				sampleAt(position)
			}
		}
	}
	return rootHits*rootDensityScale*len(program.SharedAutomaton.rootBytes) <
		samples*len(program.SharedLookup)
}

func shouldUseFixedRegexDispatch(data []byte, dispatch *fixedRegexDispatch) bool {
	if len(data) == 0 || dispatch == nil {
		return false
	}
	const maxSamples = 1024
	stride := max(1, len(data)/maxSamples)
	if stride > 1 {
		stride++
	}
	samples := 0
	bucketHits := 0
	for position := 0; position < len(data) && samples < maxSamples; position += stride {
		bucketHits += len(dispatch.buckets[data[position]])
		samples++
	}
	// Below roughly one routed pattern per sixteen sampled bytes, SIMD-backed
	// per-pattern searches are cheaper than scalar dispatch over the whole file.
	return bucketHits*16 >= samples
}

//nolint:revive // cache and cancellation state stay explicit on the matching hot path
func (s *Scanner) addLocalNonTextMatches(
	ctx context.Context,
	rule *CompiledRule,
	data []byte,
	cache *nonTextMatchCache,
	useSharedAutomaton bool,
) error {
	if rule == nil {
		return ctx.Err()
	}
	for id, regexInfo := range rule.RegexPatterns {
		if err := ctx.Err(); err != nil {
			return err
		}
		if matches, ok := s.getNonTextMatches(cache, regexInfo.cacheIndex, useSharedAutomaton); ok {
			addCachedMatches(s.matchCtx, id, matches)
			continue
		}
		modifiers := rule.StringModifiers[id]
		addRegexMatchesWithModifiersCached(s.matchCtx, id, regexInfo, data, modifiers, &s.regexByteSetCache)
		if s.matchCtx.maxMatchesPerPattern <= 0 && regexInfo.cacheIndex >= 0 && regexInfo.cacheIndex < len(cache.matches) {
			dst := cache.matches[regexInfo.cacheIndex][:0]
			dst = append(dst, s.matchCtx.spans[id]...)
			cache.set(regexInfo.cacheIndex, dst)
		}
	}
	for id, pattern := range rule.HexPatterns {
		if err := ctx.Err(); err != nil {
			return err
		}
		if pattern != nil {
			if matches, ok := s.getNonTextMatches(cache, pattern.cacheIndex, useSharedAutomaton); ok {
				addCachedMatches(s.matchCtx, id, matches)
				continue
			}
		}
		for _, m := range findHexMatches(pattern, data, ctx.Done()) {
			m.Pattern = id
			if matchPassesModifiers(data, m, rule.StringModifiers[id], false) {
				s.matchCtx.AddMatch(m)
			}
		}
		if s.matchCtx.maxMatchesPerPattern <= 0 && pattern != nil && pattern.cacheIndex >= 0 && pattern.cacheIndex < len(cache.matches) {
			dst := cache.matches[pattern.cacheIndex][:0]
			dst = append(dst, s.matchCtx.spans[id]...)
			cache.set(pattern.cacheIndex, dst)
		}
	}
	return ctx.Err()
}

func addCachedMatches(ctx *MatchContext, id string, matches []matchSpan) {
	for _, match := range matches {
		ctx.addMatchSpan(id, match)
	}
}

func (s *Scanner) prepareInterpreter(rule *CompiledRule) {
	s.interp.stringArena = s.interp.stringArena[:0]

	s.interp.SetCurrentRule(rule.Name)
	s.interp.SetMatchContext(s.matchCtx)
	s.interp.SetRuleResults(s.ruleResults)

	if rule.Automaton != nil {
		for idx, str := range rule.Automaton.strings {
			s.interp.SetMemoryString(idx, str.Identifier)
		}
	}
	s.setExternalVariables(rule)
	s.setGlobalVariables(rule)
}

func (s *Scanner) setExternalVariables(rule *CompiledRule) {
	for name, slot := range rule.ExternalSlots {
		value, ok := s.externalValues[name]
		if !ok {
			s.interp.memory[slot] = Value{Type: ValueTypeUndefined}
			continue
		}
		s.interp.memory[slot] = value.toInterpreterValue(s.interp)
	}
}

func (s *Scanner) setGlobalVariables(rule *CompiledRule) {
	for name, slot := range rule.GlobalSlots {
		value, ok := rule.GlobalValues[name]
		if !ok {
			s.interp.memory[slot] = Value{Type: ValueTypeUndefined}
			continue
		}
		s.interp.memory[slot] = value.toInterpreterValue(s.interp)
	}
}

func (v compiledGlobalValue) toInterpreterValue(interp *Interpreter) Value {
	switch v.valueType {
	case ValueTypeInt:
		return Value{Type: ValueTypeInt, IntVal: v.intVal}
	case ValueTypeDouble:
		return Value{Type: ValueTypeDouble, DoubleVal: v.doubleVal}
	case ValueTypeString:
		idx := len(interp.stringArena)
		interp.stringArena = append(interp.stringArena, v.stringVal)
		return Value{Type: ValueTypeString, StringRef: int64(idx)}
	default:
		return Value{Type: ValueTypeUndefined}
	}
}

// SetExternalVariables replaces runtime values for declared external variables.
func (s *Scanner) SetExternalVariables(vars map[string]any) error {
	values, err := normalizeExternalVariables(s.program, vars)
	if err != nil {
		return err
	}
	s.externalValues = values
	s.externalErr = nil
	return nil
}

type externalValue struct {
	valueType ValueType
	intVal    int64
	doubleVal float64
	stringVal string
}

func (v externalValue) toInterpreterValue(interp *Interpreter) Value {
	switch v.valueType {
	case ValueTypeInt:
		return Value{Type: ValueTypeInt, IntVal: v.intVal}
	case ValueTypeDouble:
		return Value{Type: ValueTypeDouble, DoubleVal: v.doubleVal}
	case ValueTypeString:
		idx := len(interp.stringArena)
		interp.stringArena = append(interp.stringArena, v.stringVal)
		return Value{Type: ValueTypeString, StringRef: int64(idx)}
	default:
		return Value{Type: ValueTypeUndefined}
	}
}

func normalizeExternalVariables(program *CompiledProgram, vars map[string]any) (map[string]externalValue, error) {
	if len(vars) == 0 {
		return nil, nil
	}

	declared := declaredExternalVariables(program)
	values := make(map[string]externalValue, len(vars))
	for name, raw := range vars {
		if !declared[name] {
			return nil, fmt.Errorf("external variable %q is not declared", name)
		}
		value, err := normalizeExternalValue(raw)
		if err != nil {
			return nil, fmt.Errorf("external variable %q: %w", name, err)
		}
		values[name] = value
	}
	return values, nil
}

func declaredExternalVariables(program *CompiledProgram) map[string]bool {
	declared := make(map[string]bool)
	if program == nil {
		return declared
	}
	for _, rule := range program.Rules {
		for name := range rule.ExternalSlots {
			declared[name] = true
		}
	}
	return declared
}

func normalizeExternalValue(value any) (externalValue, error) {
	switch v := value.(type) {
	case bool:
		if v {
			return externalValue{valueType: ValueTypeInt, intVal: 1}, nil
		}
		return externalValue{valueType: ValueTypeInt, intVal: 0}, nil
	case int:
		return externalValue{valueType: ValueTypeInt, intVal: int64(v)}, nil
	case int8:
		return externalValue{valueType: ValueTypeInt, intVal: int64(v)}, nil
	case int16:
		return externalValue{valueType: ValueTypeInt, intVal: int64(v)}, nil
	case int32:
		return externalValue{valueType: ValueTypeInt, intVal: int64(v)}, nil
	case int64:
		return externalValue{valueType: ValueTypeInt, intVal: v}, nil
	case uint:
		return normalizeExternalUint(uint64(v))
	case uint8:
		return normalizeExternalUint(uint64(v))
	case uint16:
		return normalizeExternalUint(uint64(v))
	case uint32:
		return normalizeExternalUint(uint64(v))
	case uint64:
		return normalizeExternalUint(v)
	case float32:
		return externalValue{valueType: ValueTypeDouble, doubleVal: float64(v)}, nil
	case float64:
		return externalValue{valueType: ValueTypeDouble, doubleVal: v}, nil
	case string:
		return externalValue{valueType: ValueTypeString, stringVal: v}, nil
	default:
		return externalValue{}, fmt.Errorf("unsupported value type %T", value)
	}
}

func normalizeExternalUint(value uint64) (externalValue, error) {
	if value > math.MaxInt64 {
		return externalValue{}, fmt.Errorf("unsigned integer %d exceeds int64 range", value)
	}
	return externalValue{valueType: ValueTypeInt, intVal: int64(value)}, nil
}

func cloneExternalValues(values map[string]externalValue) map[string]externalValue {
	if len(values) == 0 {
		return nil
	}
	cloned := make(map[string]externalValue, len(values))
	for name, value := range values {
		cloned[name] = value
	}
	return cloned
}

func (s *Scanner) populateMatchEvidence(ctx context.Context, data []byte, matches map[string][]Match) error {
	if s.matchDataMax <= 0 && !s.matchContextEnabled {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for id, perStringMatches := range matches {
		if err := ctx.Err(); err != nil {
			return err
		}
		for i := range perStringMatches {
			if err := ctx.Err(); err != nil {
				return err
			}
			s.populateSingleMatchEvidence(data, &perStringMatches[i])
		}
		matches[id] = perStringMatches
	}
	return nil
}

func (s *Scanner) populateSingleMatchEvidence(data []byte, match *Match) {
	if match.Offset < 0 || match.Length < 0 || match.Offset > int64(len(data)) {
		return
	}
	endOffset := match.Offset + int64(match.Length)
	if endOffset < match.Offset || endOffset > int64(len(data)) {
		return
	}

	start := int(match.Offset)
	end := int(endOffset)
	if s.matchDataMax > 0 {
		copyLength := match.Length
		if copyLength > s.matchDataMax {
			copyLength = s.matchDataMax
			match.MatchedDataTruncated = true
		}
		match.MatchedData = copyBytes(data[start : start+copyLength])
	}
	if s.matchContextEnabled {
		beforeStart := start - s.matchContextBefore
		if beforeStart < 0 {
			beforeStart = 0
		}
		afterEnd := end + s.matchContextAfter
		if afterEnd > len(data) {
			afterEnd = len(data)
		}
		match.ContextBefore = copyBytes(data[beforeStart:start])
		match.ContextAfter = copyBytes(data[end:afterEnd])
	}
}

func copyBytes(src []byte) []byte {
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}

func materializeMatches(src map[string][]matchSpan) map[string][]Match {
	matches := make(map[string][]Match, len(src))
	for id, spans := range src {
		if len(spans) == 0 {
			continue
		}
		dst := make([]Match, len(spans))
		for index, span := range spans {
			dst[index] = Match{Pattern: id, Offset: span.Offset, Length: span.Length}
		}
		matches[id] = dst
	}
	return matches
}

// filterPrivateStrings removes private strings from the matches map.
func filterPrivateStrings(rule *CompiledRule, matches map[string][]Match) map[string][]Match {
	for id := range matches {
		if rule.IsPrivateString(id) {
			delete(matches, id)
		}
	}
	return matches
}
