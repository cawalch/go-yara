package compiler

import (
	"context"
	"io"

	"github.com/cawalch/go-yara/internal/wordmatch"
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
	tagsFilter  map[string]bool // non-empty means: only report rules with these tags
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
	evaluatedRules      map[string]bool

	booleanRoutingEnabled bool
	booleanRouting        *wordmatch.RoutedScanner

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
	// Public rules whose conditions matched during the current compact scan.
	// The indices are retained across calls; returned RuleMatch values are owned.
	matchedRuleIndices []int
	// Single-block scans reuse this slot to expose absolute addresses to the
	// interpreter without allocating a []MemoryBlock per event.
	blockContext  [1]MemoryBlock
	blockFileSize int64
	blockScan     bool

	// Test-only escape hatch used by parity coverage.
	prefilterDisabled bool

	// Hooks & Telemetry
	hookMask              hookMask
	hooks                 *ScanHooks
	telemetrySink         *ScanTelemetry
	trackTelemetryLatency bool
	ruleGate              RuleGateFunc
	matchHook             MatchHook
	pollByteStride        int
	maxMatchesLimit       int
	onMaxMatchesExceeded  func(rule string, count int)
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

// WithTagsFilter reports rules with at least one of the given tags.
// Their dependencies and all global rules are evaluated regardless of tags.
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
	if program != nil && program.preparationErr == nil {
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
	s.recomputeHookMask()
	s.selectEvaluatedRules()
	s.allEvaluatedRulesRequireSharedPatterns = s.computeAllEvaluatedRulesRequireSharedPatterns()
	if s.booleanRoutingEnabled && len(s.tagsFilter) == 0 && program != nil &&
		program.preparationErr == nil && program.booleanRouting != nil {
		if plan := program.booleanRouting(); plan != nil {
			s.booleanRouting = plan.NewScanner()
		}
	}
	return s
}

func (s *Scanner) computeAllEvaluatedRulesRequireSharedPatterns() bool {
	if s == nil || s.program == nil || s.program.preparationErr != nil {
		return false
	}
	for _, rule := range s.program.Rules {
		if !s.shouldEvaluateRule(rule) {
			continue
		}
		if rule.IsGlobal {
			s.evaluatedGlobalRules = append(s.evaluatedGlobalRules, rule.Index)
		}
		if !s.program.ruleHasCompleteSharedPrefilter(rule) {
			s.alwaysEvaluateSharedRules = append(s.alwaysEvaluateSharedRules, rule.Index)
		}
	}
	return len(s.alwaysEvaluateSharedRules) == 0
}

func (cp *CompiledProgram) ruleHasCompleteSharedPrefilter(rule *CompiledRule) bool {
	if !rule.RequiresStringMatch || len(rule.prefilterStrings) == 0 {
		return false
	}
	for _, info := range rule.prefilterStrings {
		switch info.class {
		case prefilterStringText:
		case prefilterStringNonText:
			if info.cacheIndex < 0 || info.cacheIndex >= len(cp.sharedNonTextCaches) ||
				!cp.sharedNonTextCaches[info.cacheIndex] {
				return false
			}
		default:
			return false
		}
	}
	return true
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
	interp.PreserveRuleResults = true
	return interp
}

// Close releases resources held by the Scanner.
func (s *Scanner) Close() {
	if s == nil {
		return
	}
	if s.interp != nil {
		s.interp.Release()
	}
	if s.matchCtx != nil {
		s.matchCtx.Release()
	}
	*s = Scanner{}
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

// MatchingRules returns detailed public rule matches without materializing a
// boolean result or match-map entry for every evaluated rule. Reuse a Scanner
// for high-throughput event streams.
func (cp *CompiledProgram) MatchingRules(data []byte) ([]RuleMatch, error) {
	return cp.MatchingRulesWithContext(context.Background(), data)
}

// MatchingRulesWithContext returns detailed public rule matches without
// materializing per-rule results for rules that did not match.
func (cp *CompiledProgram) MatchingRulesWithContext(ctx context.Context, data []byte) ([]RuleMatch, error) {
	scanner := NewScanner(cp)
	defer scanner.Close()
	return scanner.MatchingRulesWithContext(ctx, data)
}

// MatchingRulesInBlock evaluates public rules against one explicit block in a
// logical address space. Match offsets are absolute, and fileSize is visible to
// rule conditions. Patterns cannot inspect bytes outside block.
func (cp *CompiledProgram) MatchingRulesInBlock(
	block MemoryBlock,
	fileSize int64,
) ([]RuleMatch, error) {
	return cp.MatchingRulesInBlockWithContext(context.Background(), block, fileSize)
}

// MatchingRulesInBlockWithContext evaluates public rules against one explicit
// block without constructing the all-rules maps in ScanResult.
func (cp *CompiledProgram) MatchingRulesInBlockWithContext(
	ctx context.Context,
	block MemoryBlock,
	fileSize int64,
) ([]RuleMatch, error) {
	scanner := NewScanner(cp)
	defer scanner.Close()
	return scanner.MatchingRulesInBlockWithContext(ctx, block, fileSize)
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
