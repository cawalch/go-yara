package compiler

import (
	"context"
	"errors"
	"runtime"
	"time"
)

var (
	// ErrScanAborted is returned when a PollHook returns PollAbort.
	ErrScanAborted = errors.New("scan aborted by poll hook")

	// ErrMatchLimitExceeded is returned when max matches limit is exceeded and configured to abort.
	ErrMatchLimitExceeded = errors.New("scan match limit exceeded")
)

type hookMask uint32

const (
	hookBitScanLifecycle    hookMask = 1 << 0
	hookBitPrefilter        hookMask = 1 << 1
	hookBitPoll             hookMask = 1 << 2
	hookBitRuleProfile      hookMask = 1 << 3
	hookBitPatternProfile   hookMask = 1 << 4
	hookBitMatch            hookMask = 1 << 5
	hookBitTelemetry        hookMask = 1 << 6
	hookBitTelemetryLatency hookMask = 1 << 7
	hookBitRuleGate         hookMask = 1 << 8
	hookBitMaxMatches       hookMask = 1 << 9
	hookBitChunkBoundary    hookMask = 1 << 10

	defaultPollByteStride = 64 * 1024
)

// ScanTelemetry tracks aggregate and phase metrics for scans.
// It is designed to be mutated in-place with zero heap allocations.
type ScanTelemetry struct {
	TotalScans   uint64
	BytesScanned int64
	TotalMatches uint64

	PrefilterRejects uint64
	RulesPruned      uint64
	RulesEvaluated   uint64

	CandidateHits      uint64
	VerifiedMatches    uint64
	FalseCandidateHits uint64

	PrefilterDurationNs uint64
	PatternSearchNs     uint64
	ConditionEvalNs     uint64
	TotalScanDurationNs uint64
}

// Reset clears all counters for reuse in pooled workloads.
func (t *ScanTelemetry) Reset() {
	if t != nil {
		*t = ScanTelemetry{}
	}
}

// PollAction controls scanner execution when a poll event fires.
type PollAction uint8

const (
	// PollContinue instructs the scanner to continue execution normally.
	PollContinue PollAction = iota
	// PollYield yields CPU execution time to other goroutines via runtime.Gosched.
	PollYield
	// PollThrottle pauses scanning for the duration returned by PollHook before resuming.
	PollThrottle
	// PollAbort terminates the scanning operation immediately with context.Canceled.
	PollAbort
)

// ScanPhase indicates the scanner execution phase during polling.
type ScanPhase uint8

const (
	// PhaseUnknown represents an unspecified scanner execution phase.
	PhaseUnknown ScanPhase = iota
	// PhasePrefilter represents the prefilter candidate screening phase.
	PhasePrefilter
	// PhasePatternSearch represents the pattern scanning and verification phase.
	PhasePatternSearch
	// PhaseRuleCondition represents the bytecode rule condition evaluation phase.
	PhaseRuleCondition
	// PhaseBlockScan represents multi-block memory scanning aggregation.
	PhaseBlockScan
)

func (p ScanPhase) String() string {
	switch p {
	case PhasePrefilter:
		return "prefilter"
	case PhasePatternSearch:
		return "pattern_search"
	case PhaseRuleCondition:
		return "rule_condition"
	case PhaseBlockScan:
		return "block_scan"
	default:
		return "unknown"
	}
}

// PollProgress conveys current position during long-running scans.
type PollProgress struct {
	BytesScanned   int64
	TotalBytes     int64 // -1 if unknown
	Phase          ScanPhase
	CurrentRule    string
	RulesEvaluated int
	TotalRules     int
}

// PollHook is invoked cooperatively at stride intervals during scans.
type PollHook func(ctx context.Context, p PollProgress) (PollAction, time.Duration)

// RuleProfile captures performance attributes of an evaluated rule.
type RuleProfile struct {
	RuleName        string
	RuleIndex       int
	Duration        time.Duration
	ConditionSteps  int
	Matched         bool
	Pruned          bool
	CandidateHits   int
	VerifiedMatches int
}

// PatternProfile captures candidate verification cost for a specific pattern.
type PatternProfile struct {
	RuleName        string
	StringID        string
	Kind            StringKind
	CandidateHits   int
	VerifiedMatches int
	Selectivity     float64
}

// RuleEfficiencyHook receives profiling events after each rule evaluation.
type RuleEfficiencyHook func(profile RuleProfile)

// PatternEfficiencyHook receives profiling events for individual patterns.
type PatternEfficiencyHook func(profile PatternProfile)

// PrefilterStage identifies the prefilter evaluation tier.
type PrefilterStage uint8

const (
	// PrefilterStageWordRouting represents Tier 0 word-match prefiltering.
	PrefilterStageWordRouting PrefilterStage = iota
	// PrefilterStageCompactMask represents Tier 1 compact bitmask prefiltering.
	PrefilterStageCompactMask
	// PrefilterStagesharedAutomaton represents Tier 2 shared Aho-Corasick automaton screening.
	PrefilterStagesharedAutomaton
	// PrefilterStageHeaderConstraints represents Tier 3 fixed-offset header constraint evaluation.
	PrefilterStageHeaderConstraints
)

func (s PrefilterStage) String() string {
	switch s {
	case PrefilterStageWordRouting:
		return "word_routing"
	case PrefilterStageCompactMask:
		return "compact_mask"
	case PrefilterStagesharedAutomaton:
		return "shared_automaton"
	case PrefilterStageHeaderConstraints:
		return "header_constraints"
	default:
		return "unknown"
	}
}

// PrefilterDecision describes the outcome of a prefilter stage.
type PrefilterDecision struct {
	Stage          PrefilterStage
	Rejected       bool
	CandidateCount int
	DurationNs     int64
}

// PrefilterHook receives prefilter decisions.
type PrefilterHook func(d PrefilterDecision)

// RuleGateFunc allows dynamic rule skipping based on external metadata.
// Returning false skips rule evaluation immediately.
type RuleGateFunc func(rule *CompiledRule) bool

// MatchAction determines scanner behavior after a rule matches.
type MatchAction uint8

const (
	// MatchActionContinue continues evaluating remaining rules normally.
	MatchActionContinue MatchAction = iota
	// MatchActionStopScan aborts scanning of all subsequent rules immediately upon match.
	MatchActionStopScan
	// MatchActionSkipRule skips further pattern verification for the current rule.
	MatchActionSkipRule
)

// MatchHook is invoked immediately when a public rule matches.
type MatchHook func(rule *CompiledRule, match RuleMatch) MatchAction

// ChunkHook is called at chunk or block boundaries in streaming scans.
type ChunkHook func(offset int64, chunkSize int, matchesFound int)

// ScanHooks groups all scanner event callbacks and configuration.
type ScanHooks struct {
	OnScanStart    func(ctx context.Context, inputLen int64)
	OnScanComplete func(ctx context.Context, result *ScanResult, duration time.Duration)

	OnPrefilter PrefilterHook
	RuleGate    RuleGateFunc

	OnPoll         PollHook
	PollByteStride int

	OnRuleEvaluated  RuleEfficiencyHook
	OnPatternProfile PatternEfficiencyHook

	OnMatch MatchHook

	OnChunk ChunkHook

	MaxMatchesPerRule    int
	OnMaxMatchesExceeded func(rule string, count int)
}

// WithHooks configures a comprehensive ScanHooks structure on the scanner.
func WithHooks(hooks ScanHooks) ScannerOption {
	return func(s *Scanner) {
		copied := hooks
		s.hooks = &copied
		s.recomputeHookMask()
	}
}

// WithTelemetry registers an external telemetry sink updated in-place (counters only, zero latency cost).
func WithTelemetry(sink *ScanTelemetry) ScannerOption {
	return func(s *Scanner) {
		s.telemetrySink = sink
		s.trackTelemetryLatency = false
		s.recomputeHookMask()
	}
}

// WithTelemetryLatency registers a telemetry sink that also measures scan duration.
func WithTelemetryLatency(sink *ScanTelemetry) ScannerOption {
	return func(s *Scanner) {
		s.telemetrySink = sink
		s.trackTelemetryLatency = true
		s.recomputeHookMask()
	}
}

// WithPollHook configures cooperative polling and throttling.
func WithPollHook(hook PollHook, byteStride int) ScannerOption {
	return func(s *Scanner) {
		if s.hooks == nil {
			s.hooks = &ScanHooks{}
		}
		s.hooks.OnPoll = hook
		s.hooks.PollByteStride = byteStride
		s.recomputeHookMask()
	}
}

// WithRuleProfiling enables execution timing and profiling per rule.
func WithRuleProfiling(hook RuleEfficiencyHook) ScannerOption {
	return func(s *Scanner) {
		if s.hooks == nil {
			s.hooks = &ScanHooks{}
		}
		s.hooks.OnRuleEvaluated = hook
		s.recomputeHookMask()
	}
}

// WithPrefilterHook attaches prefilter observability.
func WithPrefilterHook(hook PrefilterHook) ScannerOption {
	return func(s *Scanner) {
		if s.hooks == nil {
			s.hooks = &ScanHooks{}
		}
		s.hooks.OnPrefilter = hook
		s.recomputeHookMask()
	}
}

// WithRuleGate allows caller to dynamically filter rules per scan.
func WithRuleGate(gate RuleGateFunc) ScannerOption {
	return func(s *Scanner) {
		s.ruleGate = gate
		s.recomputeHookMask()
	}
}

// WithMatchHook registers an immediate match callback.
func WithMatchHook(hook MatchHook) ScannerOption {
	return func(s *Scanner) {
		s.matchHook = hook
		s.recomputeHookMask()
	}
}

// WithMaxMatches configures a safety ceiling on matches per rule.
func WithMaxMatches(limit int, onExceeded func(rule string, count int)) ScannerOption {
	return func(s *Scanner) {
		s.maxMatchesLimit = limit
		s.onMaxMatchesExceeded = onExceeded
		s.recomputeHookMask()
	}
}

// WithChunkHook registers a chunk boundary hook for streaming/block scanners.
func WithChunkHook(hook ChunkHook) ScannerOption {
	return func(s *Scanner) {
		if s.hooks == nil {
			s.hooks = &ScanHooks{}
		}
		s.hooks.OnChunk = hook
		s.recomputeHookMask()
	}
}

func (s *Scanner) recomputeHookMask() {
	if s == nil {
		return
	}
	s.hookMask = 0
	if s.telemetrySink != nil {
		s.hookMask |= hookBitTelemetry
		if s.trackTelemetryLatency {
			s.hookMask |= hookBitTelemetryLatency
		}
	}
	if s.ruleGate != nil {
		s.hookMask |= hookBitRuleGate
	}
	if s.matchHook != nil {
		s.hookMask |= hookBitMatch
	}
	if s.maxMatchesLimit > 0 {
		s.hookMask |= hookBitMaxMatches
	}
	s.applyHooksConfig()
}

func (s *Scanner) applyHooksConfig() {
	if s.hooks == nil {
		return
	}
	h := s.hooks
	if h.OnScanStart != nil || h.OnScanComplete != nil {
		s.hookMask |= hookBitScanLifecycle
	}
	if h.OnPrefilter != nil {
		s.hookMask |= hookBitPrefilter
	}
	if h.RuleGate != nil {
		s.hookMask |= hookBitRuleGate
		if s.ruleGate == nil {
			s.ruleGate = h.RuleGate
		}
	}
	s.applyPollHookConfig(h)
	if h.OnRuleEvaluated != nil {
		s.hookMask |= hookBitRuleProfile
	}
	if h.OnPatternProfile != nil {
		s.hookMask |= hookBitPatternProfile
	}
	if h.OnMatch != nil {
		s.hookMask |= hookBitMatch
		if s.matchHook == nil {
			s.matchHook = h.OnMatch
		}
	}
	if h.OnChunk != nil {
		s.hookMask |= hookBitChunkBoundary
	}
	if h.MaxMatchesPerRule > 0 {
		s.hookMask |= hookBitMaxMatches
		if s.maxMatchesLimit <= 0 {
			s.maxMatchesLimit = h.MaxMatchesPerRule
			s.onMaxMatchesExceeded = h.OnMaxMatchesExceeded
		}
	}
}

func (s *Scanner) applyPollHookConfig(h *ScanHooks) {
	if h.OnPoll == nil {
		return
	}
	s.hookMask |= hookBitPoll
	if s.pollByteStride <= 0 {
		if h.PollByteStride > 0 {
			s.pollByteStride = h.PollByteStride
		} else {
			s.pollByteStride = defaultPollByteStride
		}
	}
}

func (s *Scanner) dispatchScanStart(ctx context.Context, inputLen int64) {
	if s.hooks != nil && s.hooks.OnScanStart != nil {
		s.hooks.OnScanStart(ctx, inputLen)
	}
}

func (s *Scanner) dispatchScanComplete(ctx context.Context, result *ScanResult, duration time.Duration) {
	if s.hooks != nil && s.hooks.OnScanComplete != nil {
		s.hooks.OnScanComplete(ctx, result, duration)
	}
}

func (s *Scanner) dispatchPrefilter(decision PrefilterDecision) {
	if s.hooks != nil && s.hooks.OnPrefilter != nil {
		s.hooks.OnPrefilter(decision)
	}
}

func (s *Scanner) dispatchPoll(ctx context.Context, progress PollProgress) error {
	if s.hooks == nil || s.hooks.OnPoll == nil {
		return ctx.Err()
	}
	action, throttle := s.hooks.OnPoll(ctx, progress)
	switch action {
	case PollAbort:
		return ErrScanAborted
	case PollYield:
		runtime.Gosched()
	case PollThrottle:
		if throttle > 0 {
			time.Sleep(throttle)
		}
	case PollContinue:
	}
	return ctx.Err()
}

func (s *Scanner) dispatchRuleEvaluated(profile RuleProfile) {
	if s.hooks != nil && s.hooks.OnRuleEvaluated != nil {
		s.hooks.OnRuleEvaluated(profile)
	}
}

func (s *Scanner) dispatchChunk(offset int64, chunkSize int, matchesFound int) {
	if s.hooks != nil && s.hooks.OnChunk != nil {
		s.hooks.OnChunk(offset, chunkSize, matchesFound)
	}
}
