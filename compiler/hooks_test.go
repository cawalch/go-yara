package compiler

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestHooksScanLifecycleAndTelemetry(t *testing.T) {
	ruleSource := `
rule test_magic {
    strings:
        $magic = "MAGIC"
        $body = "PAYLOAD"
    condition:
        $magic at 0 and $body
}
rule test_clean {
    strings:
        $token = "UNIQUE_CLEAN_TOKEN"
    condition:
        $token
}
`
	program, err := NewCompiler().CompileSource(ruleSource)
	require.NoError(t, err)

	var scanStartCalled atomic.Bool
	var scanCompleteCalled atomic.Bool
	var startInputLen int64
	var completedMatches int

	var telemetry ScanTelemetry

	hooks := ScanHooks{
		OnScanStart: func(ctx context.Context, inputLen int64) {
			scanStartCalled.Store(true)
			startInputLen = inputLen
		},
		OnScanComplete: func(ctx context.Context, result *ScanResult, duration time.Duration) {
			scanCompleteCalled.Store(true)
			completedMatches = len(result.MatchedRules)
		},
	}

	scanner := NewScanner(
		program,
		WithHooks(hooks),
		WithTelemetryLatency(&telemetry),
	)
	defer scanner.Close()

	// 1. Scan clean data (should fast reject)
	cleanData := []byte("clean data without any pattern")
	res1, err := scanner.Scan(cleanData)
	require.NoError(t, err)
	require.Empty(t, res1.MatchedRules)
	require.True(t, scanStartCalled.Load())
	require.True(t, scanCompleteCalled.Load())
	require.Equal(t, int64(len(cleanData)), startInputLen)
	require.Equal(t, 0, completedMatches)

	require.Equal(t, uint64(1), telemetry.TotalScans)
	require.Equal(t, int64(len(cleanData)), telemetry.BytesScanned)
	require.Equal(t, uint64(1), telemetry.PrefilterRejects)
	require.Equal(t, uint64(0), telemetry.TotalMatches)
	require.Greater(t, telemetry.TotalScanDurationNs, uint64(0))

	// 2. Scan data with matching payload but wrong offset (should be pruned by header constraint)
	scanStartCalled.Store(false)
	scanCompleteCalled.Store(false)
	wrongOffsetData := []byte("wrong MAGIC at offset 6 and PAYLOAD")
	res2, err := scanner.Scan(wrongOffsetData)
	require.NoError(t, err)
	require.Empty(t, res2.MatchedRules)
	require.Contains(t, res2.PrunedRules, "test_magic")
	require.True(t, scanStartCalled.Load())
	require.True(t, scanCompleteCalled.Load())

	require.Equal(t, uint64(2), telemetry.TotalScans)
	require.Greater(t, telemetry.RulesPruned, uint64(0))

	// 3. Scan matching data
	scanStartCalled.Store(false)
	scanCompleteCalled.Store(false)
	matchingData := []byte("MAGIC header with PAYLOAD inside")
	res3, err := scanner.Scan(matchingData)
	require.NoError(t, err)
	require.Len(t, res3.MatchedRules, 1)
	require.Equal(t, "test_magic", res3.MatchedRules[0].Rule)
	require.True(t, scanStartCalled.Load())
	require.True(t, scanCompleteCalled.Load())
	require.Equal(t, 1, completedMatches)

	require.Equal(t, uint64(3), telemetry.TotalScans)
	require.Equal(t, uint64(1), telemetry.TotalMatches)
	require.Greater(t, telemetry.RulesEvaluated, uint64(0))
	require.Greater(t, telemetry.VerifiedMatches, uint64(0))
}

func TestHooksPollAction(t *testing.T) {
	ruleSource := `
rule slow_rule {
    strings:
        $a = "target"
    condition:
        $a
}
`
	program, err := NewCompiler().CompileSource(ruleSource)
	require.NoError(t, err)

	data := []byte("target target target")

	// Case A: PollContinue
	pollCount := 0
	scannerA := NewScanner(program, WithPollHook(func(ctx context.Context, p PollProgress) (PollAction, time.Duration) {
		pollCount++
		require.Equal(t, PhaseRuleCondition, p.Phase)
		require.Equal(t, int64(len(data)), p.BytesScanned)
		return PollContinue, 0
	}, 1024))
	defer scannerA.Close()

	resA, err := scannerA.Scan(data)
	require.NoError(t, err)
	require.Len(t, resA.MatchedRules, 1)
	require.Greater(t, pollCount, 0)

	// Case B: PollYield
	yieldCount := 0
	scannerB := NewScanner(program, WithPollHook(func(ctx context.Context, p PollProgress) (PollAction, time.Duration) {
		yieldCount++
		return PollYield, 0
	}, 1024))
	defer scannerB.Close()

	resB, err := scannerB.Scan(data)
	require.NoError(t, err)
	require.Len(t, resB.MatchedRules, 1)
	require.Greater(t, yieldCount, 0)

	// Case C: PollThrottle
	throttleCount := 0
	scannerC := NewScanner(program, WithPollHook(func(ctx context.Context, p PollProgress) (PollAction, time.Duration) {
		throttleCount++
		return PollThrottle, 100 * time.Microsecond
	}, 1024))
	defer scannerC.Close()

	start := time.Now()
	resC, err := scannerC.Scan(data)
	require.NoError(t, err)
	require.Len(t, resC.MatchedRules, 1)
	require.Greater(t, throttleCount, 0)
	require.GreaterOrEqual(t, time.Since(start), 100*time.Microsecond)

	// Case D: PollAbort
	scannerD := NewScanner(program, WithPollHook(func(ctx context.Context, p PollProgress) (PollAction, time.Duration) {
		return PollAbort, 0
	}, 1024))
	defer scannerD.Close()

	_, err = scannerD.Scan(data)
	require.ErrorIs(t, err, ErrScanAborted)
}

func TestHooksRuleProfiling(t *testing.T) {
	ruleSource := `
rule rule_a {
    strings:
        $a = "alpha"
    condition:
        $a
}
rule rule_b {
    strings:
        $b = "beta"
    condition:
        $b and for all i in (1..10) : ( i > 0 )
}
rule rule_pruned {
    strings:
        $m = "MAGIC"
    condition:
        $m at 0
}
`
	program, err := NewCompiler().CompileSource(ruleSource)
	require.NoError(t, err)

	profiles := make(map[string]RuleProfile)
	scanner := NewScanner(program, WithRuleProfiling(func(profile RuleProfile) {
		profiles[profile.RuleName] = profile
	}))
	defer scanner.Close()

	data := []byte("non-magic alpha beta payload")
	res, err := scanner.Scan(data)
	require.NoError(t, err)
	require.Len(t, res.MatchedRules, 2)

	require.Contains(t, profiles, "rule_a")
	require.True(t, profiles["rule_a"].Matched)
	require.False(t, profiles["rule_a"].Pruned)
	require.Greater(t, profiles["rule_a"].Duration, time.Duration(0))

	require.Contains(t, profiles, "rule_b")
	require.True(t, profiles["rule_b"].Matched)
	require.False(t, profiles["rule_b"].Pruned)
	require.GreaterOrEqual(t, profiles["rule_b"].ConditionSteps, 10)

	require.Contains(t, profiles, "rule_pruned")
	require.False(t, profiles["rule_pruned"].Matched)
	require.True(t, profiles["rule_pruned"].Pruned)
}

func TestHooksPrefilterAndRuleGate(t *testing.T) {
	ruleSource := `
rule alpha {
    strings:
        $a = "keyword_alpha"
    condition:
        $a
}
rule beta {
    strings:
        $b = "keyword_beta"
    condition:
        $b
}
`
	program, err := NewCompiler().CompileSource(ruleSource)
	require.NoError(t, err)

	// Test RuleGate: skip rule "beta" dynamically
	scanner := NewScanner(
		program,
		WithRuleGate(func(rule *CompiledRule) bool {
			return rule.Name != "beta"
		}),
	)
	defer scanner.Close()

	data := []byte("both keyword_alpha and keyword_beta are present")
	res, err := scanner.Scan(data)
	require.NoError(t, err)
	require.Len(t, res.MatchedRules, 1)
	require.Equal(t, "alpha", res.MatchedRules[0].Rule)

	// Test PrefilterHook on clean input
	var prefilterDecisions []PrefilterDecision
	scannerClean := NewScanner(
		program,
		WithPrefilterHook(func(d PrefilterDecision) {
			prefilterDecisions = append(prefilterDecisions, d)
		}),
	)
	defer scannerClean.Close()

	matches, err := scannerClean.Matches([]byte("completely clean input"))
	require.NoError(t, err)
	require.False(t, matches)
	require.NotEmpty(t, prefilterDecisions)
	require.True(t, prefilterDecisions[0].Rejected)
}

func TestHooksStreamingMatchDelivery(t *testing.T) {
	ruleSource := `
rule first {
    strings:
        $a = "common"
    condition:
        $a
}
rule second {
    strings:
        $b = "common"
    condition:
        $b
}
`
	program, err := NewCompiler().CompileSource(ruleSource)
	require.NoError(t, err)

	data := []byte("common token")

	// Case 1: MatchActionStopScan on first match
	var matchedRules []string
	scannerStop := NewScanner(program, WithMatchHook(func(rule *CompiledRule, match RuleMatch) MatchAction {
		matchedRules = append(matchedRules, match.Rule)
		return MatchActionStopScan
	}))
	defer scannerStop.Close()

	resStop, err := scannerStop.Scan(data)
	require.NoError(t, err)
	require.Len(t, resStop.MatchedRules, 1)
	require.Len(t, matchedRules, 1)

	// Case 2: MatchActionSkipRule (skip rule "first")
	scannerSkip := NewScanner(program, WithMatchHook(func(rule *CompiledRule, match RuleMatch) MatchAction {
		if match.Rule == "first" {
			return MatchActionSkipRule
		}
		return MatchActionContinue
	}))
	defer scannerSkip.Close()

	resSkip, err := scannerSkip.Scan(data)
	require.NoError(t, err)
	require.Len(t, resSkip.MatchedRules, 1)
	require.Equal(t, "second", resSkip.MatchedRules[0].Rule)
}

func TestHooksBlockScannerAndChunkHook(t *testing.T) {
	ruleSource := `
rule block_rule {
    strings:
        $pattern = "PAYLOAD"
    condition:
        $pattern
}
`
	program, err := NewCompiler().CompileSource(ruleSource)
	require.NoError(t, err)

	chunkOffsets := make([]int64, 0)
	bs := NewBlockScanner(
		program,
		WithChunkHook(func(offset int64, chunkSize int, matchesFound int) {
			chunkOffsets = append(chunkOffsets, offset)
		}),
	)
	defer bs.Close()

	err = bs.Scan(0, []byte("start block without pattern"))
	require.NoError(t, err)
	err = bs.Scan(1000, []byte("second block with PAYLOAD"))
	require.NoError(t, err)

	res, err := bs.Finish()
	require.NoError(t, err)
	require.Len(t, res.MatchedRules, 1)
	require.Equal(t, "block_rule", res.MatchedRules[0].Rule)

	require.Equal(t, []int64{0, 1000}, chunkOffsets)
}

func TestHooksStreamingProcessorChunkHook(t *testing.T) {
	ruleSource := `
rule stream_rule {
    strings:
        $s = "FINDME"
    condition:
        $s
}
`
	program, err := NewCompiler().CompileSource(ruleSource)
	require.NoError(t, err)

	sp := NewStreamingProcessor(program)
	sp.ChunkSize = 32

	chunksHit := 0
	sp.ChunkHook = func(offset int64, chunkSize int, matchesFound int) {
		chunksHit++
	}

	data := []byte("012345678901234567890123456789FINDME0123456789")
	matches, err := sp.ProcessBytes(context.Background(), data)
	require.NoError(t, err)
	require.NotEmpty(t, matches)
	require.Greater(t, chunksHit, 0)
}

func TestHooksZeroAllocationsWhenDisabled(t *testing.T) {
	ruleSource := `
rule fast_reject {
    strings:
        $a = "MUST_MATCH"
    condition:
        $a
}
`
	program, err := NewCompiler().CompileSource(ruleSource)
	require.NoError(t, err)

	data := []byte("clean input without token")

	// 1. Scanner without hooks
	scannerClean := NewScanner(program)
	defer scannerClean.Close()

	// Warm up
	_, _ = scannerClean.Matches(data)

	allocsClean := testing.AllocsPerRun(100, func() {
		_, _ = scannerClean.Matches(data)
	})
	require.Equal(t, float64(0), allocsClean, "disabled hooks must have exactly 0 allocs/op")

	// 2. Scanner with in-place telemetry
	var telemetry ScanTelemetry
	scannerTelem := NewScanner(program, WithTelemetry(&telemetry))
	defer scannerTelem.Close()

	// Warm up
	_, _ = scannerTelem.Matches(data)

	allocsTelem := testing.AllocsPerRun(100, func() {
		_, _ = scannerTelem.Matches(data)
	})
	require.Equal(t, float64(0), allocsTelem, "in-place telemetry must have exactly 0 allocs/op")
	require.Equal(t, uint64(102), telemetry.TotalScans)
	require.Equal(t, uint64(102), telemetry.PrefilterRejects)
}
