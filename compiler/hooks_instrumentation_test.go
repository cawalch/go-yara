package compiler

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

//nolint:revive // shared test adapter keeps the scan method and its inputs explicit
func telemetryScan(t *testing.T, scanner *Scanner, method string, ctx context.Context, data []byte) (int, error) {
	t.Helper()
	switch method {
	case "scan":
		result, err := scanner.ScanWithContext(ctx, data)
		if result == nil {
			return 0, err
		}
		return len(result.MatchedRules), err
	case "boolean":
		matched, err := scanner.MatchesWithContext(ctx, data)
		if matched {
			return 1, err
		}
		return 0, err
	case "rules":
		result, err := scanner.MatchingRulesWithContext(ctx, data)
		return len(result), err
	case "block":
		result, err := scanner.MatchingRulesInBlockWithContext(ctx, MemoryBlock{Base: 4096, Data: data}, 8192)
		return len(result), err
	default:
		t.Fatal("unknown method")
		return 0, nil
	}
}

func TestInstrumentationScanMethods(t *testing.T) {
	program, err := NewCompiler().CompileSource(`rule r { strings: $a="marker" condition: $a }`)
	require.NoError(t, err)
	for _, method := range []string{"scan", "boolean", "rules", "block"} {
		for _, latency := range []bool{false, true} {
			t.Run(method+"/"+map[bool]string{false: "counters", true: "latency"}[latency], func(t *testing.T) {
				var metrics ScanTelemetry
				completed, started := 0, 0
				option := WithTelemetry(&metrics)
				if latency {
					option = WithTelemetryLatency(&metrics)
				}
				scanner := NewScanner(program, option, WithHooks(ScanHooks{
					OnScanStart: func(context.Context, int64) { started++ },
					OnScanComplete: func(_ context.Context, result *ScanResult, duration time.Duration) {
						completed++
						require.Equal(t, uint64(completed), metrics.TotalScans)
						require.Equal(t, []uint64{1, 1, 2}[completed-1], metrics.TotalMatches)
						if latency {
							require.Greater(t, metrics.TotalScanDurationNs, uint64(0))
						}
						require.Greater(t, duration, time.Duration(0))
						if method == "boolean" {
							require.Nil(t, result)
						} else {
							require.NotNil(t, result)
						}
					},
				}))
				defer scanner.Close()
				for _, input := range []string{"marker marker", "clean", "marker"} {
					count, err := telemetryScan(t, scanner, method, context.Background(), []byte(input))
					require.NoError(t, err)
					require.Equal(t, map[bool]int{true: 1, false: 0}[input != "clean"], count)
				}
				require.Equal(t, 3, started)
				require.Equal(t, 3, completed)
				require.Equal(t, uint64(3), metrics.TotalScans)
				require.Equal(t, int64(24), metrics.BytesScanned)
				require.Equal(t, uint64(2), metrics.TotalMatches)
				phases := metrics.PrefilterDurationNs + metrics.PatternSearchNs + metrics.ConditionEvalNs
				if latency {
					require.Positive(t, metrics.PrefilterDurationNs)
					require.Positive(t, metrics.PatternSearchNs)
					require.Positive(t, metrics.ConditionEvalNs)
					require.LessOrEqual(t, phases, metrics.TotalScanDurationNs)
				} else {
					require.Zero(t, phases)
					require.Zero(t, metrics.TotalScanDurationNs)
				}
				metrics.Reset()
				require.Equal(t, ScanTelemetry{}, metrics)
			})
		}
	}
}

func TestInstrumentationEarlyStopAndFailure(t *testing.T) {
	program, err := NewCompiler().CompileSource(`rule a { condition:true } rule b { condition:true }`)
	require.NoError(t, err)
	for _, latency := range []bool{false, true} {
		var metrics ScanTelemetry
		option := WithTelemetry(&metrics)
		if latency {
			option = WithTelemetryLatency(&metrics)
		}
		scanner := NewScanner(program, option, WithMatchHook(func(*CompiledRule, RuleMatch) MatchAction { return MatchActionStopScan }))
		result, err := scanner.Scan(nil)
		require.NoError(t, err)
		require.Len(t, result.MatchedRules, 1)
		require.Equal(t, uint64(1), metrics.TotalMatches)
		if latency {
			require.Positive(t, metrics.TotalScanDurationNs)
		} else {
			require.Zero(t, metrics.TotalScanDurationNs)
		}
		scanner.Close()
	}
	for _, method := range []string{"scan", "boolean", "rules", "block"} {
		t.Run(method, func(t *testing.T) {
			var metrics ScanTelemetry
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			completed := 0
			scanner := NewScanner(program, WithTelemetryLatency(&metrics), WithHooks(ScanHooks{
				OnScanStart:    func(context.Context, int64) { cancel() },
				OnScanComplete: func(context.Context, *ScanResult, time.Duration) { completed++ },
			}))
			defer scanner.Close()
			_, err := telemetryScan(t, scanner, method, ctx, nil)
			require.ErrorIs(t, err, context.Canceled)
			require.Equal(t, uint64(1), metrics.TotalScans)
			require.Zero(t, metrics.TotalMatches)
			require.Positive(t, metrics.TotalScanDurationNs)
			require.Zero(t, completed)
			// An already cancelled attempt fails before start and leaves the sink alone.
			snapshot := metrics
			_, err = telemetryScan(t, scanner, method, ctx, nil)
			require.ErrorIs(t, err, context.Canceled)
			require.Equal(t, snapshot, metrics)
		})
	}
}

func TestInstrumentationRuleStepsAndStaleMatches(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
rule first { strings:$a="marker" condition:$a and for all i in (1..5):(uint8(i) >= 0) }
rule second { strings:$a="marker" condition:$a and for all i in (1..5):(uint8(i) >= 0) }
rule missing { strings:$a="absent" $b="marker" condition:$a and $b }`)
	require.NoError(t, err)
	profiles := map[string]RuleProfile{}
	scanner := NewScanner(program, WithReportedMatchesOnly(), WithRuleProfiling(func(p RuleProfile) { profiles[p.RuleName] = p }))
	defer scanner.Close()
	_, err = scanner.Scan([]byte("marker marker"))
	require.NoError(t, err)
	require.Equal(t, 5, profiles["first"].ConditionSteps)
	require.Equal(t, 5, profiles["second"].ConditionSteps)
	require.Contains(t, profiles, "missing")
	require.Zero(t, profiles["missing"].ConditionSteps)
	require.Zero(t, profiles["missing"].VerifiedMatches)
}

func TestInstrumentationPatternProfiles(t *testing.T) {
	for _, shared := range []bool{true, false} {
		t.Run(map[bool]string{true: "shared", false: "local"}[shared], func(t *testing.T) {
			program, err := NewCompiler().CompileSource(`rule r {
strings: $text="needle" fullword $regex=/abc[0-9]+z/ $hex={41 42 ?? 44} $fallback=/[0-9]+/
condition:any of them }`)
			require.NoError(t, err)
			if !shared {
				program.sharedAutomaton = nil
			}
			profiles := map[string]PatternProfile{}
			scanner := NewScanner(program, WithHooks(ScanHooks{OnPatternProfile: func(p PatternProfile) {
				require.NotContains(t, profiles, p.StringID)
				profiles[p.StringID] = p
			}}))
			defer scanner.Close()
			result, err := scanner.Scan([]byte("xneedle needle abc12z ABXD 123"))
			require.NoError(t, err)
			require.Len(t, profiles, 4)
			for id, profile := range profiles {
				require.Equal(t, len(result.Matches["r"][id]), profile.VerifiedMatches)
			}
			require.Equal(t, 2, profiles["$text"].CandidateHits)
			require.True(t, profiles["$text"].CandidateHitsKnown)
			require.Equal(t, 1, profiles["$text"].VerifiedMatches)
			require.Equal(t, 0.5, profiles["$text"].Selectivity)
			require.False(t, profiles["$fallback"].CandidateHitsKnown)
			require.Zero(t, profiles["$fallback"].Selectivity)
			if shared {
				require.True(t, profiles["$regex"].CandidateHitsKnown)
				require.Positive(t, profiles["$regex"].CandidateHits)
			}
			clear(profiles)
			_, err = scanner.Scan([]byte("needle"))
			require.NoError(t, err)
			require.Equal(t, 1, profiles["$text"].CandidateHits)
			require.Zero(t, profiles["$regex"].VerifiedMatches)
			clear(profiles)
			_, err = scanner.MatchingRules([]byte("needle abc12z ABXD 123"))
			require.NoError(t, err)
			require.Len(t, profiles, 4) // Materialization must not duplicate callbacks.
		})
	}
}

func TestInstrumentationBlockAccumulator(t *testing.T) {
	program, err := NewCompiler().CompileSource(`rule r { strings:$a="marker" condition:#a==2 }`)
	require.NoError(t, err)
	var metrics ScanTelemetry
	profiles, completions := 0, 0
	blocks := NewBlockScanner(program, WithTelemetryLatency(&metrics), WithHooks(ScanHooks{
		OnPatternProfile: func(p PatternProfile) { profiles++; require.Equal(t, 1, p.VerifiedMatches) },
		OnScanComplete: func(_ context.Context, r *ScanResult, _ time.Duration) {
			completions++
			require.Len(t, r.MatchedRules, 1)
			require.Equal(t, uint64(completions), metrics.TotalMatches)
		},
	}))
	defer blocks.Close()
	for _, base := range []int64{0, 4096} {
		require.NoError(t, blocks.Scan(base, []byte("marker")))
	}
	require.Equal(t, 2, profiles)
	require.Positive(t, metrics.PatternSearchNs)
	require.Zero(t, metrics.TotalScans)
	_, err = blocks.Finish()
	require.NoError(t, err)
	require.Equal(t, int64(12), metrics.BytesScanned)
	require.Equal(t, uint64(1), metrics.TotalScans)
	require.Positive(t, metrics.ConditionEvalNs)
	require.LessOrEqual(t, metrics.PrefilterDurationNs+metrics.PatternSearchNs+metrics.ConditionEvalNs, metrics.TotalScanDurationNs)
	blocks.Reset()
	metrics.Reset()
	require.NoError(t, blocks.Scan(0, []byte("marker")))
	require.NoError(t, blocks.Scan(100, []byte("marker")))
	// This interval is separate from the sink's lifetime.
	completions = 0
	_, err = blocks.Finish()
	require.NoError(t, err)
	require.Equal(t, int64(12), metrics.BytesScanned)
}

func TestInstrumentationPrefilterDurationsAndLatencyAllocations(t *testing.T) {
	program, err := NewCompiler().CompileSource(`rule r { strings:$a="marker" condition:$a at 0 }`)
	require.NoError(t, err)
	var decisions []PrefilterDecision
	var metrics ScanTelemetry
	scanner := NewScanner(program, WithTelemetryLatency(&metrics), WithPrefilterHook(func(d PrefilterDecision) { decisions = append(decisions, d) }))
	defer scanner.Close()
	_, err = scanner.Matches([]byte("clean"))
	require.NoError(t, err)
	_, err = scanner.Scan([]byte("marker" + strings.Repeat("x", 2000)))
	require.NoError(t, err)
	require.NotEmpty(t, decisions)
	for _, decision := range decisions {
		require.Positive(t, decision.DurationNs)
	}
	scannerPlain := NewScanner(program, WithTelemetryLatency(&metrics))
	defer scannerPlain.Close()
	input := []byte("clean")
	_, err = scannerPlain.Matches(input)
	require.NoError(t, err)
	require.Zero(t, testing.AllocsPerRun(100, func() { _, _ = scannerPlain.Matches(input) }))
}

func TestInstrumentationPollAbortTiming(t *testing.T) {
	program, err := NewCompiler().CompileSource(`rule r { condition:true }`)
	require.NoError(t, err)
	var metrics ScanTelemetry
	scanner := NewScanner(program, WithTelemetryLatency(&metrics), WithPollHook(func(context.Context, PollProgress) (PollAction, time.Duration) { return PollAbort, 0 }, 1))
	defer scanner.Close()
	_, err = scanner.Scan(nil)
	require.True(t, errors.Is(err, ErrScanAborted))
	require.Positive(t, metrics.TotalScanDurationNs)
	require.Zero(t, metrics.TotalMatches)
}

func BenchmarkInstrumentation(b *testing.B) {
	program, err := NewCompiler().CompileSource(`rule r { strings:$a="marker" condition:$a }`)
	if err != nil {
		b.Fatal(err)
	}
	for _, mode := range []string{"disabled", "counters", "latency", "patterns"} {
		b.Run(mode, func(b *testing.B) {
			var metrics ScanTelemetry
			var options []ScannerOption
			switch mode {
			case "counters":
				options = append(options, WithTelemetry(&metrics))
			case "latency":
				options = append(options, WithTelemetryLatency(&metrics))
			case "patterns":
				options = append(options, WithHooks(ScanHooks{OnPatternProfile: func(PatternProfile) {}}))
			}
			scanner := NewScanner(program, options...)
			defer scanner.Close()
			input := []byte("marker marker")
			_, _ = scanner.Matches(input)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				_, _ = scanner.Matches(input)
			}
		})
	}
}

func TestInstrumentationWordRoutingAndFastScan(t *testing.T) {
	program, err := NewCompiler().CompileSource(`rule r { strings:$a="long_literal_marker" condition:$a }`)
	require.NoError(t, err)
	var metrics ScanTelemetry
	var decisions []PrefilterDecision
	scanner := NewScanner(program, WithBooleanRouting(), WithTelemetryLatency(&metrics), WithPrefilterHook(func(d PrefilterDecision) { decisions = append(decisions, d) }))
	defer scanner.Close()
	require.NotNil(t, scanner.booleanRouting)
	matched, err := scanner.Matches([]byte("long_literal_marker"))
	require.NoError(t, err)
	require.True(t, matched)
	require.Equal(t, uint64(1), metrics.TotalMatches)
	require.Positive(t, metrics.PrefilterDurationNs)
	require.Zero(t, metrics.PatternSearchNs)
	require.Zero(t, metrics.ConditionEvalNs)
	require.Equal(t, PrefilterStageWordRouting, decisions[0].Stage)
	require.Positive(t, decisions[0].DurationNs)
	require.Equal(t, 1, decisions[0].CandidateCount)
	var profiles []PatternProfile
	fast := NewScanner(program, WithFastScan(), WithHooks(ScanHooks{OnPatternProfile: func(p PatternProfile) { profiles = append(profiles, p) }}))
	defer fast.Close()
	result, err := fast.Scan([]byte("long_literal_marker long_literal_marker"))
	require.NoError(t, err)
	require.Len(t, profiles, 1)
	require.Equal(t, len(result.Matches["r"]["$a"]), profiles[0].VerifiedMatches)
	require.Equal(t, 1, profiles[0].VerifiedMatches)
}

func TestInstrumentationSharedCacheAttribution(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
rule first { strings:$a=/anchor[0-9]+end/ condition:$a }
rule second { strings:$b=/anchor[0-9]+end/ condition:$b }
rule third { strings:$c=/another[0-9]+tail/ condition:$c }`)
	require.NoError(t, err)
	var profiles []PatternProfile
	var metrics ScanTelemetry
	scanner := NewScanner(program, WithTelemetry(&metrics), WithHooks(ScanHooks{OnPatternProfile: func(p PatternProfile) { profiles = append(profiles, p) }}))
	defer scanner.Close()
	data := []byte(strings.Repeat(" ", 256) + "anchor12end anchorNOPEend")
	require.True(t, shouldUseSharedPatternAutomaton(data, program))
	result, err := scanner.Scan(data)
	require.NoError(t, err)
	require.Len(t, result.MatchedRules, 2)
	require.Len(t, profiles, 2)
	for _, profile := range profiles {
		require.True(t, profile.CandidateHitsKnown)
		require.Equal(t, 2, profile.CandidateHits)
		require.Equal(t, 1, profile.VerifiedMatches)
	}
	require.Equal(t, uint64(4), metrics.CandidateHits) // Each logical consumer gets the shared hits.
	require.Equal(t, uint64(2), metrics.VerifiedMatches)
	require.Equal(t, uint64(2), metrics.FalseCandidateHits)
}

func TestInstrumentationNilSink(t *testing.T) {
	program, err := NewCompiler().CompileSource(`rule r {condition:true}`)
	require.NoError(t, err)
	scanner := NewScanner(program, WithTelemetryLatency(nil))
	defer scanner.Close()
	_, err = scanner.Scan(nil)
	require.NoError(t, err)
	blocks := NewBlockScanner(program, WithTelemetryLatency(nil))
	defer blocks.Close()
	require.NoError(t, blocks.Scan(0, []byte("data")))
	_, err = blocks.Finish()
	require.NoError(t, err)
}
