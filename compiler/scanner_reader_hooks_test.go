package compiler

import (
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPollAbortsPublicScanEntryPoints(t *testing.T) {
	program, err := NewCompiler().CompileSource(`rule r { strings: $a = "marker" condition: $a }`)
	require.NoError(t, err)
	input := []byte("clean")

	for _, tc := range []struct {
		name string
		scan func(*Scanner) error
	}{
		{"Scan", func(s *Scanner) error { _, err := s.Scan(input); return err }},
		{"Matches", func(s *Scanner) error { _, err := s.Matches(input); return err }},
		{"MatchingRules", func(s *Scanner) error { _, err := s.MatchingRules(input); return err }},
		{"MatchingRulesInBlock", func(s *Scanner) error {
			_, err := s.MatchingRulesInBlock(MemoryBlock{Data: input}, int64(len(input)))
			return err
		}},
		{"ScanReader", func(s *Scanner) error {
			_, err := s.ScanReader(hookTestReader(func([]byte) (int, error) {
				t.Error("reader read after abort")
				return 0, io.EOF
			}))
			return err
		}},
		{"MatchesReader", func(s *Scanner) error {
			_, err := s.MatchesReader(strings.NewReader("clean"))
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scanner := program.NewScanner(WithPollHook(func(_ context.Context, p PollProgress) (PollAction, time.Duration) {
				require.Zero(t, p.BytesScanned)
				return PollAbort, 0
			}, 0))
			defer scanner.Close()
			require.ErrorIs(t, tc.scan(scanner), ErrScanAborted)
		})
	}

	blocks := program.NewBlockScanner(WithPollHook(func(_ context.Context, p PollProgress) (PollAction, time.Duration) {
		require.Equal(t, PhaseBlockScan, p.Phase)
		require.Zero(t, p.BytesScanned)
		return PollAbort, 0
	}, 0))
	defer blocks.Close()
	require.ErrorIs(t, blocks.Scan(0, input), ErrScanAborted)
}

type hookTestReader func([]byte) (int, error)

func (read hookTestReader) Read(p []byte) (int, error) { return read(p) }

func TestReaderHooksAndTelemetry(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
rule present { strings: $a = "marker" condition: $a }
rule absent { strings: $a = "absent" condition: $a }
rule header { condition: uint8(0) == 0 }
`)
	require.NoError(t, err)

	var events []string
	var decisions []PrefilterDecision
	var patterns []PatternProfile
	var rules []RuleProfile
	var telemetry ScanTelemetry
	s := program.NewScanner(WithTelemetry(&telemetry), WithHooks(ScanHooks{
		OnScanStart: func(_ context.Context, size int64) {
			require.Equal(t, int64(-1), size)
			events = append(events, "start")
		},
		OnChunk: func(offset int64, size, matches int) {
			require.Equal(t, int64(0), offset)
			require.Equal(t, len("marker"), size)
			require.Equal(t, 1, matches)
			events = append(events, "chunk")
		},
		OnPrefilter:      func(d PrefilterDecision) { decisions = append(decisions, d) },
		OnPatternProfile: func(p PatternProfile) { patterns = append(patterns, p) },
		OnRuleEvaluated:  func(p RuleProfile) { rules = append(rules, p) },
		OnScanComplete: func(_ context.Context, result *ScanResult, _ time.Duration) {
			require.NotNil(t, result)
			require.Equal(t, int64(len("marker")), telemetry.BytesScanned)
			events = append(events, "complete")
		},
	}))
	defer s.Close()
	input := strings.NewReader("marker")
	r := hookTestReader(func(p []byte) (int, error) {
		require.NotEmpty(t, events)
		require.Equal(t, "start", events[0])
		return input.Read(p)
	})
	result, err := s.ScanReader(r)
	require.NoError(t, err)
	require.Len(t, result.MatchedRules, 1)
	require.Equal(t, []string{"start", "chunk", "complete"}, events)
	require.True(t, slices.ContainsFunc(decisions, func(d PrefilterDecision) bool {
		return d.Stage == PrefilterStageHeaderConstraints
	}))
	require.True(t, slices.ContainsFunc(patterns, func(p PatternProfile) bool {
		return p.RuleName == "present" && p.StringID == "$a" && p.CandidateHitsKnown &&
			p.CandidateHits == 1 && p.VerifiedMatches == 1
	}))
	require.True(t, slices.ContainsFunc(rules, func(p RuleProfile) bool {
		return p.RuleName == "absent" && !p.Matched && !p.Pruned && p.CandidateHits == 0
	}))
	require.Equal(t, uint64(1), telemetry.TotalScans)
	require.Equal(t, uint64(1), telemetry.TotalMatches)
	require.Equal(t, uint64(1), telemetry.CandidateHits)
}

func TestReaderHookFailureAndBooleanCompletion(t *testing.T) {
	program, err := NewCompiler().CompileSource(`rule r { strings: $a = "marker" condition: $a }`)
	require.NoError(t, err)

	var starts, completions int
	var telemetry ScanTelemetry
	s := program.NewScanner(WithTelemetryLatency(&telemetry), WithHooks(ScanHooks{
		OnScanStart: func(context.Context, int64) { starts++ },
		OnScanComplete: func(_ context.Context, result *ScanResult, _ time.Duration) {
			require.Nil(t, result)
			completions++
		},
	}))
	defer s.Close()
	readErr := errors.New("read failed")
	_, err = s.ScanReader(io.MultiReader(strings.NewReader("abc"), hookTestReader(func([]byte) (int, error) {
		return 0, readErr
	})))
	require.ErrorIs(t, err, readErr)
	require.Equal(t, 1, starts)
	require.Zero(t, completions)
	require.Equal(t, int64(3), telemetry.BytesScanned)
	require.Zero(t, telemetry.TotalMatches)

	matched, err := s.MatchesReader(strings.NewReader("marker"))
	require.NoError(t, err)
	require.True(t, matched)
	require.Equal(t, 2, starts)
	require.Equal(t, 1, completions)
	require.Equal(t, uint64(2), telemetry.TotalScans)
	require.Equal(t, uint64(1), telemetry.TotalMatches)
	require.Positive(t, telemetry.TotalScanDurationNs)
	require.Positive(t, telemetry.PatternSearchNs)
	require.Positive(t, telemetry.ConditionEvalNs)
	require.LessOrEqual(t, telemetry.PrefilterDurationNs+telemetry.PatternSearchNs+telemetry.ConditionEvalNs, telemetry.TotalScanDurationNs)
}

func TestReaderPollThrottleThenAbortAtNextChunk(t *testing.T) {
	program, err := NewCompiler().CompileSource(`rule r { strings: $a = "needle" condition: $a }`)
	require.NoError(t, err)
	var chunks []int64
	s := program.NewScanner(WithStreamChunkSize(4), WithHooks(ScanHooks{
		OnChunk: func(offset int64, size, matches int) {
			require.Equal(t, 4, size)
			require.Zero(t, matches)
			chunks = append(chunks, offset)
		},
		OnPoll: func(_ context.Context, p PollProgress) (PollAction, time.Duration) {
			require.Equal(t, int64(-1), p.TotalBytes)
			if p.BytesScanned == 0 {
				return PollThrottle, time.Millisecond
			}
			require.Equal(t, int64(4), p.BytesScanned)
			return PollAbort, 0
		},
	}))
	defer s.Close()
	started := time.Now()
	_, err = s.ScanReader(strings.NewReader("abcdefghijkl"))
	require.ErrorIs(t, err, ErrScanAborted)
	require.GreaterOrEqual(t, time.Since(started), time.Millisecond)
	require.Equal(t, []int64{0}, chunks)
}

func TestReaderPollStopsAtKnownEOF(t *testing.T) {
	program, err := NewCompiler().CompileSource(`rule r { condition: true }`)
	require.NoError(t, err)
	scanner := program.NewScanner(WithStreamChunkSize(4), WithPollHook(func(_ context.Context, p PollProgress) (PollAction, time.Duration) {
		if p.BytesScanned > 0 {
			return PollAbort, 0
		}
		return PollContinue, 0
	}, 0))
	defer scanner.Close()

	result, err := scanner.ScanReader(strings.NewReader("abcd"))
	require.NoError(t, err)
	require.Len(t, result.MatchedRules, 1)
}
