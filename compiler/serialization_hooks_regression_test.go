package compiler

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSerializationRoundTripPreservesDeadStringsAndDeadRules(t *testing.T) {
	source := `
rule DeadRuleWithStrings {
	strings:
		$a = "never_used"
		$r = /dead_regex_[0-9]+/
		$h = { DE AD BE EF }
	condition:
		false
}
rule LiveRuleWithDeadString {
	strings:
		$live = "keep_me"
		$dead = "unused_text"
	condition:
		$live
}`
	c := NewCompiler()
	program, err := c.CompileSourceWithContext(context.Background(), source)
	require.NoError(t, err)
	require.NoError(t, program.Validate())

	raw, err := program.MarshalBinary()
	require.NoError(t, err)

	reloaded, err := UnmarshalCompiledProgram(raw)
	require.NoError(t, err)
	require.NoError(t, reloaded.Validate())

	res, err := reloaded.Scan([]byte("keep_me"))
	require.NoError(t, err)
	require.False(t, res.RuleResults["DeadRuleWithStrings"])
	require.True(t, res.RuleResults["LiveRuleWithDeadString"])
}

func TestCompiledProgramSetExternalVariablesConcurrentWithScan(t *testing.T) {
	source := `
external flag

rule ExtCheck {
	condition:
		flag == true
}`
	c := NewCompiler()
	program, err := c.CompileSourceWithContext(context.Background(), source)
	require.NoError(t, err)

	var wg sync.WaitGroup
	for i := range 4 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := range 50 {
				if id%2 == 0 {
					_ = program.SetExternalVariables(map[string]any{"flag": j%2 == 0})
				} else {
					_, err := program.Scan([]byte("payload"))
					assert.NoError(t, err)
				}
			}
		}(i)
	}
	wg.Wait()
}

func TestPollThrottleHonorsContextCancellation(t *testing.T) {
	source := `
rule ThrottleRule {
	strings:
		$a = "needle"
	condition:
		$a
}`
	c := NewCompiler()
	program, err := c.CompileSourceWithContext(context.Background(), source)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	scanner := program.NewScanner(WithPollHook(func(context.Context, PollProgress) (PollAction, time.Duration) {
		cancel()
		return PollThrottle, 5 * time.Second
	}, 1))
	defer scanner.Close()

	start := time.Now()
	_, err = scanner.ScanWithContext(ctx, []byte("needle"))
	elapsed := time.Since(start)
	require.ErrorIs(t, err, context.Canceled)
	require.Less(t, elapsed, time.Second, "PollThrottle must wake immediately on ctx cancellation")
}

func TestMatchesWithContextCompactPrefilterRejectTelemetry(t *testing.T) {
	source := `
rule CompactTarget {
	strings:
		$a = "UNIQUE_MAGIC_TOKEN_XYZ"
	condition:
		$a
}`
	c := NewCompiler()
	program, err := c.CompileSourceWithContext(context.Background(), source)
	require.NoError(t, err)

	var telemetry ScanTelemetry
	scanner := program.NewScanner(WithTelemetry(&telemetry))
	defer scanner.Close()

	input := bytes.Repeat([]byte("a"), 512)
	matched, err := scanner.Matches(input)
	require.NoError(t, err)
	require.False(t, matched)
	require.Equal(t, uint64(1), telemetry.TotalScans)
	require.Equal(t, int64(len(input)), telemetry.BytesScanned)
	require.Equal(t, uint64(1), telemetry.PrefilterRejects)
}

func TestMatchActionSkipRuleDoesNotLeakEvidence(t *testing.T) {
	source := `
rule SkippedSecret {
	strings:
		$s = /secret=([a-z0-9]+)/ capture(val = 1)
	evidence:
		cred = (val) within 0 of val
	condition:
		$s
}`
	c := NewCompiler()
	program, err := c.CompileSourceWithContext(context.Background(), source)
	require.NoError(t, err)

	scanner := program.NewScanner(
		WithEvidence(1024),
		WithMatchHook(func(*CompiledRule, RuleMatch) MatchAction {
			return MatchActionSkipRule
		}),
	)
	defer scanner.Close()

	res, err := scanner.Scan([]byte("secret=abc123"))
	require.NoError(t, err)
	require.Empty(t, res.MatchedRules)
	require.Empty(t, res.Evidence)
}

func TestNilContextAndNilOptionAndNilScannerDoNotPanic(t *testing.T) {
	c := NewCompiler(nil)
	//nolint:staticcheck // intentionally testing nil context safety
	program, err := c.CompileSourceWithContext(nil, `rule R { condition: true }`)
	require.NoError(t, err)

	scanner := program.NewScanner(nil)
	defer scanner.Close()

	var nilScanner *Scanner
	matched, err := nilScanner.MatchesReaderWithContext(context.Background(), bytes.NewReader([]byte("x")))
	require.NoError(t, err)
	require.False(t, matched)
}
