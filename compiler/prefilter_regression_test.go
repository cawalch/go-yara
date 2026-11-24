package compiler

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAhoCorasickNocaseAfterBothCaseSensitiveBranches(t *testing.T) {
	source := `
rule CaseSensitiveLower {
	strings:
		$a = "a1_lower"
	condition:
		$a
}
rule CaseSensitiveUpper {
	strings:
		$b = "A2_upper"
	condition:
		$b
}
rule NocasePattern {
	strings:
		$c = "a3_mixed" nocase
	condition:
		$c
}
rule DeepCaseSensitiveLower {
	strings:
		$d = "px1_lower"
	condition:
		$d
}
rule DeepCaseSensitiveUpper {
	strings:
		$e = "pX2_upper"
	condition:
		$e
}
rule DeepNocasePattern {
	strings:
		$f = "px3_mixed" nocase
	condition:
		$f
}`
	c := NewCompiler()
	program, err := c.CompileSourceWithContext(context.Background(), source)
	require.NoError(t, err)

	for _, tc := range []struct {
		name  string
		input string
		want  string
	}{
		{"root_lower", "xxx a3_mixed yyy", "NocasePattern"},
		{"root_upper", "xxx A3_MIXED yyy", "NocasePattern"},
		{"deep_lower", "xxx px3_mixed yyy", "DeepNocasePattern"},
		{"deep_upper", "xxx PX3_MIXED yyy", "DeepNocasePattern"},
		{"deep_mixed", "xxx pX3_mixed yyy", "DeepNocasePattern"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := program.Scan([]byte(tc.input))
			require.NoError(t, err)
			require.True(t, res.RuleResults[tc.want], "expected %s to match %q", tc.want, tc.input)

			matched, err := program.Matches([]byte(tc.input))
			require.NoError(t, err)
			require.True(t, matched, "Matches() should return true for %q", tc.input)
		})
	}
}

func TestSharedNonTextFanoutDoesNotCorruptCandidates(t *testing.T) {
	// Two regexes sharing the exact same literal atom ("ABCD") where the first
	// filters candidates with atomOccurrenceValid (e.g., anchor/prefix check)
	// and the second fans out from the same lookup slot.
	source := `
rule FanoutOne {
	strings:
		$r1 = /fooABCD[0-9]{2}/
	condition:
		$r1
}
rule FanoutTwo {
	strings:
		$r2 = /barABCD[a-z]{2}/
	condition:
		$r2
}`
	c := NewCompiler()
	program, err := c.CompileSourceWithContext(context.Background(), source)
	require.NoError(t, err)

	input := []byte("zzz barABCDxy zzz fooABCD12 zzz")
	res, err := program.Scan(input)
	require.NoError(t, err)
	require.True(t, res.RuleResults["FanoutOne"])
	require.True(t, res.RuleResults["FanoutTwo"])
}

func TestShortCircuitedHexDoesNotPoisonSharedCache(t *testing.T) {
	// Private monotonic rule matches on first occurrence and may short-circuit;
	// public rule shares the exact same hex pattern and requires >= 2 occurrences.
	source := `
private rule Helper {
	strings:
		$h = { 11 22 ?? 44 }
	condition:
		$h
}
rule NeedsTwo {
	strings:
		$h = { 11 22 ?? 44 }
	condition:
		Helper and #h >= 2
}`
	c := NewCompiler()
	program, err := c.CompileSourceWithContext(context.Background(), source)
	require.NoError(t, err)

	data := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x00, 0x11, 0x22, 0x99, 0x44}
	matched, err := program.Matches(data)
	require.NoError(t, err)
	require.True(t, matched)

	res, err := program.Scan(data)
	require.NoError(t, err)
	require.True(t, res.RuleResults["NeedsTwo"])
}

func TestXorHexPatternWithPrecedingJumpMatches(t *testing.T) {
	source := `
rule XorFixedJump {
	strings:
		$h = { [4] 41 42 43 44 } xor(0x01-0x0f)
	condition:
		$h
}
rule XorVarJump {
	strings:
		$h = { 10 [2-4] 41 42 43 } xor(0x01-0x0f)
	condition:
		$h
}`
	c := NewCompiler()
	program, err := c.CompileSourceWithContext(context.Background(), source)
	require.NoError(t, err)

	const key byte = 0x05
	// Fixed jump: 4 arbitrary bytes + ("ABCD" ^ 0x05)
	fixedData := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0x41 ^ key, 0x42 ^ key, 0x43 ^ key, 0x44 ^ key}
	res, err := program.Scan(fixedData)
	require.NoError(t, err)
	require.True(t, res.RuleResults["XorFixedJump"], "XorFixedJump should match")

	// Var jump: (0x10 ^ 0x05) + 3 bytes + ("ABC" ^ 0x05)
	varData := []byte{0x10 ^ key, 0x01, 0x02, 0x03, 0x41 ^ key, 0x42 ^ key, 0x43 ^ key}
	res2, err := program.Scan(varData)
	require.NoError(t, err)
	require.True(t, res2.RuleResults["XorVarJump"], "XorVarJump should match")

	// Overlapping variable-jump candidates must not emit duplicate matches for the same start offset.
	overlapData := []byte{0x10 ^ key, 0x41 ^ key, 0x42 ^ key, 0x43 ^ key, 0x41 ^ key, 0x42 ^ key, 0x43 ^ key}
	res3, err := program.Scan(overlapData)
	require.NoError(t, err)
	require.True(t, res3.RuleResults["XorVarJump"])
	require.Len(t, res3.Matches["XorVarJump"]["$h"], 1, "overlapping diff anchors must not emit duplicate start offsets")
}
