package compiler

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConditionPrefilterNotUndefinedIsSound(t *testing.T) {
	source := `
rule NotUndefinedOffset {
	strings:
		$a = "never_present_literal"
	condition:
		not (not @a or false)
}
rule NotUndefinedLength {
	strings:
		$a = "never_present_literal"
	condition:
		not (not !a or false)
}`
	c := NewCompiler()
	program, err := c.CompileSourceWithContext(context.Background(), source)
	require.NoError(t, err)

	res, err := program.Scan([]byte("completely unrelated payload"))
	require.NoError(t, err)
	require.True(t, res.RuleResults["NotUndefinedOffset"])
	require.True(t, res.RuleResults["NotUndefinedLength"])

	matched, err := program.Matches([]byte("completely unrelated payload"))
	require.NoError(t, err)
	require.True(t, matched)
}

func TestStrictLibyaraAllowsValidRegexModifiers(t *testing.T) {
	source := `
rule StrictRegexModifiers {
	strings:
		$r1 = /hello/ nocase
		$r2 = /world/ wide ascii fullword
	condition:
		$r1 and $r2
}`
	c := NewCompiler(WithStrictLibyaraCompatibility(true))
	program, err := c.CompileSourceWithContext(context.Background(), source)
	require.NoError(t, err)

	res, err := program.Scan([]byte("HELLO world"))
	require.NoError(t, err)
	require.True(t, res.RuleResults["StrictRegexModifiers"])
}

func TestOfPercentExactIntegerPrecisionAndUndefinedBounds(t *testing.T) {
	// 29 of 100 strings matched: float64(29)/100.0*100.0 == 28.999999999999996 < 29.0.
	var sb strings.Builder
	sb.WriteString("rule Exact29Percent {\nstrings:\n")
	for idx := range 100 {
		fmt.Fprintf(&sb, "\t$s%02d = \"tok_%02d\"\n", idx, idx)
	}
	sb.WriteString("condition:\n\t29% of them\n}\n")

	c := NewCompiler()
	program, err := c.CompileSourceWithContext(context.Background(), sb.String())
	require.NoError(t, err)

	var data strings.Builder
	for idx := range 29 {
		fmt.Fprintf(&data, "tok_%02d ", idx)
	}
	res, err := program.Scan([]byte(data.String()))
	require.NoError(t, err)
	require.True(t, res.RuleResults["Exact29Percent"], "29/100 must satisfy 29%% of them")

	// Undefined percentage in `of them in (...)` must evaluate undefined (falsy), not true.
	undefSource := `
rule UndefPercentIn {
	strings:
		$a = "alpha"
		$b = "missing"
	condition:
		@b% of ($a) in (0..10)
}
rule UndefPercentAt {
	strings:
		$a = "alpha"
		$b = "missing"
	condition:
		@b% of ($a) at 0
}`
	program2, err := c.CompileSourceWithContext(context.Background(), undefSource)
	require.NoError(t, err)
	res2, err := program2.Scan([]byte("alpha"))
	require.NoError(t, err)
	require.False(t, res2.RuleResults["UndefPercentIn"])
	require.False(t, res2.RuleResults["UndefPercentAt"])
}

func TestFloatExternalVariableWithFloatLiteral(t *testing.T) {
	source := `
external score

rule FloatExt {
	condition:
		score == 1.5 and (score + 0.5) == 2.0
}`
	c := NewCompiler()
	program, err := c.CompileSourceWithContext(context.Background(), source)
	require.NoError(t, err)

	scanner := program.NewScanner(WithExternalVariables(map[string]any{
		"score": 1.5,
	}))
	defer scanner.Close()

	res, err := scanner.Scan([]byte("payload"))
	require.NoError(t, err)
	require.True(t, res.RuleResults["FloatExt"])
}

func TestForLoopHexIntegerTuple(t *testing.T) {
	source := `
rule HexTupleLoop {
	condition:
		for any i in (0x00, 0x04) : (uint8(i) == 0x41)
}`
	c := NewCompiler()
	program, err := c.CompileSourceWithContext(context.Background(), source)
	require.NoError(t, err)

	res, err := program.Scan([]byte("XXXXA"))
	require.NoError(t, err)
	require.True(t, res.RuleResults["HexTupleLoop"])
}

func TestPECalculateChecksumUnalignedELfanewLibyaraParity(t *testing.T) {
	// Libyara iterates 32-bit aligned words and only skips OptionalHeader.CheckSum
	// when its offset is 4-byte aligned. Verify unaligned e_lfanew preserves parity.
	const eLfanew uint32 = 0x82
	checksumOff := int(eLfanew) + 88
	bufWithZero := make([]byte, 256)
	for i := range bufWithZero {
		bufWithZero[i] = byte((i*37 + 13) & 0xff)
	}
	bufWithZero[checksumOff] = 0
	bufWithZero[checksumOff+1] = 0
	bufWithZero[checksumOff+2] = 0
	bufWithZero[checksumOff+3] = 0

	bufWithNonZero := append([]byte(nil), bufWithZero...)
	binary.LittleEndian.PutUint32(bufWithNonZero[checksumOff:checksumOff+4], 0x12345678)

	c1, _, ok1 := peCalculateChecksumBytes(bufWithZero, eLfanew, nil)
	c2, _, ok2 := peCalculateChecksumBytes(bufWithNonZero, eLfanew, nil)
	require.True(t, ok1)
	require.True(t, ok2)
	require.NotEqual(t, c1, c2, "unaligned CheckSum field must match libyara aligned-only exclusion")
}

func TestInterpreterCleanupStackPreservesCapacity(t *testing.T) {
	interp := NewInterpreter(nil)
	defer interp.Release()
	origCap := cap(interp.stack)
	require.GreaterOrEqual(t, origCap, 256)

	for range 10 {
		interp.stack = append(interp.stack, Value{Type: ValueTypeInt, IntVal: 1}, Value{Type: ValueTypeInt, IntVal: 2})
		interp.cleanupStack()
		require.Equal(t, origCap, cap(interp.stack))
		interp.stack = interp.stack[:0]
	}
}
