package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cawalch/go-yara/compiler"
)

func TestFilterNegatedRulesOmitsPrivateAndPreservesTagsAndMeta(t *testing.T) {
	source := `
private rule HiddenHelper {
	strings:
		$h = "absent_helper"
	condition:
		$h
}
rule PublicTagged : alpha beta {
	meta:
		author = "tester"
	strings:
		$a = "absent_a"
	condition:
		$a
}
rule PublicOtherTag : gamma {
	strings:
		$b = "absent_b"
	condition:
		$b
}`
	c := compiler.NewCompiler()
	program, err := c.CompileSourceWithContext(context.Background(), source)
	require.NoError(t, err)

	res, err := program.Scan([]byte("no matches here"))
	require.NoError(t, err)

	rules := filterScanRules(program, res, &commandArgs{negate: true, tagFilter: "alpha"})
	require.Len(t, rules, 1)
	require.Equal(t, "PublicTagged", rules[0].Rule)
	require.Equal(t, []string{"alpha", "beta"}, rules[0].Tags)
	require.Equal(t, "tester", rules[0].Meta["author"])
}

func TestFormatEntryPreviewUsesMatchedDataWithoutRetainingBuffer(t *testing.T) {
	e := printEntry{
		id:          "$s",
		offset:      1024,
		length:      5,
		matchedData: []byte("hello"),
	}
	require.Equal(t, "hello", formatEntryPreview(e, nil))
	require.Equal(t, "", formatMatchPreview([]byte("abc"), -1, 2))
	require.Equal(t, "", formatMatchPreview([]byte("abc"), 2, -1))
	require.Equal(t, "", formatMatchPreview([]byte("abc"), 2, 5))
}
