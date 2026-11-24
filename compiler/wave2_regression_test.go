package compiler

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cawalch/go-yara/regex"
)

func TestHexCommentsInsideGroupsAndBraces(t *testing.T) {
	source := `
rule HexWithComments {
	strings:
		$h = { ( 41 /* | ) } */ | 42 ) // }
			43 }
	condition:
		$h
}`
	c := NewCompiler()
	program, err := c.CompileSourceWithContext(context.Background(), source)
	require.NoError(t, err)

	res, err := program.Scan([]byte("AC"))
	require.NoError(t, err)
	require.True(t, res.RuleResults["HexWithComments"])

	res2, err := program.Scan([]byte("BC"))
	require.NoError(t, err)
	require.True(t, res2.RuleResults["HexWithComments"])
}

func TestDeepNestingLimitsPreventStackOverflow(t *testing.T) {
	t.Run("hex_nesting_limit", func(t *testing.T) {
		deepHex := strings.Repeat("(", 80) + "41" + strings.Repeat(")", 80)
		_, err := parseHexTokens(deepHex)
		require.Error(t, err)
	})

	t.Run("regex_nesting_limit", func(t *testing.T) {
		deepRegex := strings.Repeat("(", 200) + "a" + strings.Repeat(")", 200)
		_, err := regex.NewParser(0).Parse(deepRegex)
		require.Error(t, err)
	})

	t.Run("unary_operator_recursion_limit", func(t *testing.T) {
		c := NewCompiler(WithMaxRecursionDepth(32))
		src := "rule DeepUnary { condition: " + strings.Repeat("not ", 64) + "true }"
		_, err := c.CompileSourceWithContext(context.Background(), src)
		require.Error(t, err)
	})
}

func TestDiamondAndSiblingIncludesWithinRootBaseDir(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	require.NoError(t, os.MkdirAll(sub, 0o755))

	require.NoError(t, os.WriteFile(filepath.Join(dir, "common.yar"), []byte(`
rule CommonRule {
	strings:
		$c = "COMMON_TOKEN"
	condition:
		$c
}`), 0o600))

	require.NoError(t, os.WriteFile(filepath.Join(sub, "child.yar"), []byte(`
include "../common.yar"
rule ChildRule {
	condition:
		CommonRule
}`), 0o600))

	rootPath := filepath.Join(dir, "root.yar")
	require.NoError(t, os.WriteFile(rootPath, []byte(`
include "common.yar"
include "sub/child.yar"
rule RootRule {
	condition:
		CommonRule and ChildRule
}`), 0o600))

	c := NewCompiler()
	program, err := c.CompileFileWithContext(context.Background(), rootPath)
	require.NoError(t, err)

	res, err := program.Scan([]byte("COMMON_TOKEN"))
	require.NoError(t, err)
	require.True(t, res.RuleResults["RootRule"])
}
