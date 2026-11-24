package compiler

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParserAndSemanticRegressionFixes(t *testing.T) {
	c := NewCompiler()

	t.Run("unterminated_call_args_rejected", func(t *testing.T) {
		_, err := c.CompileSourceWithContext(context.Background(), `rule R { condition: uint32(0 }`)
		require.Error(t, err)
	})

	t.Run("string_offset_expression_index", func(t *testing.T) {
		program, err := c.CompileSourceWithContext(context.Background(), `
rule ExprIndex {
	strings:
		$a = "hi"
	condition:
		for any i in (1..2) : (@a[i + 0] >= 0)
}`)
		require.NoError(t, err)
		res, err := program.Scan([]byte("hi hi"))
		require.NoError(t, err)
		require.True(t, res.RuleResults["ExprIndex"])
	})

	t.Run("not_string_and_at_operator_are_boolean", func(t *testing.T) {
		program, err := c.CompileSourceWithContext(context.Background(), `
external ext_off
rule BoolTyping {
	strings:
		$a = "hello"
	condition:
		(not $a) == false and ($a at ext_off) == true
}`)
		require.NoError(t, err)
		scanner := program.NewScanner(WithExternalVariables(map[string]any{"ext_off": 0}))
		defer scanner.Close()
		res, err := scanner.Scan([]byte("hello"))
		require.NoError(t, err)
		require.True(t, res.RuleResults["BoolTyping"])
	})

	t.Run("hex_without_leading_space_after_brace", func(t *testing.T) {
		program, err := c.CompileSourceWithContext(context.Background(), `rule H { strings: $h = {41 42 43} condition: $h }`)
		require.NoError(t, err)
		res, err := program.Scan([]byte("ABC"))
		require.NoError(t, err)
		require.True(t, res.RuleResults["H"])
	})
}
