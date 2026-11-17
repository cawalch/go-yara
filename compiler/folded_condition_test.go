package compiler

import (
	"bytes"
	"testing"
)

// Rule compilation folds once before dead-string detection. Verify that
// bypassing the old two additional passes preserves emitted bytecode.
func TestFoldedConditionBytecode(t *testing.T) {
	for _, condition := range []string{
		"(1 + 2) * 3 == 9 and $a",
		"false and ($a or $b)",
		"true or uint8(0) == 1",
		"not (0 or $a)",
		"defined (false or uint8(0))",
		"not (true and uint8(0))",
		"filesize < 2KB and ($a or $b)",
		"uint16(1 + 1) == 0x5a4d and $a",
		"$a at (1 + 2)",
		"#a > (2 - 1) and @a[2] == 3",
		"!a[2] == 3",
		"(1 + 1) of ($a, $b)",
		"for any of ($a, $b) : ($)",
		"for (1 + 1) i in (1..3) : (i > 0)",
	} {
		t.Run(condition, func(t *testing.T) {
			parsed, err := NewCompiler().compileParseWithContext(t.Context(),
				`rule sample { strings: $a = "a" $b = "b" condition: `+condition+` }`)
			if err != nil {
				t.Fatal(err)
			}
			expr := FoldConstants(parsed.Rules[0].Condition)
			var bytecodes [2][]byte
			for i := range bytecodes {
				emitter := newEmitter()
				cc := newConditionCompiler(emitter, map[string]int{"$a": 0, "$b": 1})
				if i == 0 {
					err = cc.compileExpression(expr)
				} else {
					err = cc.CompileBooleanExpression(FoldConstants(expr), false)
				}
				if err != nil {
					t.Fatal(err)
				}
				if err = cc.resolveJumps(); err != nil {
					t.Fatal(err)
				}
				bytecodes[i], err = emitter.GetBytecode()
				if err != nil {
					t.Fatal(err)
				}
			}
			if !bytes.Equal(bytecodes[0], bytecodes[1]) {
				t.Fatal("additional constant-folding passes changed bytecode")
			}
		})
	}
}
