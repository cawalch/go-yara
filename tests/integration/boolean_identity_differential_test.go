package integration

import (
	"fmt"
	"strings"
	"testing"
)

func TestLibyaraBooleanIdentityFolding(t *testing.T) {
	for _, operand := range []string{
		`uint8(0) == 1`, `uint8(filesize) == 1`, `not (uint8(0) == 1)`,
		`@a[1] == 0`, `$a at @a[2]`, `$a in (0..@a[2])`,
		`uint8(0)`, `@a[2]`, `#a`, `2`, `0`, `-3`, `0.0`, `0.5`, `""`, `"a"`, `uint8(0) * 0.5`,
		`hash.md5(0, filesize)`, `hash.md5(0, 1)`,
		`defined @a[2]`, `$a`, `($a or uint8(filesize) == 1)`,
	} {
		t.Run(operand, func(t *testing.T) {
			var source strings.Builder
			if strings.HasPrefix(operand, "hash.") {
				source.WriteString(`import "hash"`)
			}
			source.WriteString(`rule healthy { condition: true }`)
			index := 0
			for _, identity := range []string{`true and (%s)`, `(%s) and true`, `false or (%s)`, `(%s) or false`} {
				for _, wrap := range []string{`%s`, `not (%s)`, `defined (%s)`, `not defined (%s)`, `not not (%s)`} {
					// Observe counts so fast mode preserves the same occurrence evidence.
					fmt.Fprintf(&source, `
rule r%d { strings: $a = "a" condition: #a >= 0 and (%s) }
`, index, fmt.Sprintf(wrap, fmt.Sprintf(identity, operand)))
					index++
				}
			}
			checkLibyaraScanMatrix(t, differentialScanCase{
				source:       source.String(),
				inputs:       [][]byte{nil, {0}, {1}, {2}, []byte("a"), []byte("aa"), []byte("b"), nil, []byte("a")},
				readerChunks: []int{1, 3},
			})
		})
	}
}
