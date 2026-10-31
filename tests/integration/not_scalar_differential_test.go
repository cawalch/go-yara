package integration

import (
	"fmt"
	"strings"
	"testing"
)

func TestLibyaraNotScalarOperands(t *testing.T) {
	for _, operand := range []string{
		`true`, `false`, `0`, `2`, `-3`, `0.0`, `-0.0`, `0.5`, `-0.5`,
		`""`, `"a"`, `"\x00"`, `"\x00a"`,
		`uint8(0) * 0.5`, `uint8(0) * -0.5`, `uint8(filesize) * 0.5`,
		`math.mean(0, filesize)`, `math.mean(0, 0)`, `math.mean(-1, 1)`,
		`hash.md5(0, filesize)`, `hash.md5(0, 1)`, `math.to_string(uint8(0))`, `math.to_string(1, 7)`,
	} {
		t.Run(operand, func(t *testing.T) {
			var source strings.Builder
			source.WriteString(`import "hash" import "math" rule healthy { condition: true }`)
			for index, wrap := range []string{
				`not (%s)`, `not not (%s)`, `defined (not (%s))`, `not defined (not (%s))`,
				`not (true and (%s))`, `not (false or (%s))`,
				`(not (%s)) or true`, `(not (%s)) and true`,
				`not ((not (%s)) and true)`, `defined ((not (%s)) or false)`,
			} {
				fmt.Fprintf(&source, `rule r%d { strings: $a="a" condition: #a >= 0 and (%s) }`, index, fmt.Sprintf(wrap, operand))
			}
			checkLibyaraScanMatrix(t, differentialScanCase{
				source:       source.String(),
				inputs:       [][]byte{nil, {0}, {1}, {2}, []byte("a"), []byte("ab"), nil, []byte("a")},
				readerChunks: []int{1, 3},
			})
		})
	}
}
