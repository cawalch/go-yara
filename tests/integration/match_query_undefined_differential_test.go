package integration

import (
	"fmt"
	"strings"
	"testing"
)

func TestLibyaraUndefinedMatchQueries(t *testing.T) {
	for _, query := range []string{
		`$a at @a[1]`, `$a at @a[0]`, `$a at @a[2]`,
		`$a at uint8(filesize)`, `$a at uint8(0)`,
		`$a in (@a[1]..filesize)`, `$a in (0..@a[1])`,
		`$a in (@a[2]..@a[2])`, `$a in (uint8(filesize)..filesize)`,
		`$a in (0..uint8(filesize))`,
		`#a >= 2 and $a at @a[2]`,
		`any of them at @a[2]`, `none of them at @a[2]`,
		`all of them in (@a[1]..filesize)`, `none of them in (0..@a[2])`,
		`any of them in (@a[2]..@a[2])`,
	} {
		t.Run(query, func(t *testing.T) {
			var source strings.Builder
			source.WriteString(`rule healthy { condition: true }`)
			for index, wrap := range []string{
				`%s`, `not (%s)`, `defined (%s)`, `not defined (%s)`,
				`(%s) or true`, `not ((%s) and filesize >= 0)`,
			} {
				// Observing the count keeps occurrence reporting comparable in fast mode.
				fmt.Fprintf(&source, `
rule query%d { strings: $a = "a" condition: #a >= 0 and (%s) }
`, index, fmt.Sprintf(wrap, query))
			}
			checkLibyaraScanMatrix(t, differentialScanCase{
				source:       source.String(),
				inputs:       [][]byte{nil, []byte("b"), []byte("a"), []byte("aa"), []byte("baab"), {0, 'a'}, []byte("b")},
				readerChunks: []int{1, 3},
			})
		})
	}
}
