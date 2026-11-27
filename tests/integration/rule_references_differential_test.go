package integration

import (
	"fmt"
	"strings"
	"testing"
)

func TestLibyaraWideRuleReferences(t *testing.T) {
	var source strings.Builder
	for i := range 300 {
		switch i {
		case 255, 256, 299:
			fmt.Fprintf(&source, "private rule r%d { strings: $a = \"edge%d\" condition: $a }\n", i, i)
		default:
			fmt.Fprintf(&source, "private rule r%d { condition: false }\n", i)
		}
	}
	source.WriteString(`
rule compact_reference { condition: r255 }
rule direct_reference { condition: r256 and not r299 }
rule mixed_references { condition: r255 and (r256 or r299) }
rule wide_reference { condition: r299 }
`)
	checkLibyaraScanMatrix(t, differentialScanCase{
		source: source.String(),
		inputs: [][]byte{[]byte("edge255"), []byte("edge256"), []byte("edge299"),
			[]byte("edge255 edge256"), []byte("edge256 edge299"), []byte("reject")},
		readerChunks: []int{4},
	})
}
