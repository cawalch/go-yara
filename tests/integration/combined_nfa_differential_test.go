package integration

import (
	"fmt"
	"strings"
	"testing"
)

func TestLibyaraCombinedNFA(t *testing.T) {
	for _, expression := range []string{`key=[a-z]{16,32}!`, `key=[a-z]{16,32}?!`, `key=[a-z]{16,32}a`, `key=[a-z]{16,32}?a`, `key=(ab|a)[a-z]{16,24}!`, `key=(a|ab)[a-z]{16,24}!`, `key=[^a-z]{16,32}!`, `key=(aa|a)?[a-z]{16,32}!`} {
		for _, modifier := range []string{"", "nocase", "wide", "ascii wide fullword"} {
			t.Run(expression+modifier, func(t *testing.T) {
				var source strings.Builder
				fmt.Fprintf(&source, `rule target {strings:$a=/%s/ %s condition:#a>0}`, expression, modifier)
				for i := range 8 {
					fmt.Fprintf(&source, "\nrule shared%d {strings:$a=/key=[a-z]{16,%d}!/ %s condition:#a>0}", i, 64+i, modifier)
				}
				hit := []byte("!key=" + strings.Repeat("a", 40) + "!key=ab" + strings.Repeat("a", 20) + "!")
				binary := append([]byte("key="), []byte(strings.Repeat("\x80\x00\xff", 8))...)
				binary = append(binary, '!')
				checkLibyaraScanMatrix(t, differentialScanCase{source: source.String(), readerChunks: []int{1, 31, 64}, inputs: [][]byte{hit, []byte(strings.ToUpper(string(hit))), releaseWideBytes(hit), binary, []byte("key=" + strings.Repeat("a", 15) + "!"), nil}})
			})
		}
	}
}
