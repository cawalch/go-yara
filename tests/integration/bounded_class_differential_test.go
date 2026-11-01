package integration

import (
	"fmt"
	"strings"
	"testing"
)

func TestLibyaraBoundedClasses(t *testing.T) {
	for _, expression := range []string{`key=[A-Za-z0-9_-]{32,64}`, `key=[a-z]{32,64}?`, `[a-z]{32,64}`, `key=[^a-z]{16,32}`, `key=\d{32}`, `key=[\x00\x80-\xff]{16,32}`} {
		for _, modifier := range []string{"", "nocase", "wide", "ascii wide fullword"} {
			t.Run(expression+modifier, func(t *testing.T) {
				var source strings.Builder
				fmt.Fprintf(&source, `rule target {strings:$a=/%s/ %s condition:#a>0}`, expression, modifier)
				// Distinct verifiers force the shared non-text path as well.
				for i := range 32 {
					fmt.Fprintf(&source, "\nrule shared%d {strings:$a=/key=[A-Za-z0-9_-]{32,%d}/ condition:#a>0}", i, 65+i)
				}
				hit := []byte("!key=" + strings.Repeat("a", 65) + "!key=" + strings.Repeat("7", 40) + "!")
				checkLibyaraScanMatrix(t, differentialScanCase{
					source: source.String(), readerChunks: []int{1, 31, 64},
					inputs: [][]byte{hit, []byte(strings.ToUpper(string(hit))), releaseWideBytes(hit), []byte("key=" + strings.Repeat("a", 31)), append([]byte("key="), []byte(strings.Repeat("\x80\x00\xff", 11))...), nil},
				})
			})
		}
	}
}
