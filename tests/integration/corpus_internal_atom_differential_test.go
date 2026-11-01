package integration

import (
	"fmt"
	"strings"
	"testing"
)

func TestLibyaraCorpusInternalAtoms(t *testing.T) {
	for _, suffix := range []string{`[0-9]{2}`, `(a?b)+`, `.*?END`} {
		for _, modifier := range []string{"", "nocase", "wide", "ascii wide fullword"} {
			t.Run(suffix+modifier, func(t *testing.T) {
				var source strings.Builder
				for i := range 40 {
					fmt.Fprintf(&source, "rule internal_%d {strings:$a=/key=[a-z][a-z][a-z][a-z]TOKEN_%08d%s/ %s condition:#a>0}\n", i, i, suffix, modifier)
				}
				hit := []byte("!key=abcdTOKEN_0000003942ababEND!key=wxyzTOKEN_0000000173bEND!")
				checkLibyaraScanMatrix(t, differentialScanCase{
					source: source.String(), readerChunks: []int{1, 7, 127},
					inputs: [][]byte{hit, []byte(strings.ToUpper(string(hit))), releaseWideBytes(hit), []byte("key=1234TOKEN_0000003942ababEND"), []byte("key=abcdnot_a_token"), nil, hit},
				})
			})
		}
	}
	var folded strings.Builder
	folded.WriteString(`
rule a {strings:$a=/^key=[0-9]{2}[aA][bB][cC][dD][eE][fF][gG][hH]/ condition:$a}
rule b {strings:$a=/^key=[0-9]{2}[qQ][rR][sS][tT][uU][vV][wW][xX]/ condition:$a}`)
	for i := range 30 {
		fmt.Fprintf(&folded, "rule extra%d {strings:$a=/key=[0-9]{2}TOKEN_%08d/ condition:$a}\n", i, i)
	}
	checkLibyaraScanMatrix(t, differentialScanCase{
		source:       folded.String(),
		readerChunks: []int{1, 7},
		inputs:       [][]byte{[]byte("key=12aBcDeFgH"), []byte("key=12QrStUvWx"), []byte("KEY=12aBcDeFgH"), []byte("!key=12QrStUvWx"), nil},
	})
}
