package integration

import (
	"fmt"
	"testing"
)

func TestLibyaraStartAtomRepeatEntries(t *testing.T) {
	for _, pattern := range []string{
		`^!(a?.)+`, `^!(a??.)+?`, `^!((a?)?.)+`,
		`(x|y)(a?.)+`, `(x|xy)(a?.)+`, `(xy|x)(a?.)+`,
		`(x|xy)(a??.)+?`, `(xy|x)(a??.)+?`, `^(x|xy)(a?.)+`,
		`\b(x|xy)(a?.)+`, `\B(x|xy)(a?.)+`, `(\x00|x)(a?.)+`,
		`(x|X)(a?.)+`, `(x|y)((a?.){1,2})+`, `(x|y)(a?.)+.*`,
		// Keep consuming backward prefixes and unaffected loops on their paths.
		`(x|xy)(a?.)+xyz`, `^(a?.)+xyz`, `(x|xy).*`,
	} {
		for _, modifier := range []string{"", "nocase", "wide", "ascii wide", "fullword", "ascii wide fullword"} {
			t.Run(pattern+modifier, func(t *testing.T) {
				source := fmt.Sprintf(`rule p {strings:$a=/%s/ %s condition:#a>0}
rule two {strings:$a=/%s/ %s condition:#a>0 and !a[1]==2}
rule three {strings:$a=/%s/ %s condition:#a>0 and !a[1]==3}
rule inverse {strings:$a=/%s/ %s condition:#a>0 and !a[1]!=2}`, pattern, modifier, pattern, modifier, pattern, modifier, pattern, modifier)
				checkLibyaraScanMatrix(t, differentialScanCase{
					source: source, readerChunks: []int{1, 2, 7},
					inputs: [][]byte{[]byte("!b!b"), []byte("x!y!"), []byte("xy!!"), []byte("xya!a!"),
						[]byte("axy!!"), []byte("xyabxyz"), releaseWideBytes([]byte("Xy!Y!")), {0, '!', 'x', '!'}, nil, []byte("xy!!")},
				})
			})
		}
	}
}
