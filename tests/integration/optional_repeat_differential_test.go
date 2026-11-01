package integration

import (
	"fmt"
	"testing"
)

func TestLibyaraOptionalRepeatEntries(t *testing.T) {
	for _, pattern := range []string{
		`(a?.)+`, `((a?)?.)+`, `(a?b?.)+`, `((a?.){1,2})+`, `((a?.){2})+`,
		`(a??.)+?`, `([a]?.)+`, `((a?.)+)+`, `^(a?.)+$`,
		// Suffix atoms verify backwards; do not apply forward-only policy.
		`(a?.)+!`, `(a?.)+b`, `(a?.)*`, `(a?.){1,3}`,
	} {
		for _, modifier := range []string{"", "nocase", "wide", "ascii wide", "fullword", "ascii wide fullword"} {
			t.Run(pattern+modifier, func(t *testing.T) {
				source := fmt.Sprintf(`rule p {strings:$a=/%s/ %s condition:#a>0}
rule exact {strings:$a=/%s/ %s condition:#a==2 and @a[1]==0 and !a[1]==1 and @a[2]==1 and !a[2]==1}
rule inverse {strings:$a=/%s/ %s condition:#a==2 and !a[1]!=1}`, pattern, modifier, pattern, modifier, pattern, modifier)
				checkLibyaraScanMatrix(t, differentialScanCase{
					source: source, readerChunks: []int{1, 2, 7},
					inputs: [][]byte{{0, '!'}, []byte("!!"), []byte("!a!a!"), []byte("abab"),
						releaseWideBytes([]byte("!A!A!")), {0, 'a', 0, '!'}, nil, {0, '!'}},
				})
			})
		}
	}
}
