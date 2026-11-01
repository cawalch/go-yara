package integration

import (
	"fmt"
	"testing"
)

func TestLibyaraPrefixOptionalRepeatEntries(t *testing.T) {
	for _, pattern := range []string{
		`!(a?.)+`, `!((a?)?.)+`, `!(a?b?.)+`, `!((a?.){1,2})+`,
		`!((a?.){2})+`, `!(a??.)+?`, `!([a]?.)+`, `xyz(a?.)+`,
		// A suffix-selected atom still requires backward verification.
		`!(a?.)+xyz`, `(a?.)+!`, `!(a?.)*`,
	} {
		for _, modifier := range []string{"", "nocase", "wide", "ascii wide", "fullword", "ascii wide fullword"} {
			t.Run(pattern+modifier, func(t *testing.T) {
				source := fmt.Sprintf(`rule p {strings:$a=/%s/ %s condition:#a>0}
rule exact {strings:$a=/%s/ %s condition:#a==2 and @a[1]==0 and !a[1]==2 and @a[2]==2 and !a[2]==2}
rule inverse {strings:$a=/%s/ %s condition:#a==2 and !a[1]!=2}`, pattern, modifier, pattern, modifier, pattern, modifier)
				checkLibyaraScanMatrix(t, differentialScanCase{
					source: source, readerChunks: []int{1, 2, 7},
					inputs: [][]byte{[]byte("!b!b"), []byte("!a!a!"), []byte("!abxyz"), []byte("xyz!xyz!"),
						releaseWideBytes([]byte("!A!A!")), {0, '!', 0, '!'}, nil, []byte("!b!b")},
				})
			})
		}
	}
}
