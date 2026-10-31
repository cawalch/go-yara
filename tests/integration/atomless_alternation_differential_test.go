package integration

import (
	"fmt"
	"testing"
)

func TestLibyaraAtomlessAlternationPriority(t *testing.T) {
	for _, pattern := range []string{
		`(ab|[a])`, `([a]|ab)`, `(a[b]|[a])`, `(abc|[a]b|[a])`, `([a]|[a]b|abc)`,
		`(a[bc]|[a])`, `(ab[c]|[a])`, `(a.|[a])`, `(a\w|[a])`, `(ab|[a])+?`, `(ab|[a])+`,
		`(ab|[a])*?`, `(ab|[a])*`, `(ab|[a])?`, `(ab|[a])??`, `(ab|[a]){1,2}?`, `(ab|[a]){1,2}`,
		`(ab|a)`, `(a|ab)`, `a+?`, `(ab|a)+`, `[ab]+?`,
	} {
		for _, modifier := range []string{"", "nocase", "wide", "wide nocase", "ascii wide", "fullword", "wide fullword", "ascii wide fullword"} {
			t.Run(pattern+modifier, func(t *testing.T) {
				source := fmt.Sprintf(`rule p {strings:$a=/%s/ %s condition:#a>0}
rule count_two {strings:$a=/%s/ %s condition:#a==2}
rule length_four {strings:$a=/%s/ %s condition:!a[1]==4}
rule healthy {condition:true}`, pattern, modifier, pattern, modifier, pattern, modifier)
				checkLibyaraScanMatrix(t, differentialScanCase{source: source, inputs: [][]byte{
					[]byte("ab"), releaseWideBytes([]byte("ab")), []byte("abc"), []byte("abab"), releaseWideBytes([]byte("abab")),
					[]byte("ab!"), releaseWideBytes([]byte("AB!")), nil, []byte("a"), {'a', 0, 'b', 1}, {'a', 0, 'b'}, {'!', 'a', 0, 'b', 0, '!'}, []byte("ab"),
				}})
			})
		}
	}
}

func TestLibyaraAtomlessAlternationBoundedReaders(t *testing.T) {
	for _, pattern := range []string{`(ab|[a])`, `([a]|ab)`, `(abc|[a]b|[a])`, `(ab[c]|[a])`, `(ab|[a]){1,2}?`, `(ab|[a]){1,2}`} {
		t.Run(pattern, func(t *testing.T) {
			checkLibyaraScanMatrix(t, differentialScanCase{
				source: fmt.Sprintf(`rule p {strings:$a=/%s/ ascii wide fullword condition:#a>0} rule healthy {condition:true}`, pattern),
				inputs: [][]byte{[]byte("ab!"), releaseWideBytes([]byte("abab!")), nil, {'!', 'a', 0, 'b', 0, '!'}}, readerChunks: []int{1, 3},
			})
		})
	}
}
