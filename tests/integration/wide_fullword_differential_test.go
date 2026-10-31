package integration

import (
	"fmt"
	"testing"
)

func TestLibyaraWideFullwordBoundaries(t *testing.T) {
	for _, pattern := range []string{
		`[a]`, `[a]{1}`, `[ab]+`, `[ab]+?`, `[ab]*`, `a*`, `a*?`, `a?`, `a{0,2}`, `[a]{1,2}`,
		`\w`, `\w+`, `\d`, `[^b]`, `.`, `.+`, `(a|[b])`, `([a]|[b])`, `(ab|[c])`, `(a|b)*`,
		`a`, `(a)`, `a+`, `a{1,2}`, `[a]b`, `a[b]`, `a*b`, `a|b`, `([a]|b)c`, `a([b]|c)`,
	} {
		for _, modifier := range []string{"fullword", "wide fullword", "ascii wide fullword", "wide nocase fullword"} {
			t.Run(pattern+modifier, func(t *testing.T) {
				source := fmt.Sprintf(`rule occurrences {strings:$a=/%s/ %s condition:#a>0}
rule count_two {strings:$a=/%s/ %s condition:#a==2}
rule length_two {strings:$a=/%s/ %s condition:!a[1]==2}
rule healthy {condition:true}`, pattern, modifier, pattern, modifier, pattern, modifier)
				checkLibyaraScanMatrix(t, differentialScanCase{source: source, inputs: [][]byte{
					{'a', 'a', 0}, {'a', 0, 'a', 0}, {'a', 0, 'b', 'c', 'd'}, nil, {'a', 0, '!'},
					{'x', 'a', 0}, {'!', 'a', 0, 'b', 0}, {'A', 0, 'A', 0}, []byte("aab!"), releaseWideBytes([]byte("abc!")),
					{'a', 0, 'a', 0},
				}})
			})
		}
	}
}

func TestLibyaraWideFullwordBoundedReaders(t *testing.T) {
	for _, pattern := range []string{`[a]`, `[a]{1,2}`, `a{0,2}`, `[a]b`, `a[b]`, `a|b`} {
		t.Run(pattern, func(t *testing.T) {
			checkLibyaraScanMatrix(t, differentialScanCase{
				source: fmt.Sprintf(`rule p {strings:$a=/%s/ ascii wide fullword condition:#a>=1} rule healthy {condition:true}`, pattern),
				inputs: [][]byte{{'a', 0, 'a', 0}, {'a', 'a', 0}, {'a', 0, 'b', 'c', 'd'}, nil, releaseWideBytes([]byte("abab"))}, readerChunks: []int{1, 3},
			})
		})
	}
}
