package integration

import (
	"fmt"
	"strings"
	"testing"
)

func TestLibyaraStreamUnboundedFinalization(t *testing.T) {
	for _, modifier := range []string{"", "fullword", "wide", "ascii wide nocase fullword"} {
		t.Run(modifier, func(t *testing.T) {
			var source strings.Builder
			for i, pattern := range []string{`a.*b`, `a.*?b`, `a.*$`, `^a.*b|cd`, `(a|ab)+`, `(ab|a)+?`, `a+?`, `a*`, `[a]+`, `xyz.*?`} {
				for j, condition := range []string{`#a>0`, `#a==2 and !a[1]==5`, `#a==2 and !a[1]!=5`} {
					fmt.Fprintf(&source, "rule p%d_c%d {strings:$a=/%s/ %s condition:%s}\n", i, j, pattern, modifier, condition)
				}
			}
			var inputs [][]byte
			for _, input := range []string{"ab ab", "ab abx", "abab", "ab", "!ab!cd!", "xyzab", "aaaa", "AB AB"} {
				inputs = append(inputs, []byte(input), releaseWideBytes([]byte(input)))
			}
			inputs = append(inputs, nil, []byte("ab ab"))
			checkLibyaraScanMatrix(t, differentialScanCase{source: source.String(), inputs: inputs, readerChunks: []int{1, 2, 7}})
		})
	}
}
