package integration

import (
	"fmt"
	"strings"
	"testing"
)

func TestLibyaraFullwordAlternatives(t *testing.T) {
	patterns := []string{`/a|ab/`, `/ab|a/`, `/a|a!/`, `/a!|a/`, `/(a|ab)+/`, `/(a|ab)+b/`, `/(a|a!)+/`,
		`/((a|ab)|abc)/`, `/a|a!b/`, `/ab|abcd/`, `/abcd|abcde/`, `/abcd(e|ef)/`, `/a+/`, `"a"`, `/a|a\x00/`}
	for _, tc := range []struct {
		modifier string
		patterns []string
	}{
		{"", patterns}, {"fullword", patterns}, {"fullword nocase", patterns},
		{"wide fullword", patterns}, {"ascii wide fullword", patterns}, {"ascii wide fullword nocase", patterns},
	} {
		modifier := tc.modifier
		t.Run(modifier, func(t *testing.T) {
			var source strings.Builder
			for i, pattern := range tc.patterns {
				for j, condition := range []string{`#a >= 1 and !a[1] >= 0`, `!a[1] == 2`, `#a == 2`} {
					fmt.Fprintf(&source, "rule p%d_c%d { strings: $a = %s %s condition: %s }\n", i, j, pattern, modifier, condition)
				}
			}
			inputs := [][]byte{nil}
			for _, input := range []string{"ab", "AB", "abab", "ababb", "abcd", "abcde", "abcdef", "a!", "a!b", "a!ab", "a!a!", "zab", "abz", "_ab_", "a_b", "!", "a\x00"} {
				inputs = append(inputs, []byte(input), releaseWideBytes([]byte(input)))
			}
			checkLibyaraScanMatrix(t, differentialScanCase{source: source.String(), inputs: inputs})
		})
	}
}
