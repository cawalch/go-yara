package integration

import (
	"fmt"
	"strings"
	"testing"
)

func TestLibyaraZeroLengthFullword(t *testing.T) {
	patterns := []string{`/a*/`, `/a{0}/`, `/a{0,2}/`, `/^a*/`, `/^$/`, `/$/`, `/a?/`}
	for _, tc := range []struct {
		modifier string
		patterns []string
	}{
		{"", patterns}, {"fullword", patterns}, {"fullword nocase", patterns},
		{"wide", patterns}, {"wide fullword", patterns}, {"ascii wide fullword", patterns},
		{"wide ascii fullword nocase", patterns},
	} {
		modifier := tc.modifier
		t.Run(modifier, func(t *testing.T) {
			var source strings.Builder
			for i, pattern := range tc.patterns {
				for j, condition := range []string{`#a >= 1 and !a[1] >= 0`, `#a == 0`, `!a[1] == 0`, `#a == 2`} {
					fmt.Fprintf(&source, "rule p%d_c%d { strings: $a = %s %s condition: %s }\n", i, j, pattern, modifier, condition)
				}
			}
			inputs := [][]byte{nil}
			for _, input := range []string{"!", "!!", "_", "b", "!b", "b!", "a", "bb", "a!", "!a", "ab", "A!", "1!", "!1", "\x00", "a\x00!", "!\x00a"} {
				inputs = append(inputs, []byte(input), releaseWideBytes([]byte(input)))
			}
			inputs = append(inputs, nil, []byte("!"))
			checkLibyaraScanMatrix(t, differentialScanCase{source: source.String(), inputs: inputs})
		})
	}
}
