package integration

import (
	"fmt"
	"strings"
	"testing"
)

func TestLibyaraRegexEncodingCollisions(t *testing.T) {
	patterns := []string{
		`"a"`, `/a/`, `/a+/`, `/[ab]+/`, `/a.{0,4}/`, `/a.*?/`,
		`/a\x00+/`, `/[a]{1}/`, `/[a]/`, `/(a|b)+/`, `/(a|ab)+/`,
	}
	for _, tc := range []struct {
		modifier string
		patterns []string
	}{
		{"ascii wide", patterns}, {"wide ascii", patterns}, {"ascii wide nocase", patterns},
		{"ascii wide fullword", []string{`"a"`, `/a/`, `/a+/`, `/a.{0,4}/`, `/a.*?/`}},
	} {
		modifier := tc.modifier
		t.Run(modifier, func(t *testing.T) {
			var source strings.Builder
			for i, pattern := range tc.patterns {
				for j, condition := range []string{`#a >= 1 and !a[1] >= 0`, `!a[1] == 2`, `#a == 2`} {
					fmt.Fprintf(&source, "rule p%d_c%d { strings: $a = %s %s condition: %s }\n", i, j, pattern, modifier, condition)
				}
			}
			inputs := [][]byte{[]byte("a\x00"), []byte("a\x00a\x00"), []byte("a\x00bcd"),
				[]byte("aa\x00"), []byte("A\x00B\x00"), []byte("a\x00\x00\x00\x00!"), []byte("!"), nil, []byte("a\x00")}
			checkLibyaraScanMatrix(t, differentialScanCase{source: source.String(), inputs: inputs})
		})
	}
}
