package integration

import (
	"fmt"
	"strings"
	"testing"
)

func TestLibyaraLazyFullwordAlternatives(t *testing.T) {
	for _, tc := range []struct{ pattern, input string }{
		{`(ab|a)+?`, "abab"}, {`(a|ab)+?`, "abab"},
		{`(abc|a)+?`, "abcabc"}, {`(a|abc)+?`, "abcabc"},
		{`((ab|a)|abc)+?`, "abcab"}, {`(ABC123|A)+?`, "ABC123"},
		{`(a|abcdefgh)+?`, "abcdefgh"}, {`(abcdefgh|a)+?`, "abcdefgh"},
		{`(a|ab|b)+?`, "abab"}, {`(ab|cd)+?`, "abcd"},
		{`(A|ab)+?`, "ABAB"}, {`(ab|A)+?`, "ABAB"},
	} {
		for _, mod := range []string{"fullword", "nocase fullword", "wide fullword", "wide nocase fullword", "ascii wide fullword", "ascii wide nocase fullword"} {
			t.Run(tc.pattern+mod, func(t *testing.T) {
				source := fmt.Sprintf(`rule p{strings:$a=/%s/ %s condition:#a>0} rule length_two{strings:$a=/%s/ %s condition:!a[1]==2} rule two{strings:$a=/%s/ %s condition:#a==2} rule healthy{condition:true}`, tc.pattern, mod, tc.pattern, mod, tc.pattern, mod)
				malformed := releaseWideBytes([]byte(tc.input))
				malformed[len(malformed)-1] = 1
				checkLibyaraScanMatrix(t, differentialScanCase{source: source, inputs: [][]byte{[]byte(tc.input), []byte(tc.input + "X"), []byte(tc.input + "!" + tc.input), releaseWideBytes([]byte(tc.input)), releaseWideBytes([]byte(strings.ToUpper(tc.input))), malformed, nil, []byte(tc.input)}})
			})
		}
	}
}

func TestLibyaraLazyFullwordControls(t *testing.T) {
	for _, tc := range []struct{ pattern, modifier, input string }{
		{`(ab|[a])+?`, "fullword", "ab"}, {`(ab|[a])+?`, "wide fullword", "a\x00b\x00"},
		{`abcd(e|ef)`, "fullword", "abcdef"}, {`[a!]+`, "fullword", "a!ab"},
		{`(ab|a)+?`, "", "abab"}, {`(ab|a)+?`, "wide nocase", "A\x00B\x00A\x00B\x00"},
		{`(a|ab)+`, "fullword", "abab"}, {`(a|ab){1,2}?`, "fullword", "abab"},
		{`(ab|a)*?`, "fullword", "ab"}, {`(a|a!)+?`, "fullword", "a!a!"},
		{`(a|\x00a)+?`, "ascii wide fullword", "\x00a\x00a"}, {`(a|a_)+?`, "fullword", "a_a_"},
	} {
		t.Run(tc.pattern+tc.modifier, func(t *testing.T) {
			source := fmt.Sprintf(`rule p{strings:$a=/%s/ %s condition:#a>0} rule healthy{condition:true}`, tc.pattern, tc.modifier)
			checkLibyaraScanMatrix(t, differentialScanCase{source: source, inputs: [][]byte{[]byte(tc.input), nil, []byte(tc.input)}})
		})
	}
}
