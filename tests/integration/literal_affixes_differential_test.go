package integration

import (
	"fmt"
	"strings"
	"testing"
)

func TestLibyaraLiteralAffixes(t *testing.T) {
	for _, tc := range []struct{ pattern, input string }{
		{`x(a|ab)`, "xab"}, {`x(ab|a)`, "xab"},
		{`abcd(e|ef)`, "abcdef"}, {`abcd(ef|e)`, "abcdef"},
		{`x(a|ab)b`, "xabb"}, {`x(ab|a)xyz`, "xabxyz"},
		{`x((a|ab)|abc)`, "xabc"}, {`x(a|ab)(c|cd)`, "xabcd"},
		{`x(a|ab)(cd|c)`, "xabcd"}, {`(a|ab)x(c|cd)`, "abxcd"},
		{`(a|ab)(c|cd)xyz`, "abcdxyz"}, {`(a|ab)xy(c|cd)`, "abxycd"},
		{`aaa(bbb|bbbb!)`, "aaabbbb!"}, {`x(\x00|\x00a)`, "x\x00a"},
		{`(\x00|\x00a)xyz`, "\x00axyz"}, {`(\x00|\x00a)(b|bc)`, "\x00abc"},
	} {
		for _, mod := range []string{"", "nocase", "wide", "wide nocase", "fullword", "ascii wide nocase fullword"} {
			t.Run(tc.pattern+mod, func(t *testing.T) {
				source := fmt.Sprintf(`rule p {strings:$a=/%s/ %s condition:#a>0} rule length_three {strings:$a=/%s/ %s condition:!a[1]==3} rule two {strings:$a=/%s/ %s condition:#a==2} rule healthy {condition:true}`, tc.pattern, mod, tc.pattern, mod, tc.pattern, mod)
				malformed := releaseWideBytes([]byte(tc.input))
				malformed[len(malformed)-1] = 1
				checkLibyaraScanMatrix(t, differentialScanCase{source: source, inputs: [][]byte{[]byte(tc.input), []byte(tc.input + "X"), []byte(tc.input + "!" + tc.input), releaseWideBytes([]byte(tc.input)), releaseWideBytes([]byte(strings.ToUpper(tc.input))), malformed, nil, []byte(tc.input)}, readerChunks: []int{1, 3}})
			})
		}
	}
}

func TestLibyaraLiteralAffixControls(t *testing.T) {
	for _, tc := range []struct{ pattern, modifier, input string }{
		{`[a!]+`, "fullword", "a!ab"}, {`x(a|ab)+b`, "fullword", "xabab"},
		{`x(a|[b])`, "fullword", "xb"}, {`x(ab|cd)y`, "fullword", "xaby"},
		{`(a|ab){1,2}`, "fullword", "abab"}, {`(abc|ab)`, "wide nocase", "A\x00B\x00C\x00D\x00"},
	} {
		t.Run(tc.pattern+tc.modifier, func(t *testing.T) {
			source := fmt.Sprintf(`rule p {strings:$a=/%s/ %s condition:#a>0} rule healthy {condition:true}`, tc.pattern, tc.modifier)
			checkLibyaraScanMatrix(t, differentialScanCase{source: source, inputs: [][]byte{[]byte(tc.input), nil, []byte(tc.input)}})
		})
	}
}
