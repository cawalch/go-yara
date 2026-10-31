package integration

import (
	"fmt"
	"strings"
	"testing"
)

func TestLibyaraUnboundedAtomEndpoints(t *testing.T) {
	for _, tc := range []struct{ pattern, input string }{
		{`\x00(\x00|\x00a)+`, "\x00\x00\x00\x00\x00\x00"}, {`\x00(\x00a|\x00)+`, "\x00\x00\x00\x00\x00\x00"},
		{`(abc|ab)+`, "abcabc"}, {`(ab|abc)+`, "abcabc"},
		{`(abcd!!x|abcd!)+?`, "abcd!!x"}, {`(abcd!|abcd!!x)+?`, "abcd!!x"},
		{`x(ab|a)+?`, "xabab"}, {`x(a|ab)+?`, "xabab"},
		{`(a|ab)+b`, "ababb"}, {`(ab|a)+?b`, "ababb"},
		{`(a|ab)+xyz`, "ababxyz"}, {`(ab|a)+?xyz`, "ababxyz"},
		{`(a|ab)*xyz`, "ababxyz"}, {`(ab|a)*?xyz`, "ababxyz"},
		{`x(a|ab)*xyz`, "xababxyz"}, {`x(ab|a)*?xyz`, "xababxyz"},
		{`(!a|!ab)+?`, "!a!a"}, {`(ba|ba!!a)+?!`, "baba!!a!!a"}, {`(aa|aaaa)+xyz`, "aaaxyz"},
		{`(ab|cd!)+?`, "abcd!"}, {`(ab|cd)+?`, "abcd"},
		{`(!|!\x00a)+`, "!\x00a!\x00a"}, {`(!\x00a|!)+?`, "!\x00a!\x00a"},
		{`(a|a!)+b`, "a!a!b"}, {`(a!ab|a)+?`, "a!aba!ab"},
		{`hello(ab|a)+?`, "helloabab"}, {`(a|ab)*`, "abab"},
	} {
		for _, mod := range []string{"", "nocase", "wide", "wide nocase", "fullword", "wide fullword", "ascii wide fullword", "ascii wide nocase fullword"} {
			t.Run(tc.pattern+mod, func(t *testing.T) {
				source := fmt.Sprintf(`rule p{strings:$a=/%s/ %s condition:#a>0} rule two{strings:$a=/%s/ %s condition:#a==2} rule length_five{strings:$a=/%s/ %s condition:!a[1]==5} rule healthy{condition:true}`, tc.pattern, mod, tc.pattern, mod, tc.pattern, mod)
				malformed := releaseWideBytes([]byte(tc.input))
				malformed[len(malformed)-1] = 1
				checkLibyaraScanMatrix(t, differentialScanCase{source: source, inputs: [][]byte{[]byte(tc.input), []byte(tc.input + "X"), []byte(tc.input + "!" + tc.input), releaseWideBytes([]byte(tc.input)), releaseWideBytes([]byte(strings.ToUpper(tc.input))), malformed, nil, []byte(tc.input)}})
			})
		}
	}
}
