package integration

import (
	"fmt"
	"strings"
	"testing"
)

func TestLibyaraAffixedRepeats(t *testing.T) {
	for _, tc := range []struct {
		pattern, input string
		bounded        bool
	}{
		{`xy(ab|a)+?`, "xyabab", false}, {`hello(ab|a)+?`, "helloabab", false}, {`xy(a|ab)+?`, "xyabab", false},
		{`hello(ab|a)+?b`, "helloababb", false}, {`hello(ab|a)*?b`, "helloababb", false},
		{`x(a|ab){1,2}b`, "xabab", true}, {`x(ab|a){1,2}b`, "xabab", true},
		{`x(a|ab){1,2}?b`, "xabab", true}, {`x(ab|a){1,2}?b`, "xabab", true},
		{`x(a|ab){2,3}b`, "xababab", true}, {`x(ab|a){2,3}?b`, "xababab", true},
		{`hello(a|ab){1,2}b`, "helloabab", true}, {`hello(ab|a){1,2}?b`, "helloabab", true},
		{`x(a|ab){1,2}xyz`, "xababxyz", true}, {`x(ab|a){1,2}?xyz`, "xababxyz", true},
		{`(a|ab){0,2}xyz`, "ababxyz", true}, {`(ab|a){0,2}?xyz`, "ababxyz", true},
		{`hello(a|ab){0,2}b`, "helloabab", true}, {`hello(a|ab){0,0}b`, "hellob", true},
		{`x((a|ab)|abc){1,2}b`, "xabcabb", true}, {`x(abc|ab){2,2}?`, "xabcabc", true},
		{`x(!\x00a|!){1,2}`, "x!\x00a!\x00a", true}, {`\x00(\x00|\x00a){1,2}b`, "\x00\x00a\x00ab", true},
		{`x(a|ab){1,2}(c|cd)`, "xababcd", true}, {`(a|ab)x(c|cd){1,2}`, "abxcdcd", true},
	} {
		for _, mod := range []string{"", "nocase", "wide", "wide nocase", "fullword", "wide fullword", "ascii wide fullword", "ascii wide nocase fullword"} {
			t.Run(tc.pattern+mod, func(t *testing.T) {
				source := fmt.Sprintf(`rule p{strings:$a=/%s/ %s condition:#a>0} rule two{strings:$a=/%s/ %s condition:#a==2} rule length_five{strings:$a=/%s/ %s condition:!a[1]==5} rule healthy{condition:true}`, tc.pattern, mod, tc.pattern, mod, tc.pattern, mod)
				malformed := releaseWideBytes([]byte(tc.input))
				malformed[len(malformed)-1] = 1
				c := differentialScanCase{source: source, inputs: [][]byte{[]byte(tc.input), []byte(tc.input + "X"), []byte(tc.input + "!" + tc.input), releaseWideBytes([]byte(tc.input)), releaseWideBytes([]byte(strings.ToUpper(tc.input))), malformed, nil, []byte(tc.input)}}
				if tc.bounded {
					c.readerChunks = []int{1, 3}
				}
				checkLibyaraScanMatrix(t, c)
			})
		}
	}
}

func TestLibyaraAffixedRepeatControls(t *testing.T) {
	for _, tc := range []struct{ pattern, mod, input string }{
		{`x(ab|a)+?`, "", "xabab"}, {`x(ab|a)+?`, "wide nocase", "X\x00A\x00B\x00A\x00B\x00"},
		{`(ab|a)+?`, "fullword", "abab"}, {`(abc|ab){1,2}`, "wide nocase", "A\x00B\x00C\x00A\x00B\x00C\x00"},
		{`hello(a|ab)+b`, "", "helloababb"}, {`abcd(e|ef)`, "fullword", "abcdef"},
		{`[a!]+`, "fullword", "a!ab"}, {`hello(ab|[a])+?`, "", "helloabab"},
	} {
		t.Run(tc.pattern+tc.mod, func(t *testing.T) {
			source := fmt.Sprintf(`rule p{strings:$a=/%s/ %s condition:#a>0} rule healthy{condition:true}`, tc.pattern, tc.mod)
			checkLibyaraScanMatrix(t, differentialScanCase{source: source, inputs: [][]byte{[]byte(tc.input), nil, []byte(tc.input)}})
		})
	}
}
