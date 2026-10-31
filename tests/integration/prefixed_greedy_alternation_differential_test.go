package integration

import (
	"fmt"
	"strings"
	"testing"
)

func TestLibyaraPrefixedGreedyAlternation(t *testing.T) {
	for _, prefix := range []struct{ pattern, input string }{{"x", "x"}, {"!", "!"}, {"hello", "hello"}, {`\x00\x00`, "\x00\x00"}} {
		for _, alt := range []string{"a|ab", "ab|a", "a|aa"} {
			for _, repeat := range []string{"+", "*"} {
				for _, suffix := range []string{"b", "xyz"} {
					for _, mod := range []string{"", "wide nocase", "ascii wide fullword"} {
						pattern := prefix.pattern + "(" + alt + ")" + repeat + suffix
						t.Run(pattern+mod, func(t *testing.T) {
							source := fmt.Sprintf(`rule p {strings:$a=/%s/ %s condition:#a>0} rule length_five {strings:$a=/%s/ %s condition:!a[1]==5} rule two {strings:$a=/%s/ %s condition:#a==2} rule healthy {condition:true}`, pattern, mod, pattern, mod, pattern, mod)
							input := prefix.input + "abab" + suffix
							checkLibyaraScanMatrix(t, differentialScanCase{source: source, inputs: [][]byte{[]byte(input), []byte(prefix.input + "aaaaaa" + suffix), []byte(input + " " + input), releaseWideBytes([]byte(input)), releaseWideBytes([]byte(strings.ToUpper(input))), []byte(input + "X"), nil, []byte(input)}})
						})
					}
				}
			}
		}
	}
}
func TestLibyaraPrefixedAtomPolicyControls(t *testing.T) {
	for _, tc := range []struct{ pattern, modifier, input string }{
		{`x(a|a!)+`, "", "xa!ab"},
		{`x(a|a!)*!@#$`, "fullword", "xaa!aa!@#$"},
		{`hello(a|ab)+b`, "", "helloabab"},
		{`x(a|abc|b)+`, "", "xabc"},
		{`x(a|abc|b)+`, "wide", "xabc"},
		{`x(a|abcdefghij|bcdefg|h)+`, "", "xabcdefghij"},
		{`x(a|abcdefghij|bcdefg|h)+`, "wide", "xabcdefghij"},
		{`x(a|a!)+a`, "fullword", "xaa!aaX"},
		{`x(a|a!)+a`, "wide fullword", "xaa!aaX"},
		{`abcd(e|ef)`, "fullword", "abcdef"},
		{`[a!]+`, "fullword", "a!ab"},
		{`x(a|ab)+?b`, "", "xabab"},
	} {
		t.Run(tc.pattern+tc.modifier, func(t *testing.T) {
			source := fmt.Sprintf(`rule p {strings:$a=/%s/ %s condition:#a>0} rule healthy {condition:true}`, tc.pattern, tc.modifier)
			checkLibyaraScanMatrix(t, differentialScanCase{source: source, inputs: [][]byte{[]byte(tc.input), releaseWideBytes([]byte(tc.input)), nil}})
		})
	}
}
