package integration

import (
	"fmt"
	"strings"
	"testing"
)

func TestLibyaraSymbolicPrefixes(t *testing.T) {
	chain := strings.Repeat(`(a|b)`, 8)
	word := strings.Repeat("a", 8)
	nul := strings.Repeat(`\x00`, 70)
	zero := strings.Repeat("\x00", 70)
	for _, tc := range []struct{ pattern, input string }{
		{`(a|aa)` + chain + `(a\x00b\x00CCCC|\x00b)`, strings.Repeat("a", 10) + "\x00b\x00CCCC"},
		{`(a|aa){1,1}` + chain + `(a\x00b\x00CCCC|\x00b)`, strings.Repeat("a", 10) + "\x00b\x00CCCC"},
		{`(a|ab)` + chain + `aaa`, "ab" + word + "aaa"}, {`(ab|a)` + chain + `aaa`, "ab" + word + "aaa"},
		{`(a|ab)` + strings.Repeat(`(a|b)`, 7) + `aaa`, "ab" + strings.Repeat("a", 7) + "aaa"},
		{`(a|ab)` + strings.Repeat(`(a|b)`, 20) + `aaa`, "ab" + strings.Repeat("a", 20) + "aaa"},
		{nul + `(a|ab)` + chain + `xyz!`, zero + "ab" + word + "xyz!"},
		{`(a|ab)` + strings.Repeat(`(a|b)`, 7) + nul + `xyz!`, "ab" + strings.Repeat("a", 7) + zero + "xyz!"},
		{`(a|ab)` + chain + `abcd(e|ef)`, "ab" + word + "abcdef"},
		{`(a|ab)` + chain + `abcd(ef|e)`, "ab" + word + "abcdef"},
		{`(a|ab)` + chain + `(xyz|xy)`, "ab" + word + "xyz"},
		{`(a|ab)` + chain + `(xy|xyz)`, "ab" + word + "xyz"},
		{`(a|ab){9,9}xyz`, strings.Repeat("ab", 9) + "xyz"},
		{`(a|ab){1,9}xyz`, strings.Repeat("ab", 9) + "xyz"},
		{`(a|ab){0,9}?xyz`, strings.Repeat("ab", 9) + "xyz"},
		{`(ab|a){0,9}xyz`, strings.Repeat("ab", 9) + "xyz"},
		{`(a|ab)` + chain + `(abcd!!x|abcd!){1,2}?`, "ab" + word + "abcd!!x"},
		{`(a|ab)` + chain + `(abcd!|abcd!!x){1,2}?`, "ab" + word + "abcd!!x"},
		{`(\x00|\x00a)` + strings.Repeat(`(\x00|b)`, 8) + `\x00\x00a`, strings.Repeat("\x00", 11) + "a"},
		{`(a|ab)` + chain + `abcd[ef]+`, "ab" + word + "abcdeef"},
	} {
		for _, mod := range []string{"", "nocase", "wide", "wide nocase", "fullword", "wide fullword", "ascii wide fullword", "ascii wide nocase fullword"} {
			t.Run(tc.pattern+mod, func(t *testing.T) {
				source := fmt.Sprintf(`rule p{strings:$a=/%s/ %s condition:#a>0} rule two{strings:$a=/%s/ %s condition:#a==2} rule length_thirteen{strings:$a=/%s/ %s condition:!a[1]==13} rule healthy{condition:true}`, tc.pattern, mod, tc.pattern, mod, tc.pattern, mod)
				malformed := releaseWideBytes([]byte(tc.input))
				malformed[len(malformed)-1] = 1
				checkLibyaraScanMatrix(t, differentialScanCase{source: source, inputs: [][]byte{[]byte(tc.input), []byte(tc.input + "X"), []byte(tc.input + "!" + tc.input), releaseWideBytes([]byte(tc.input)), releaseWideBytes([]byte(strings.ToUpper(tc.input))), malformed, nil, []byte(tc.input)}, readerChunks: []int{1, 3}})
			})
		}
	}
}
