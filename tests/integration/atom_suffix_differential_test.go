package integration

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

func TestLibyaraRepeatedAtomSuffixBounds(t *testing.T) {
	for _, tc := range []struct {
		pattern, input string
		bounded        bool
	}{
		{`0(ab|aba)+!`, "0" + strings.Repeat("ab", 9) + "!", false},
		{`0(ab|aba)+!`, "0" + strings.Repeat("ab", 10) + "!", false},
		{`0(ab|aba)+?!`, "0" + strings.Repeat("aba", 12) + "!", false},
		{`0(bc|bcb){1,3000}!`, "0" + strings.Repeat("bc", 10) + "!", true},
		{`(ABC|ABCb)+bcd`, strings.Repeat("ABCb", 8) + "bcd", false},
		{`0(ab){2,20}!`, "0" + strings.Repeat("ab", 20) + "!", true},
		{`0(ab){20}!`, "0" + strings.Repeat("ab", 20) + "!", true},
		{`0((ab|aba){1,2}){2,10}!`, "0" + strings.Repeat("aba", 20) + "!", true},
		{`0([Aa][Bb])+!`, "0" + strings.Repeat("Ab", 20) + "!", false},
		{`0([Aa][Bb]){2,20}!`, "0" + strings.Repeat("aB", 20) + "!", true},
		{`0(ab|cd)+!`, "0" + strings.Repeat("abcd", 10) + "!", false},
		{`0(ab|cd){2,20}!`, "0" + strings.Repeat("abcd", 10) + "!", true},
		{`(ab|cd)EF[0-9]{40}`, "abEF" + strings.Repeat("1", 40), true},
	} {
		for _, mod := range []string{"", "fullword", "nocase fullword", "wide fullword", "ascii wide nocase fullword"} {
			t.Run(tc.pattern+mod+strconv.Itoa(len(tc.input)), func(t *testing.T) {
				source := fmt.Sprintf(`rule p{strings:$a=/%s/ %s condition:#a>0} rule healthy{condition:true}`, tc.pattern, mod)
				input := []byte(tc.input)
				c := differentialScanCase{source: source, inputs: [][]byte{
					input, []byte(tc.input + "X"), []byte(tc.input + "!" + tc.input),
					releaseWideBytes(input), releaseWideBytes([]byte(strings.ToUpper(tc.input))),
					input[:len(input)-1], nil, input,
				}}
				if tc.bounded {
					c.readerChunks = []int{1, 3}
				}
				checkLibyaraScanMatrix(t, c)
			})
		}
	}
}
