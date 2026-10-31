package integration

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestLibyaraLazyPositiveRepetition(t *testing.T) {
	for _, tc := range []struct{ pattern, input string }{
		{`a+?`, "aa\x00"}, {`a\x00+?`, "a\x00\x00\x00\x00!"},
		{`[a]+?`, "aaa!"}, {`[^x]+?`, "abcx"}, {`.+?`, "abc\n"},
		{`\d+?`, "123!"}, {`\D+?`, "abc1"}, {`\w+?`, "abc!"}, {`\W+?`, "!!!a"},
		{`\s+?`, "   a"}, {`\S+?`, "aaa "},
		{`a{1,3}?`, "aaaa!"}, {`a{2,4}?`, "aaaaa!"}, {`a{2,}?`, "aaaaa!"}, {`(a)+?`, "aaa!"}, {`(ab)+?`, "abab!"}, {`(a!)+?`, "a!a!"}, {`a{1,}?`, "aaaa!"}, {`za+?`, "zaaa!"}, {`a+?b`, "aaab"},
	} {
		modifiers := []string{"ascii", "wide", "ascii wide", "nocase", "ascii fullword"}
		if tc.pattern == "a+?" || tc.pattern == "(a)+?" || tc.pattern == "(ab)+?" || tc.pattern == "(a!)+?" {
			modifiers = append(modifiers, "wide fullword", "ascii wide fullword", "wide nocase fullword")
		}
		for _, modifier := range modifiers {
			t.Run(tc.pattern+modifier, func(t *testing.T) {
				input := []byte(tc.input)
				if strings.Contains(modifier, "nocase") {
					input = bytes.ToUpper(input)
				}
				if strings.Contains(modifier, "wide") && !strings.Contains(modifier, "ascii") {
					input = releaseWideBytes(input)
				}
				source := fmt.Sprintf(`rule observed {strings:$a=/%s/ %s condition:#a>0}
rule first_length {strings:$a=/%s/ %s condition:!a[1]==1}
rule second_length {strings:$a=/%s/ %s condition:!a[2]==1}
rule healthy {condition:true}`, tc.pattern, modifier, tc.pattern, modifier, tc.pattern, modifier)
				checkLibyaraScanMatrix(t, differentialScanCase{source: source, inputs: [][]byte{input, nil, []byte("!"), input, releaseWideBytes([]byte(tc.input))}, readerChunks: []int{1, 3}})
			})
		}
	}
}

func TestLibyaraLazyPositiveGreedyControls(t *testing.T) {
	for _, pattern := range []string{`a+`, `[a]+`, `a{1,3}`, `a{2,}`, `a{2,4}`} {
		for _, modifier := range []string{"ascii", "wide", "ascii wide", "nocase"} {
			t.Run(pattern+modifier, func(t *testing.T) {
				input := []byte("aaaaa!")
				if strings.Contains(modifier, "wide") && !strings.Contains(modifier, "ascii") {
					input = releaseWideBytes(input)
				}
				checkLibyaraScanMatrix(t, differentialScanCase{
					source: fmt.Sprintf(`rule p {strings:$a=/%s/ %s condition:#a>0 and !a[1]>=1} rule healthy {condition:true}`, pattern, modifier),
					inputs: [][]byte{input, nil, []byte("!"), input},
				})
			})
		}
	}
}
