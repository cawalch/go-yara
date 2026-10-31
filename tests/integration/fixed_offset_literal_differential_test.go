package integration

import (
	"fmt"
	"strings"
	"testing"
)

func TestLibyaraFixedOffsetLiterals(t *testing.T) {
	for _, condition := range []string{
		`$a at 1`, `$a at (0 + 1)`, `$a at 0`, `$a at -1`,
		`not ($a at 1)`, `not ($a at 4)`,
		`$a at 1 or $a at 1`, `$a at 1 or $a at 2`,
		`#a >= 0 and $a at 1`, `@a[1] >= 0 and $a at 1`, `!a[1] == 1 and $a at 1`,
		`$a and $a at 1`, `$a at 1 and $a in (0..filesize)`,
		`false and #a > 0 or $a at 1`,
		`any of ($a) and $a at 1`, `any of them at 1`,
		`$a at (filesize - 2)`, `a and $a at 1`,
		`$a at 1 and for any of ($b) : ($ at 2)`,
		`$a at 1 and for any of ($b) : ($ at 1)`,
		`$a at 1 and for any of ($b) : ($)`,
		`for any of ($b) : ($ at 2) and $a at 1`,
	} {
		t.Run(condition, func(t *testing.T) {
			declarations := `$a = "a"`
			if strings.Contains(condition, "$b") {
				declarations += ` $b = "a"`
			}
			checkLibyaraScanMatrix(t, differentialScanCase{
				source: fmt.Sprintf(`
rule a { condition: true }
rule fixed { strings: %s condition: %s }
rule all_matches { strings: $a = "a" condition: #a >= 0 }
rule mixed { strings: $a = "a" $b = "a" condition: $a at 1 and #b >= 0 }
`, declarations, condition),
				inputs:       [][]byte{[]byte("aaa"), []byte("aba"), nil, []byte("baab"), []byte("a"), []byte("aaa")},
				readerChunks: []int{1, 2},
			})
		})
	}
	for _, tc := range []struct {
		name, declaration string
		offset            int
		data              []byte
	}{
		{"overlap", `"aa"`, 1, []byte("aaaaa")},
		{"nocase", `"a" nocase`, 1, []byte("aAa")},
		{"fullword", `"a" fullword`, 2, []byte("a a a")},
		{"wide", `"a" wide`, 2, []byte{'a', 0, 'a', 0, 'a', 0}},
		{"ascii_wide", `"a" ascii wide`, 1, []byte{'a', 'a', 0, 'a'}},
		{"xor", `"a" xor`, 1, []byte("bbb")},
		{"base64_control", `"aaa" base64`, 4, []byte("YWFhYWFh")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkLibyaraScanMatrix(t, differentialScanCase{
				source: fmt.Sprintf(`rule fixed { strings: $a = %s condition: $a at %d }
rule control { strings: $a = %s condition: #a >= 0 and $a at %d }`, tc.declaration, tc.offset, tc.declaration, tc.offset),
				inputs: [][]byte{tc.data, nil, tc.data}, readerChunks: []int{1, 3},
			})
		})
	}
}
