package integration

import (
	"bytes"
	"fmt"
	"testing"
)

func TestLibyaraFixedOffsetNonText(t *testing.T) {
	for _, tc := range []struct {
		pattern string
		unit    string
	}{
		{`/a/`, "a"}, {`/abcd/`, "abcd"}, {`/\x61\x62/`, "ab"}, {`/a\./`, "a."},
		{`/(a)/`, "a"}, {`/a(a)/`, "aa"}, {`/((abcd))/`, "abcd"},
		{`/[a]/`, "a"}, {`/[a-a]/`, "a"}, {`/a{1}/`, "a"}, {`/a{2}/`, "aa"},
		{`/a{1,1}/`, "a"}, {`/a{0}a/`, "a"}, {`/a|a/`, "a"}, {`/a+/`, "a"}, {`/^a/`, "a"}, {`/a$/`, "a"}, {`/a\b/`, "a"},
		{`{61}`, "a"}, {`{61 62 63 64}`, "abcd"}, {`{(61)}`, "a"},
		{`{61 (62)}`, "ab"}, {`{((61))}`, "a"}, {`{(61|61)}`, "a"},
		{`{6?}`, "a"}, {`{?1}`, "a"}, {`{~62}`, "a"}, {`{??}`, "a"}, {`{61 [1] 61}`, "aaa"},
	} {
		t.Run(tc.pattern, func(t *testing.T) {
			checkLibyaraScanMatrix(t, differentialScanCase{
				source: fmt.Sprintf(`
rule fixed { strings: $a=%s condition: $a at %d }
rule observed { strings: $a=%s condition: #a >= 0 and $a at %d }
rule other_offset { strings: $a=%s condition: $a at %d }
rule inverse { strings: $a=%s condition: not ($a at %d) }
rule healthy { condition: true }`, tc.pattern, len(tc.unit), tc.pattern, len(tc.unit), tc.pattern, 2*len(tc.unit), tc.pattern, len(tc.unit)),
				inputs:       [][]byte{bytes.Repeat([]byte(tc.unit), 4), nil, []byte("z"), []byte(tc.unit), bytes.Repeat([]byte(tc.unit), 4)},
				readerChunks: []int{1, 3},
			})
		})
	}
	for _, condition := range []string{
		`$a at 1`, `not ($a at 1)`, `$a at 1 or $a at 2`, `!a[1] == 1 and $a at 1`,
		`@a[1] == 0 and $a at 1`, `$a and $a at 1`, `false and #a > 0 or $a at 1`,
		`any of them at 1`, `$a at (filesize - 2)`,
	} {
		for _, pattern := range []string{`/a/`, `{61}`} {
			t.Run(pattern+condition, func(t *testing.T) {
				checkLibyaraScanMatrix(t, differentialScanCase{
					source: fmt.Sprintf(`rule query { strings: $a=%s condition: %s } rule healthy { condition: true }`, pattern, condition),
					inputs: [][]byte{[]byte("aaa"), []byte("aba"), nil, []byte("aaa")}, readerChunks: []int{1, 3},
				})
			})
		}
	}
	for _, tc := range []struct {
		pattern string
		offset  int
		data    []byte
	}{
		{`/abc/i`, 3, []byte("abcABCabc")}, {`/a/ fullword`, 2, []byte("a a a")},
		{`/ab/ wide`, 4, releaseWideBytes([]byte("ababab"))},
		{`/a/ ascii wide`, 1, []byte{'a', 'a', 0, 'a'}},
	} {
		t.Run(tc.pattern, func(t *testing.T) {
			checkLibyaraScanMatrix(t, differentialScanCase{
				source: fmt.Sprintf(`rule fixed { strings: $a=%s condition: $a at %d }`, tc.pattern, tc.offset),
				inputs: [][]byte{tc.data, nil, tc.data}, readerChunks: []int{1, 3},
			})
		})
	}
}
