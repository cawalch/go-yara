package integration

import (
	"fmt"
	"testing"
)

func TestLibyaraBoundedLiteralAlternation(t *testing.T) {
	for _, alt := range []string{`a|ab`, `ab|a`, `abc|ab`, `a|ab|bcde|c`, `aaaa!x|aaaa`, `(a|ab)|abc`} {
		for _, repeat := range []string{"{1,2}", "{2,3}", "{1,2}?", "{2,2}?"} {
			for _, mod := range []string{"", "wide", "nocase", "wide nocase", "fullword", "ascii wide fullword"} {
				pattern := "(" + alt + ")" + repeat
				t.Run(pattern+mod, func(t *testing.T) {
					src := fmt.Sprintf(`rule p {strings:$a=/%s/ %s condition:#a>0}
rule two {strings:$a=/%s/ %s condition:#a==2}
rule length_three {strings:$a=/%s/ %s condition:!a[1]==3}
rule healthy {condition:true}`, pattern, mod, pattern, mod, pattern, mod)
					checkLibyaraScanMatrix(t, differentialScanCase{source: src, inputs: [][]byte{[]byte("abab"), []byte("aaaa!xaaaa!x"), []byte("abcdeabcde"), releaseWideBytes([]byte("abab")), releaseWideBytes([]byte("ABCABC")), nil, {'a', 0, 'b', 1}, {'a', 0, 'b'}, {'!', 'a', 0, 'b', 0, '!'}, []byte("abab")}, readerChunks: []int{1, 3}})
				})
			}
		}
	}
}

func TestLibyaraBoundedAlternationControls(t *testing.T) {
	for _, pattern := range []string{`(a|ab){0,2}`, `(ab|cd){1,2}?`, `(a|[b]){1,2}`, `abcd(e|ef)`, `(a|ab)+`, `[ab]{1,3}`} {
		t.Run(pattern, func(t *testing.T) {
			checkLibyaraScanMatrix(t, differentialScanCase{source: fmt.Sprintf(`rule p {strings:$a=/%s/ ascii wide fullword condition:#a>0} rule healthy {condition:true}`, pattern), inputs: [][]byte{[]byte("abab"), []byte("abcdef"), releaseWideBytes([]byte("abab")), nil}})
		})
	}
}

func TestLibyaraBoundedEncodingCollision(t *testing.T) {
	for _, repeat := range []string{"{1,2}", "{1,2}?"} {
		for _, mod := range []string{"ascii wide fullword", "ascii wide nocase fullword"} {
			t.Run(repeat+mod, func(t *testing.T) {
				source := fmt.Sprintf(`rule p {strings:$a=/(!\x00a|!)%s/ %s condition:#a>0} rule healthy {condition:true}`, repeat, mod)
				checkLibyaraScanMatrix(t, differentialScanCase{source: source, inputs: [][]byte{[]byte("!\x00a!\x00a"), []byte("!\x00A!\x00A"), releaseWideBytes([]byte("!\x00a!\x00a")), releaseWideBytes([]byte("!\x00A!\x00A")), nil, []byte("!\x00a!\x00a")}, readerChunks: []int{1, 3}})
			})
		}
	}
}
