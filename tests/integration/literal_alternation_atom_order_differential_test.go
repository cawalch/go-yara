package integration

import (
	"fmt"
	"testing"
)

func TestLibyaraLiteralAlternationAtomOrder(t *testing.T) {
	for _, alt := range []string{`abc|ab`, `ab|abc`, `a|ab`, `(a|ab)|abc`, `aaaa!x|aaaa`, `!\x00a|!`, `abcde|abcd`, `A|ab`} {
		for _, mod := range []string{"", "nocase", "wide", "wide nocase", "ascii wide nocase", "fullword", "wide nocase fullword", "ascii wide nocase fullword"} {
			t.Run(alt+mod, func(t *testing.T) {
				source := fmt.Sprintf(`rule p {strings:$a=/(%s)/ %s condition:#a>0} rule length_six {strings:$a=/(%s)/ %s condition:!a[1]==6} rule two {strings:$a=/(%s)/ %s condition:#a==2} rule healthy {condition:true}`, alt, mod, alt, mod, alt, mod)
				checkLibyaraScanMatrix(t, differentialScanCase{source: source, inputs: [][]byte{[]byte("abcd"), []byte("ABCD"), releaseWideBytes([]byte("abcd")), releaseWideBytes([]byte("ABCD")), releaseWideBytes([]byte("ABcD")), []byte("aaaa!xaaaa!x"), []byte("!\x00a!\x00a"), {'a', 0, 'b', 1}, nil, releaseWideBytes([]byte("ABCD"))}, readerChunks: []int{1, 3}})
			})
		}
	}
}

func TestLibyaraLiteralAlternationAtomControls(t *testing.T) {
	for _, pattern := range []string{`(abc|xyz)`, `(ab|[a])`, `(abc|ab){1,2}`, `(a|ab)+`, `(ab|a)+?`, `hello(a|ab)+b`, `abcd(e|ef)`} {
		t.Run(pattern, func(t *testing.T) {
			source := fmt.Sprintf(`rule p {strings:$a=/%s/ wide nocase condition:#a>0} rule healthy {condition:true}`, pattern)
			checkLibyaraScanMatrix(t, differentialScanCase{source: source, inputs: [][]byte{[]byte("abcd"), releaseWideBytes([]byte("ABCD")), releaseWideBytes([]byte("ABCABC")), nil}})
		})
	}
}
