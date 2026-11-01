package integration

import (
	"bytes"
	"fmt"
	"testing"
)

func TestLibyaraVerificationReuse(t *testing.T) {
	for _, pattern := range []string{`a.*b`, `a.*?b`, `a(a|aa)*b`, `a.*\bb`, `(xy|x)(a?.)+`, `(x|xy)(a??.)+?`} {
		for _, modifier := range []string{"", "nocase", "ascii wide", "fullword"} {
			t.Run(pattern+modifier, func(t *testing.T) {
				source := fmt.Sprintf(`rule p {strings:$a=/%s/ %s condition:#a>0}
rule multiple {strings:$a=/%s/ %s condition:#a>1}
rule two {strings:$a=/%s/ %s condition:#a>0 and !a[1]==2}`, pattern, modifier, pattern, modifier, pattern, modifier)
				negative := bytes.Repeat([]byte("a"), 192)
				mixed := append(bytes.Clone(negative), []byte("\nabb!xy!!xy!AAB ")...)
				checkLibyaraScanMatrix(t, differentialScanCase{source: source, readerChunks: []int{7, 127}, inputs: [][]byte{negative, mixed, releaseWideBytes(mixed), nil, mixed}})
			})
		}
	}
}
