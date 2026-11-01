package integration

import (
	"fmt"
	"strings"
	"testing"
)

func TestLibyaraCorpusPrefixAtoms(t *testing.T) {
	for _, suffix := range []string{`[a-z]{1,4}`, `(a?b)+`, `.*?END`, `(xy|z){1,3}`} {
		for _, modifier := range []string{"", "nocase", "ascii wide fullword"} {
			t.Run(suffix+modifier, func(t *testing.T) {
				var source strings.Builder
				for i := range 40 {
					fmt.Fprintf(&source, "rule family_%d {strings:$a=/provider_ab%c%c=api_key=%s/ %s condition:#a>0}\n", i, 'a'+i/26, 'a'+i%26, suffix, modifier)
				}
				fmt.Fprintf(&source, "rule shifted {strings:$a=/provider_ryoqfi=api_key=%s/ %s condition:#a>0}\n", suffix, modifier)
				hit := []byte("!provider_abcd=api_key=ababxyzzEND!provider_abad=api_key=zzEND!provider_ryoqfi=api_key=xyzzEND!")
				checkLibyaraScanMatrix(t, differentialScanCase{
					source: source.String(), readerChunks: []int{1, 7},
					inputs: [][]byte{hit, []byte(strings.ToUpper(string(hit))), releaseWideBytes(hit), []byte("provider_none=api_key=ababxyzzEND"), nil, hit},
				})
			})
		}
	}
}
