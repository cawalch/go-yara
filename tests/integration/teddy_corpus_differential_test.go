package integration

import (
	"fmt"
	"strings"
	"testing"
)

func TestLibyaraTeddyCorpus(t *testing.T) {
	var source strings.Builder
	for i := range 96 {
		modifier := ""
		prefix := "api"
		switch i % 3 {
		case 1:
			modifier = " nocase"
			prefix = "sec"
		case 2:
			modifier = " ascii wide fullword"
			prefix = "wide"
		}
		fmt.Fprintf(&source, "rule family_%d {strings:$a=\"%s_token_%02d\" %s condition:$a}\n", i, prefix, i, modifier)
	}
	clean := []byte(strings.Repeat("request completed status=200 normal activity ", 24))
	hit := append([]byte(nil), clean...)
	copy(hit[511:], "SEC_token_94")
	hit[len(hit)-29] = '!'
	copy(hit[len(hit)-28:], releaseWideBytes([]byte("wide_token_95")))
	copy(hit[len(hit)-2:], "!!")
	near := []byte(strings.Repeat("api_api sec_sec wide_wide ", 48))
	checkLibyaraScanMatrix(t, differentialScanCase{
		source: source.String(), readerChunks: []int{7, 127},
		inputs: [][]byte{clean, hit, near, []byte("api_token_00"), nil, hit},
	})
}
