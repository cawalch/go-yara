package compiler

import (
	"bytes"
	"strings"
	"testing"
)

func BenchmarkEvidenceOwnership(b *testing.B) {
	source := `rule r {strings:$a=/token=([a-z]+):([a-z]*)/ capture(name=1,secret=2,whole=0)
 evidence:pair=(name,secret) within 0 of secret condition:#a>0}`
	captureOnly := `rule r {strings:$a=/token=([a-z]+):([a-z]*)/ capture(name=1,secret=2,whole=0) condition:#a>0}`
	for _, tc := range []struct {
		name, source, input, path string
		limit                     int
	}{
		{"clean", source, strings.Repeat("clean record\n", 512), "buffer", 64},
		{"sparse_optional", `rule r {strings:$a=/(a)?x/ capture(value=1) condition:#a>0}`, "ax" + strings.Repeat("x", 511), "buffer", 64},
		{"single", source, "token=name:secret!", "buffer", 64},
		{"dense", source, strings.Repeat("token=name:secret!", 512), "buffer", 64},
		{"captures_only", captureOnly, strings.Repeat("token=name:secret!", 512), "buffer", 64},
		{"truncated", source, strings.Repeat("token=name:secret!", 512), "buffer", 2},
		{"empty", source, strings.Repeat("token=name:!", 512), "buffer", 64},
		{"large_capture", source, "token=name:" + strings.Repeat("s", 8192) + "!", "buffer", 16384},
		{"reader", source, strings.Repeat("token=name:secret!", 128), "reader", 64},
		{"block", source, strings.Repeat("token=name:secret!", 128), "block", 64},
	} {
		b.Run(tc.name, func(b *testing.B) {
			p := mustCompileBenchmarkProgram(b, tc.source)
			s := p.NewScanner(WithEvidence(tc.limit), WithStreamChunkSize(127), WithStreamEarlyTermination(false))
			defer s.Close()
			blocks := p.NewBlockScanner(WithEvidence(tc.limit))
			defer blocks.Close()
			data := []byte(tc.input)
			scan := func() {
				var err error
				switch tc.path {
				case "reader":
					_, err = s.ScanReader(bytes.NewReader(data))
				case "block":
					blocks.Reset()
					err = blocks.Scan(4096, data)
					if err == nil {
						_, err = blocks.Finish()
					}
				default:
					_, err = s.Scan(data)
				}
				if err != nil {
					b.Fatal(err)
				}
			}
			scan()
			b.ReportAllocs()
			b.SetBytes(int64(len(data)))
			b.ResetTimer()
			for b.Loop() {
				scan()
			}
		})
	}
}
