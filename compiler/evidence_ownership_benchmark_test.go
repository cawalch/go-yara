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
		borrowed                  bool
	}{
		{"clean", source, strings.Repeat("clean record\n", 512), "buffer", 64, false},
		{"sparse_optional", `rule r {strings:$a=/(a)?x/ capture(value=1) condition:#a>0}`, "ax" + strings.Repeat("x", 511), "buffer", 64, false},
		{"single", source, "token=name:secret!", "buffer", 64, false},
		{"dense", source, strings.Repeat("token=name:secret!", 512), "buffer", 64, false},
		{"dense_borrowed", source, strings.Repeat("token=name:secret!", 512), "buffer", 64, true},
		{"captures_only", captureOnly, strings.Repeat("token=name:secret!", 512), "buffer", 64, false},
		{"truncated", source, strings.Repeat("token=name:secret!", 512), "buffer", 2, false},
		{"empty", source, strings.Repeat("token=name:!", 512), "buffer", 64, false},
		{"large_capture", source, "token=name:" + strings.Repeat("s", 8192) + "!", "buffer", 16384, false},
		{"reader", source, strings.Repeat("token=name:secret!", 128), "reader", 64, false},
		{"block", source, strings.Repeat("token=name:secret!", 128), "block", 64, false},
	} {
		b.Run(tc.name, func(b *testing.B) {
			p := mustCompileBenchmarkProgram(b, tc.source)
			opts := []ScannerOption{WithEvidence(tc.limit), WithStreamChunkSize(127), WithStreamEarlyTermination(false)}
			if tc.borrowed {
				opts = append(opts, WithBorrowedEvidence(true))
			}
			s := p.NewScanner(opts...)
			defer s.Close()
			blockOpts := []ScannerOption{WithEvidence(tc.limit)}
			if tc.borrowed {
				blockOpts = append(blockOpts, WithBorrowedEvidence(true))
			}
			blocks := p.NewBlockScanner(blockOpts...)
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
