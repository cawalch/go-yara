package compiler

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func BenchmarkSharedNonTextFastScan(b *testing.B) {
	data := bytes.Repeat([]byte("unrelated content\x00"), 1<<17)
	for _, tc := range []struct {
		name    string
		pattern string
	}{
		{"regex", `/cmd_run_[0-9a-f]{8}/`},
		{"hex", `{ 4D 5A ?? ?? 90 00 }`},
	} {
		b.Run(tc.name, func(b *testing.B) {
			var source strings.Builder
			for i := range 512 {
				fmt.Fprintf(&source, `rule r%d { strings: $a = "TOKEN_%d_0000" $b = %s condition: any of them }`+"\n", i, i, tc.pattern)
			}
			program, err := NewCompiler().CompileSource(source.String())
			if err != nil {
				b.Fatal(err)
			}
			for _, mode := range []struct {
				name string
				opts []ScannerOption
			}{
				{"full", nil},
				{"fast", []ScannerOption{WithFastScan()}},
			} {
				b.Run(mode.name, func(b *testing.B) {
					opts := append([]ScannerOption{WithoutMatches(), WithoutRuleResults()}, mode.opts...)
					scanner := program.NewScanner(opts...)
					defer scanner.Close()
					b.ReportAllocs()
					b.SetBytes(int64(len(data)))
					for b.Loop() {
						result, err := scanner.Scan(data)
						if err != nil || len(result.MatchedRules) != 0 {
							b.Fatalf("expected a clean reject, got %v (%v)", result, err)
						}
					}
				})
			}
		})
	}
}
