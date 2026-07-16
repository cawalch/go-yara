package compiler

import (
	"fmt"
	"testing"
)

// BenchmarkSingleRuleScanSize measures the fixed-rule-count scaling axis. It
// deliberately uses a clean payload so the benchmark is dominated by the scan
// rather than by result construction for a large number of matches.
func BenchmarkSingleRuleScanSize(b *testing.B) {
	cases := []struct {
		name   string
		source string
	}{
		{
			name: "text",
			source: `rule single_text {
				strings: $a = "suspicious_payload" nocase
				condition: $a
			}`,
		},
		{
			name: "regex",
			source: `rule single_regex {
				strings: $a = /malwa[a-z]{1,2}\.exe/i
				condition: $a
			}`,
		},
		{
			name: "hex",
			source: `rule single_hex {
				strings: $a = { 0A 0B [2-4] 0C 0D }
				condition: $a
			}`,
		},
		{
			name: "mixed",
			source: `rule single_mixed {
				strings:
					$text = "suspicious_payload" wide nocase
					$regex = /malwa[a-z]{1,2}\.exe/i
					$hex1 = { 0A 0B [2-4] 0C 0D }
					$hex2 = { DE AD BE EF }
				condition: any of them
			}`,
		},
	}

	for _, benchmark := range cases {
		program, err := NewCompiler().CompileSource(benchmark.source)
		if err != nil {
			b.Fatalf("compile %s: %v", benchmark.name, err)
		}
		for _, size := range []int{16 << 10, 64 << 10, 256 << 10, 1 << 20} {
			b.Run(fmt.Sprintf("%s/%dKiB", benchmark.name, size>>10), func(b *testing.B) {
				scanner := NewScanner(program)
				defer scanner.Close()
				data := make([]byte, size)
				for idx := range data {
					data[idx] = byte(idx % 251)
				}

				b.SetBytes(int64(len(data)))
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					if _, err := scanner.Scan(data); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
