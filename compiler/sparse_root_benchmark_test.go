package compiler

import (
	"bytes"
	"testing"
)

func BenchmarkSparseRootTextSet(b *testing.B) {
	for _, benchmark := range []struct {
		name   string
		source string
	}{
		{
			name: "distinct_roots",
			source: `rule r {
				strings:
					$s1 = "alpha"
					$s2 = "bravo"
					$s3 = "charlie"
					$s4 = "delta"
					$s5 = "echo"
				condition:
					any of them
			}`,
		},
		{
			name: "mixed_absent_and_dense_roots",
			source: `rule r {
				strings:
					$s1 = "cardnumber"
					$s2 = "cardnum"
					$s3 = "ccnumber"
					$s4 = "cardholder"
					$s5 = "nameoncard"
				condition:
					any of them
			}`,
		},
	} {
		b.Run(benchmark.name, func(b *testing.B) {
			program, err := NewCompiler().CompileSource(benchmark.source)
			if err != nil {
				b.Fatal(err)
			}
			scanner := NewScanner(program)
			defer scanner.Close()
			data := bytes.Repeat([]byte("benignFillerCode123 "), (1<<20)/20)

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
