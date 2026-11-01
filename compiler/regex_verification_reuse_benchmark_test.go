package compiler

import (
	"bytes"
	"fmt"
	"testing"
)

// Complete scans include occurrence materialization; repeated negatives exercise
// bounded failed-state reuse, while successful and lazy cases are controls.
func BenchmarkRegexVerificationReuse(b *testing.B) {
	for _, size := range []int{128, 512, 4096, 4097} {
		for _, tc := range []struct {
			name, pattern string
			data          []byte
		}{
			{"negative", "a.*b", bytes.Repeat([]byte("a"), size)},
			{"positive", "a+b", append(bytes.Repeat([]byte("a"), size), 'b')},
			{"lazy", "(ab|aba)+?", bytes.Repeat([]byte("ab"), size)},
			{"settled", "(xy|x)(a?.)+", append([]byte("xy"), bytes.Repeat([]byte("a!"), size)...)},
		} {
			b.Run(fmt.Sprintf("%s/%d", tc.name, size), func(b *testing.B) {
				p := mustCompileStreamingProgram(b, `rule p {strings:$a=/`+tc.pattern+`/ condition:#a>0}`)
				s := p.NewScanner()
				defer s.Close()
				if _, err := s.Scan(tc.data); err != nil {
					b.Fatal(err)
				}
				b.ReportAllocs()
				b.SetBytes(int64(len(tc.data)))
				b.ResetTimer()
				for b.Loop() {
					if _, err := s.Scan(tc.data); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
