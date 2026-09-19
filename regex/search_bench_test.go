package regex

import (
	"bytes"
	"fmt"
	"testing"
)

func BenchmarkBooleanSearch(b *testing.B) {
	for _, size := range []int{2048, 4096, 8192} {
		b.Run(fmt.Sprintf("MissingSuffix/%d", size), func(b *testing.B) {
			code := mustCompile(b, "a+b")
			input := bytes.Repeat([]byte{'a'}, size)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				Exec(code, input, FlagsScan)
			}
		})
	}
	for _, pattern := range []string{"needle", "a+", "^a+$"} {
		b.Run(pattern, func(b *testing.B) {
			code := mustCompile(b, pattern)
			input := bytes.Repeat([]byte{'a'}, 128)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				Exec(code, input, FlagsScan)
			}
		})
	}
}
