package compiler

import (
	"fmt"
	"strings"
	"testing"
)

func BenchmarkACBuild(b *testing.B) {
	for _, count := range []int{128, 4096} {
		for _, shared := range []bool{false, true} {
			patterns := make([]string, count)
			for i := range patterns {
				prefix := fmt.Sprintf("%08x", uint32(i)*2654435761)
				suffix := strings.Repeat("literal_payload_", 2)
				if shared {
					prefix, suffix = suffix, prefix
				}
				patterns[i] = prefix + suffix
			}
			b.Run(fmt.Sprintf("patterns=%d/shared=%t", count, shared), func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					ac := newacAutomatonWithCapacity(min(count*4, 32768), count, count)
					for _, pattern := range patterns {
						if err := ac.AddString(pattern, []byte(pattern), false, false); err != nil {
							b.Fatal(err)
						}
					}
					if err := ac.Compile(); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
