package compiler

import (
	"fmt"
	"runtime"
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

// BenchmarkACRetainedHeap reports the heap retained by one live, compiled
// automaton. Compile releases the 1,036 B/state construction rows, so this
// metric drops by roughly two thirds for 16-bit tables even though the
// build-time allocation rate in BenchmarkACBuild is unchanged.
func BenchmarkACRetainedHeap(b *testing.B) {
	const count = 2048
	patterns := make([]string, count)
	for i := range patterns {
		patterns[i] = fmt.Sprintf("%08x", uint32(i)*2654435761) + strings.Repeat("literal_payload_", 2)
	}
	var ac *acAutomaton
	b.ReportAllocs()
	for b.Loop() {
		ac = newacAutomatonWithCapacity(min(count*4, 32768), count, count)
		for _, pattern := range patterns {
			if err := ac.AddString(pattern, []byte(pattern), false, false); err != nil {
				b.Fatal(err)
			}
		}
		if err := ac.Compile(); err != nil {
			b.Fatal(err)
		}
		// Collect the previous iteration's automaton and measure the live
		// heap with exactly one compiled automaton retained via ac.
		runtime.GC()
		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)
		b.ReportMetric(float64(mem.HeapAlloc), "retained-B/op")
	}
	if ac == nil || ac.GetStateCount() == 0 {
		b.Fatal("benchmark built no states")
	}
}
