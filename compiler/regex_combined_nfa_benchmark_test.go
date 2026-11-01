package compiler

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

func combinedNFASource(count int, suffix string) string {
	var s strings.Builder
	for i := range count {
		fmt.Fprintf(&s, "rule r%d {strings:$a=/key=[a-z0-9]{%d,%d}%s/ condition:#a>0}\n", i, 16+i/128, 32+i%128, suffix)
	}
	return s.String()
}

func BenchmarkCombinedNFA(b *testing.B) {
	for _, count := range []int{1, 4, 16, 64, 256, 1024} {
		p := mustCompileBenchmarkProgram(b, combinedNFASource(count, "!"))
		for _, n := range []int{15, 32, 64, 128} {
			data := []byte("key=" + strings.Repeat("a", n) + "!")
			b.Run(fmt.Sprintf("rules=%d/run=%d", count, n), func(b *testing.B) { benchmarkScannerMatches(b, p, data) })
		}
		b.Run(fmt.Sprintf("rules=%d/clean", count), func(b *testing.B) { benchmarkScannerMatches(b, p, []byte(strings.Repeat("ordinary log message ", 64))) })
	}
}

func BenchmarkCombinedNFACompile(b *testing.B) {
	for _, count := range []int{64, 256} {
		source := combinedNFASource(count, "!")
		b.Run(strconv.Itoa(count), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				mustCompileBenchmarkProgram(b, source)
			}
		})
	}
}
