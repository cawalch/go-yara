package compiler

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

func boundedClassSource(count int, fixed bool) string {
	var source strings.Builder
	for i := range count {
		bounds := fmt.Sprintf("32,%d", 64+i)
		if fixed {
			bounds = strconv.Itoa(32 + i)
		}
		fmt.Fprintf(&source, "rule class%d {strings:$a=/key=[A-Za-z0-9_-]{%s}/ condition:$a}\n", i, bounds)
	}
	return source.String()
}

func BenchmarkBoundedClassScan(b *testing.B) {
	for _, count := range []int{1, 64} {
		for _, fixed := range []bool{false, true} {
			p := mustCompileBenchmarkProgram(b, boundedClassSource(count, fixed))
			for _, n := range []int{15, 32, 64, 256} {
				data := append([]byte("key="), bytes.Repeat([]byte{'a'}, n)...)
				b.Run(fmt.Sprintf("rules=%d/fixed=%t/run=%d", count, fixed, n), func(b *testing.B) { benchmarkScannerMatches(b, p, data) })
			}
			for _, tc := range []struct{ name, data string }{
				{"clean", strings.Repeat("ordinary log message ", 64)},
				{"invalid", "key=" + strings.Repeat("a", 15) + "!" + strings.Repeat("a", 64)},
			} {
				b.Run(fmt.Sprintf("rules=%d/fixed=%t/%s", count, fixed, tc.name), func(b *testing.B) { benchmarkScannerMatches(b, p, []byte(tc.data)) })
			}
		}
	}
}

func BenchmarkBoundedClassCompile(b *testing.B) {
	source := boundedClassSource(64, false)
	b.ReportAllocs()
	for b.Loop() {
		mustCompileBenchmarkProgram(b, source)
	}
}
