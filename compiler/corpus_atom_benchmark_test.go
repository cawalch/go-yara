package compiler

import (
	"fmt"
	"strings"
	"testing"
)

func corpusAtomPrefix(index int) string {
	var name [4]byte
	for i := range name {
		name[len(name)-1-i] = 'a' + byte(index%26)
		index /= 26
	}
	return "provider_" + string(name[:]) + "=api_key="
}

func corpusAtomSource(count int) string {
	var source strings.Builder
	for i := range count {
		fmt.Fprintf(&source, "rule corpus_%d { strings: $a = /%s[a-z]{16}/ condition: $a }\n", i, corpusAtomPrefix(i))
	}
	return source.String()
}

func BenchmarkCorpusPrefixAtoms(b *testing.B) {
	for _, count := range []int{1, 64, 512, 10000} {
		p := mustCompileBenchmarkProgram(b, corpusAtomSource(count))
		for _, input := range []struct{ name, data string }{
			{"clean", "level=info request completed status=200"},
			{"shared_atom", "provider_none=api_key=abcdefghijklmnop"},
			{"match", corpusAtomPrefix(count-1) + "abcdefghijklmnop"},
		} {
			b.Run(fmt.Sprintf("rules=%d/%s", count, input.name), func(b *testing.B) { benchmarkScannerMatches(b, p, []byte(input.data)) })
		}
	}
}

func BenchmarkCorpusPrefixCompile(b *testing.B) {
	for _, count := range []int{64, 512, 10000} {
		source := corpusAtomSource(count)
		b.Run(fmt.Sprintf("rules=%d", count), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				mustCompileBenchmarkProgram(b, source)
			}
		})
	}
}
