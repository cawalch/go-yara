package compiler

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func corpusInternalSource(count int) string {
	var source strings.Builder
	for i := range count {
		fmt.Fprintf(&source, "rule internal_%d {strings:$a=/key=[a-z]{4}TOKEN_%08d[0-9]{2}/ condition:$a}\n", i, i)
	}
	return source.String()
}

func BenchmarkCorpusInternalAtoms(b *testing.B) {
	for _, count := range []int{1, 64, 512, 10000} {
		p := mustCompileBenchmarkProgram(b, corpusInternalSource(count))
		for _, input := range []struct{ name, data string }{
			{"clean", "level=info request completed status=200"},
			{"shared_prefix", "key=abcdnot_a_token status=200"},
			{"match", fmt.Sprintf("key=abcdTOKEN_%08d42", count-1)},
			{"near_atom", fmt.Sprintf("key=1234TOKEN_%08d42", count-1)},
		} {
			b.Run(fmt.Sprintf("rules=%d/%s", count, input.name), func(b *testing.B) { benchmarkScannerMatches(b, p, []byte(input.data)) })
		}
	}
}

func BenchmarkCorpusInternalCompile(b *testing.B) {
	source := corpusInternalSource(10000)
	b.ReportAllocs()
	var p *CompiledProgram
	for b.Loop() {
		p = mustCompileBenchmarkProgram(b, source)
	}
	b.ReportMetric(float64(len(p.sharedAutomaton.states)), "ac_states")
}

func BenchmarkCorpusInternalRecords(b *testing.B) {
	for _, count := range []int{512, 10000} {
		p := mustCompileBenchmarkProgram(b, corpusInternalSource(count))
		for _, size := range []int{1024, 65536} {
			clean := bytes.Repeat([]byte("level=info request completed status=200 "), size/38+2)[:size]
			prefix := bytes.Clone(clean)
			copy(prefix, "key=abcdnot_a_token ")
			hit := bytes.Clone(clean)
			token := fmt.Sprintf("key=abcdTOKEN_%08d42", count-1)
			copy(hit[len(hit)-len(token):], token)
			for _, input := range []struct {
				name string
				data []byte
			}{{"clean", clean}, {"prefix", prefix}, {"tail_hit", hit}} {
				b.Run(fmt.Sprintf("rules=%d/bytes=%d/%s", count, size, input.name), func(b *testing.B) { benchmarkScannerMatches(b, p, input.data) })
			}
		}
	}
}

func corpusDiverseInternalSource(count int) string {
	var source strings.Builder
	for i := range count {
		fmt.Fprintf(&source, "rule diverse%d {strings:$a=/key=[a-z]{4}%c%07x[0-9]{2}/ condition:$a}\n", i, 'a'+i%26, i)
	}
	return source.String()
}

func BenchmarkCorpusInternalDiverse(b *testing.B) {
	for _, count := range []int{512, 10000} {
		p := mustCompileBenchmarkProgram(b, corpusDiverseInternalSource(count))
		for _, input := range []struct{ name, data string }{
			{"clean", strings.Repeat("level=info request completed status=200 ", 1681)},
			{"shared_prefix", "key=abcdnot_a_token"},
			{"match", fmt.Sprintf("key=abcd%c%07x42", 'a'+(count-1)%26, count-1)},
		} {
			b.Run(fmt.Sprintf("rules=%d/%s", count, input.name), func(b *testing.B) { benchmarkScannerMatches(b, p, []byte(input.data)) })
		}
	}
}
