package compiler

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func teddyCorpusSource(count int) string {
	var source strings.Builder
	for i := range count {
		// Four distinct prefixes; the complete literals remain distinct.
		fmt.Fprintf(&source, "rule family_%d {strings:$a=\"%s_token_%05d\" condition:$a}\n", i, []string{"api", "key", "sec", "tok"}[i%4], i)
	}
	return source.String()
}

func BenchmarkTeddyCorpus(b *testing.B) {
	for _, count := range []int{64, 512, 10000} {
		p := mustCompileBenchmarkProgram(b, teddyCorpusSource(count))
		for _, size := range []int{64, 1024, 65536} {
			clean := bytes.Repeat([]byte("request completed status=200 normal activity "), size/40+2)[:size]
			near := bytes.Repeat([]byte("request completed status=200 key=value normal activity "), size/50+2)[:size]
			dense := bytes.Repeat([]byte("api api api key key key sec sec sec tok tok tok "), size/40+2)[:size]
			lateDense := bytes.Clone(dense)
			copy(lateDense[:min(128, size)], clean)
			hit := bytes.Clone(clean)
			copy(hit[len(hit)-len("tok_token_00003"):], "tok_token_00003")
			for _, input := range []struct {
				name string
				data []byte
			}{{"clean", clean}, {"near_prefix", near}, {"dense", dense}, {"late_dense", lateDense}, {"tail_hit", hit}} {
				b.Run(fmt.Sprintf("rules=%d/bytes=%d/%s", count, size, input.name), func(b *testing.B) { benchmarkScannerMatches(b, p, input.data) })
			}
		}
	}
}

func BenchmarkTeddyCorpusCompile(b *testing.B) {
	source := teddyCorpusSource(10000)
	b.ReportAllocs()
	for b.Loop() {
		mustCompileBenchmarkProgram(b, source)
	}
}

func BenchmarkTeddyCorpusDiversity(b *testing.B) {
	for _, groups := range []int{8, 16, 64, 65} {
		var source strings.Builder
		for i := range 512 {
			fmt.Fprintf(&source, "rule div_%d {strings:$a=\"t%02x_token_%05d\" condition:$a}\n", i, i%groups, i)
		}
		p := mustCompileBenchmarkProgram(b, source.String())
		data := bytes.Repeat([]byte("request completed status=200 normal activity "), 1500)[:65536]
		b.Run(fmt.Sprintf("prefixes=%d", groups), func(b *testing.B) { benchmarkScannerMatches(b, p, data) })
	}
}
