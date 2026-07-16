package compiler

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func BenchmarkMandatoryRegexAtomScanner(b *testing.B) {
	var source strings.Builder
	patternIndex := 0
	for ruleIndex := range 8 {
		visibility := ""
		if ruleIndex >= 6 {
			visibility = "private "
		}
		fmt.Fprintf(&source, "%srule regex_family_%d {\nstrings:\n", visibility, ruleIndex)
		patternsInRule := 2
		if ruleIndex == 7 {
			patternsInRule = 1
		}
		for stringIndex := range patternsInRule {
			fmt.Fprintf(
				&source,
				"$pattern_%d = /[a-z]{1,8}family_%02d_%02d_marker/\n",
				stringIndex,
				ruleIndex,
				patternIndex,
			)
			patternIndex++
		}
		source.WriteString("condition: any of them\n}\n")
	}

	program, err := NewCompiler().CompileSource(source.String())
	if err != nil {
		b.Fatal(err)
	}
	scanner := NewScanner(program)
	defer scanner.Close()

	for _, size := range []int{16 * 1024, 1024 * 1024} {
		b.Run(fmt.Sprintf("%dKiB", size/1024), func(b *testing.B) {
			data := make([]byte, size)
			b.SetBytes(int64(size))
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

func BenchmarkNoCaseMandatoryRegexAtomScanner(b *testing.B) {
	program, err := NewCompiler().CompileSource(`
		rule nocase_internal_atom {
			strings:
				$pattern = /(exp[-_ ]?date|expir(y|ation))\b/ nocase
			condition:
				$pattern
		}
	`)
	if err != nil {
		b.Fatal(err)
	}
	scanner := NewScanner(program)
	defer scanner.Close()

	for _, size := range []int{16 * 1024, 1024 * 1024} {
		b.Run(fmt.Sprintf("%dKiB", size/1024), func(b *testing.B) {
			data := bytes.Repeat([]byte(" benignFillerCode123"), size/20+1)[:size]
			b.SetBytes(int64(size))
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

func BenchmarkSharedMandatoryRegexAtomScale(b *testing.B) {
	for _, ruleCount := range []int{20, 50, 100, 500} {
		b.Run(fmt.Sprintf("rules_%d", ruleCount), func(b *testing.B) {
			var source strings.Builder
			for ruleIndex := range ruleCount {
				fmt.Fprintf(
					&source,
					"rule internal_atom_%d { strings: $pattern = /[a-z]{1,8}family_%04d_marker/ condition: $pattern }\n",
					ruleIndex,
					ruleIndex,
				)
			}
			program, err := NewCompiler().CompileSource(source.String())
			if err != nil {
				b.Fatal(err)
			}
			scanner := NewScanner(program)
			defer scanner.Close()
			data := make([]byte, 100*1024)

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

func BenchmarkAtomlessRegexScanner(b *testing.B) {
	for _, benchmark := range []struct {
		name    string
		pattern func(int) string
	}{
		{
			name: "leading_class",
			pattern: func(index int) string {
				return fmt.Sprintf("[a-%c]{%d}[0-9]{4}", 'k'+rune(index%10), 2+index%4)
			},
		},
		{
			name: "leading_any",
			pattern: func(index int) string {
				return fmt.Sprintf(".{%d}[a-z]{%d}", 2+index%4, 2+(index/4)%4)
			},
		},
	} {
		b.Run(benchmark.name, func(b *testing.B) {
			var source strings.Builder
			patternIndex := 0
			for ruleIndex := range 8 {
				visibility := ""
				if ruleIndex >= 6 {
					visibility = "private "
				}
				fmt.Fprintf(&source, "%srule atomless_%d {\nstrings:\n", visibility, ruleIndex)
				patternsInRule := 2
				if ruleIndex == 7 {
					patternsInRule = 1
				}
				for stringIndex := range patternsInRule {
					fmt.Fprintf(
						&source,
						"$pattern_%d = /%s/\n",
						stringIndex,
						benchmark.pattern(patternIndex),
					)
					patternIndex++
				}
				source.WriteString("condition: any of them\n}\n")
			}

			program, err := NewCompiler().CompileSource(source.String())
			if err != nil {
				b.Fatal(err)
			}
			scanner := NewScanner(program)
			defer scanner.Close()
			for _, size := range []int{16 * 1024, 1024 * 1024} {
				b.Run(fmt.Sprintf("%dKiB", size/1024), func(b *testing.B) {
					data := make([]byte, size)
					b.SetBytes(int64(size))
					b.ReportAllocs()
					b.ResetTimer()
					for b.Loop() {
						if _, err := scanner.Scan(data); err != nil {
							b.Fatal(err)
						}
					}
				})
			}
		})
	}
}

func BenchmarkRegexByteSetCandidateMemory(b *testing.B) {
	program, err := NewCompiler().CompileSource(`
		rule candidate_heavy {
			strings:
				$a = /[a]{2}[0-9]/
				$b = /[b]{2}[0-9]/
				$c = /[c]{2}[0-9]/
				$d = /[d]{2}[0-9]/
				$e = /[e]{2}[0-9]/
				$f = /[f]{2}[0-9]/
				$g = /[g]{2}[0-9]/
				$h = /[h]{2}[0-9]/
			condition:
				any of them
		}
	`)
	if err != nil {
		b.Fatal(err)
	}
	data := bytes.Repeat([]byte("a0b0c0d0e0f0g0h0"), (1<<20)/16)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := program.Scan(data); err != nil {
			b.Fatal(err)
		}
	}
}
