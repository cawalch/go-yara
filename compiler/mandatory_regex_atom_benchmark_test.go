package compiler

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/regex"
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

func BenchmarkLiteralAlternationRegexScanner(b *testing.B) {
	for _, benchmark := range []struct {
		name    string
		pattern string
	}{
		{name: "single_literal", pattern: `/cardholder\b/`},
		{name: "single_literal_nocase", pattern: `/cardholder\b/ nocase`},
		{name: "literal_alternation", pattern: `/(cardholder|nameoncard|expiry|expiration)\b/`},
		{name: "literal_alternation_nocase", pattern: `/(cardholder|nameoncard|expiry|expiration)\b/ nocase`},
	} {
		b.Run(benchmark.name, func(b *testing.B) {
			program, err := NewCompiler().CompileSource(fmt.Sprintf(`
				rule literal_alternation {
					strings:
						$pattern = %s
					condition:
						$pattern
				}
			`, benchmark.pattern))
			if err != nil {
				b.Fatal(err)
			}
			scanner := NewScanner(program)
			defer scanner.Close()

			for _, size := range []int{16 * 1024, 1024 * 1024} {
				b.Run(fmt.Sprintf("%dKiB", size/1024), func(b *testing.B) {
					data := bytes.Repeat([]byte("benignFillerCode123 "), size/20+1)[:size]
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

func BenchmarkNoCaseRegexLiteralSearchDensity(b *testing.B) {
	literal := []byte("cardholder")
	for _, benchmark := range []struct {
		name string
		data []byte
		want int
	}{
		{
			name: "negative",
			data: bytes.Repeat([]byte("benignFillerCode123 "), (1<<20)/20),
		},
		{
			name: "sparse",
			data: func() []byte {
				data := bytes.Repeat([]byte("benignFillerCode123 "), (1<<20)/20)
				for offset := 32 << 10; offset+len(literal) <= len(data); offset += 64 << 10 {
					copy(data[offset:], "CARDHOLDER")
				}
				return data
			}(),
			want: 16,
		},
		{
			name: "dense",
			data: bytes.Repeat([]byte("cardholder "), (1<<20)/11),
			want: (1 << 20) / 11,
		},
	} {
		b.Run(benchmark.name, func(b *testing.B) {
			b.SetBytes(int64(len(benchmark.data)))
			b.ReportAllocs()
			for b.Loop() {
				searcher := newRegexLiteralSearcher(benchmark.data, literal, regex.FlagsNoCase)
				matches := 0
				for pos := 0; pos <= len(benchmark.data); {
					match := searcher.index(pos)
					if match < 0 {
						break
					}
					matches++
					pos = match + 1
				}
				if matches != benchmark.want {
					b.Fatalf("matches = %d, want %d", matches, benchmark.want)
				}
			}
		})
	}
}

func BenchmarkVariableAlternationRegexSet(b *testing.B) {
	for _, benchmark := range []struct {
		name   string
		source string
	}{
		{
			name: "single_variable_alternation",
			source: `rule r {
				strings:
					$c4 = /(cardholder|card[-_ ]?holder|nameoncard|name[-_ ]on[-_ ]card)\b/ nocase
				condition:
					$c4
			}`,
		},
		{
			name: "four_regexes",
			source: `rule r {
				strings:
					$c1 = /["'#.\[]\s*(card[-_ ]?number|cardnum|ccnumber|cc[-_]number|pan)\b/ nocase
					$c2 = /["'#.\[]\s*(cvv|cvc|cvv2|card[-_ ]?cvc|securitycode|security[-_ ]code)\b/ nocase
					$c3 = /(exp[-_ ]?date|expir(y|ation)|card[-_ ]?expiry|cc[-_]exp)\b/ nocase
					$c4 = /(cardholder|card[-_ ]?holder|nameoncard|name[-_ ]on[-_ ]card)\b/ nocase
				condition:
					2 of ($c*)
			}`,
		},
		{
			name: "literal_equivalent",
			source: `rule r {
				strings:
					$c1 = "cardnumber" nocase
					$c2 = "card_number" nocase
					$c3 = "cardnum" nocase
					$c4 = "ccnumber" nocase
					$c5 = "cvv" nocase
					$c6 = "cvc" nocase
					$c7 = "cvv2" nocase
					$c8 = "securitycode" nocase
					$c9 = "cardholder" nocase
					$c10 = "nameoncard" nocase
				condition:
					2 of ($c*)
			}`,
		},
	} {
		b.Run(benchmark.name, func(b *testing.B) {
			program, err := NewCompiler().CompileSource(benchmark.source)
			if err != nil {
				b.Fatal(err)
			}
			scanner := NewScanner(program)
			defer scanner.Close()
			data := bytes.Repeat([]byte("benignFillerCode123 "), (1<<20)/20)

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

func BenchmarkCombinedRegexAtomScale(b *testing.B) {
	for _, regexCount := range []int{1, 2, 4, 8, 16} {
		b.Run(fmt.Sprintf("regexes_%d", regexCount), func(b *testing.B) {
			var source strings.Builder
			source.WriteString("rule combined_regex_atoms {\nstrings:\n")
			for index := range regexCount {
				fmt.Fprintf(
					&source,
					"$pattern_%d = /[\"'#.\\[]\\s*(tok%02d_number|tok%02d_code)\\b/ nocase\n",
					index,
					index,
					index,
				)
			}
			source.WriteString("condition: any of them\n}\n")

			program, err := NewCompiler().CompileSource(source.String())
			if err != nil {
				b.Fatal(err)
			}
			scanner := NewScanner(program)
			defer scanner.Close()
			data := bytes.Repeat([]byte("benignFillerCode123 "), (1<<20)/20)

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

func BenchmarkFixedRegexClassSequence(b *testing.B) {
	program, err := NewCompiler().CompileSource(`
		rule fixed_class_sequences {
			strings:
				$a = /[ai]{2}[0-9]/
				$b = /[bj]{2}[0-9]/
				$c = /[ck]{2}[0-9]/
				$d = /[dl]{2}[0-9]/
				$e = /[em]{2}[0-9]/
				$f = /[fn]{2}[0-9]/
				$g = /[go]{2}[0-9]/
				$h = /[hp]{2}[0-9]/
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
