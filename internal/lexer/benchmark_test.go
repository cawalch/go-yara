package lexer_test

import (
	"strings"
	"testing"

	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/token"
)

func BenchmarkLexer_Basic(b *testing.B) {
	b.ReportAllocs()
	input := "rule r { condition and or (1 + 2) }"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l := lexer.New(input)
		for l.NextToken().Type != token.EOF {
			// Consume tokens for benchmarking
		}
	}
}

func BenchmarkLexer_ManyIdentifiers(b *testing.B) {
	b.ReportAllocs()
	var sb strings.Builder
	for i := 0; i < 2000; i++ {
		sb.WriteString("ident")
		sb.WriteByte(' ')
	}
	input := sb.String()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l := lexer.New(input)
		for l.NextToken().Type != token.EOF {
			// Consume tokens for benchmarking
		}
	}
}

func BenchmarkLexer_StringLiterals(b *testing.B) {
	b.ReportAllocs()
	var sb strings.Builder
	for i := 0; i < 2000; i++ {
		sb.WriteString("\"abcdefg\"")
		sb.WriteByte(' ')
	}
	input := sb.String()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l := lexer.New(input)
		for l.NextToken().Type != token.EOF {
			// Consume tokens for benchmarking
		}
	}
}

func BenchmarkLexer_MixedRule(b *testing.B) {
	b.ReportAllocs()
	input := "rule r: tag1 tag2 {\n meta: a = 1\n strings: $a = \"abc\"\n condition: (1 < 2 and 3 >= 4) or pe.entry_point == 0x1000\n}"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l := lexer.New(input)
		for l.NextToken().Type != token.EOF {
			// Consume tokens for benchmarking
		}
	}
}

func BenchmarkLexer_KeywordsOnly(b *testing.B) {
	b.ReportAllocs()
	var sb strings.Builder
	for i := 0; i < 5000; i++ {
		sb.WriteString("rule meta strings condition and or ")
	}
	input := sb.String()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l := lexer.New(input)
		for l.NextToken().Type != token.EOF {
			// Consume tokens for benchmarking
		}
	}
}

func BenchmarkLexer_HexStrings(b *testing.B) {
	b.ReportAllocs()
	input := `{ E2 34 A1 C8 23 FB } { ?? A? ?B ?? } { F4 23 [4-6] 62 B4 } { ~FF ~00 ~A? } { F4 23 ( 62 B4 | 56 ) 45 }`
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l := lexer.New(input)
		for l.NextToken().Type != token.EOF {
			// Consume tokens for benchmarking
		}
	}
}

func BenchmarkLexer_HexIntegers(b *testing.B) {
	b.ReportAllocs()
	var sb strings.Builder
	for i := 0; i < 1000; i++ {
		sb.WriteString("0x1000 0xFF 0xABCDEF 0x401000 ")
	}
	input := sb.String()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l := lexer.New(input)
		for l.NextToken().Type != token.EOF {
			// Consume tokens for benchmarking
		}
	}
}

func BenchmarkLexer_SizeSuffixes(b *testing.B) {
	b.ReportAllocs()
	var sb strings.Builder
	for i := 0; i < 1000; i++ {
		sb.WriteString("1KB 100MB 0x1000KB 512mb ")
	}
	input := sb.String()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l := lexer.New(input)
		for l.NextToken().Type != token.EOF {
			// Consume tokens for benchmarking
		}
	}
}

func BenchmarkLexer_QuantifierKeywords(b *testing.B) {
	b.ReportAllocs()
	var sb strings.Builder
	for i := 0; i < 1000; i++ {
		sb.WriteString("all of them any of none ")
	}
	input := sb.String()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l := lexer.New(input)
		for l.NextToken().Type != token.EOF {
			// Consume tokens for benchmarking
		}
	}
}

func BenchmarkLexer_ArithmeticOperators(b *testing.B) {
	b.ReportAllocs()
	var sb strings.Builder
	for i := 0; i < 1000; i++ {
		sb.WriteString("1 + 2 * 3 - 4 / 5 % 6 ")
	}
	input := sb.String()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l := lexer.New(input)
		for l.NextToken().Type != token.EOF {
			// Consume tokens for benchmarking
		}
	}
}

func BenchmarkLexer_Phase1AllFeatures(b *testing.B) {
	b.ReportAllocs()
	var sb strings.Builder
	for i := 0; i < 100; i++ {
		sb.WriteString("rule Test { condition: all of them and 0x1000KB + 100MB * 2 / 1024 % 3 == 0xFF and any of ($a, $b) and not false } ")
	}
	input := sb.String()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l := lexer.New(input)
		for l.NextToken().Type != token.EOF {
			// Consume tokens for benchmarking
		}
	}
}

// Phase 2 String Modifier Benchmarks

func BenchmarkLexer_StringModifiers_Basic(b *testing.B) {
	b.ReportAllocs()
	var sb strings.Builder
	for i := 0; i < 1000; i++ {
		sb.WriteString("nocase wide ascii fullword private xor base64 base64wide ")
	}
	input := sb.String()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l := lexer.New(input)
		for l.NextToken().Type != token.EOF {
			// Consume tokens for benchmarking
		}
	}
}

func BenchmarkLexer_StringModifiers_WithStrings(b *testing.B) {
	b.ReportAllocs()
	var sb strings.Builder
	for i := 0; i < 500; i++ {
		sb.WriteString(`"malware" nocase wide "virus" ascii fullword { E2 34 A1 } private /pattern/i base64 `)
	}
	input := sb.String()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l := lexer.New(input)
		for l.NextToken().Type != token.EOF {
			// Consume tokens for benchmarking
		}
	}
}

func BenchmarkLexer_StringModifiers_Complex(b *testing.B) {
	b.ReportAllocs()
	var sb strings.Builder
	for i := 0; i < 200; i++ {
		sb.WriteString(`"text" nocase wide ascii fullword private xor base64 base64wide `)
	}
	input := sb.String()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l := lexer.New(input)
		for l.NextToken().Type != token.EOF {
			// Consume tokens for benchmarking
		}
	}
}

func BenchmarkLexer_Phase2AllFeatures(b *testing.B) {
	b.ReportAllocs()
	var sb strings.Builder
	for i := 0; i < 50; i++ {
		sb.WriteString(`rule Test {
			strings:
				$a = "malware" nocase wide
				$b = { E2 34 A1 } private
				$c = /pattern/i ascii fullword
			condition:
				any of them and filesize > 100KB
		} `)
	}
	input := sb.String()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l := lexer.New(input)
		for l.NextToken().Type != token.EOF {
			// Consume tokens for benchmarking
		}
	}
}

func BenchmarkLexer_StringModifiers_ErrorRecovery(b *testing.B) {
	b.ReportAllocs()
	var sb strings.Builder
	for i := 0; i < 500; i++ {
		sb.WriteString(`"text" nocase invalidmod wide "other" ascii `)
	}
	input := sb.String()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l := lexer.New(input)
		for l.NextToken().Type != token.EOF {
			// Consume tokens for benchmarking
		}
	}
}

func BenchmarkLexer_StringModifiers_CaseSensitive(b *testing.B) {
	b.ReportAllocs()
	var sb strings.Builder
	for i := 0; i < 1000; i++ {
		sb.WriteString("nocase NOCASE NoCase wide WIDE Wide ascii ASCII Ascii ")
	}
	input := sb.String()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l := lexer.New(input)
		for l.NextToken().Type != token.EOF {
			// Consume tokens for benchmarking
		}
	}
}

// Phase 3 Bitwise Operators and Data Type Functions Benchmarks

func BenchmarkLexer_BitwiseOperators_Basic(b *testing.B) {
	b.ReportAllocs()
	var sb strings.Builder
	for i := 0; i < 1000; i++ {
		sb.WriteString("& | ^ ~ << >> ")
	}
	input := sb.String()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l := lexer.New(input)
		for l.NextToken().Type != token.EOF {
			// Consume tokens for benchmarking
		}
	}
}

func BenchmarkLexer_DataTypeFunctions_Basic(b *testing.B) {
	b.ReportAllocs()
	var sb strings.Builder
	for i := 0; i < 1000; i++ {
		sb.WriteString("uint32 int16be uint8 int32 uint16be int8 ")
	}
	input := sb.String()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l := lexer.New(input)
		for l.NextToken().Type != token.EOF {
			// Consume tokens for benchmarking
		}
	}
}

func BenchmarkLexer_FileOperations_Basic(b *testing.B) {
	b.ReportAllocs()
	var sb strings.Builder
	for i := 0; i < 1000; i++ {
		sb.WriteString("filesize entrypoint ")
	}
	input := sb.String()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l := lexer.New(input)
		for l.NextToken().Type != token.EOF {
			// Consume tokens for benchmarking
		}
	}
}

func BenchmarkLexer_Phase3_ComplexRule(b *testing.B) {
	b.ReportAllocs()
	input := `rule Phase3Benchmark {
		meta:
			author = "benchmark"
			version = "3.0"
		strings:
			$a = "malware" nocase wide
			$b = { E2 34 A1 C8 } private
			$c = /[a-z]{32}/i ascii
		condition:
			any of them and
			filesize > 1MB and filesize < 100KB and
			uint32(0) == 0x5A4D and uint32(entrypoint) & 0xFF00 == 0x4D00 and
			int16be(entrypoint + 4) > 0 and uint16(2) & 0xFF00 == 0x4D00 and
			uint8(filesize - 1) != 0x00 and (filesize >> 10) < 1024 and
			~uint16(2) == 0xFFFF and (flags | 0x01) != 0
	}`
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l := lexer.New(input)
		for l.NextToken().Type != token.EOF {
			// Consume tokens for benchmarking
		}
	}
}

func BenchmarkLexer_Phase3_AllFeatures(b *testing.B) {
	b.ReportAllocs()
	input := `uint32(entrypoint) & 0xFF00 >> 8 | 0x01 ^ 0xAA ~ data << 2 filesize int16be uint8be`
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l := lexer.New(input)
		for l.NextToken().Type != token.EOF {
			// Consume tokens for benchmarking
		}
	}
}
