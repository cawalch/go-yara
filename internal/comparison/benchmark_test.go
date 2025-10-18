package comparison

import (
	"testing"

	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/token"
)

// BenchmarkGoYaraLexer benchmarks the Go YARA lexer implementation.
func BenchmarkGoYaraLexer(b *testing.B) {
	testData, err := LoadTestData()
	if err != nil {
		b.Fatalf("Failed to load test data: %v", err)
	}
	
	for _, td := range testData {
		b.Run(td.Name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(td.Content)))
			b.ResetTimer()
			
			for i := 0; i < b.N; i++ {
				l := lexer.New(td.Content)
				for {
					tok := l.NextToken()
					if tok.Type == token.EOF {
						break
					}
				}
			}
		})
	}
}

// BenchmarkCYaraCompiler benchmarks the C YARA compiler (includes lexing + parsing).
func BenchmarkCYaraCompiler(b *testing.B) {
	testData, err := LoadTestData()
	if err != nil {
		b.Fatalf("Failed to load test data: %v", err)
	}
	
	for _, td := range testData {
		b.Run(td.Name, func(b *testing.B) {
			yc, err := NewYaraCompiler()
			if err != nil {
				b.Fatalf("Failed to create YARA compiler: %v", err)
			}
			defer yc.Close()
			
			b.ReportAllocs()
			b.SetBytes(int64(len(td.Content)))
			b.ResetTimer()
			
			for i := 0; i < b.N; i++ {
				err := yc.CompileString(td.Content)
				if err != nil {
					b.Fatalf("Compilation failed: %v", err)
				}
			}
		})
	}
}

// BenchmarkGoYaraLexer_Benchmark runs benchmarks on specific benchmark rules.
func BenchmarkGoYaraLexer_Benchmark(b *testing.B) {
	benchRules := GetBenchmarkRules()
	
	for _, td := range benchRules {
		b.Run(td.Name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(td.Content)))
			b.ResetTimer()
			
			for i := 0; i < b.N; i++ {
				l := lexer.New(td.Content)
				for {
					tok := l.NextToken()
					if tok.Type == token.EOF {
						break
					}
				}
			}
		})
	}
}

// BenchmarkCYaraCompiler_Benchmark runs benchmarks on specific benchmark rules.
func BenchmarkCYaraCompiler_Benchmark(b *testing.B) {
	benchRules := GetBenchmarkRules()
	
	for _, td := range benchRules {
		b.Run(td.Name, func(b *testing.B) {
			yc, err := NewYaraCompiler()
			if err != nil {
				b.Fatalf("Failed to create YARA compiler: %v", err)
			}
			defer yc.Close()
			
			b.ReportAllocs()
			b.SetBytes(int64(len(td.Content)))
			b.ResetTimer()
			
			for i := 0; i < b.N; i++ {
				err := yc.CompileString(td.Content)
				if err != nil {
					b.Fatalf("Compilation failed: %v", err)
				}
			}
		})
	}
}

// BenchmarkGoYaraLexer_Simple is a simple benchmark for quick testing.
func BenchmarkGoYaraLexer_Simple(b *testing.B) {
	input := `rule test { condition: true }`
	
	b.ReportAllocs()
	b.SetBytes(int64(len(input)))
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		l := lexer.New(input)
		for {
			tok := l.NextToken()
			if tok.Type == token.EOF {
				break
			}
		}
	}
}

// BenchmarkCYaraCompiler_Simple is a simple benchmark for quick testing.
func BenchmarkCYaraCompiler_Simple(b *testing.B) {
	input := `rule test { condition: true }`
	
	yc, err := NewYaraCompiler()
	if err != nil {
		b.Fatalf("Failed to create YARA compiler: %v", err)
	}
	defer yc.Close()
	
	b.ReportAllocs()
	b.SetBytes(int64(len(input)))
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		err := yc.CompileString(input)
		if err != nil {
			b.Fatalf("Compilation failed: %v", err)
		}
	}
}

// BenchmarkGoYaraLexer_Complex benchmarks a complex rule.
func BenchmarkGoYaraLexer_Complex(b *testing.B) {
	input := `rule ComplexRule {
	meta:
		author = "test"
	strings:
		$a = "malware" nocase wide
		$b = { E2 34 A1 C8 }
		$c = "trojan" ascii
	condition:
		any of them and
		filesize > 102400 and filesize < 52428800 and
		uint32(0) == 0x5A4D
}`

	b.ReportAllocs()
	b.SetBytes(int64(len(input)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		l := lexer.New(input)
		for {
			tok := l.NextToken()
			if tok.Type == token.EOF {
				break
			}
		}
	}
}

// BenchmarkCYaraCompiler_Complex benchmarks a complex rule.
func BenchmarkCYaraCompiler_Complex(b *testing.B) {
	input := `rule ComplexRule {
	meta:
		author = "test"
	strings:
		$a = "malware" nocase wide
		$b = { E2 34 A1 C8 }
		$c = "trojan" ascii
	condition:
		any of them and
		filesize > 102400 and filesize < 52428800 and
		uint32(0) == 0x5A4D
}`

	yc, err := NewYaraCompiler()
	if err != nil {
		b.Fatalf("Failed to create YARA compiler: %v", err)
	}
	defer yc.Close()

	b.ReportAllocs()
	b.SetBytes(int64(len(input)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		err := yc.CompileString(input)
		if err != nil {
			b.Fatalf("Compilation failed: %v", err)
		}
	}
}

