package lexer_test

import (
	"context"
	"testing"
	"time"

	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/token"
)

// BenchmarkTargeted_Basic benchmarks the targeted lexer with basic input.
func BenchmarkTargeted_Basic(b *testing.B) {
	b.ReportAllocs()
	input := "rule r { condition and or (1 + 2) }"
	b.ResetTimer()

	// Add timeout to prevent hanging
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	done := make(chan bool)
	go func() {
		for i := 0; i < b.N; i++ {
			l := lexer.NewTargeted(input)
			for {
				tok := l.NextToken()
				if tok.Type == token.EOF {
					break
				}
			}
		}
		done <- true
	}()

	select {
	case <-done:
		// Benchmark completed successfully
	case <-ctx.Done():
		b.Fatalf("Benchmark timed out after 30 seconds")
	}
}

// BenchmarkTargeted_Keywords benchmarks keyword processing with targeted optimizations.
func BenchmarkTargeted_Keywords(b *testing.B) {
	b.ReportAllocs()
	input := "rule meta strings condition and or not true false all any none of"
	b.ResetTimer()

	// Add timeout to prevent hanging
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	done := make(chan bool)
	go func() {
		for i := 0; i < b.N; i++ {
			l := lexer.NewTargeted(input)
			for {
				tok := l.NextToken()
				if tok.Type == token.EOF {
					break
				}
			}
		}
		done <- true
	}()

	select {
	case <-done:
		// Benchmark completed successfully
	case <-ctx.Done():
		b.Fatalf("Benchmark timed out after 30 seconds")
	}
}

// BenchmarkTargeted_StringLiterals benchmarks string literal processing with targeted optimizations.
func BenchmarkTargeted_StringLiterals(b *testing.B) {
	b.ReportAllocs()
	input := `"test string" "another string" "escaped \"string\""`
	b.ResetTimer()

	// Add timeout to prevent hanging
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	done := make(chan bool)
	go func() {
		for i := 0; i < b.N; i++ {
			l := lexer.NewTargeted(input)
			for {
				tok := l.NextToken()
				if tok.Type == token.EOF {
					break
				}
			}
		}
		done <- true
	}()

	select {
	case <-done:
		// Benchmark completed successfully
	case <-ctx.Done():
		b.Fatalf("Benchmark timed out after 30 seconds")
	}
}

// BenchmarkTargeted_HexStrings benchmarks hex string processing with targeted optimizations.
func BenchmarkTargeted_HexStrings(b *testing.B) {
	b.ReportAllocs()
	input := `{ E2 34 A1 C8 } { ?? A? ?B } { F4 23 [4-6] 62 B4 }`
	b.ResetTimer()

	// Add timeout to prevent hanging
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	done := make(chan bool)
	go func() {
		for i := 0; i < b.N; i++ {
			l := lexer.NewTargeted(input)
			for {
				tok := l.NextToken()
				if tok.Type == token.EOF {
					break
				}
			}
		}
		done <- true
	}()

	select {
	case <-done:
		// Benchmark completed successfully
	case <-ctx.Done():
		b.Fatalf("Benchmark timed out after 30 seconds")
	}
}

// BenchmarkTargeted_ComplexRule benchmarks a complex YARA rule with targeted optimizations.
func BenchmarkTargeted_ComplexRule(b *testing.B) {
	b.ReportAllocs()
	input := `rule ComplexRule {
		meta:
			author = "test"
			version = "1.0"
		strings:
			$a = "malware" nocase wide
			$b = { E2 34 A1 C8 } private
			$c = /[a-z]{32}/i ascii fullword
		condition:
			any of them and
			filesize > 1MB and filesize < 100KB and
			uint32(0) == 0x5A4D and uint32(entrypoint) & 0xFF00 == 0x4D00 and
			int16be(entrypoint + 4) > 0 and uint16(2) & 0xFF00 == 0x4D00 and
			uint8(filesize - 1) != 0x00 and (filesize >> 10) < 1024 and
			~uint16(2) == 0xFFFF and (flags | 0x01) != 0
	}`
	b.ResetTimer()

	// Add timeout to prevent hanging
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	done := make(chan bool)
	go func() {
		for i := 0; i < b.N; i++ {
			l := lexer.NewTargeted(input)
			for {
				tok := l.NextToken()
				if tok.Type == token.EOF {
					break
				}
			}
		}
		done <- true
	}()

	select {
	case <-done:
		// Benchmark completed successfully
	case <-ctx.Done():
		b.Fatalf("Benchmark timed out after 30 seconds")
	}
}

// BenchmarkComparison_TargetedVsOriginal compares targeted vs original lexer.
func BenchmarkComparison_TargetedVsOriginal(b *testing.B) {
	b.Run("Original", func(b *testing.B) {
		b.ReportAllocs()
		input := "rule test { condition: true and false or 1 + 2 * 3 }"
		b.ResetTimer()

		// Add timeout to prevent hanging
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		done := make(chan bool)
		go func() {
			for i := 0; i < b.N; i++ {
				l := lexer.New(input)
				for {
					tok := l.NextToken()
					if tok.Type == token.EOF {
						break
					}
				}
			}
			done <- true
		}()

		select {
		case <-done:
			// Benchmark completed successfully
		case <-ctx.Done():
			b.Fatalf("Benchmark timed out after 30 seconds")
		}
	})

	b.Run("Targeted", func(b *testing.B) {
		b.ReportAllocs()
		input := "rule test { condition: true and false or 1 + 2 * 3 }"
		b.ResetTimer()

		// Add timeout to prevent hanging
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		done := make(chan bool)
		go func() {
			for i := 0; i < b.N; i++ {
				l := lexer.NewTargeted(input)
				for {
					tok := l.NextToken()
					if tok.Type == token.EOF {
						break
					}
				}
			}
			done <- true
		}()

		select {
		case <-done:
			// Benchmark completed successfully
		case <-ctx.Done():
			b.Fatalf("Benchmark timed out after 30 seconds")
		}
	})
}
