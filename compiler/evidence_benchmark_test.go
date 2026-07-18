package compiler

import (
	"bytes"
	"testing"
)

func BenchmarkEvidenceScanPaths(b *testing.B) {
	input := bytes.Repeat([]byte("prefix token=abcdefghijklmnop suffix\n"), 512)
	normal := mustCompileBenchmarkProgram(b, `
rule tokens {
    strings:
        $token = /token=([A-Za-z0-9]+)/
    condition:
        $token
}
`)
	declared := mustCompileBenchmarkProgram(b, `
rule tokens {
    strings:
        $token = /token=([A-Za-z0-9]+)/ capture(secret = 1)
    evidence:
        candidate = (secret) within 0 of secret
    condition:
        $token
}
`)

	benchmarks := []struct {
		name    string
		program *CompiledProgram
		options []ScannerOption
	}{
		{"normal", normal, nil},
		{"capture_declared_evidence_disabled", declared, nil},
		{"match_heavy_evidence_enabled", declared, []ScannerOption{WithEvidence(64)}},
	}
	for _, benchmark := range benchmarks {
		b.Run(benchmark.name, func(b *testing.B) {
			scanner := benchmark.program.NewScanner(benchmark.options...)
			defer scanner.Close()
			b.ReportAllocs()
			b.SetBytes(int64(len(input)))
			for range b.N {
				if _, err := scanner.Scan(input); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func mustCompileBenchmarkProgram(b *testing.B, source string) *CompiledProgram {
	b.Helper()
	program, err := NewCompiler().CompileSource(source)
	if err != nil {
		b.Fatalf("CompileSource() error = %v", err)
	}
	return program
}
