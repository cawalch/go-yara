package compiler

import "testing"

const moduleSetupTextSource = `rule text { strings: $a = "needle" condition: $a }`

func BenchmarkModuleRegistryCompile(b *testing.B) {
	for _, tc := range []struct {
		name   string
		source string
		opts   []Option
	}{
		{"TextOnly", moduleSetupTextSource, nil},
		{"TextOnlyWithWarnings", moduleSetupTextSource, []Option{WithWarnings(true)}},
		{"TextOnlyWithMaxInputSize", moduleSetupTextSource, []Option{WithMaxInputSize(50 * 1024 * 1024)}},
		{"ImportUnusedPE", `import "pe" rule text { condition: true }`, nil},
		{"UsedMath", `import "math" rule math { condition: math.mean(0, filesize) > 0 }`, nil},
		{"UsedPEQuery", `import "pe" rule pe { condition: pe.is_pe }`, nil},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := NewCompiler(tc.opts...).CompileSource(tc.source); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkModuleRegistrySerialize(b *testing.B) {
	for _, tc := range []struct {
		name   string
		source string
	}{
		{"TextOnly", moduleSetupTextSource},
		{"UsedPEQuery", `import "pe" rule pe { condition: pe.is_pe }`},
	} {
		program, err := NewCompiler().CompileSource(tc.source)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := program.MarshalBinary(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkModuleRegistryNonPEScan(b *testing.B) {
	for _, tc := range []struct {
		name   string
		source string
	}{
		{"TextOnly", moduleSetupTextSource},
		{"UsedPEQuery", `import "pe" rule pe { condition: pe.is_pe }`},
	} {
		program, err := NewCompiler().CompileSource(tc.source)
		if err != nil {
			b.Fatal(err)
		}
		scanner := NewScanner(program, WithoutMatches(), WithoutRuleResults())
		data := []byte("completely unrelated payload for clean rejection")
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(data)))
			b.ResetTimer()
			for b.Loop() {
				if _, err := scanner.MatchingRules(data); err != nil {
					b.Fatal(err)
				}
			}
		})
		scanner.Close()
	}
}
