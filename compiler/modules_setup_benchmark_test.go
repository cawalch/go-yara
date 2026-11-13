package compiler

import "testing"

const moduleSetupTextSource = `rule text { strings: $a = "needle" condition: $a }`

func BenchmarkModuleRegistryCompile(b *testing.B) {
	for _, tc := range []struct {
		name   string
		source string
	}{
		{"TextOnly", moduleSetupTextSource},
		{"ImportUnusedPE", `import "pe" rule text { condition: true }`},
		{"UsedMath", `import "math" rule math { condition: math.mean(0, filesize) > 0 }`},
		{"UsedPEQuery", `import "pe" rule pe { condition: pe.is_pe }`},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := NewCompiler().CompileSource(tc.source); err != nil {
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
