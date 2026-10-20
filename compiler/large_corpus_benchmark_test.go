package compiler

import (
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"
)

// generateLargeBenchmarkCorpus produces a realistic multi-rule corpus mixing
// text literals (with ascii/wide/nocase modifiers), hex patterns with jumps/masks,
// regexes with character classes/quantifiers, and varied boolean conditions.
func generateLargeBenchmarkCorpus(numRules int) string {
	var sb strings.Builder
	// Pre-size builder estimate: ~250 bytes per rule
	sb.Grow(numRules * 250)

	for i := range numRules {
		fmt.Fprintf(&sb, "rule corp_rule_%d {\n", i)
		sb.WriteString("    meta:\n")
		fmt.Fprintf(&sb, "        author = \"threat_intel_%d\"\n", i%10)
		fmt.Fprintf(&sb, "        severity = %d\n", (i%5)+1)
		sb.WriteString("    strings:\n")

		// 1. Text string with modifiers
		mod := ""
		switch i % 4 {
		case 0:
			mod = " ascii wide"
		case 1:
			mod = " nocase"
		case 2:
			mod = " ascii"
		case 3:
			mod = " wide"
		}
		fmt.Fprintf(&sb, "        $s1 = \"MalwarePayloadToken_%d_\"%s\n", i, mod)

		// 2. Secondary text string
		fmt.Fprintf(&sb, "        $s2 = \"/api/v1/telemetry_beacon_%d\"\n", i%50)

		// 3. Hex pattern
		if i%3 == 0 {
			fmt.Fprintf(&sb, "        $hex1 = { 4D 5A 90 %02X [2-8] ( 50 45 | 45 50 ) 00 00 }\n", i%256)
		} else {
			fmt.Fprintf(&sb, "        $hex1 = { E8 ?? ?? ?? ?? 85 C0 74 %02X 8B 4D }\n", i%256)
		}

		// 4. Regex pattern
		if i%2 == 0 {
			fmt.Fprintf(&sb, "        $re1 = /cmd_handler_[0-9]{2,4}_[a-z]{4}/ nocase\n")
		} else {
			fmt.Fprintf(&sb, "        $re1 = /token_[0-9a-f]{16,32}/\n")
		}

		// Condition variety
		sb.WriteString("    condition:\n")
		switch i % 5 {
		case 0:
			sb.WriteString("        $s1 or ($s2 and $hex1)\n")
		case 1:
			sb.WriteString("        any of ($s*, $hex*)\n")
		case 2:
			sb.WriteString("        1 of ($s*) and ($hex1 or $re1)\n")
		case 3:
			sb.WriteString("        2 of them\n")
		case 4:
			sb.WriteString("        $s1 and ($re1 or $hex1)\n")
		}
		sb.WriteString("}\n\n")
	}

	return sb.String()
}

// generateBenchmarkPayloads builds a clean buffer and a buffer with planted hits.
func generateBenchmarkPayloads(size int, targetRuleIdx int) (clean []byte, hit []byte) {
	rng := rand.New(rand.NewPCG(42, uint64(size)))
	words := []string{
		"function", "return", "if", "else", "var", "const", "require",
		"module", "exports", "window", "document", "GetProcAddress",
		"echo", "printf", "malloc", "free", "struct", "static", "inline",
		"include", "import", "class", "public", "private", "protected",
	}

	var sb strings.Builder
	sb.Grow(size)
	for sb.Len() < size {
		sb.WriteString(words[rng.IntN(len(words))])
		if rng.IntN(6) == 0 {
			sb.WriteByte('\n')
		} else {
			sb.WriteByte(' ')
		}
	}
	raw := []byte(sb.String())
	if len(raw) > size {
		raw = raw[:size]
	}

	clean = make([]byte, len(raw))
	copy(clean, raw)

	hit = make([]byte, len(raw))
	copy(hit, raw)

	// Plant a hit for rule targetRuleIdx near the middle
	plantToken := fmt.Sprintf("MalwarePayloadToken_%d_", targetRuleIdx)
	plantOffset := len(hit) / 2
	if plantOffset+len(plantToken) < len(hit) {
		copy(hit[plantOffset:], plantToken)
	}

	return clean, hit
}

// BenchmarkLargeCorpusCompile measures compiler throughput and heap allocations
// across rule sets ranging from 100 to 2,000 rules.
func BenchmarkLargeCorpusCompile(b *testing.B) {
	for _, ruleCount := range []int{100, 500, 1000, 2000} {
		source := generateLargeBenchmarkCorpus(ruleCount)
		b.Run(fmt.Sprintf("rules=%d", ruleCount), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(source)))
			b.ResetTimer()
			for b.Loop() {
				compiler := NewCompiler()
				prog, err := compiler.CompileSource(source)
				if err != nil {
					b.Fatalf("CompileSource error: %v", err)
				}
				if len(prog.Rules) != ruleCount {
					b.Fatalf("got %d rules, want %d", len(prog.Rules), ruleCount)
				}
			}
		})
	}
}

// BenchmarkLargeCorpusScannerInit measures the latency of instantiating a Scanner
// from a pre-compiled program with hundreds or thousands of rules.
func BenchmarkLargeCorpusScannerInit(b *testing.B) {
	for _, ruleCount := range []int{500, 2000} {
		source := generateLargeBenchmarkCorpus(ruleCount)
		prog, err := NewCompiler().CompileSource(source)
		if err != nil {
			b.Fatalf("CompileSource error: %v", err)
		}

		b.Run(fmt.Sprintf("rules=%d", ruleCount), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				scanner := NewScanner(prog)
				scanner.Close()
			}
		})
	}
}

// BenchmarkLargeCorpusScanClean measures clean-file fast-rejection throughput
// (which constitutes >99.9% of production AV/EDR scanning workloads).
func BenchmarkLargeCorpusScanClean(b *testing.B) {
	for _, ruleCount := range []int{500, 2000} {
		source := generateLargeBenchmarkCorpus(ruleCount)
		prog, err := NewCompiler().CompileSource(source)
		if err != nil {
			b.Fatalf("CompileSource error: %v", err)
		}

		for _, size := range []int{64 * 1024, 1024 * 1024, 10 * 1024 * 1024} {
			clean, _ := generateBenchmarkPayloads(size, 0)
			sizeLabel := fmt.Sprintf("%dKB", size/1024)
			if size >= 1024*1024 {
				sizeLabel = fmt.Sprintf("%dMB", size/(1024*1024))
			}

			b.Run(fmt.Sprintf("rules=%d/%s/DefaultScan", ruleCount, sizeLabel), func(b *testing.B) {
				scanner := NewScanner(prog)
				defer scanner.Close()
				b.ReportAllocs()
				b.SetBytes(int64(len(clean)))
				b.ResetTimer()
				for b.Loop() {
					res, scanErr := scanner.Scan(clean)
					if scanErr != nil {
						b.Fatal(scanErr)
					}
					if len(res.MatchedRules) != 0 {
						b.Fatalf("unexpected matches: %d", len(res.MatchedRules))
					}
				}
			})

			b.Run(fmt.Sprintf("rules=%d/%s/ZeroAllocMatches", ruleCount, sizeLabel), func(b *testing.B) {
				scanner := NewScanner(prog, WithoutMatches())
				defer scanner.Close()
				b.ReportAllocs()
				b.SetBytes(int64(len(clean)))
				b.ResetTimer()
				for b.Loop() {
					res, scanErr := scanner.Scan(clean)
					if scanErr != nil {
						b.Fatal(scanErr)
					}
					if len(res.MatchedRules) != 0 {
						b.Fatalf("unexpected matches: %d", len(res.MatchedRules))
					}
				}
			})

			b.Run(fmt.Sprintf("rules=%d/%s/ProgramMatchingRules", ruleCount, sizeLabel), func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(clean)))
				b.ResetTimer()
				for b.Loop() {
					matched, scanErr := prog.MatchingRules(clean)
					if scanErr != nil {
						b.Fatal(scanErr)
					}
					if len(matched) != 0 {
						b.Fatalf("unexpected matches: %d", len(matched))
					}
				}
			})
		}
	}
}

// BenchmarkLargeCorpusScanHit measures throughput when matches occur in large payloads.
func BenchmarkLargeCorpusScanHit(b *testing.B) {
	for _, ruleCount := range []int{500, 2000} {
		source := generateLargeBenchmarkCorpus(ruleCount)
		prog, err := NewCompiler().CompileSource(source)
		if err != nil {
			b.Fatalf("CompileSource error: %v", err)
		}

		for _, size := range []int{64 * 1024, 1024 * 1024, 10 * 1024 * 1024} {
			_, hit := generateBenchmarkPayloads(size, 50)
			sizeLabel := fmt.Sprintf("%dKB", size/1024)
			if size >= 1024*1024 {
				sizeLabel = fmt.Sprintf("%dMB", size/(1024*1024))
			}

			b.Run(fmt.Sprintf("rules=%d/%s/DefaultScan", ruleCount, sizeLabel), func(b *testing.B) {
				scanner := NewScanner(prog)
				defer scanner.Close()
				b.ReportAllocs()
				b.SetBytes(int64(len(hit)))
				b.ResetTimer()
				for b.Loop() {
					res, scanErr := scanner.Scan(hit)
					if scanErr != nil {
						b.Fatal(scanErr)
					}
					if len(res.MatchedRules) == 0 {
						b.Fatal("expected match, got 0")
					}
				}
			})

			b.Run(fmt.Sprintf("rules=%d/%s/ZeroAllocMatches", ruleCount, sizeLabel), func(b *testing.B) {
				scanner := NewScanner(prog, WithoutMatches())
				defer scanner.Close()
				b.ReportAllocs()
				b.SetBytes(int64(len(hit)))
				b.ResetTimer()
				for b.Loop() {
					res, scanErr := scanner.Scan(hit)
					if scanErr != nil {
						b.Fatal(scanErr)
					}
					if len(res.MatchedRules) == 0 {
						b.Fatal("expected match, got 0")
					}
				}
			})

			b.Run(fmt.Sprintf("rules=%d/%s/ProgramMatchingRules", ruleCount, sizeLabel), func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(hit)))
				b.ResetTimer()
				for b.Loop() {
					matched, scanErr := prog.MatchingRules(hit)
					if scanErr != nil {
						b.Fatal(scanErr)
					}
					if len(matched) == 0 {
						b.Fatal("expected match, got 0")
					}
				}
			})
		}
	}
}

// BenchmarkLargeCorpusSerialization measures program binary encoding & decoding latency.
func BenchmarkLargeCorpusSerialization(b *testing.B) {
	for _, ruleCount := range []int{500, 2000} {
		source := generateLargeBenchmarkCorpus(ruleCount)
		prog, err := NewCompiler().CompileSource(source)
		if err != nil {
			b.Fatalf("CompileSource error: %v", err)
		}

		marshaled, err := prog.MarshalBinary()
		if err != nil {
			b.Fatalf("MarshalBinary error: %v", err)
		}

		b.Run(fmt.Sprintf("Marshal/rules=%d", ruleCount), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(marshaled)))
			b.ResetTimer()
			for b.Loop() {
				_, err := prog.MarshalBinary()
				if err != nil {
					b.Fatal(err)
				}
			}
		})

		b.Run(fmt.Sprintf("Unmarshal/rules=%d", ruleCount), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(marshaled)))
			b.ResetTimer()
			for b.Loop() {
				if _, err := UnmarshalCompiledProgram(marshaled); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestLargeCorpusEquivalence(t *testing.T) {
	source := generateLargeBenchmarkCorpus(50)
	prog, err := NewCompiler().CompileSource(source)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	clean, hit := generateBenchmarkPayloads(16*1024, 10)

	scanner := NewScanner(prog)
	defer scanner.Close()

	cleanRes, err := scanner.Scan(clean)
	if err != nil {
		t.Fatalf("scan clean: %v", err)
	}
	if len(cleanRes.MatchedRules) != 0 {
		t.Errorf("clean matched %d rules, want 0", len(cleanRes.MatchedRules))
	}

	hitRes, err := scanner.Scan(hit)
	if err != nil {
		t.Fatalf("scan hit: %v", err)
	}
	if len(hitRes.MatchedRules) == 0 {
		t.Errorf("hit matched 0 rules, want > 0")
	}
	if !hitRes.RuleResults["corp_rule_10"] {
		t.Errorf("corp_rule_10 did not match")
	}

	// Verify serialization roundtrip preserves matches
	data, err := prog.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	roundtrip, err := UnmarshalCompiledProgram(data)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	rtScanner := NewScanner(roundtrip)
	defer rtScanner.Close()
	rtHitRes, err := rtScanner.Scan(hit)
	if err != nil {
		t.Fatalf("rt scan hit: %v", err)
	}
	if len(rtHitRes.MatchedRules) != len(hitRes.MatchedRules) {
		t.Errorf("roundtrip matching rules count mismatch: got %d, want %d", len(rtHitRes.MatchedRules), len(hitRes.MatchedRules))
	}
}
