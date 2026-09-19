package compiler

import (
	"fmt"
	"testing"
)

func TestScanContracts(t *testing.T) {
	for _, tc := range []struct {
		name, source, input string
	}{
		{"dependencies", `
private rule helper { strings: $a = "needle" condition: $a }
rule middle { condition: helper }
rule selected : selected { condition: middle }
rule unrelated { condition: for all i in (1..3) : (i > 0) }
`, "needle"},
		{"global_dependencies", `
private rule helper { strings: $a = "needle" condition: $a }
rule middle { condition: helper }
global rule gate { condition: middle }
rule selected : selected { condition: true }
`, "needle"},
		{"occurrence_order", `
rule selected : selected {
 strings: $a = /ab/ ascii wide
 condition: #a == 2 and @a[1] == 0 and !a[1] == 2 and @a[2] == 4 and !a[2] == 4
}`, "ab--a\x00b\x00"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			program, err := NewCompiler().CompileSource(tc.source)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := program.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			loaded, err := UnmarshalCompiledProgram(encoded)
			if err != nil {
				t.Fatal(err)
			}
			for index, candidate := range []*CompiledProgram{program, loaded} {
				for mode, options := range [][]ScannerOption{nil, {WithFastScan()}, {WithReportedMatchesOnly()}, {WithFastScan(), WithReportedMatchesOnly()}} {
					t.Run(fmt.Sprintf("program%d/mode%d", index, mode), func(t *testing.T) {
						options = append(options, WithTagsFilter([]string{"selected"}), WithItersmax(1))
						scanner := NewScanner(candidate, options...)
						defer scanner.Close()
						blocks := NewBlockScanner(candidate, options...)
						defer blocks.Close()
						for _, input := range []string{tc.input, "missing", tc.input} {
							data := []byte(input)
							want := input == tc.input
							check := func(api string, got []RuleMatch, err error) {
								t.Helper()
								if err != nil || int64(len(got)) != boolToInt(want) || want && got[0].Rule != "selected" {
									t.Fatalf("%s(%q) = (%+v, %v), want selected=%v", api, input, got, err, want)
								}
							}
							full, err := scanner.Scan(data)
							if err != nil {
								t.Fatal(err)
							}
							check("Scan", full.MatchedRules, nil)
							matched, err := scanner.MatchesWithContext(t.Context(), data)
							if err != nil || matched != want {
								t.Fatalf("Matches(%q) = (%v, %v), want %v", input, matched, err, want)
							}
							rules, err := scanner.MatchingRules(data)
							check("MatchingRules", rules, err)
							rules, err = scanner.MatchingRulesInBlock(MemoryBlock{Data: data}, int64(len(data)))
							check("MatchingRulesInBlock", rules, err)
							blocks.Reset()
							if err := blocks.Scan(0, data); err != nil {
								t.Fatal(err)
							}
							full, err = blocks.Finish()
							if err != nil {
								t.Fatal(err)
							}
							check("BlockScanner", full.MatchedRules, nil)
						}
					})
				}
			}
		})
	}
}
