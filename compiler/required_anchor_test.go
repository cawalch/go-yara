package compiler

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestRequiredAnchorMixedAPIReuse(t *testing.T) {
	var source strings.Builder
	for i := 0; i < 8; i++ {
		fmt.Fprintf(&source, `rule r%d { strings: $source="service" $indicator="rejected_%02d" condition: all of them }`, i, i)
	}
	program, err := NewCompiler().CompileSource(source.String())
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
	for _, candidate := range []*CompiledProgram{program, loaded, NewCompiledProgram(program.Rules)} {
		for _, fast := range []bool{false, true} {
			scanner := candidate.NewScanner()
			scanner.fastScan = fast
			defer scanner.Close()
			for _, input := range []string{"service", "service rejected_03", "service"} {
				data := []byte(input)
				want := strings.Contains(input, "rejected")
				got, err := scanner.MatchesWithContext(context.Background(), data)
				if err != nil || got != want {
					t.Fatalf("Matches %q: %v,%v", input, got, err)
				}
				if !want && len(scanner.candidateRuleIndices) != 0 {
					t.Fatal("common marker activated compact candidates")
				}
				report, err := scanner.Scan(data)
				if err != nil || len(report.Matches) != 8 || len(report.RuleResults) != 8 {
					t.Fatalf("Scan %q: %+v,%v", input, report, err)
				}
				if scanner.compactCandidates {
					t.Fatal("Scan retained compact routing mode")
				}
				for _, matches := range report.Matches {
					if len(matches["$source"]) != 1 {
						t.Fatal("Scan dropped false-rule source occurrence")
					}
				}
				rules, err := scanner.MatchingRules(data)
				if err != nil || len(rules) > 0 != want {
					t.Fatalf("MatchingRules %q: %+v,%v", input, rules, err)
				}
				again, err := scanner.Scan(data)
				if err != nil || !reflect.DeepEqual(report, again) {
					t.Fatalf("Scan after compact differs: %+v,%v", again, err)
				}
				scanner.reportedMatchesOnly = true
				compact, err := scanner.Scan(data)
				scanner.reportedMatchesOnly = false
				if err != nil || len(compact.MatchedRules) > 0 != want || len(compact.RuleResults) != 8 {
					t.Fatalf("reported Scan %q: %+v,%v", input, compact, err)
				}
			}
		}
	}
}

func TestRequiredAnchorSharedRegexParity(t *testing.T) {
	var source strings.Builder
	for i := 0; i < 40; i++ {
		fmt.Fprintf(&source, `rule r%d { strings: $source="service" $indicator=/denied_%02d=[0-9]{4}/ condition: $source and $indicator }`, i, i%20)
	}
	program, err := NewCompiler().CompileSource(source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, covered := range program.sharedNonTextCaches {
		if !covered {
			t.Fatal("fixture requires shared regex coverage")
		}
	}
	scanner := program.NewScanner()
	defer scanner.Close()
	oracle := program.NewScanner()
	defer oracle.Close()
	oracle.prefilterDisabled = true
	for _, data := range []string{"service", "service denied_00=123x", "service denied_00=1234", "denied_00=1234", "service"} {
		got, err := scanner.MatchingRules([]byte(data))
		if err != nil {
			t.Fatal(err)
		}
		want, err := oracle.MatchingRules([]byte(data))
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("%q: got%+v want%+v err%v", data, got, want, err)
		}
		if data == "service" && len(scanner.candidateRuleIndices) != 0 {
			t.Fatal("text source activated regex-anchored rules")
		}
		if data == "service denied_00=1234" && len(got) != 2 {
			t.Fatalf("deduplicated regex missed consumers: %v", got)
		}
		full, err := scanner.Scan([]byte(data))
		if err != nil {
			t.Fatal(err)
		}
		fullWant, err := oracle.Scan([]byte(data))
		if err != nil || !reflect.DeepEqual(full, fullWant) {
			t.Fatalf("full Scan %q differs", data)
		}
	}
}

func TestRequiredAnchorBooleanParity(t *testing.T) {
	for _, condition := range []string{"$a and $b", "$a or $b", "($a and $b) or ($a and $c)", "all of them", "all of ($a, $b)", "any of them", "not $a", "$a and #b > 0", "$a or filesize > 0"} {
		source := fmt.Sprintf(`rule rule1 {strings: $a="event" $b="failed" fullword $c="denied" nocase condition:%s} rule rule2 {strings: $a="event" $b="special" condition:all of them}`, condition)
		program, err := NewCompiler().CompileSource(source)
		if err != nil {
			t.Fatal(err)
		}
		scanner := program.NewScanner()
		defer scanner.Close()
		oracle := program.NewScanner()
		defer oracle.Close()
		oracle.prefilterDisabled = true
		for mask := 0; mask < 16; mask++ {
			var pieces []string
			for bit, word := range []string{"event", "failed", "DENIED", "special"} {
				if mask&(1<<bit) != 0 {
					pieces = append(pieces, word)
				}
			}
			for _, separator := range []string{" ", ""} {
				input := []byte(strings.Join(pieces, separator))
				got, err := scanner.MatchingRulesInBlock(MemoryBlock{Base: 1024, Data: input}, 4096)
				if err != nil {
					t.Fatal(err)
				}
				want, err := oracle.MatchingRulesInBlock(MemoryBlock{Base: 1024, Data: input}, 4096)
				if err != nil || !reflect.DeepEqual(got, want) {
					t.Fatalf("%s, %q: got%v want%v err%v", condition, input, got, want, err)
				}
			}
		}
	}
}

func TestRequiredAnchorSharedRegexDifferentConsumers(t *testing.T) {
	var source strings.Builder
	for i := 0; i < 40; i++ {
		fmt.Fprintf(&source, `rule r%d {strings: $common="service" $pattern=/denied_%02d=[0-9]{4}/ condition:all of them}`, i, i)
	}
	source.WriteString(`rule text_anchor {strings: $a_regex=/denied_00=[0-9]{4}/ $z_text="rare marker" condition:all of them}
 rule regex_anchor {strings: $a_regex=/denied_00=[0-9]{4}/ $z_common="service" condition:all of them}`)
	program, err := NewCompiler().CompileSource(source.String())
	if err != nil {
		t.Fatal(err)
	}
	cacheIndex := program.Rules[0].RegexPatterns["$pattern"].cacheIndex
	if !program.sharedNonTextCaches[cacheIndex] || !reflect.DeepEqual(program.compactNonTextCacheRules[cacheIndex], []int{0, 41}) {
		t.Fatalf("mixed anchor routes=%v", program.compactNonTextCacheRules[cacheIndex])
	}
	scanner := program.NewScanner()
	defer scanner.Close()
	oracle := program.NewScanner()
	defer oracle.Close()
	oracle.prefilterDisabled = true
	for _, data := range []string{"service", "service denied_00=1234", "rare marker denied_00=1234", "rare marker", "service rare marker denied_00=1234", "service denied_00=123x rare marker", "service"} {
		got, err := scanner.MatchingRules([]byte(data))
		if err != nil {
			t.Fatal(err)
		}
		want, err := oracle.MatchingRules([]byte(data))
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("%q: got%v want%v err%v", data, got, want, err)
		}
		if data == "service denied_00=1234" && scanner.candidateRuleSeen[40] {
			t.Fatal("regex hit activated text-anchored consumer")
		}
		full, err := scanner.Scan([]byte(data))
		if err != nil {
			t.Fatal(err)
		}
		fullWant, err := oracle.Scan([]byte(data))
		if err != nil || !reflect.DeepEqual(full, fullWant) {
			t.Fatalf("full Scan %q differs", data)
		}
	}
}
