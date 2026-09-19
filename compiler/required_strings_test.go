package compiler

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestRequiredStringsPreparation(t *testing.T) {
	program, err := NewCompiler().CompileSource(`rule example { strings: $a = "alpha" $b = "beta" condition: all of them }`)
	if err != nil {
		t.Fatal(err)
	}
	rebuilt := NewCompiledProgram(program.Rules)
	encoded, err := program.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := UnmarshalCompiledProgram(encoded)
	if err != nil {
		t.Fatal(err)
	}
	program.Rules[0].requiredStrings[0] = "$mutated"
	for _, candidate := range []*CompiledProgram{rebuilt, loaded} {
		if !reflect.DeepEqual(candidate.Rules[0].requiredStrings, []string{"$a", "$b"}) {
			t.Fatalf("required strings = %v", candidate.Rules[0].requiredStrings)
		}
	}
	program.Rules[0].requiredStrings = nil
	encoded, err = program.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := UnmarshalCompiledProgram(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(legacy.Rules[0].requiredStrings) != 0 {
		t.Fatal("absent optional metadata must disable gate")
	}
	for _, candidate := range []*CompiledProgram{rebuilt, loaded, legacy} {
		for _, options := range [][]ScannerOption{nil, {WithFastScan()}, {WithReportedMatchesOnly()}, {WithFastScan(), WithReportedMatchesOnly()}} {
			scanner := candidate.NewScanner(options...)
			defer scanner.Close()
			for _, data := range [][]byte{nil, []byte("alpha"), []byte("alpha beta"), []byte("beta"), nil} {
				want := string(data) == "alpha beta"
				got, err := scanner.Matches(data)
				if err != nil || got != want {
					t.Fatalf("Matches(%q) = %v,%v", data, got, err)
				}
				report, err := scanner.Scan(data)
				if err != nil || len(report.MatchedRules) > 0 != want || len(report.PrunedRules) != 0 {
					t.Fatalf("Scan(%q) = %+v,%v", data, report, err)
				}
				if !scanner.reportedMatchesOnly && string(data) == "alpha" && len(report.Matches["example"]["$a"]) != 1 {
					t.Fatal("default Scan lost nonmatching rule's occurrence")
				}
				rules, err := scanner.MatchingRulesInBlock(MemoryBlock{Base: 4096, Data: data}, 8192)
				if err != nil || len(rules) > 0 != want {
					t.Fatalf("block(%q) = %+v,%v", data, rules, err)
				}
			}
			canceled, cancel := context.WithCancel(context.Background())
			cancel()
			if _, err := scanner.MatchesWithContext(canceled, []byte("alpha")); !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		}
	}
}

func TestRequiredStringsPreserveErrors(t *testing.T) {
	sentinel := errors.New("module failure")
	module := Module{Name: "fail", Functions: map[string]ModuleFunction{"check": {
		Signatures: []ModuleSignature{{}}, ReturnType: ModuleBoolean,
		Evaluate: func(ModuleContext, []ModuleValue) (ModuleValue, error) { return ModuleValue{}, sentinel },
	}}}
	for _, condition := range []string{"$a and fail.check() and $b", "fail.check() and all of them", "($a and fail.check()) or ($b and fail.check())"} {
		program, err := NewCompiler(WithModule(module)).CompileSource(`import "fail" rule example { strings: $a="alpha" $b="beta" condition: ` + condition + ` }`)
		if err != nil {
			t.Fatal(err)
		}
		if len(program.Rules[0].requiredStrings) != 0 {
			t.Fatalf("unsafe gate for %s", condition)
		}
		if _, err := program.Matches([]byte("alpha")); err == nil {
			t.Fatalf("%s: %v", condition, err)
		}
	}
}

func TestRequiredStringsSharedRegexParity(t *testing.T) {
	var source strings.Builder
	for i := 0; i < 40; i++ {
		fmt.Fprintf(&source, `rule r%d { strings: $source="event" $indicator=/denied_%02d=[0-9]{4}/ condition: $source and $indicator }`, i, i)
	}
	program, err := NewCompiler().CompileSource(source.String())
	if err != nil {
		t.Fatal(err)
	}
	if len(program.sharedNonTextCaches) != 40 || !program.sharedNonTextCaches[0] {
		t.Fatal("fixture must use shared regex verification")
	}
	scanner := program.NewScanner(WithFastScan())
	defer scanner.Close()
	for _, data := range []string{"event", "event denied_00=12xx", "event denied_00=1234", "denied_00=1234", "event denied_00=1234 denied_10=9876", "event"} {
		got, err := scanner.MatchingRules([]byte(data))
		if err != nil {
			t.Fatal(err)
		}
		scanner.prefilterDisabled = true
		want, err := scanner.MatchingRules([]byte(data))
		scanner.prefilterDisabled = false
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("%q: got %+v want %+v error %v", data, got, want, err)
		}
	}
}

func TestRequiredStringsGateWorkBound(t *testing.T) {
	program, err := NewCompiler().CompileSource(`rule example { strings: $a="alpha" $b="beta" condition: all of them }`)
	if err != nil {
		t.Fatal(err)
	}
	scanner := program.NewScanner()
	defer scanner.Close()
	data := []byte(strings.Repeat("alpha ", 256))
	if shared, err := scanner.preparePatternScan(context.Background(), data); err != nil || !shared {
		t.Fatalf("shared=%v error=%v", shared, err)
	}
	if scanner.missingRequiredString(program.Rules[0]) {
		t.Fatal("exhausted gate must fall back to full evaluation")
	}
	matched, err := scanner.Matches(data)
	if err != nil || matched {
		t.Fatalf("Matches=%v error=%v", matched, err)
	}
}

func TestRequiredGateBooleanParity(t *testing.T) {
	for _, condition := range []string{
		"$a and $b", "$a or $b", "($a and $b) or ($a and $c)",
		"all of ($a, $b)", "all of ($prefix*)", "all of ($missing*)", "any of them", "none of them", "2 of them",
		"not $a", "$a and not $b", "$a or filesize > 0", "$a and #b > 0", "all of them at 0",
	} {
		source := fmt.Sprintf(`rule example { strings: $a = "alpha" fullword $b = /beta[0-9]+/ $c = { 67 61 6D 6D 61 } $prefix1 = "delta" $prefix2 = "theta" nocase condition: %s }`, condition)
		program, err := NewCompiler().CompileSource(source)
		if err != nil {
			t.Fatal(err)
		}
		rule := program.Rules[0]
		gate := rule.requiredStrings
		scanner := program.NewScanner()
		defer scanner.Close()
		for mask := 0; mask < 32; mask++ {
			var pieces []string
			for bit, text := range []string{"alpha", "beta12", "gamma", "delta", "THETA"} {
				if mask&(1<<bit) != 0 {
					pieces = append(pieces, text)
				}
			}
			for _, separator := range []string{" ", ""} {
				data := []byte(strings.Join(pieces, separator))
				got, err := scanner.Matches(data)
				if err != nil {
					t.Fatal(err)
				}
				rule.requiredStrings = nil
				want, err := scanner.Matches(data)
				rule.requiredStrings = gate
				if err != nil || got != want {
					t.Fatalf("condition %s input %q: %v != %v error %v", condition, data, got, want, err)
				}
			}
		}
	}
}
