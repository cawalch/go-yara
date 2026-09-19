package compiler

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/cawalch/go-yara/internal/wordmatch"
)

func booleanRoutingSource() string {
	var source strings.Builder
	for i := 0; i < 16; i++ {
		fmt.Fprintf(&source, `rule route%d { strings: $a="code%02d_SHARED_0123456789ABCDE" $b="event" condition: all of them }`+"\n", i, i)
	}
	return source.String()
}

func compileBooleanRouting(t *testing.T, source string) *CompiledProgram {
	t.Helper()
	program, err := NewCompiler().CompileSource(source)
	if err != nil {
		t.Fatal(err)
	}
	return program
}

func TestBooleanRoutingMatchesAndDetailedReuse(t *testing.T) {
	program := compileBooleanRouting(t, booleanRoutingSource())
	routed := NewScanner(program, WithBooleanRouting(), WithMatchData(8), WithMatchContext(2, 2))
	ordinary := NewScanner(program, WithMatchData(8), WithMatchContext(2, 2))
	defer routed.Close()
	defer ordinary.Close()
	for _, input := range []string{"clean", "event", "code03_SHARED_0123456789ABCDE", "event code03_SHARED_0123456789ABCDE", "event code00_SHARED_0123456789ABCDE code15_SHARED_0123456789ABCDE", ""} {
		data := []byte(input)
		want, wantErr := ordinary.Matches(data)
		got, err := routed.MatchesWithContext(nil, data) //nolint:staticcheck // nil context is supported by scanner APIs
		if got != want || fmt.Sprint(err) != fmt.Sprint(wantErr) {
			t.Fatalf("%q: (%v,%v) != (%v,%v)", input, got, err, want, wantErr)
		}
		if routed.booleanRouting == nil {

			t.Fatal("eligible Matches did not activate routing")
		}
		wantScan, wantErr := ordinary.Scan(data)
		gotScan, err := routed.Scan(data)
		if !reflect.DeepEqual(gotScan, wantScan) || fmt.Sprint(err) != fmt.Sprint(wantErr) {
			t.Fatalf("Scan differs for %q", input)
		}
		wantRules, wantErr := ordinary.MatchingRules(data)
		gotRules, err := routed.MatchingRules(data)
		if !reflect.DeepEqual(gotRules, wantRules) || fmt.Sprint(err) != fmt.Sprint(wantErr) {
			t.Fatalf("MatchingRules differs for %q", input)
		}
		block := MemoryBlock{Base: 37, Data: data}
		wantRules, wantErr = ordinary.MatchingRulesInBlock(block, 10000)
		gotRules, err = routed.MatchingRulesInBlock(block, 10000)
		if !reflect.DeepEqual(gotRules, wantRules) || fmt.Sprint(err) != fmt.Sprint(wantErr) {
			t.Fatalf("MatchingRulesInBlock differs for %q", input)
		}
	}
	if ordinary.booleanRouting != nil {
		t.Fatal("default scanner activated routing")
	}
	fresh := NewScanner(program, WithBooleanRouting())
	defer fresh.Close()
	_, _ = fresh.Scan([]byte("event code00_SHARED_0123456789ABCDE"))
	_, _ = fresh.MatchingRules(nil)
	if fresh.booleanRouting == nil {
		t.Fatal("opt-in constructor did not prepare Boolean scanner")
	}
	large := append(bytes.Repeat([]byte{'x'}, 1025), []byte("event code01_SHARED_0123456789ABCDE")...)
	if matched, err := fresh.Matches(large); !matched || err != nil {
		t.Fatalf("large-input fallback = %v,%v", matched, err)
	}
}

func TestBooleanRoutingFallbackConditionsAndModifiers(t *testing.T) {
	const text = "SHARED_LITERAL_0123456789"
	cases := []struct {
		name, source string
		options      []ScannerOption
	}{
		{"or", `rule r { strings: $a="` + text + `" $b="alternative" condition: $a or $b }`, nil},
		{"false", `rule r { strings: $a="` + text + `" condition: $a and false }`, nil},
		{"count", `rule r { strings: $a="` + text + `" condition: #a == 2 }`, nil},
		{"offset", `rule r { strings: $a="` + text + `" condition: $a at 3 }`, nil},
		{"private", `private rule r { strings: $a="` + text + `" condition: $a }`, nil},
		{"global", `global rule r { strings: $a="` + text + `" condition: $a }`, nil},
		{"dependency", `private rule helper { strings: $a="` + text + `" condition: $a } rule r { condition: helper }`, nil},
		{"global_value", `global unused="value" rule r { strings: $a="` + text + `" condition: $a }`, nil},
		{"tags", `rule r : selected { strings: $a="` + text + `" condition: $a }`, []ScannerOption{WithTagsFilter([]string{"other"})}},
		{"short", `rule r { strings: $a="x" condition: $a }`, nil},
		{"wide", `rule r { strings: $a="` + text + `" wide condition: $a }`, nil},
		{"fullword", `rule r { strings: $a="` + text + `" fullword condition: $a }`, nil},
		{"xor", `rule r { strings: $a="` + text + `" xor condition: $a }`, nil},
		{"unbounded_regex", `rule r { strings: $a=/SHARED_LITERAL_0123456789.*/ condition: $a }`, nil},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			program := compileBooleanRouting(t, test.source)
			ordinary := NewScanner(program, test.options...)
			routed := NewScanner(program, append([]ScannerOption{WithBooleanRouting()}, test.options...)...)
			defer ordinary.Close()
			defer routed.Close()
			for _, input := range []string{"", "x", "alternative", text, "aaa" + text, text + " " + text} {
				want, wantErr := ordinary.Matches([]byte(input))
				got, err := routed.Matches([]byte(input))
				if got != want || fmt.Sprint(err) != fmt.Sprint(wantErr) {
					t.Fatalf("%q: (%v,%v) != (%v,%v)", input, got, err, want, wantErr)
				}
			}
			if routed.booleanRouting != nil {
				t.Fatal("unsupported portfolio activated routing")
			}
		})
	}
}

func TestBooleanRoutingErrorsAndCancellation(t *testing.T) {
	invalid := NewScanner(NewCompiledProgram([]*CompiledRule{nil}), WithBooleanRouting())
	defer invalid.Close()
	if _, err := invalid.Matches(nil); err == nil {
		t.Fatal("routing suppressed preparation error")
	}
	program := compileBooleanRouting(t, booleanRoutingSource())
	scanner := NewScanner(program, WithBooleanRouting(), WithExternalVariables(map[string]any{"unknown": true}))
	defer scanner.Close()
	if _, err := scanner.Matches(nil); err == nil {
		t.Fatal("routing suppressed external error")
	}
	if err := scanner.SetExternalVariables(nil); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if matched, err := scanner.MatchesWithContext(ctx, []byte("event code00_SHARED_0123456789ABCDE")); matched || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled scan = %v,%v", matched, err)
	}
	if matched, err := scanner.Matches([]byte("event code00_SHARED_0123456789ABCDE")); !matched || err != nil {
		t.Fatalf("reuse = %v,%v", matched, err)
	}
	loop := compileBooleanRouting(t, `rule loop { strings: $a="SHARED_LITERAL_0123456789" condition: $a and (for all i in (1..3) : (true)) }`)
	limited := NewScanner(loop, WithBooleanRouting(), WithItersmax(1))
	defer limited.Close()
	if _, err := limited.Matches([]byte("SHARED_LITERAL_0123456789")); err == nil || !strings.Contains(err.Error(), "iteration limit") {
		t.Fatalf("iteration error = %v", err)
	}
	if limited.booleanRouting != nil {
		t.Fatal("loop activated routing")
	}
	module := Module{Name: "fail", Functions: map[string]ModuleFunction{"check": {
		Signatures: []ModuleSignature{{Arguments: []ModuleValueType{ModuleInteger}}}, ReturnType: ModuleBoolean,
		Evaluate: func(ModuleContext, []ModuleValue) (ModuleValue, error) {
			return ModuleValue{}, errors.New("routing module failure")
		},
	}}}
	failing, err := NewCompiler(WithModule(module)).CompileSource(`import "fail" ` + booleanRoutingSource() + `rule errorful { strings: $a="event" $b="absent" condition: $a and fail.check(0) and $b }`)
	if err != nil {
		t.Fatal(err)
	}
	failure := NewScanner(failing, WithBooleanRouting())
	defer failure.Close()
	if _, err := failure.Matches([]byte("event code00_SHARED_0123456789ABCDE")); err == nil || !strings.Contains(err.Error(), "routing module failure") {
		t.Fatalf("module error = %v", err)
	}
	if failure.booleanRouting != nil {
		t.Fatal("errorful portfolio activated routing")
	}
}

func TestBooleanRoutingPreparationAndConcurrentScanners(t *testing.T) {
	program := compileBooleanRouting(t, booleanRoutingSource())
	rebuilt := NewCompiledProgram(program.Rules)
	blob, err := program.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := UnmarshalCompiledProgram(blob)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		program *CompiledProgram
		active  bool
	}{{"constructor", rebuilt, true}, {"serialized", loaded, false}} {
		t.Run(test.name, func(t *testing.T) {
			scanner := NewScanner(test.program, WithBooleanRouting())
			defer scanner.Close()
			if matched, err := scanner.Matches([]byte("event code00_SHARED_0123456789ABCDE")); !matched || err != nil {
				t.Fatalf("Matches = %v,%v", matched, err)
			}
			if (scanner.booleanRouting != nil) != test.active {
				t.Fatalf("routing active = %v", scanner.booleanRouting != nil)
			}
		})
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			scanner := NewScanner(program, WithBooleanRouting())
			defer scanner.Close()
			for j := 0; j < 10; j++ {
				data := []byte(fmt.Sprintf("event code%02d_SHARED_0123456789ABCDE", i))
				if got, err := scanner.Matches(data); !got || err != nil {
					t.Errorf("concurrent positive = %v,%v", got, err)
					return
				}
				if got, err := scanner.Matches(nil); got || err != nil {
					t.Errorf("concurrent negative = %v,%v", got, err)
					return
				}
			}
		}(i)
	}
	wg.Wait()
}

func TestBooleanRoutingUnknownFallsBack(t *testing.T) {
	program := compileBooleanRouting(t, `rule expensive { strings: $a=/ANCHOR_LONG_0123456789[ab]{0,1024}[ab]{0,1024}Z/ condition: $a }`)
	scanner := NewScanner(program, WithBooleanRouting())
	defer scanner.Close()
	if scanner.booleanRouting == nil {
		t.Fatal("bounded regex did not activate routing")
	}
	data := append([]byte("ANCHOR_LONG_0123456789"), bytes.Repeat([]byte{'a'}, 900)...)
	for _, suffix := range []string{"", "Z", ""} {
		input := append(bytes.Clone(data), suffix...)
		if got := scanner.booleanRouting.Match(input); got != wordmatch.Unknown {
			t.Fatalf("suffix %q did not exhaust work: %v", suffix, got)
		}
		got, err := scanner.Matches(input)
		want, wantErr := program.Matches(input)
		if got != want || fmt.Sprint(err) != fmt.Sprint(wantErr) || got != (suffix == "Z") {
			t.Fatalf("suffix %q: (%v,%v) != (%v,%v)", suffix, got, err, want, wantErr)
		}
	}
}

func TestBooleanRoutingAnonymousAndUnusedPatterns(t *testing.T) {
	for _, source := range []string{
		`rule anonymous { strings: $="FIRST_LITERAL_0123456789" $="SECOND_LITERAL_0123456789" condition: all of them }`,
		`rule unused { strings: $a="FIRST_LITERAL_0123456789" $b="SECOND_LITERAL_0123456789" $unused=/a+b/ condition: $a and $b }`,
		`rule folded { strings: $a="FIRST_LITERAL_0123456789" nocase $b=/SECOND_LITERAL_[0-9]{10}/ condition: all of them }`,
	} {
		program := compileBooleanRouting(t, source)
		scanner := NewScanner(program, WithBooleanRouting())
		defer scanner.Close()
		if scanner.booleanRouting == nil {
			t.Fatalf("eligible portfolio declined: %s", source)
		}
		for _, input := range []string{"", "FIRST_LITERAL_0123456789", "FIRST_LITERAL_0123456789 SECOND_LITERAL_0123456789", "first_literal_0123456789 SECOND_LITERAL_0123456789"} {
			got, err := scanner.Matches([]byte(input))
			want, wantErr := program.Matches([]byte(input))
			if got != want || fmt.Sprint(err) != fmt.Sprint(wantErr) {
				t.Fatalf("%s, %q: (%v,%v) != (%v,%v)", source, input, got, err, want, wantErr)
			}
		}
	}
}
