package compiler

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const compactPrefilterRules = `
rule first { strings: $source="event" $rare="rare_one" fullword $value=/value=[0-9]{4}/ condition: $source and $rare }
rule second { strings: $source="event" $rare="rare_two" condition: all of them }
`

func compactPrefilterParity(t *testing.T, program *CompiledProgram, inputs [][]byte) {
	t.Helper()
	for _, options := range [][]ScannerOption{nil, {WithFastScan()}, {WithReportedMatchesOnly()}} {
		fast, oracle := program.NewScanner(options...), program.NewScanner(options...)
		oracle.prefilterDisabled = true
		defer fast.Close()
		defer oracle.Close()
		for _, data := range inputs {
			got, err := fast.Matches(data)
			want, wantErr := oracle.Matches(data)
			if got != want || fmt.Sprint(err) != fmt.Sprint(wantErr) {
				t.Fatalf("Matches(%q): %v,%v != %v,%v", data, got, err, want, wantErr)
			}
			actual, err := fast.MatchingRules(data)
			expected, wantErr := oracle.MatchingRules(data)
			if !reflect.DeepEqual(actual, expected) || fmt.Sprint(err) != fmt.Sprint(wantErr) {
				t.Fatalf("MatchingRules(%q): %+v,%v != %+v,%v", data, actual, err, expected, wantErr)
			}
			block := MemoryBlock{Base: 4096, Data: data}
			actual, err = fast.MatchingRulesInBlock(block, 8192)
			expected, wantErr = oracle.MatchingRulesInBlock(block, 8192)
			if !reflect.DeepEqual(actual, expected) || fmt.Sprint(err) != fmt.Sprint(wantErr) {
				t.Fatalf("block(%q): %+v,%v != %+v,%v", data, actual, err, expected, wantErr)
			}
			assertPrefilterResultParity(t, prefilterParityScanners{fast: fast, full: oracle}, prefilterParityInput{data: data})
		}
	}
}

func TestCompactPrefilterRejectionAndReuse(t *testing.T) {
	program, err := NewCompiler().CompileSource(compactPrefilterRules)
	if err != nil {
		t.Fatal(err)
	}
	if program.compactPrefilter == nil {
		t.Fatal("missing compact gate for shared source and distinct required literals")
	}
	scanner := program.NewScanner()
	defer scanner.Close()
	data := []byte("event value=1234 event")
	if !scanner.compactPrefilterRejects(context.Background(), data) {
		t.Fatal("common source alone passed compact gate")
	}
	if got, err := scanner.Matches(data); got || err != nil {
		t.Fatalf("Matches = %v,%v", got, err)
	}
	if len(scanner.globalMatches) != 0 || len(scanner.nonTextCache.ready) != 0 || len(scanner.matchCtx.spans) != 0 || len(scanner.prefilterCandidates) != 0 {
		t.Fatal("raw rejection prepared spans or candidate/cache storage")
	}
	report, err := scanner.Scan(data)
	if err != nil || len(report.Matches["first"]["$source"]) != 2 || len(report.Matches["first"]["$value"]) != 1 {
		t.Fatalf("Scan lost unmatched-rule spans: %+v,%v", report, err)
	}
	compactPrefilterParity(t, program, [][]byte{data, []byte("event rare_one value=1234"), data, []byte("rare_one"), []byte("event xrare_onez"), []byte("event rare_two"), nil, []byte("event rare_one rare_two"), data})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := scanner.MatchesWithContext(ctx, data); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if got, err := scanner.MatchesWithContext(nil, []byte("event rare_two")); !got || err != nil {
		t.Fatalf("nil context = %v,%v", got, err)
	}
}

func TestCompactPrefilterEncodedLiterals(t *testing.T) {
	for _, modifier := range []string{"nocase ascii wide", "xor(1-2) ascii wide"} {
		t.Run(modifier, func(t *testing.T) {
			source := fmt.Sprintf(`rule a { strings: $source="event" $rare="rare_one" %s condition: all of them }
rule b { strings: $source="event" $rare="rare_two" %s condition: all of them }`, modifier, modifier)
			program, err := NewCompiler().CompileSource(source)
			if err != nil {
				t.Fatal(err)
			}
			if program.compactPrefilter == nil {
				t.Fatal("encoded literals disabled compact gate")
			}
			inputs := [][]byte{nil, []byte("event"), []byte("rare_one")}
			for _, text := range []string{"rare_one", "rare_two"} {
				for _, wide := range []bool{false, true} {
					for _, key := range []byte{0, 1, 2} {
						plain := strings.ToUpper(text)
						if strings.HasPrefix(modifier, "xor") {
							plain = text
						}
						var encoded []byte
						for _, b := range []byte(plain) {
							encoded = append(encoded, b^key)
							if wide {
								encoded = append(encoded, key)
							}
						}
						data := append([]byte("event "), encoded...)
						want := key == 0
						if strings.HasPrefix(modifier, "xor") {
							want = key != 0
						}
						if got, err := program.Matches(data); got != want || err != nil {
							t.Fatalf("wide=%v key=%d: %v,%v want %v", wide, key, got, err, want)
						}
						inputs = append(inputs, data)
					}
				}
			}
			compactPrefilterParity(t, program, inputs)
		})
	}
}

func TestCompactPrefilterFallbacks(t *testing.T) {
	for i, extra := range []string{
		`rule single { strings: $a="solo" condition: $a }`,
		`rule regex_one { strings: $a=/alias=[0-9]{4}/ condition: $a }
rule regex_two { strings: $a=/alias=[0-9]{4}/ condition: $a }
rule alternate { strings: $a=/(phone|mobile)=[0-9]{4}/ condition: $a }`,
		`rule optional { strings: $a="optional" condition: not $a }`,
		`rule unchecked { condition: filesize > 0 }`,
	} {
		program, err := NewCompiler().CompileSource(compactPrefilterRules + extra)
		if err != nil {
			t.Fatal(err)
		}
		if (program.compactPrefilter != nil) != (i == 0) {
			t.Fatalf("fallback %d has unexpected gate eligibility", i)
		}
		compactPrefilterParity(t, program, [][]byte{nil, []byte("event"), []byte("solo"), []byte("alias=1234"), []byte("phone=1234"), []byte("mobile=1234"), []byte("alias=12xx"), []byte("event rare_two"), []byte("clean"), nil})
	}
	module := Module{Name: "fail", Functions: map[string]ModuleFunction{"check": {
		Signatures: []ModuleSignature{{}}, ReturnType: ModuleBoolean,
		Evaluate: func(ModuleContext, []ModuleValue) (ModuleValue, error) {
			return ModuleValue{}, errors.New("module failure")
		},
	}}}
	program, err := NewCompiler(WithModule(module)).CompileSource(`import "fail" ` + compactPrefilterRules + `rule unsafe { strings: $a="unsafe" condition: fail.check() and $a }`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := program.Matches([]byte("clean")); err == nil {
		t.Fatal("compact gate suppressed condition error")
	}
	compactPrefilterParity(t, program, [][]byte{nil, []byte("clean"), []byte("unsafe"), []byte("event rare_one")})
}

func TestCompactPrefilterPreparation(t *testing.T) {
	program, err := NewCompiler().CompileSource(compactPrefilterRules)
	if err != nil {
		t.Fatal(err)
	}
	rebuilt := NewCompiledProgram(program.Rules)
	blob, err := program.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := UnmarshalCompiledProgram(blob)
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []*CompiledProgram{rebuilt, loaded} {
		if candidate.compactPrefilter == nil {
			t.Fatal("preparation lost compact gate")
		}
		compactPrefilterParity(t, candidate, [][]byte{[]byte("event"), []byte("event rare_one"), []byte("event rare_two"), nil})
	}
	for _, rule := range program.Rules {
		rule.requiredStrings = nil
	}
	blob, err = program.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := UnmarshalCompiledProgram(blob)
	if err != nil {
		t.Fatal(err)
	}
	if legacy.compactPrefilter != nil {
		t.Fatal("missing required-string metadata enabled selective gate")
	}
	compactPrefilterParity(t, legacy, [][]byte{[]byte("event"), []byte("event rare_one"), nil})
}
