package compiler

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const compactPrefilterPadding = `
rule padding0 { strings: $source="event" $rare="sentinel_0" condition: all of them }
rule padding1 { strings: $source="event" $rare="sentinel_1" condition: all of them }
rule padding2 { strings: $source="event" $rare="sentinel_2" condition: all of them }
rule padding3 { strings: $source="event" $rare="sentinel_3" condition: all of them }
rule padding4 { strings: $source="event" $rare="sentinel_4" condition: all of them }
rule padding5 { strings: $source="event" $rare="sentinel_5" condition: all of them }
`

const compactPrefilterRules = `
rule first { strings: $source="event" $rare="rare_one" fullword $value=/value=[0-9]{4}/ condition: $source and $rare }
rule second { strings: $source="event" $rare="rare_two" condition: all of them }
` + compactPrefilterPadding

//nolint:revive // parity inputs include scanner options
func compactPrefilterParity(t *testing.T, program *CompiledProgram, inputs [][]byte, extra ...ScannerOption) {
	t.Helper()
	for _, options := range [][]ScannerOption{nil, {WithFastScan()}, {WithReportedMatchesOnly()}} {
		options = append(options, extra...)
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
	for _, size := range []int{1024, 1025} {
		input := []byte(strings.Repeat(" ", size))
		copy(input, "event")
		if got := scanner.compactPrefilterRejects(context.Background(), input); got != (size == 1024) {
			t.Fatalf("rejection for %d bytes = %v", size, got)
		}
	}
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
	if got, err := scanner.MatchesWithContext(nil, []byte("event rare_two")); !got || err != nil { //nolint:staticcheck // verify supported nil contexts
		t.Fatalf("nil context = %v,%v", got, err)
	}
}

func TestCompactPrefilterEncodedLiterals(t *testing.T) {
	for _, modifier := range []string{"nocase ascii wide", "xor(1-2) ascii wide"} {
		t.Run(modifier, func(t *testing.T) {
			source := fmt.Sprintf(`rule a { strings: $source="event" $rare="rare_one" %s condition: all of them }
rule b { strings: $source="event" $rare="rare_two" %s condition: all of them }`, modifier, modifier) + compactPrefilterPadding
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
	for _, condition := range []string{"fail.check() and $a", "$a and fail.check() and $b"} {
		program, err := NewCompiler(WithModule(module)).CompileSource(`import "fail" ` + compactPrefilterRules + `rule unsafe { strings: $a="event" $b="unsafe" condition: ` + condition + ` }`)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := program.Matches([]byte("event")); err == nil {
			t.Fatal("compact gate suppressed condition error before absent rare literal")
		}
		compactPrefilterParity(t, program, [][]byte{[]byte("event"), []byte("event unsafe"), []byte("event rare_one")})
	}
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

func TestCompactPrefilterMixedCaseTransitions(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
rule a { strings: $common="A" nocase $rare="aX" condition: all of them }
rule b { strings: $common="A" nocase $rare="Ay" condition: all of them }
rule c { strings: $common="A" nocase $rare="az" nocase condition: all of them }` +
		strings.ReplaceAll(compactPrefilterPadding, `"event"`, `"A" nocase`))
	if err != nil {
		t.Fatal(err)
	}
	if program.compactPrefilter == nil {
		t.Fatal("mixed case-sensitive/nocase cover must reuse the original trie")
	}
	compactPrefilterParity(t, program, [][]byte{[]byte("Az"), []byte("aZ"), []byte("AZ"), []byte("az"), []byte("aX"), []byte("Ay")})
}

func TestCompactPrefilterSharedRegexCover(t *testing.T) {
	var source strings.Builder
	source.WriteString(compactPrefilterRules)
	for i := range 32 {
		fmt.Fprintf(&source, `rule regex_%d { strings: $a=/alias%02d=[0-9]{4}/ condition: $a }`, i, i)
	}
	source.WriteString(`rule alias_copy { strings: $a=/alias00=[0-9]{4}/ condition: $a }
rule alternate { strings: $a=/(phone|mobile)=[0-9]{4}/ condition: $a }`)
	program, err := NewCompiler().CompileSource(source.String())
	if err != nil {
		t.Fatal(err)
	}
	if program.compactPrefilter == nil {
		t.Fatal("shared regex fixture must activate compact gate")
	}
	for _, rule := range program.Rules[2:] {
		if !program.ruleHasCompleteSharedPrefilter(rule) {
			t.Fatalf("%s lacks shared atom coverage", rule.Name)
		}
	}
	matches, err := program.MatchingRules([]byte("alias00=1234"))
	if err != nil || len(matches) != 2 {
		t.Fatalf("alias fanout = %+v,%v", matches, err)
	}
	compactPrefilterParity(t, program, [][]byte{nil, []byte("event"), []byte("alias00=1234"), []byte("alias31=1234"), []byte("phone=1234"), []byte("mobile=1234"), []byte("alias00=12xx"), []byte("event rare_two"), nil})
}

func TestCompactPrefilterGlobalPrivateTags(t *testing.T) {
	source := strings.Replace(compactPrefilterRules, "rule first {", "rule first : wanted {", 1) + `
private global rule guard { strings: $a="permit" condition: $a }
private rule hidden { strings: $a="private" condition: $a }`
	program, err := NewCompiler().CompileSource(source)
	if err != nil {
		t.Fatal(err)
	}
	if program.compactPrefilter == nil {
		t.Fatal("global/private fixture must activate compact gate")
	}
	inputs := [][]byte{nil, []byte("event"), []byte("event rare_one"), []byte("permit event rare_one"), []byte("permit private"), []byte("permit event rare_two"), []byte("permit event rare_one rare_two private"), nil}
	compactPrefilterParity(t, program, inputs)
	compactPrefilterParity(t, program, inputs, WithTagsFilter([]string{"wanted"}))
}

func TestCompactPrefilterBase64(t *testing.T) {
	for _, modifier := range []string{"base64", "base64wide"} {
		source := fmt.Sprintf(`rule a { strings: $source="event" $rare="rare_one" %s condition: all of them }
rule b { strings: $source="event" $rare="rare_two" %s condition: all of them }`, modifier, modifier) + compactPrefilterPadding
		program, err := NewCompiler().CompileSource(source)
		if err != nil {
			t.Fatal(err)
		}
		if program.compactPrefilter == nil {
			t.Fatal("base64 fixture must activate compact gate")
		}
		inputs := [][]byte{nil, []byte("event"), []byte("event rare_one")}
		for _, text := range []string{"rare_one", "rare_two"} {
			for _, prefix := range []string{"", "x", "xy"} {
				encoded := base64.StdEncoding.EncodeToString([]byte(prefix + text + "zz"))
				data := []byte("event ")
				for _, b := range []byte(encoded) {
					data = append(data, b)
					if modifier == "base64wide" {
						data = append(data, 0)
					}
				}
				if got, err := program.Matches(data); !got || err != nil {
					t.Fatalf("%s alignment %d: %v,%v", modifier, len(prefix), got, err)
				}
				inputs = append(inputs, data)
			}
		}
		compactPrefilterParity(t, program, inputs)
	}
}

func TestCompactPrefilterAutomatonReplacement(t *testing.T) {
	program, err := NewCompiler().CompileSource(compactPrefilterRules)
	if err != nil {
		t.Fatal(err)
	}
	gate := program.compactPrefilter
	if gate == nil || gate.automaton != program.SharedAutomaton {
		t.Fatal("compact gate must retain the original shared automaton")
	}
	program.SetSharedAutomaton(nil)
	scanner := program.NewScanner()
	defer scanner.Close()
	if scanner.compactPrefilterRejects(context.Background(), []byte("event")) {
		t.Fatal("replaced shared automaton must bypass the compact gate")
	}
	compactPrefilterParity(t, program, [][]byte{[]byte("event"), []byte("event rare_one"), []byte("event rare_two"), nil})
}

func TestCompactPrefilterSmallFanout(t *testing.T) {
	for _, count := range []int{2, 4} {
		var source strings.Builder
		for i := range count {
			fmt.Fprintf(&source, `rule r%d { strings: $common="event" $rare="rare%d" condition: all of them }`, i, i)
		}
		program, err := NewCompiler().CompileSource(source.String())
		if err != nil {
			t.Fatal(err)
		}
		if program.compactPrefilter != nil {
			t.Fatalf("%d-way fanout must bypass the compact gate", count)
		}
		compactPrefilterParity(t, program, [][]byte{[]byte("event"), []byte("event rare0"), []byte("rare1"), nil})
	}
}
