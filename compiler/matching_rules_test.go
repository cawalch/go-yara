package compiler

import (
	"context"
	"fmt"
	"reflect"
	"testing"
)

const matchingRulesParitySource = `
global rule guard : selected {
    strings: $g = /guard[0-9]{2}/
    condition: $g
}

private rule helper : selected {
    strings: $h = "alpha"
    condition: $h
}

rule dependent : selected {
    meta:
        owner = "soc"
        priority = 7
    strings: $d = /fo(o|x)trot/
    condition: helper and $d
}

rule counted : selected {
    strings: $c = /beta[0-9]/
    condition: #c >= 2
}

rule positioned : selected {
    strings: $p = { 4d 5a [0-2] 50 45 }
    condition: $p at 0
}

rule folded_wide : selected {
    strings: $w = "Delta" nocase wide ascii
    condition: $w
}

rule negated : selected {
    strings: $n = "forbidden"
    condition: not $n
}

rule atomless : selected {
    strings: $a = /a*/
    condition: $a
}

rule unselected : other {
    strings: $u = /unselected[0-9]+/
    condition: $u
}
`

func TestScannerMatchingRulesMatchesScanResult(t *testing.T) {
	program, err := NewCompiler().CompileSource(matchingRulesParitySource)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := program.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := UnmarshalCompiledProgram(blob)
	if err != nil {
		t.Fatal(err)
	}

	corpus := [][]byte{
		[]byte("clean"),
		[]byte("guard42"),
		[]byte("guard42 alpha foxtrot"),
		[]byte("guard42 beta1 beta2"),
		[]byte("guard42 MZxxPE"),
		[]byte("guard42 DELTA"),
		append([]byte("guard42 "), []byte{'D', 0, 'e', 0, 'l', 0, 't', 0, 'a', 0}...),
		[]byte("guard42 unselected123"),
		[]byte("alpha foxtrot guard42"),
		[]byte("alpha foxtrot"),
		[]byte("clean"),
	}
	options := [][]ScannerOption{
		{WithFastScan()},
		{WithFastScan(), WithTagsFilter([]string{"selected"})},
		{WithFastScan(), WithMatchData(8), WithMatchContext(2, 3)},
	}
	for _, candidateProgram := range []*CompiledProgram{program, loaded} {
		for _, scannerOptions := range options {
			for _, disablePrefilter := range []bool{false, true} {
				compact := NewScanner(candidateProgram, scannerOptions...)
				compact.prefilterDisabled = disablePrefilter
				full := NewScanner(candidateProgram, scannerOptions...)
				for iteration := range 3 {
					for index, input := range corpus {
						got, gotErr := compact.MatchingRules(input)
						result, wantErr := full.Scan(input)
						if fmt.Sprint(gotErr) != fmt.Sprint(wantErr) {
							t.Fatalf(
								"prefilter=%v iteration %d input %d %q errors differ: compact=%v full=%v",
								disablePrefilter,
								iteration,
								index,
								input,
								gotErr,
								wantErr,
							)
						}
						if gotErr == nil && !matchingRulesEqual(got, result.MatchedRules) {
							t.Fatalf(
								"prefilter=%v iteration %d input %d %q:\ncompact=%#v\nfull=%#v",
								disablePrefilter,
								iteration,
								index,
								input,
								got,
								result.MatchedRules,
							)
						}
					}
				}
				compact.Close()
				full.Close()
			}
		}
	}
}

func TestScannerMatchingRulesPreservesEvidence(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
rule credential : selected {
    strings:
        $uri = /postgres:\/\/([^: ]+):([^@ ]+)@([^\/ ]+)/ capture(username = 1, secret = 2, endpoint = 3)
    evidence:
        login = (endpoint, username, secret) within 64 of secret
    condition:
        $uri
}
`)
	if err != nil {
		t.Fatal(err)
	}
	options := []ScannerOption{WithFastScan(), WithEvidence(128), WithMatchData(16), WithMatchContext(2, 2)}
	compact := NewScanner(program, options...)
	defer compact.Close()
	full := NewScanner(program, options...)
	defer full.Close()
	data := []byte("x postgres://alice:hunter2@db.internal y")

	got, err := compact.MatchingRules(data)
	if err != nil {
		t.Fatal(err)
	}
	want, err := full.Scan(data)
	if err != nil {
		t.Fatal(err)
	}
	if !matchingRulesEqual(got, want.MatchedRules) {
		t.Fatalf("compact=%#v\nfull=%#v", got, want.MatchedRules)
	}
}

func TestScannerMatchingRulesReturnsOwnedResults(t *testing.T) {
	program, err := NewCompiler().CompileSource(matchingRulesParitySource)
	if err != nil {
		t.Fatal(err)
	}
	scanner := NewScanner(program, WithFastScan(), WithMatchData(16))
	defer scanner.Close()
	data := []byte("guard42 alpha foxtrot")

	first, err := scanner.MatchingRules(data)
	if err != nil {
		t.Fatal(err)
	}
	dependent := matchingRuleByName(t, first, "dependent")
	dependent.Tags[0] = "mutated"
	dependent.Meta["owner"] = "mutated"
	dependent.Matches["$d"][0].MatchedData[0] = 'X'

	second, err := scanner.MatchingRules(data)
	if err != nil {
		t.Fatal(err)
	}
	dependent = matchingRuleByName(t, second, "dependent")
	if dependent.Tags[0] != "selected" || dependent.Meta["owner"] != "soc" ||
		string(dependent.Matches["$d"][0].MatchedData) != "foxtrot" {
		t.Fatalf("later result reused caller-owned state: %#v", dependent)
	}
}

func TestMatchingRulesContextAndNilProgram(t *testing.T) {
	var scanner *Scanner
	if got, err := scanner.MatchingRules(nil); err != nil || got != nil {
		t.Fatalf("nil scanner MatchingRules() = (%v, %v), want (nil, nil)", got, err)
	}
	if got, err := (*CompiledProgram)(nil).MatchingRules(nil); err != nil || got != nil {
		t.Fatalf("nil program MatchingRules() = (%v, %v), want (nil, nil)", got, err)
	}

	program, err := NewCompiler().CompileSource(`rule always { condition: true }`)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := program.MatchingRulesWithContext(ctx, nil); err != context.Canceled {
		t.Fatalf("MatchingRulesWithContext() error = %v, want context.Canceled", err)
	}
}

func TestScannerMatchingRulesCleanRejectHasNoAllocations(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
rule api_key {
    strings:
        $gate = "api_key"
        $value = /secret_[A-Z]{2}[0-9]{6}/
    condition:
        all of them
}
`)
	if err != nil {
		t.Fatal(err)
	}
	scanner := NewScanner(program, WithFastScan())
	defer scanner.Close()
	data := []byte(`{"level":"info","message":"request completed"}`)
	if matches, err := scanner.MatchingRules(data); err != nil || len(matches) != 0 {
		t.Fatalf("warm-up MatchingRules() = (%v, %v), want no matches", matches, err)
	}

	var scanErr error
	allocations := testing.AllocsPerRun(1000, func() {
		_, scanErr = scanner.MatchingRules(data)
	})
	if scanErr != nil {
		t.Fatalf("MatchingRules() error = %v", scanErr)
	}
	if allocations != 0 {
		t.Fatalf("clean reject allocations = %v, want 0", allocations)
	}
}

func FuzzScannerMatchingRulesParity(f *testing.F) {
	for _, seed := range [][]byte{
		nil,
		[]byte("clean"),
		[]byte("guard42"),
		[]byte("guard42 alpha foxtrot"),
		[]byte("guard42 beta1 beta2"),
		[]byte("MZxxPE"),
		{'D', 0, 'e', 0, 'l', 0, 't', 0, 'a', 0},
	} {
		f.Add(seed)
	}
	program, err := NewCompiler().CompileSource(matchingRulesParitySource)
	if err != nil {
		f.Fatal(err)
	}
	compact := NewScanner(program, WithFastScan())
	defer compact.Close()
	full := NewScanner(program, WithFastScan())
	full.prefilterDisabled = true
	defer full.Close()
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 64*1024 {
			return
		}
		got, gotErr := compact.MatchingRules(input)
		want, wantErr := full.Scan(input)
		if fmt.Sprint(gotErr) != fmt.Sprint(wantErr) {
			t.Fatalf("input %q errors differ: compact=%v full=%v", input, gotErr, wantErr)
		}
		if gotErr == nil && !matchingRulesEqual(got, want.MatchedRules) {
			t.Fatalf("input %q: compact=%#v full=%#v", input, got, want.MatchedRules)
		}
	})
}

func matchingRuleByName(t *testing.T, matches []RuleMatch, name string) *RuleMatch {
	t.Helper()
	for index := range matches {
		if matches[index].Rule == name {
			return &matches[index]
		}
	}
	t.Fatalf("rule %q absent from %#v", name, matches)
	return nil
}

func matchingRulesEqual(left, right []RuleMatch) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !reflect.DeepEqual(left[index], right[index]) {
			return false
		}
	}
	return true
}
