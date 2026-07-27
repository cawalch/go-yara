package compiler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"
)

const prefilterParityRules = `
rule direct {
    strings:
        $a = "alpha"
    condition:
        $a
}

rule counted {
    strings:
        $b = "beta"
    condition:
        #b >= 2
}

rule combined {
    strings:
        $c = /charlie[0-9]+/
        $d = { 44 45 4c 54 41 }
    condition:
        any of them and filesize > 8
}

rule negated {
    strings:
        $e = "echo"
    condition:
        not $e
}

rule dependency {
    strings:
        $f = "foxtrot"
    condition:
        direct and $f
}

rule contact_field {
    strings:
        $contact = /"(phone|phone_number|mobile)":"[0-9]{7}"/
    condition:
        $contact
}

private rule hidden {
    strings:
        $g = "golf"
    condition:
        $g
}
`

func TestPrefilterFastRejectResultParity(t *testing.T) {
	program, err := NewCompiler().CompileSource(prefilterParityRules)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}

	corpus := [][]byte{
		nil,
		[]byte(`{"message":"clean"}`),
		[]byte("alpha"),
		[]byte("beta beta"),
		[]byte("charlie42"),
		[]byte("DELTA"),
		[]byte("alpha foxtrot"),
		[]byte(`{"phone":"1234567"}`),
		[]byte(`{"phone":"1234567","mobile":"7654321"}`),
		[]byte(`{"mobile":"7654321","phone":"1234567"}`),
		[]byte("echo"),
		[]byte("golf"),
		[]byte("alpha beta beta charlie7 DELTA echo foxtrot golf"),
	}
	modes := []struct {
		name    string
		options []ScannerOption
	}{
		{name: "default"},
		{name: "reported matches only", options: []ScannerOption{WithReportedMatchesOnly()}},
	}
	for _, mode := range modes {
		t.Run(mode.name, func(t *testing.T) {
			fast := NewScanner(program, mode.options...)
			defer fast.Close()
			full := NewScanner(program, mode.options...)
			full.prefilterDisabled = true
			defer full.Close()
			for index, data := range corpus {
				assertPrefilterResultParity(
					t,
					prefilterParityScanners{fast: fast, full: full},
					prefilterParityInput{name: fmt.Sprintf("corpus[%d]", index), data: data},
				)
			}
		})
	}
}

func TestScanGlobalPrefilterRejectResultParity(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
rule direct {
    strings:
        $a = "alpha"
    condition:
        $a
}

rule fixed_offset {
    strings:
        $mz = "MZ"
    condition:
        $mz at 0
}
`)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}
	for _, options := range [][]ScannerOption{
		nil,
		{WithReportedMatchesOnly()},
	} {
		fast := NewScanner(program, options...)
		full := NewScanner(program, options...)
		full.prefilterDisabled = true
		assertPrefilterResultParity(
			t,
			prefilterParityScanners{fast: fast, full: full},
			prefilterParityInput{name: "global reject", data: []byte("clean")},
		)
		fast.Close()
		full.Close()
	}
}

func FuzzPrefilterFastRejectResultParity(f *testing.F) {
	for _, seed := range [][]byte{
		nil,
		[]byte("clean"),
		[]byte("alpha beta"),
		[]byte("charlie42 DELTA"),
		[]byte("alpha foxtrot golf"),
		[]byte(`{"phone":"1234567","mobile":"7654321"}`),
	} {
		f.Add(seed)
	}

	program, err := NewCompiler().CompileSource(prefilterParityRules)
	if err != nil {
		f.Fatalf("CompileSource() error = %v", err)
	}
	fast := NewScanner(program)
	defer fast.Close()
	full := NewScanner(program)
	full.prefilterDisabled = true
	defer full.Close()

	f.Fuzz(func(t *testing.T, data []byte) {
		assertPrefilterResultParity(
			t,
			prefilterParityScanners{fast: fast, full: full},
			prefilterParityInput{name: "fuzz input", data: data},
		)
	})
}

type prefilterParityScanners struct {
	fast *Scanner
	full *Scanner
}

type prefilterParityInput struct {
	name string
	data []byte
}

func assertPrefilterResultParity(
	t testing.TB,
	scanners prefilterParityScanners,
	input prefilterParityInput,
) {
	t.Helper()
	fastResult, fastErr := scanners.fast.Scan(input.data)
	fullResult, fullErr := scanners.full.Scan(input.data)
	if fmt.Sprint(fastErr) != fmt.Sprint(fullErr) {
		t.Fatalf("%s errors differ: fast=%v full=%v", input.name, fastErr, fullErr)
	}
	if fastErr != nil {
		return
	}
	fastJSON, err := json.Marshal(fastResult)
	if err != nil {
		t.Fatalf("%s fast result marshal error = %v", input.name, err)
	}
	fullJSON, err := json.Marshal(fullResult)
	if err != nil {
		t.Fatalf("%s full result marshal error = %v", input.name, err)
	}
	if !bytes.Equal(fastJSON, fullJSON) {
		t.Fatalf("%s result mismatch\n fast: %s\n full: %s", input.name, fastJSON, fullJSON)
	}
}

func TestScannerMatchesMatchesScanResult(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
global rule guard {
    strings:
        $g = "guard"
    condition:
        $g
}

rule public {
    strings:
        $a = "public"
    condition:
        $a
}

private rule hidden {
    strings:
        $h = "hidden"
    condition:
        $h
}
`)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}
	scanner := NewScanner(program)
	defer scanner.Close()

	for _, data := range [][]byte{
		[]byte("clean"),
		[]byte("guard"),
		[]byte("guard public"),
		[]byte("public"),
		[]byte("guard hidden"),
	} {
		result, err := scanner.Scan(data)
		if err != nil {
			t.Fatalf("Scan(%q) error = %v", data, err)
		}
		got, err := scanner.Matches(data)
		if err != nil {
			t.Fatalf("Matches(%q) error = %v", data, err)
		}
		want := len(result.MatchedRules) != 0
		if got != want {
			t.Fatalf("Matches(%q) = %v, want %v from Scan", data, got, want)
		}
	}
}

func TestScannerMatchesCleanRejectHasNoAllocations(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
rule api_key {
    strings:
        $gate = "api_key"
        $value = "secret_value"
    condition:
        all of them
}
`)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}
	scanner := NewScanner(program)
	defer scanner.Close()
	data := []byte(`{"level":"info","message":"request completed"}`)
	if matched, err := scanner.Matches(data); err != nil || matched {
		t.Fatalf("warm-up Matches() = (%v, %v), want (false, nil)", matched, err)
	}

	var scanErr error
	allocations := testing.AllocsPerRun(1000, func() {
		_, scanErr = scanner.Matches(data)
	})
	if scanErr != nil {
		t.Fatalf("Matches() error = %v", scanErr)
	}
	if allocations != 0 {
		t.Fatalf("clean reject allocations = %v, want 0", allocations)
	}
}

func TestScannerMatchesLeadingAlternationCleanRejectHasNoAllocations(t *testing.T) {
	tests := []struct {
		name   string
		source string
	}{
		{
			name: "alternation rule",
			source: `
rule contact {
    strings:
        $value = /"(phone|phone_number|mobile)":"[0-9]{7}"/
    condition:
        $value
}
`,
		},
		{
			name: "mixed ruleset",
			source: `
rule api_key {
    strings:
        $value = "api_key"
    condition:
        $value
}

rule contact {
    strings:
        $value = /"(phone|phone_number|mobile)":"[0-9]{7}"/
    condition:
        $value
}
`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			program, err := NewCompiler().CompileSource(test.source)
			if err != nil {
				t.Fatalf("CompileSource() error = %v", err)
			}
			scanner := NewScanner(program)
			defer scanner.Close()
			data := []byte(`{"level":"info","message":"request completed"}`)
			if matched, err := scanner.Matches(data); err != nil || matched {
				t.Fatalf("warm-up Matches() = (%v, %v), want (false, nil)", matched, err)
			}

			var scanErr error
			allocations := testing.AllocsPerRun(1000, func() {
				_, scanErr = scanner.Matches(data)
			})
			if scanErr != nil {
				t.Fatalf("Matches() error = %v", scanErr)
			}
			if allocations != 0 {
				t.Fatalf("clean reject allocations = %v, want 0", allocations)
			}
		})
	}
}

func TestScannerMatchesDoesNotRejectUnprefilteredRegex(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
rule literal_gate {
    strings:
        $gate = "unseen_literal"
    condition:
        $gate
}

rule atomless_regex {
    strings:
        $empty = /a*/
    condition:
        $empty
}
`)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}
	scanner := NewScanner(program)
	defer scanner.Close()
	matched, err := scanner.Matches([]byte("clean"))
	if err != nil {
		t.Fatalf("Matches() error = %v", err)
	}
	if !matched {
		t.Fatal("Matches() rejected an atomless regex that matches the input")
	}
}

func TestBlockScannerPrefilterResultParity(t *testing.T) {
	program, err := NewCompiler().CompileSource(prefilterParityRules)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}
	fast := NewBlockScanner(program, WithReportedMatchesOnly())
	defer fast.Close()
	full := NewBlockScanner(program, WithReportedMatchesOnly())
	full.scanner.prefilterDisabled = true
	defer full.Close()

	blocks := []MemoryBlock{
		{Base: 0, Data: []byte("alpha beta")},
		{Base: 100, Data: []byte("beta charlie42 DELTA foxtrot")},
	}
	for _, block := range blocks {
		if err := fast.Scan(block.Base, block.Data); err != nil {
			t.Fatalf("fast Scan() error = %v", err)
		}
		if err := full.Scan(block.Base, block.Data); err != nil {
			t.Fatalf("full Scan() error = %v", err)
		}
	}
	fastResult, err := fast.Finish()
	if err != nil {
		t.Fatalf("fast Finish() error = %v", err)
	}
	fullResult, err := full.Finish()
	if err != nil {
		t.Fatalf("full Finish() error = %v", err)
	}
	fastJSON, err := json.Marshal(fastResult)
	if err != nil {
		t.Fatalf("fast result marshal error = %v", err)
	}
	fullJSON, err := json.Marshal(fullResult)
	if err != nil {
		t.Fatalf("full result marshal error = %v", err)
	}
	if !bytes.Equal(fastJSON, fullJSON) {
		t.Fatalf("block result mismatch\n fast: %s\n full: %s", fastJSON, fullJSON)
	}
}
