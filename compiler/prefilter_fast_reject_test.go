package compiler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
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

rule credential_field {
    strings:
        $credential = /"[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]":"(REDACTED|null)"/
    condition:
        $credential
}

rule date_of_birth_field {
    strings:
        $dob = /"(date_of_birth|birth_date|birthdate|dateOfBirth|birthday|dob)":"[0-9]{4}"/
    condition:
        $dob
}

rule date_of_birth_assignment {
    strings:
        $iso = /"(dob|date_of_birth|birth_date|birthdate|dateOfBirth|birthday|bday)":"(19|20)[0-9]{2}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])"/
        $us = /"(dob|date_of_birth|birth_date|birthdate|dateOfBirth|birthday|bday)":"(0[1-9]|1[0-2])\/(0[1-9]|[12][0-9]|3[01])\/(19|20)[0-9]{2}"/
    condition:
        any of them
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
		[]byte(`{"PASSWORD":"REDACTED"}`),
		[]byte(`{"PassWord":"null"}`),
		[]byte(`{"P4ssWord":"REDACTED"}`),
		[]byte(`{"date_of_birth":"1984"}`),
		[]byte(`{"dateOfBirth":"2001"}`),
		[]byte(`{"dob":"1999"}`),
		[]byte(`{"dob":"99"}`),
		[]byte(`{"dob":"1984-02-29"}`),
		[]byte(`{"birth_date":"02/29/1984"}`),
		[]byte(`{"birthday":"1984-13-40"}`),
		[]byte(`{"level":"INFO","msg":"ok","status":200}`),
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
		[]byte(`{"PASSWORD":"REDACTED"}`),
		[]byte(`{"PassWord":"null"}`),
		[]byte(`{"date_of_birth":"1984"}`),
		[]byte(`{"dateOfBirth":"2001"}`),
		[]byte(`{"dob":"1999"}`),
		[]byte(`{"dob":"1984-02-29"}`),
		[]byte(`{"birth_date":"02/29/1984"}`),
		[]byte(`{"level":"INFO","msg":"ok","status":200}`),
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

func TestScannerMatchesSparseCandidateParity(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
global rule guard : selected {
    strings: $g = /guard[0-9]{2}/
    condition: $g
}

private rule helper : selected {
    strings: $h = "alpha"
    condition: $h
}

rule dependent : selected {
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
	`)
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
		[]byte("clean"),
	}
	for _, candidateProgram := range []*CompiledProgram{program, loaded} {
		for _, options := range [][]ScannerOption{
			{WithFastScan()},
			{WithFastScan(), WithTagsFilter([]string{"selected"})},
		} {
			fast := NewScanner(candidateProgram, options...)
			full := NewScanner(candidateProgram, options...)
			full.prefilterDisabled = true
			for iteration := range 3 {
				for index, input := range corpus {
					got, gotErr := fast.Matches(input)
					want, wantErr := full.Matches(input)
					if fmt.Sprint(gotErr) != fmt.Sprint(wantErr) || got != want {
						t.Fatalf(
							"iteration %d input %d %q: sparse=(%v,%v), full=(%v,%v)",
							iteration,
							index,
							input,
							got,
							gotErr,
							want,
							wantErr,
						)
					}
				}
			}
			fast.Close()
			full.Close()
		}
	}
}

func FuzzScannerMatchesSparseCandidateParity(f *testing.F) {
	for _, seed := range [][]byte{
		nil,
		[]byte("clean"),
		[]byte("alpha"),
		[]byte("beta12"),
		[]byte("alpha beta12"),
		[]byte("MZxxPE"),
		{'D', 0, 'e', 0, 'l', 0, 't', 0, 'a', 0},
	} {
		f.Add(seed)
	}
	program, err := NewCompiler().CompileSource(`
private rule helper {
    strings: $h = "alpha"
    condition: $h
}
rule dependent {
    strings: $d = /beta[0-9]{2}/
    condition: helper and $d
}
rule counted {
    strings: $c = /charlie[0-9]/
    condition: #c >= 2
}
rule positioned {
    strings: $p = { 4d 5a [0-2] 50 45 }
    condition: $p at 0
}
rule folded_wide {
    strings: $w = "Delta" nocase wide ascii
    condition: $w
}
rule atomless {
    strings: $a = /x*/
    condition: $a
}
	`)
	if err != nil {
		f.Fatal(err)
	}
	fast := NewScanner(program, WithFastScan())
	defer fast.Close()
	full := NewScanner(program, WithFastScan())
	full.prefilterDisabled = true
	defer full.Close()
	f.Fuzz(func(t *testing.T, input []byte) {
		got, gotErr := fast.Matches(input)
		want, wantErr := full.Matches(input)
		if fmt.Sprint(gotErr) != fmt.Sprint(wantErr) || got != want {
			t.Fatalf("input %q: sparse=(%v,%v), full=(%v,%v)", input, got, gotErr, want, wantErr)
		}
	})
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
	var piiRuleset bytes.Buffer
	for index := range 22 {
		fmt.Fprintf(&piiRuleset, `
rule pii_marker_%02d {
    strings:
        $value = "pii_marker_%02d"
    condition:
        $value
}
`, index, index)
	}
	piiRuleset.WriteString(`
rule pii_dob_in_assignment {
    strings:
        $iso = /"(dob|date_of_birth|birth_date|birthdate|dateOfBirth|birthday|bday)":"(19|20)[0-9]{2}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])"/
        $us = /"(dob|date_of_birth|birth_date|birthdate|dateOfBirth|birthday|bday)":"(0[1-9]|1[0-2])\/(0[1-9]|[12][0-9]|3[01])\/(19|20)[0-9]{2}"/
    condition:
        any of them
}
`)

	type allocationTest struct {
		name   string
		source string
		data   []byte
	}
	tests := []allocationTest{
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
		{
			name: "six alternatives including dob",
			source: `
rule pii_dob_in_assignment {
    strings:
        $value = /"(date_of_birth|birth_date|birthdate|dateOfBirth|birthday|dob)":"[0-9]{4}"/
    condition:
        $value
}
`,
		},
		{
			name: "head alternatives with tail group",
			source: `
rule pii_dob_in_assignment {
    strings:
        $value = /"(dob|date_of_birth|birth_date)":"(19|20)[0-9]{2}"/
    condition:
        $value
}
`,
			data: []byte(`{"level":"INFO","msg":"ok","status":200}`),
		},
		{
			name:   "23-rule PII-shaped ruleset",
			source: piiRuleset.String(),
			data:   []byte(`{"level":"INFO","msg":"ok","status":200}`),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := test.data
			if data == nil {
				data = []byte(`{"level":"info","message":"request completed"}`)
			}
			assertScannerMatchesCleanRejectHasNoAllocations(t, test.source, data)
		})
	}
}

func TestScannerMatchesAlternationHeadTailMatrixHasNoAllocations(t *testing.T) {
	headAlternatives := []string{
		"dob",
		"date_of_birth",
		"birth_date",
		"birthdate",
		"dateOfBirth",
		"birthday",
		"bday",
	}
	tails := []string{
		`[0-9]{4}`,
		`(19|20)[0-9]{2}`,
		`(19|20)[0-9]{2}-(01|02)`,
		`(19|20)[0-9]{2}-(01|02)-(03|04)`,
	}
	for _, headCount := range []int{1, 2, 3, 4, 7} {
		for tailGroups, tail := range tails {
			t.Run(fmt.Sprintf("head %d tail groups %d", headCount, tailGroups), func(t *testing.T) {
				source := fmt.Sprintf(`
rule pii_dob_in_assignment {
    strings:
        $value = /"(%s)":"%s"/
    condition:
        $value
}
`, strings.Join(headAlternatives[:headCount], "|"), tail)
				assertScannerMatchesCleanRejectHasNoAllocations(
					t,
					source,
					[]byte(`{"level":"INFO","msg":"ok","status":200}`),
				)
			})
		}
	}
}

func assertScannerMatchesCleanRejectHasNoAllocations(t *testing.T, source string, data []byte) {
	t.Helper()
	program, err := NewCompiler().CompileSource(source)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}
	scanner := NewScanner(program)
	defer scanner.Close()
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

func TestScannerMatchesCaseClassSequenceCleanRejectHasNoAllocations(t *testing.T) {
	tests := []struct {
		name   string
		source string
	}{
		{
			name: "case-class rule",
			source: `
rule credential {
    strings:
        $value = /"[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]":"(REDACTED|null)"/
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

rule credential {
    strings:
        $value = /"[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]":"(REDACTED|null)"/
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
			data := []byte(`{"level":"INFO","msg":"ok","status":200}`)
			if matched, err := scanner.Matches(data); err != nil || matched {
				t.Fatalf("warm-up Matches() = (%v, %v), want (false, nil)", matched, err)
			}

			var scanErr error
			allocations := testing.AllocsPerRun(2000, func() {
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
