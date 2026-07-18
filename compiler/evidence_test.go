package compiler

import (
	"bytes"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestCaptureReplayNestedRepeatedOptionalAndWholeMatch(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
rule capture_groups {
    strings:
        $value = /prefix:((ab|cd)+):([A-Z]+)?/ capture(whole = 0, sequence = 1, repeated = 2, optional = 3)
    condition:
        $value
}
`)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}
	rule, _ := program.GetRuleByName("capture_groups")
	if rule.FastScanSafe {
		t.Fatal("capture rule unexpectedly marked fast-scan safe")
	}
	scanner := program.NewScanner(WithEvidence(128), WithFastScan())
	defer scanner.Close()
	result, err := scanner.Scan([]byte("prefix:abcd:XYZ prefix:ab:"))
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	matches := result.Matches["capture_groups"]["$value"]
	if len(matches) != 2 {
		t.Fatalf("matches = %d, want 2", len(matches))
	}
	wantFirst := map[string]string{
		"whole": "prefix:abcd:XYZ", "sequence": "abcd", "repeated": "cd", "optional": "XYZ",
	}
	if got := captureDataByName(matches[0].Captures); !reflect.DeepEqual(got, wantFirst) {
		t.Fatalf("first captures = %#v, want %#v", got, wantFirst)
	}
	wantSecond := map[string]string{"whole": "prefix:ab:", "sequence": "ab", "repeated": "ab"}
	if got := captureDataByName(matches[1].Captures); !reflect.DeepEqual(got, wantSecond) {
		t.Fatalf("second captures = %#v, want %#v", got, wantSecond)
	}
}

func TestEvidenceCorrelationSameMatchNearestAmbiguousAndPartial(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
rule credentials {
    strings:
        $uri = /postgres:\/\/([^: ]+):([^@ ]+)@([^\/ ]+)/ capture(username = 1, secret = 2, endpoint = 3)
        $endpoint = /endpoint[ ]*=[ ]*([^ \n]+)/ capture(endpoint = 1)
        $username = /username[ ]*=[ ]*([^ \n]+)/ capture(username = 1)
        $secret = /secret[ ]*=[ ]*([^ \n]+)/ capture(secret = 1)
    evidence:
        credential = (endpoint, username, secret) within 64 of secret
    condition:
        any of them
}
`)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}

	t.Run("same outer match wins", func(t *testing.T) {
		result := scanEvidence(t, program, 128, "postgres://alice:hunter2@db.internal")
		finding := onlyFinding(t, result, "credentials", "credential")
		if finding.Status != EvidenceStatusReady {
			t.Fatalf("status = %q, want ready", finding.Status)
		}
		assertFieldData(t, finding, "endpoint", "db.internal")
		assertFieldData(t, finding, "username", "alice")
		assertFieldData(t, finding, "secret", "hunter2")
	})

	t.Run("nearest profiles stay separate", func(t *testing.T) {
		input := "endpoint = db-one\nusername = alice\nsecret = first\n" +
			strings.Repeat("#", 70) + "\nendpoint = db-two\nusername = bob\nsecret = second\n"
		result := scanEvidence(t, program, 128, input)
		findings := result.Evidence["credentials"]["credential"]
		if len(findings) != 2 {
			t.Fatalf("findings = %d, want 2", len(findings))
		}
		for index, want := range []struct{ endpoint, username, secret string }{
			{"db-one", "alice", "first"}, {"db-two", "bob", "second"},
		} {
			if findings[index].Status != EvidenceStatusReady {
				t.Fatalf("finding %d status = %q, want ready", index, findings[index].Status)
			}
			assertFieldData(t, findings[index], "endpoint", want.endpoint)
			assertFieldData(t, findings[index], "username", want.username)
			assertFieldData(t, findings[index], "secret", want.secret)
		}
	})

	t.Run("multiple candidates are retained", func(t *testing.T) {
		result := scanEvidence(t, program, 128, "username = alice\nusername = bob\nendpoint = db\nsecret = value")
		finding := onlyFinding(t, result, "credentials", "credential")
		if finding.Status != EvidenceStatusAmbiguous {
			t.Fatalf("status = %q, want ambiguous", finding.Status)
		}
		if got := len(finding.Fields["username"]); got != 2 {
			t.Fatalf("username candidates = %d, want 2", got)
		}
	})

	t.Run("missing and truncated fields are partial", func(t *testing.T) {
		missing := scanEvidence(t, program, 128, "endpoint = db\nsecret = value")
		if status := onlyFinding(t, missing, "credentials", "credential").Status; status != EvidenceStatusPartial {
			t.Fatalf("missing status = %q, want partial", status)
		}
		truncated := scanEvidence(t, program, 3, "endpoint = db\nusername = alice\nsecret = value")
		finding := onlyFinding(t, truncated, "credentials", "credential")
		if finding.Status != EvidenceStatusPartial {
			t.Fatalf("truncated status = %q, want partial", finding.Status)
		}
		if !finding.Fields["username"][0].DataTruncated || string(finding.Fields["username"][0].Data) != "ali" {
			t.Fatalf("truncated username = %#v", finding.Fields["username"][0])
		}
	})

	t.Run("excessive distance leaves field unassigned", func(t *testing.T) {
		input := "endpoint = too-far\n" + strings.Repeat("#", 80) + "\nusername = alice\nsecret = value"
		finding := onlyFinding(t, scanEvidence(t, program, 128, input), "credentials", "credential")
		if finding.Status != EvidenceStatusPartial || len(finding.Fields["endpoint"]) != 0 {
			t.Fatalf("finding = %#v, want partial without endpoint", finding)
		}
	})
}

func TestCaptureGroupZeroForTextAndHex(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
rule whole_matches {
    strings:
        $text = "secret" capture(text_value = 0)
        $hex = { 41 42 43 } capture(hex_value = 0)
    condition:
        all of them
}
`)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}
	result := scanEvidence(t, program, 16, "secret ABC")
	if got := string(result.Matches["whole_matches"]["$text"][0].Captures[0].Data); got != "secret" {
		t.Fatalf("text group zero = %q", got)
	}
	if got := string(result.Matches["whole_matches"]["$hex"][0].Captures[0].Data); got != "ABC" {
		t.Fatalf("hex group zero = %q", got)
	}
}

func TestEvidenceDisabledAndBlockScanner(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
rule token {
    strings:
        $token = /token=([A-Za-z0-9]+)/ capture(secret = 1)
    evidence:
        candidate = (secret) within 0 of secret
    condition:
        $token
}
`)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}
	disabled, err := program.Scan([]byte("token=abcdef"))
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if disabled.Evidence != nil || disabled.Matches["token"]["$token"][0].Captures != nil {
		t.Fatalf("disabled evidence unexpectedly populated: %#v", disabled)
	}
	readerScanner := program.NewScanner(WithEvidence(32))
	defer readerScanner.Close()
	readerResult, err := readerScanner.ScanReader(strings.NewReader("token=reader-value"))
	if err != nil {
		t.Fatalf("ScanReader() error = %v", err)
	}
	if got := string(onlyFinding(t, readerResult, "token", "candidate").Anchor.Data); got != "reader" {
		t.Fatalf("reader capture = %q, want reader", got)
	}

	blockScanner := program.NewBlockScanner(WithEvidence(32))
	defer blockScanner.Close()
	if err := blockScanner.Scan(4096, []byte("token=abcdef")); err != nil {
		t.Fatalf("BlockScanner.Scan() error = %v", err)
	}
	result, err := blockScanner.Finish()
	if err != nil {
		t.Fatalf("BlockScanner.Finish() error = %v", err)
	}
	finding := onlyFinding(t, result, "token", "candidate")
	if finding.Status != EvidenceStatusReady || finding.Anchor.Offset != 4102 || string(finding.Anchor.Data) != "abcdef" {
		t.Fatalf("block finding = %#v", finding)
	}
}

func TestEvidenceDoesNotExposeFilteredOrPrivateRules(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
global rule gate { condition: false }
rule filtered {
    strings:
        $token = /token=([A-Za-z0-9]+)/ capture(secret = 1)
    evidence:
        candidate = (secret) within 0 of secret
    condition:
        $token
}
private rule hidden {
    strings:
        $token = /token=([A-Za-z0-9]+)/ capture(secret = 1)
    evidence:
        candidate = (secret) within 0 of secret
    condition:
        $token
}
`)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}
	result := scanEvidence(t, program, 64, "token=sensitive")
	if result.Evidence != nil || len(result.MatchedRules) != 0 {
		t.Fatalf("filtered/private rule exposed evidence: %#v", result)
	}
	for _, rule := range []string{"filtered", "hidden"} {
		for _, match := range result.Matches[rule]["$token"] {
			if match.Captures != nil {
				t.Fatalf("%s retained captures after filtering: %#v", rule, match.Captures)
			}
		}
	}
}

func TestCaptureDeclarationPreservesOrdinaryRegexBytecode(t *testing.T) {
	plain, err := NewCompiler().CompileSource(`rule plain { strings: $a = /prefix:((ab|cd)+)/ condition: $a }`)
	if err != nil {
		t.Fatalf("plain CompileSource() error = %v", err)
	}
	captured, err := NewCompiler().CompileSource(`rule captured { strings: $a = /prefix:((ab|cd)+)/ capture(value = 1) condition: $a }`)
	if err != nil {
		t.Fatalf("captured CompileSource() error = %v", err)
	}
	plainRule, _ := plain.GetRuleByName("plain")
	capturedRule, _ := captured.GetRuleByName("captured")
	if !bytes.Equal(plainRule.RegexPatterns["$a"].Code, capturedRule.RegexPatterns["$a"].Code) {
		t.Fatal("capture declaration changed ordinary regex bytecode")
	}
	if len(plainRule.RegexPatterns["$a"].CaptureCode) != 0 || len(capturedRule.RegexPatterns["$a"].CaptureCode) == 0 {
		t.Fatal("tagged capture bytecode was not isolated to the capture-declared regex")
	}
	groupZero, err := NewCompiler().CompileSource(`rule zero { strings: $a = /(a)/ capture(value = 0) condition: $a }`)
	if err != nil {
		t.Fatalf("group-zero CompileSource() error = %v", err)
	}
	zeroRule, _ := groupZero.GetRuleByName("zero")
	if len(zeroRule.RegexPatterns["$a"].CaptureCode) != 0 {
		t.Fatal("group zero unnecessarily compiled tagged regex bytecode")
	}
}

func TestEvidenceSerializationRoundTrip(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
rule serialized_capture {
    strings:
        $pair = /user=([^ ]+) secret=([^ ]+)/ capture(username = 1, secret = 2)
    evidence:
        credential = (username, secret) within 32 of secret
    condition:
        $pair
}
`)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}
	blob, err := program.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	loaded, err := UnmarshalCompiledProgram(blob)
	if err != nil {
		t.Fatalf("UnmarshalCompiledProgram() error = %v", err)
	}
	result := scanEvidence(t, loaded, 64, "user=alice secret=hunter2")
	finding := onlyFinding(t, result, "serialized_capture", "credential")
	if finding.Status != EvidenceStatusReady {
		t.Fatalf("status = %q, want ready", finding.Status)
	}
	assertFieldData(t, finding, "username", "alice")
	assertFieldData(t, finding, "secret", "hunter2")
}

func TestStructuredSecretExampleAndRepresentativeFixture(t *testing.T) {
	program, err := NewCompiler().CompileFile("../examples/structured_secrets.yar")
	if err != nil {
		t.Fatalf("CompileFile(example) error = %v", err)
	}
	scanner := program.NewScanner(WithEvidence(8 * 1024))
	defer scanner.Close()
	result, err := scanner.ScanFile("testdata/evidence/representative.txt")
	if err != nil {
		t.Fatalf("ScanFile(fixture) error = %v", err)
	}
	for _, rule := range []string{
		"gcp_service_account_candidate",
		"tls_private_key_candidate",
		"aws_assignment_candidate",
		"database_uri_candidate",
		"freeform_token_candidate",
	} {
		if !result.RuleResults[rule] {
			t.Errorf("fixture did not match %s", rule)
		}
		if len(result.Evidence[rule]) == 0 {
			t.Errorf("fixture produced no evidence for %s", rule)
		}
	}
}

func TestCaptureSemanticValidation(t *testing.T) {
	tests := []struct {
		name, source, errorContains string
	}{
		{"out of range", `rule x { strings: $a = /(a)/ capture(value = 2) condition: $a }`, "out of range"},
		{"positive text group", `rule x { strings: $a = "a" capture(value = 1) condition: $a }`, "non-regex"},
		{"anonymous", `rule x { strings: $ = "a" capture(value = 0) condition: any of them }`, "anonymous"},
		{"private", `rule x { strings: $a = "a" private capture(value = 0) condition: $a }`, "private and capture"},
		{"duplicate binding", `rule x { strings: $a = /(a)/ capture(value = 0, value = 1) condition: $a }`, "parsing failed"},
		{"multiple modifiers", `rule x { strings: $a = /(a)/ capture(first = 0) capture(second = 1) condition: $a }`, "more than one capture"},
		{"undeclared field", `rule x { strings: $a = "a" capture(value = 0) evidence: e = (value, other) within 1 of value condition: $a }`, "undeclared capture"},
		{"duplicate field", `rule x { strings: $a = "a" capture(value = 0) evidence: e = (value, value) within 1 of value condition: $a }`, "repeats field"},
		{"anchor absent", `rule x { strings: $a = "a" capture(value = 0) evidence: e = (value) within 1 of other condition: $a }`, "not in its field list"},
		{"duplicate evidence", `rule x { strings: $a = "a" capture(value = 0) evidence: e = (value) within 1 of value e = (value) within 1 of value condition: $a }`, "duplicated"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewCompiler().CompileSource(test.source)
			if err == nil || !strings.Contains(err.Error(), test.errorContains) {
				t.Fatalf("CompileSource() error = %v, want %q", err, test.errorContains)
			}
		})
	}
}

func TestCaptureBindingLimit(t *testing.T) {
	var source strings.Builder
	source.WriteString(`rule too_many { strings: $a = /(a)/ capture(`)
	for index := range 33 {
		if index > 0 {
			source.WriteString(", ")
		}
		fmt.Fprintf(&source, "field%d = 1", index)
	}
	source.WriteString(`) condition: $a }`)
	_, err := NewCompiler().CompileSource(source.String())
	if err == nil || !strings.Contains(err.Error(), "maximum is 32") {
		t.Fatalf("CompileSource() error = %v, want binding limit", err)
	}
}

func TestCaptureReplayNocaseWideAnchorsBoundariesAndGreedy(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
rule replay_edges {
    strings:
        $anchored = /^token=([a-z]+)$/ nocase capture(anchored = 1)
        $bounded = /\bkey:([a-z]+)\b/ capture(bounded = 1)
        $greedy = /x(.+)x/ capture(greedy = 1)
		$wide = /wide:([a-z]+)/ nocase wide capture(wide_value = 1)
    condition:
        any of them
}
`)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}

	for _, test := range []struct {
		name, pattern string
		input         []byte
		want          []byte
	}{
		{"anchored nocase", "$anchored", []byte("TOKEN=Value"), []byte("Value")},
		{"word boundaries", "$bounded", []byte("a key:value!"), []byte("value")},
		{"greedy", "$greedy", []byte("xaxbxcx"), []byte("axbxc")},
		{"wide raw bytes", "$wide", wideBytes("WIDE:Value"), wideBytes("Value")},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := scanEvidence(t, program, 128, string(test.input))
			matches := result.Matches["replay_edges"][test.pattern]
			if len(matches) == 0 || len(matches[0].Captures) != 1 || !bytes.Equal(matches[0].Captures[0].Data, test.want) {
				t.Fatalf("captures = %#v, want %q", matches, test.want)
			}
		})
	}
}

func TestCorrelationTieRetainsCandidateAndIsOrderIndependent(t *testing.T) {
	plan := EvidencePlan{Name: "credential", Fields: []string{"username", "secret"}, Anchor: "secret", Within: 32}
	occurrences := []captureOccurrence{
		{capture: Capture{Name: "secret", Offset: 10, Length: 1, Data: []byte("a")}, parent: captureParent{pattern: "$a"}},
		{capture: Capture{Name: "username", Offset: 20, Length: 1, Data: []byte("u")}, parent: captureParent{pattern: "$u"}},
		{capture: Capture{Name: "secret", Offset: 30, Length: 1, Data: []byte("b")}, parent: captureParent{pattern: "$b"}},
	}
	forward := correlateEvidence([]EvidencePlan{plan}, occurrences)
	slices.Reverse(occurrences)
	sortCaptureOccurrences(occurrences)
	reversed := correlateEvidence([]EvidencePlan{plan}, occurrences)
	if !reflect.DeepEqual(forward, reversed) {
		t.Fatalf("correlation changed with input order\n forward: %#v\nreversed: %#v", forward, reversed)
	}
	findings := forward["credential"]
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(findings))
	}
	for index, finding := range findings {
		if finding.Status != EvidenceStatusAmbiguous || len(finding.Fields["username"]) != 1 {
			t.Fatalf("finding %d = %#v, want tied ambiguous username", index, finding)
		}
	}
}

func TestBlockScannerCaptureAcrossCallerOverlap(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
rule overlap {
    strings:
        $token = /token=([a-z]{6})/ capture(secret = 1)
    evidence:
        candidate = (secret) within 0 of secret
    condition:
        $token
}
`)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}
	scanner := program.NewBlockScanner(WithEvidence(32))
	defer scanner.Close()
	if err := scanner.Scan(0, []byte("xx token=abc")); err != nil {
		t.Fatalf("first Scan() error = %v", err)
	}
	if err := scanner.Scan(3, []byte("token=abcdef yy")); err != nil {
		t.Fatalf("overlap Scan() error = %v", err)
	}
	result, err := scanner.Finish()
	if err != nil {
		t.Fatalf("Finish() error = %v", err)
	}
	finding := onlyFinding(t, result, "overlap", "candidate")
	if finding.Anchor.Offset != 9 || string(finding.Anchor.Data) != "abcdef" {
		t.Fatalf("finding anchor = %#v", finding.Anchor)
	}
}

//nolint:revive // concise test helper
func scanEvidence(t *testing.T, program *CompiledProgram, cap int, input string) *ScanResult {
	t.Helper()
	scanner := program.NewScanner(WithEvidence(cap))
	defer scanner.Close()
	result, err := scanner.Scan([]byte(input))
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	return result
}

//nolint:revive // concise test helper
func onlyFinding(t *testing.T, result *ScanResult, rule, declaration string) EvidenceFinding {
	t.Helper()
	findings := result.Evidence[rule][declaration]
	if len(findings) != 1 {
		t.Fatalf("%s.%s findings = %d, want 1", rule, declaration, len(findings))
	}
	return findings[0]
}

//nolint:revive // concise test helper
func assertFieldData(t *testing.T, finding EvidenceFinding, field, want string) {
	t.Helper()
	candidates := finding.Fields[field]
	if len(candidates) != 1 || !bytes.Equal(candidates[0].Data, []byte(want)) {
		t.Fatalf("field %s = %#v, want %q", field, candidates, want)
	}
}

func captureDataByName(captures []Capture) map[string]string {
	result := make(map[string]string, len(captures))
	for _, capture := range captures {
		result[capture.Name] = string(capture.Data)
	}
	return result
}

func wideBytes(value string) []byte {
	result := make([]byte, 0, len(value)*2)
	for index := range len(value) {
		result = append(result, value[index], 0)
	}
	return result
}
