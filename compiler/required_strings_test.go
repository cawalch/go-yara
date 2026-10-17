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
		forbiddenGate := rule.forbiddenStrings
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
				rule.forbiddenStrings = nil
				scanner.prefilterDisabled = true
				want, err := scanner.Matches(data)
				scanner.prefilterDisabled = false
				rule.requiredStrings = gate
				rule.forbiddenStrings = forbiddenGate
				if err != nil || got != want {
					t.Fatalf("condition %s input %q: %v != %v error %v", condition, data, got, want, err)
				}
			}
		}
	}
}

func TestRequiredStringsWithNegatedClausesAndNonCapturingGroups(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
rule pg_cred {
	strings:
		$uri = /postgres(?:ql)?:\/\/([A-Za-z0-9_.-]+):([^@\s]{8,32})@([A-Za-z0-9.-]+)/ capture(user = 1, secret = 2, host = 3)
		$fp_local = "@localhost" nocase
		$fp_pass = ":password@" nocase
		$fp_redact = ":REDACTED@"
	evidence:
		cred = (user, secret, host) within 128 of secret
	condition:
		$uri and not any of ($fp_*)
}

rule token_cred {
	strings:
		$hdr = "Authorization"
		$tok = /gh[pousr]_[A-Za-z0-9]{36}/ capture(token = 0)
		$fp_redact = "REDACTED"
	evidence:
		cred = (token) within 0 of token
	condition:
		$hdr and $tok and not any of ($fp_*)
}

rule unprefiltered_raw_secret {
	strings:
		$ctx = "x-raw-secret"
		$raw = /[A-Za-z0-9\/+=]{40}/ capture(secret = 0)
		$fp_redact = "REDACTED"
	evidence:
		cred = (secret) within 0 of secret
	condition:
		$ctx and $raw and none of ($fp_*)
}
`)
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
	for _, candidate := range []*CompiledProgram{program, loaded} {
		if !reflect.DeepEqual(candidate.Rules[0].requiredStrings, []string{"$uri"}) {
			t.Fatalf("requiredStrings = %v, want [$uri]", candidate.Rules[0].requiredStrings)
		}
		if !reflect.DeepEqual(candidate.Rules[0].forbiddenStrings, []string{"$fp_local", "$fp_pass", "$fp_redact"}) {
			t.Fatalf("forbiddenStrings = %v, want [$fp_local $fp_pass $fp_redact]", candidate.Rules[0].forbiddenStrings)
		}
		if !reflect.DeepEqual(candidate.Rules[2].forbiddenStrings, []string{"$fp_redact"}) {
			t.Fatalf("rule[2] forbiddenStrings = %v, want [$fp_redact]", candidate.Rules[2].forbiddenStrings)
		}
	}

	scanner := loaded.NewScanner(WithEvidence(128), WithReportedMatchesOnly(), WithFastScan())
	defer scanner.Close()
	if len(scanner.alwaysEvaluateSharedRules) != 0 {
		t.Fatalf("alwaysEvaluateSharedRules = %v, want empty (unprefiltered regex gated by $ctx)", scanner.alwaysEvaluateSharedRules)
	}

	for _, benign := range []string{
		`{"Authorization":"REDACTED","stack":"internal/postgres/repo.go:42"}`,
		`{"dsn":"postgres://svc:password@localhost/db"}`,
		`{"x-raw-secret":"REDACTED","blob":"0123456789abcdefghijklmnopqrstuvwxyzABCD"}`,
	} {
		matches, scanErr := scanner.MatchingRules([]byte(benign))
		if scanErr != nil || len(matches) != 0 {
			t.Fatalf("MatchingRules(%q) = %+v, %v; want none", benign, matches, scanErr)
		}
	}

	// Default Scan() without WithReportedMatchesOnly() preserves partial non-text
	// matches even when a required sibling string ($ctx) is absent.
	fullReport, err := loaded.Scan([]byte(`{"blob":"0123456789abcdefghijklmnopqrstuvwxyzABCD"}`))
	if err != nil || fullReport.RuleResults["unprefiltered_raw_secret"] ||
		len(fullReport.Matches["unprefiltered_raw_secret"]["$raw"]) != 1 {
		t.Fatalf("default Scan() partial match = %+v, %v; want $raw recorded on non-matching rule", fullReport, err)
	}

	leaked := `{"Authorization":"REDACTED","dsn":"postgresql://svc_rw:K9mPv2xQr8Lz@pg.internal/prod"}`
	matches, err := scanner.MatchingRules([]byte(leaked))
	if err != nil || len(matches) != 1 || len(matches[0].Evidence["cred"]) != 1 ||
		matches[0].Evidence["cred"][0].Status != EvidenceStatusReady {
		t.Fatalf("MatchingRules(leaked) = %+v, %v; want ready evidence", matches, err)
	}
}
