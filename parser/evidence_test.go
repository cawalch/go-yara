package parser

import (
	"errors"
	"reflect"
	"testing"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/internal/lexer"
)

func TestParseCaptureModifierAndEvidenceSection(t *testing.T) {
	program := parseTestRule(t, `
rule structured_secret {
    strings:
        $pair = /user=([^ ]+) secret=([^ ]+)/ capture(username = 1, secret = 2)
        $whole = "token" capture(token_value = 0)
    evidence:
        credential = (username, secret) within 4KB of secret
    condition:
        any of them
}
`)
	rule := program.Rules[0]
	if len(rule.Strings) != 2 || len(rule.Evidence) != 1 {
		t.Fatalf("rule strings/evidence = %d/%d, want 2/1", len(rule.Strings), len(rule.Evidence))
	}
	bindings, ok := rule.Strings[0].Modifiers[0].Value.([]ast.CaptureBinding)
	wantBindings := []ast.CaptureBinding{{Name: "username", Group: 1}, {Name: "secret", Group: 2}}
	if !ok || !reflect.DeepEqual(bindings, wantBindings) {
		t.Fatalf("capture bindings = %#v, want %#v", rule.Strings[0].Modifiers[0].Value, wantBindings)
	}
	evidence := rule.Evidence[0]
	if evidence.Name != "credential" || !reflect.DeepEqual(evidence.Fields, []string{"username", "secret"}) ||
		evidence.Anchor != "secret" || evidence.Within != 4*1024 {
		t.Fatalf("evidence declaration = %#v", evidence)
	}
}

func TestEvidenceSectionErrorRecoveryKeepsFollowingRule(t *testing.T) {
	l := lexer.New(`
rule broken {
    strings:
        $a = "a" capture(value = 0)
    evidence:
        credential = (value) near 10 of value
    condition:
        $a
}
rule healthy { condition: true }
`)
	p := New(l)
	p.SetErrorRecovery(true)
	p.SetSkipInvalidRules(true)
	program, err := p.ParseRules()
	if err == nil {
		t.Fatal("ParseRules() error = nil, want recovered evidence error")
	}
	var partial *PartialParseError
	if !errors.As(err, &partial) {
		t.Fatalf("ParseRules() error = %T, want PartialParseError", err)
	}
	if program == nil {
		program = partial.Program
	}
	if program == nil || len(program.Rules) != 1 || program.Rules[0].Name != "healthy" {
		t.Fatalf("recovered rules = %#v, want healthy", program)
	}
	if invalid := p.InvalidRules(); len(invalid) != 1 || invalid[0].Rule == nil || invalid[0].Rule.Name != "broken" {
		t.Fatalf("invalid rules = %#v, want broken", invalid)
	}
}

func TestCaptureGrammarErrors(t *testing.T) {
	for _, source := range []string{
		`rule x { strings: $a = /(a)/ capture() condition: $a }`,
		`rule x { strings: $a = /(a)/ capture(value) condition: $a }`,
		`rule x { strings: $a = /(a)/ capture(value = -1) condition: $a }`,
		`rule x { strings: $a = /(a)/ capture(value = 1,) condition: $a }`,
		`rule x { strings: $a = /(a)/ capture(value = 1 condition: $a }`,
		`rule x { strings: $a = /(a)/ capture(value = 1) evidence: e = () within 1 of value condition: $a }`,
		`rule x { strings: $a = /(a)/ capture(value = 1) evidence: e = (value) within nope of value condition: $a }`,
	} {
		l := lexer.New(source)
		p := New(l)
		if _, err := p.ParseRules(); err == nil && len(p.Errors()) == 0 {
			t.Fatalf("invalid source parsed without errors: %s", source)
		}
	}
}
