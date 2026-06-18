package compiler

import "testing"

func TestAnonymousStringsAnyMatch(t *testing.T) {
	source := `
rule AnonymousAny {
	strings:
		$ = "foo"
		$ = "bar"
	condition:
		any of them
}`

	compiler := NewCompiler()
	program, err := compiler.CompileSource(source)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	rule := program.Rules[0]

	cases := []struct {
		name string
		data []byte
		want bool
	}{
		{name: "match_foo", data: []byte("zzz foo zzz"), want: true},
		{name: "match_bar", data: []byte("bar"), want: true},
		{name: "no_match", data: []byte("baz"), want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := evaluateRule(rule, program, tc.data)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if ok != tc.want {
				t.Fatalf("matched=%v, want %v", ok, tc.want)
			}
		})
	}
}

func TestAnonymousStringsAllOf(t *testing.T) {
	source := `
rule AnonymousAll {
	strings:
		$ = "foo"
		$ = "bar"
	condition:
		all of them
}`

	compiler := NewCompiler()
	program, err := compiler.CompileSource(source)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	rule := program.Rules[0]

	cases := []struct {
		name string
		data []byte
		want bool
	}{
		{name: "both", data: []byte("foo bar"), want: true},
		{name: "one", data: []byte("foo"), want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := evaluateRule(rule, program, tc.data)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if ok != tc.want {
				t.Fatalf("matched=%v, want %v", ok, tc.want)
			}
		})
	}
}

func TestAnonymousStringIdentifiersAssigned(t *testing.T) {
	source := `
rule AnonymousIds {
	strings:
		$ = "foo"
		$ = "bar"
		$named = "baz"
	condition:
		any of them
}`

	compiler := NewCompiler()
	program, err := compiler.CompileSource(source)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	rule := program.Rules[0]

	if len(rule.AnonymousStrings) != 2 {
		t.Fatalf("expected 2 anonymous strings, got %d", len(rule.AnonymousStrings))
	}
	for _, id := range rule.AnonymousStrings {
		if id == "$" {
			t.Fatalf("anonymous identifier should not be '$'")
		}
		if _, ok := rule.Strings[id]; !ok {
			t.Fatalf("anonymous identifier %q not present in compiled strings", id)
		}
	}
}
