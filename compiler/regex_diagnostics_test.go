package compiler

import (
	"strings"
	"testing"
)

func TestRegexMalformedPatternsRejected(t *testing.T) {
	tests := []struct {
		name      string
		pattern   string
		wantError string
	}{
		{
			name:      "reversed character class range",
			pattern:   `[z-a]`,
			wantError: "bad character range",
		},
		{
			name:      "reversed digit class range",
			pattern:   `[9-0]`,
			wantError: "bad character range",
		},
		{
			name:      "stacked star quantifier",
			pattern:   `x**`,
			wantError: "syntax error",
		},
		{
			name:      "stacked plus-star quantifier",
			pattern:   `x+*`,
			wantError: "syntax error",
		},
		{
			name:      "stacked star-plus quantifier",
			pattern:   `x*+`,
			wantError: "syntax error",
		},
		{
			name:      "stacked plus quantifier",
			pattern:   `x++`,
			wantError: "syntax error",
		},
		{
			name:      "stacked repeat interval",
			pattern:   `x{2}{3}`,
			wantError: "syntax error",
		},
		{
			name:      "inverted repeat interval bounds",
			pattern:   `a{3,2}`,
			wantError: "bad repeat interval",
		},
		{
			name:      "inverted large repeat interval bounds",
			pattern:   `a{10,2}`,
			wantError: "bad repeat interval",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := `rule r { strings: $s = /` + tt.pattern + `/ condition: $s }`
			_, err := NewCompiler().CompileSource(src)
			if err == nil {
				t.Fatalf("CompileSource() for /%s/ succeeded, want error containing %q", tt.pattern, tt.wantError)
			}
			if !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("CompileSource() for /%s/ error = %v, want substring %q", tt.pattern, err, tt.wantError)
			}
		})
	}
}

func TestRegexUnsupportedConstructDiagnostics(t *testing.T) {
	tests := []struct {
		name      string
		pattern   string
		wantError string
	}{
		{
			name:      "trailing empty alternation branch in group",
			pattern:   `(foo|)`,
			wantError: "unsupported regex construct: empty alternation branch",
		},
		{
			name:      "leading empty alternation branch in group",
			pattern:   `(|foo)`,
			wantError: "unsupported regex construct: empty alternation branch",
		},
		{
			name:      "trailing empty alternation branch",
			pattern:   `foo|`,
			wantError: "unsupported regex construct: empty alternation branch",
		},
		{
			name:      "leading empty alternation branch",
			pattern:   `|foo`,
			wantError: "unsupported regex construct: empty alternation branch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := `rule r { strings: $s = /` + tt.pattern + `/ condition: $s }`
			_, err := NewCompiler().CompileSource(src)
			if err == nil {
				t.Fatalf("CompileSource() for /%s/ succeeded, want error containing %q", tt.pattern, tt.wantError)
			}
			errMsg := err.Error()
			if !strings.Contains(errMsg, tt.wantError) {
				t.Fatalf("CompileSource() for /%s/ error = %v, want substring %q", tt.pattern, err, tt.wantError)
			}
			// Must include rule and string context
			if !strings.Contains(errMsg, "compiling rule r") || !strings.Contains(errMsg, "compiling string $s") {
				t.Fatalf("CompileSource() error missing rule/string context: %v", err)
			}
			// Must NOT leak raw AST node kind
			if strings.Contains(errMsg, "node kind") {
				t.Fatalf("CompileSource() leaked internal node kind: %v", err)
			}
		})
	}
}

func TestRegexOmittedLowerBoundCompilationAndMatching(t *testing.T) {
	// 1. Both explicit {0,3} and shorthand {,3} compile cleanly
	srcExplicit := `rule explicit { strings: $s = /a{0,3}/ condition: $s }`
	progExplicit, err := NewCompiler().CompileSource(srcExplicit)
	if err != nil {
		t.Fatalf("CompileSource(explicit) error = %v", err)
	}

	srcShorthand := `rule shorthand { strings: $s = /a{,3}/ condition: $s }`
	progShorthand, err := NewCompiler().CompileSource(srcShorthand)
	if err != nil {
		t.Fatalf("CompileSource(shorthand) error = %v", err)
	}

	// 2. Both produce identical matches across test inputs
	inputs := [][]byte{
		[]byte("aaa"),
		[]byte("aa"),
		[]byte("a"),
		[]byte("baaac"),
		[]byte("xyz"),
	}

	for _, in := range inputs {
		resExp, errExp := progExplicit.Scan(in)
		if errExp != nil {
			t.Fatalf("Scan(explicit) on %q error: %v", in, errExp)
		}
		resShort, errShort := progShorthand.Scan(in)
		if errShort != nil {
			t.Fatalf("Scan(shorthand) on %q error: %v", in, errShort)
		}

		matchesExp := len(resExp.MatchedRules)
		matchesShort := len(resShort.MatchedRules)
		if matchesExp != matchesShort {
			t.Fatalf("input %q: explicit matched %d rules, shorthand matched %d rules", in, matchesExp, matchesShort)
		}
	}

	// 3. Various spellings with whitespace and bounds compile cleanly
	validSources := []string{
		`rule r1 { strings: $s = /a{,5}/ condition: $s }`,
		`rule r2 { strings: $s = /a{ , 5 }/ condition: $s }`,
		`rule r3 { strings: $s = /a{ 3 , 8 }/ condition: $s }`,
		`rule r4 { strings: $s = /a{ 2 , }/ condition: $s }`,
		`rule r5 { strings: $s = /a{ , }/ condition: $s }`,
		`rule r6 { strings: $s = /a{,3}?/ condition: $s }`,
	}
	for _, src := range validSources {
		if _, err := NewCompiler().CompileSource(src); err != nil {
			t.Fatalf("CompileSource(%q) unexpected error: %v", src, err)
		}
	}
}
