package parser

import (
	"errors"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/token"
)

func TestStrictParseErrorPreservesDetailsAndPositions(t *testing.T) {
	t.Run("trailing_and_before_rbrace", func(t *testing.T) {
		const src = `rule broken {
    strings:
        $a = "x"
    condition:
        $a and
}`
		p := New(lexer.New(src))
		prog, err := p.ParseRulesWithContext(t.Context())
		if prog != nil || err == nil {
			t.Fatalf("ParseRulesWithContext() = (%v, %v), want nil program and error", prog, err)
		}

		parseErr, ok := errors.AsType[*ParseError](err)
		if !ok {
			t.Fatalf("error type = %T, want *ParseError", err)
		}
		if len(parseErr.Errors) != 1 {
			t.Fatalf("len(parseErr.Errors) = %d, want 1 (%v)", len(parseErr.Errors), parseErr.Errors)
		}

		synErr, ok := errors.AsType[*SyntaxError](parseErr.Errors[0])
		if !ok {
			t.Fatalf("inner error type = %T, want *SyntaxError", parseErr.Errors[0])
		}
		if synErr.Rule != "broken" {
			t.Errorf("Rule = %q, want %q", synErr.Rule, "broken")
		}
		if synErr.Position.Line != 6 || synErr.Position.Column != 1 {
			t.Errorf("Position = %d:%d, want 6:1", synErr.Position.Line, synErr.Position.Column)
		}
		msg := err.Error()
		for _, want := range []string{`rule "broken"`, "line 6, column 1", "unexpected '}'"} {
			if !strings.Contains(msg, want) {
				t.Errorf("err.Error() = %q, want substring %q", msg, want)
			}
		}
		if strings.Contains(msg, "RBRACE") || strings.Contains(msg, "{ 74 6 1}") {
			t.Errorf("err.Error() exposed raw internal token details: %q", msg)
		}
	})

	t.Run("multiple_errors_across_rules_and_top_level", func(t *testing.T) {
		const src = `bogus
rule first_bad {
    condition:
        true and
}
rule second_bad {
    strings:
        $s = 123
    condition:
        $s
}`
		p := New(lexer.New(src))
		_, err := p.ParseRulesWithContext(t.Context())
		if err == nil {
			t.Fatal("expected parse error")
		}
		parseErr, ok := errors.AsType[*ParseError](err)
		if !ok {
			t.Fatalf("error type = %T, want *ParseError", err)
		}
		if len(parseErr.Errors) < 2 {
			t.Fatalf("expected multiple collected errors, got %d (%v)", len(parseErr.Errors), parseErr.Errors)
		}
		firstSyn, ok := errors.AsType[*SyntaxError](parseErr.Errors[0])
		if !ok {
			t.Fatalf("first error = %T, want *SyntaxError", parseErr.Errors[0])
		}
		if firstSyn.Position.Line != 1 || firstSyn.Position.Column != 1 {
			t.Errorf("first position = %d:%d, want 1:1", firstSyn.Position.Line, firstSyn.Position.Column)
		}
		if !strings.Contains(firstSyn.Message, `identifier "bogus"`) {
			t.Errorf("first message = %q, want identifier description", firstSyn.Message)
		}
	})

	t.Run("various_syntax_positions", func(t *testing.T) {
		cases := []struct {
			name     string
			src      string
			wantRule string
			wantLine int
			wantSub  string
		}{
			{
				name: "missing_opening_brace",
				src: `rule no_brace
    condition: true
}`,
				wantRule: "no_brace",
				wantLine: 2,
				wantSub:  "expected '{'",
			},
			{
				name: "missing_condition_colon",
				src: `rule no_colon {
    condition
        true
}`,
				wantRule: "no_colon",
				wantLine: 3,
				wantSub:  "expected ':'",
			},
			{
				name: "missing_closing_brace_at_eof",
				src: `rule unclosed {
    condition:
        true`,
				wantRule: "unclosed",
				wantLine: 3,
				wantSub:  "end of file",
			},
			{
				name:     "import_non_string",
				src:      `import pe`,
				wantLine: 1,
				wantSub:  "expected string literal after 'import'",
			},
			{
				name: "string_missing_literal",
				src: `rule bad_str {
    strings:
        $a = )
    condition:
        $a
}`,
				wantRule: "bad_str",
				wantLine: 3,
				wantSub:  "got ')'",
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				p := New(lexer.New(tc.src))
				_, err := p.ParseRulesWithContext(t.Context())
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				synErr, ok := errors.AsType[*SyntaxError](err)
				if !ok {
					t.Fatalf("error = %v (%T), want unwrap *SyntaxError", err, err)
				}
				if synErr.Rule != tc.wantRule {
					t.Errorf("Rule = %q, want %q", synErr.Rule, tc.wantRule)
				}
				if synErr.Position.Line != tc.wantLine {
					t.Errorf("Line = %d, want %d (err=%v)", synErr.Position.Line, tc.wantLine, err)
				}
				if !strings.Contains(err.Error(), tc.wantSub) {
					t.Errorf("err.Error() = %q, want substring %q", err.Error(), tc.wantSub)
				}
			})
		}
	})
}

func TestTokenDisplayAndPositionFormatting(t *testing.T) {
	pos := token.Position{Line: 6, Column: 1}
	if got := pos.String(); got != "line 6, column 1" {
		t.Errorf("Position.String() = %q, want %q", got, "line 6, column 1")
	}
	named := token.Position{Filename: "bad.yar", Line: 6, Column: 1}
	if got := named.String(); got != "bad.yar:6:1" {
		t.Errorf("named Position.String() = %q, want %q", got, "bad.yar:6:1")
	}
	if got := (token.Token{Type: token.RBRACE, Literal: "}"}).Display(); got != "'}'" {
		t.Errorf("RBRACE Display() = %q, want %q", got, "'}'")
	}
	if got := (token.Token{Type: token.EOF}).Display(); got != "end of file" {
		t.Errorf("EOF Display() = %q, want %q", got, "end of file")
	}
}
