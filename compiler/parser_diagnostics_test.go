package compiler

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/parser"
)

func TestStrictCompilerReportsSyntaxErrorDetails(t *testing.T) {
	const src = `rule broken {
    strings:
        $a = "x"
    condition:
        $a and
}`

	c := NewCompiler()
	_, err := c.CompileSourceWithContext(t.Context(), src)
	if err == nil {
		t.Fatal("CompileSourceWithContext() succeeded, want error")
	}

	if _, ok := errors.AsType[*parser.ParseError](err); !ok {
		t.Fatalf("error = %T, want wrapped *parser.ParseError", err)
	}
	synErr, ok := errors.AsType[*parser.SyntaxError](err)
	if !ok {
		t.Fatalf("error = %v, want wrapped *parser.SyntaxError", err)
	}
	if synErr.Rule != "broken" || synErr.Position.Line != 6 || synErr.Position.Column != 1 {
		t.Fatalf("SyntaxError = %+v, want rule=broken line=6 col=1", synErr)
	}

	errText := err.Error()
	for _, want := range []string{`rule "broken"`, "line 6, column 1", "unexpected '}'"} {
		if !strings.Contains(errText, want) {
			t.Errorf("CompileSourceWithContext error = %q, want substring %q", errText, want)
		}
	}

	errs := c.GetErrors()
	if len(errs) != 1 {
		t.Fatalf("len(GetErrors()) = %d, want 1 (%+v)", len(errs), errs)
	}
	if errs[0].Phase != "parsing" || errs[0].Line != 6 || errs[0].Column != 1 {
		t.Fatalf("GetErrors()[0] = %+v, want phase=parsing line=6 col=1", errs[0])
	}
	if !strings.Contains(errs[0].Message, "unexpected '}'") {
		t.Fatalf("GetErrors()[0].Message = %q, want unexpected '}'", errs[0].Message)
	}
}

func TestIgnoreInvalidRulesReportsSyntaxPositionAndToken(t *testing.T) {
	const src = `rule broken {
    strings:
        $a = "x"
    condition:
        $a and
}`

	c := NewCompiler(WithIgnoreInvalidRules(true))
	prog, err := c.CompileSourceWithContext(t.Context(), src)
	if err != nil {
		t.Fatalf("CompileSourceWithContext() unexpected error = %v", err)
	}
	if prog.GetRuleCount() != 0 {
		t.Fatalf("GetRuleCount() = %d, want 0", prog.GetRuleCount())
	}
	ignored := c.GetIgnoredRules()
	if len(ignored) != 1 {
		t.Fatalf("len(GetIgnoredRules()) = %d, want 1", len(ignored))
	}
	ir := ignored[0]
	if ir.Rule != "broken" || ir.Line != 6 || ir.Column != 1 {
		t.Fatalf("IgnoredRule = %+v, want rule=broken line=6 col=1", ir)
	}
	if !strings.Contains(ir.Message, "unexpected '}'") || strings.Contains(ir.Message, "RBRACE") {
		t.Fatalf("IgnoredRule.Message = %q, want user-facing unexpected '}'", ir.Message)
	}
}

func TestStrictCompilerIncludePreservesSyntaxDetails(t *testing.T) {
	dir := t.TempDir()
	inc := filepath.Join(dir, "bad_inc.yar")
	main := filepath.Join(dir, "main.yar")
	if err := os.WriteFile(inc, []byte("rule inc_bad {\n    condition:\n        true and\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(main, []byte("include \"bad_inc.yar\"\nrule ok { condition: true }\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	c := NewCompiler()
	_, err := c.CompileFileWithContext(t.Context(), main)
	if err == nil {
		t.Fatal("CompileFileWithContext() succeeded, want error")
	}
	synErr, ok := errors.AsType[*parser.SyntaxError](err)
	if !ok {
		t.Fatalf("error = %v, want wrapped *parser.SyntaxError", err)
	}
	if synErr.Rule != "inc_bad" || synErr.Position.Line != 4 || synErr.Position.Column != 1 {
		t.Fatalf("include SyntaxError = %+v, want rule=inc_bad line=4 col=1", synErr)
	}
	if !strings.Contains(err.Error(), "unexpected '}'") {
		t.Fatalf("include error = %q, want unexpected '}'", err.Error())
	}
}
