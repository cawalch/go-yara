package compiler

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestIgnoreInvalidRulesKeepsValidParsedRules(t *testing.T) {
	source := `
rule broken {
    condition:
        true

rule valid {
    condition:
        true
}
`

	if _, err := NewCompiler().CompileSourceWithContext(context.Background(), source); err == nil {
		t.Fatal("strict CompileSourceWithContext() error = nil, want parse failure")
	}

	c := NewCompiler(WithIgnoreInvalidRules(true))
	program, err := c.CompileSourceWithContext(context.Background(), source)
	if err != nil {
		t.Fatalf("resilient CompileSourceWithContext() error = %v", err)
	}
	if got := program.GetRuleCount(); got != 1 {
		t.Fatalf("compiled rule count = %d, want 1; ignored = %+v", got, c.GetIgnoredRules())
	}
	if _, ok := program.GetRuleByName("valid"); !ok {
		t.Fatal("compiled program does not contain valid")
	}
	assertIgnoredRule(t, c.GetIgnoredRules(), "broken", "parsing", "")
	if c.HasErrors() {
		t.Fatalf("successful resilient compilation errors = %v", c.GetErrors())
	}
}

func TestIgnoreInvalidRulesPropagatesDependencies(t *testing.T) {
	source := `
rule bad { condition: missing_identifier }
rule dependent { condition: bad }
rule transitive { condition: dependent }
rule good { condition: true }
`

	c := NewCompiler(WithIgnoreInvalidRules(true))
	program, err := c.CompileSourceWithContext(context.Background(), source)
	if err != nil {
		t.Fatalf("CompileSourceWithContext() error = %v", err)
	}
	if got := program.GetRuleCount(); got != 1 {
		t.Fatalf("compiled rule count = %d, want 1; ignored = %+v", got, c.GetIgnoredRules())
	}
	if _, ok := program.GetRuleByName("good"); !ok {
		t.Fatal("compiled program does not contain good")
	}

	ignored := c.GetIgnoredRules()
	assertIgnoredRule(t, ignored, "bad", "semantic", "")
	assertIgnoredRule(t, ignored, "dependent", "dependency", "bad")
	assertIgnoredRule(t, ignored, "transitive", "dependency", "dependent")
	if got := c.GetStats().RulesCompiled; got != 1 {
		t.Fatalf("RulesCompiled = %d, want 1", got)
	}
}

func TestIgnoreInvalidGlobalRuleOmitsAllRules(t *testing.T) {
	source := `
global rule bad { condition: missing_identifier }
rule otherwise_valid { condition: true }
`

	c := NewCompiler(WithIgnoreInvalidRules(true))
	program, err := c.CompileSourceWithContext(context.Background(), source)
	if err != nil {
		t.Fatalf("CompileSourceWithContext() error = %v", err)
	}
	if got := program.GetRuleCount(); got != 0 {
		t.Fatalf("compiled rule count = %d, want 0", got)
	}
	assertIgnoredRule(t, c.GetIgnoredRules(), "bad", "semantic", "")
	assertIgnoredRule(t, c.GetIgnoredRules(), "otherwise_valid", "dependency", "bad")
}

func TestIgnoreInvalidRulesDoesNotHideProgramErrors(t *testing.T) {
	c := NewCompiler(WithIgnoreInvalidRules(true))
	if _, err := c.CompileSourceWithContext(
		context.Background(),
		`unexpected rule valid { condition: true }`,
	); err == nil {
		t.Fatal("CompileSourceWithContext() error = nil, want program-level parse failure")
	}
}

func TestIgnoreInvalidRulesAppliesToIncludes(t *testing.T) {
	dir := t.TempDir()
	included := filepath.Join(dir, "included.yar")
	main := filepath.Join(dir, "main.yar")
	if err := os.WriteFile(included, []byte(`
rule broken { condition: true
rule included_valid { condition: true }
`), 0o600); err != nil {
		t.Fatalf("write included rule file: %v", err)
	}
	if err := os.WriteFile(main, []byte(`
include "included.yar"
rule main_valid { condition: true }
`), 0o600); err != nil {
		t.Fatalf("write main rule file: %v", err)
	}

	c := NewCompiler(WithIgnoreInvalidRules(true))
	program, err := c.CompileFileWithContext(context.Background(), main)
	if err != nil {
		t.Fatalf("CompileFileWithContext() error = %v", err)
	}
	if got := program.GetRuleCount(); got != 2 {
		t.Fatalf("compiled rule count = %d, want 2; ignored = %+v", got, c.GetIgnoredRules())
	}
	assertIgnoredRule(t, c.GetIgnoredRules(), "broken", "parsing", "")
}

func TestIgnoredRulesResetBetweenCompilations(t *testing.T) {
	c := NewCompiler(WithIgnoreInvalidRules(true))
	if _, err := c.CompileSource(`rule bad { condition: missing_identifier }`); err != nil {
		t.Fatalf("first CompileSource() error = %v", err)
	}
	if len(c.GetIgnoredRules()) != 1 {
		t.Fatalf("first ignored rule count = %d, want 1", len(c.GetIgnoredRules()))
	}

	if _, err := c.CompileSource(`rule good { condition: true }`); err != nil {
		t.Fatalf("second CompileSource() error = %v", err)
	}
	if got := c.GetIgnoredRules(); len(got) != 0 {
		t.Fatalf("second ignored rules = %v, want none", got)
	}
}

//nolint:revive // argument-limit: test assertion helper
func assertIgnoredRule(t *testing.T, ignored []IgnoredRule, name, phase, dependency string) {
	t.Helper()
	for _, rule := range ignored {
		if rule.Rule != name {
			continue
		}
		if rule.Phase != phase || rule.Dependency != dependency {
			t.Fatalf("ignored rule %s = %+v, want phase=%s dependency=%s", name, rule, phase, dependency)
		}
		return
	}
	t.Fatalf("ignored rules = %+v, missing %s", ignored, name)
}
