package compiler

import (
	"strings"
	"testing"
)

func TestMultiRuleDiagnosticsInSinglePass(t *testing.T) {
	t.Run("parse error does not mask semantic errors in other rules", func(t *testing.T) {
		source := `
			rule bad_negative_range { strings: $a = "ab" ascii condition: $a in (-5..5) }
			rule bad_reversed_range { condition: for all i in (5..1) : (i == 0) }
			rule bad_indexed_count { condition: #x[0] == 0 }
		`
		comp := NewCompiler()
		_, err := comp.CompileSource(source)
		if err == nil {
			t.Fatal("expected compilation error, got nil")
		}
		msg := err.Error()
		for _, want := range []string{
			"bad_negative_range",
			"bad_reversed_range",
			"range lower bound can not be negative",
			"range lower bound must be less than upper bound",
			"bad_indexed_count",
		} {
			if !strings.Contains(msg, want) {
				t.Fatalf("expected error %q to contain %q", msg, want)
			}
		}
		if len(comp.GetErrors()) < 3 {
			t.Fatalf("expected at least 3 recorded errors, got %d: %+v", len(comp.GetErrors()), comp.GetErrors())
		}
	})

	t.Run("multiple parse errors all surface including global rules", func(t *testing.T) {
		source := `
			global rule bad_global { condition: #g[0] == 0 }
			rule bad_second { condition: #y[0] == 0 }
			rule bad_sem { condition: undefined_rule }
		`
		comp := NewCompiler()
		_, err := comp.CompileSource(source)
		if err == nil {
			t.Fatal("expected compilation error, got nil")
		}
		msg := err.Error()
		for _, want := range []string{"bad_global", "bad_second", "bad_sem", "undefined_rule"} {
			if !strings.Contains(msg, want) {
				t.Fatalf("expected error %q to contain %q", msg, want)
			}
		}
	})

	t.Run("multiple codegen errors surface in one pass", func(t *testing.T) {
		source := `
			rule bad_hex_1 { strings: $a = { 61 [1-2] [3-4] 62 } condition: $a }
			rule bad_hex_2 { strings: $b = { 61 { 62 } } condition: $b }
		`
		comp := NewCompiler()
		_, err := comp.CompileSource(source)
		if err == nil {
			t.Fatal("expected compilation error, got nil")
		}
		msg := err.Error()
		for _, want := range []string{"bad_hex_1", "bad_hex_2"} {
			if !strings.Contains(msg, want) {
				t.Fatalf("expected error %q to contain %q", msg, want)
			}
		}
		if len(comp.GetErrors()) != 2 {
			t.Fatalf("expected 2 codegen errors, got %d: %+v", len(comp.GetErrors()), comp.GetErrors())
		}
	})
}
