package compiler

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

func TestStreamingFileBoundary(t *testing.T) {
	// Rule matching "ABCDEF" — pattern that will span chunk boundary
	rule := &ast.Rule{
		Name: "BoundaryTest",
		Strings: []*ast.String{
			{
				Identifier: "$a",
				Pattern:    &ast.TextString{Value: "ABCDEF"},
			},
		},
		Condition: &ast.Identifier{Name: "$a"},
	}

	compiledRules, err := NewRuleCompiler().CompileProgram(&ast.Program{Rules: []*ast.Rule{rule}})
	if err != nil {
		t.Fatalf("CompileProgram failed: %v", err)
	}
	program := NewCompiledProgram(compiledRules)

	sp := NewStreamingProcessor(program)
	sp.ChunkSize = 4      // Small chunk size to force boundary crossing
	sp.MaxConcurrency = 1 // Force single thread to test deadlock conditions that occur in CI

	// Create temp file with pattern spanning chunks
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.dat")
	if err := os.WriteFile(tmpFile, []byte("123ABCDEF456"), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	matches, err := sp.ProcessFile(context.Background(), tmpFile)
	if err != nil {
		t.Fatalf("ProcessFile failed: %v", err)
	}

	found := false
	for _, m := range matches {
		if m.Rule == "BoundaryTest" && m.Pattern == "$a" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected match for 'ABCDEF' in file stream with boundary crossing, got %d matches", len(matches))
	}
}

func TestStreamingBytesBoundary(t *testing.T) {
	// Test that ProcessBytes also handles boundary crossing correctly
	rule := &ast.Rule{
		Name: "BytesBoundary",
		Strings: []*ast.String{
			{
				Identifier: "$a",
				Pattern:    &ast.TextString{Value: "XYZW"},
			},
		},
		Condition: &ast.Identifier{Name: "$a"},
	}

	compiledRules, err := NewRuleCompiler().CompileProgram(&ast.Program{Rules: []*ast.Rule{rule}})
	if err != nil {
		t.Fatalf("CompileProgram failed: %v", err)
	}
	program := NewCompiledProgram(compiledRules)

	sp := NewStreamingProcessor(program)
	sp.ChunkSize = 2      // Very small chunks
	sp.MaxConcurrency = 1 // Force single thread to test deadlock conditions that occur in CI

	matches, err := sp.ProcessBytes(context.Background(), []byte("__XYZW__"))
	if err != nil {
		t.Fatalf("ProcessBytes failed: %v", err)
	}

	found := false
	for _, m := range matches {
		if m.Rule == "BytesBoundary" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected match for 'XYZW' in byte stream with boundary crossing, got %d matches", len(matches))
	}
}

func TestStreamingConditionNotEvaluated(t *testing.T) {
	// StreamingProcessor only evaluates string patterns (AC automaton), not conditions.
	// This test documents current behavior: a rule with condition:false will still
	// report string matches because conditions are not evaluated in streaming mode.
	rule := &ast.Rule{
		Name: "FalseCondition",
		Strings: []*ast.String{
			{
				Identifier: "$a",
				Pattern:    &ast.TextString{Value: "foo"},
			},
		},
		Condition: &ast.Literal{Type: token.FALSE, Value: false},
	}

	compiledRules, err := NewRuleCompiler().CompileProgram(&ast.Program{Rules: []*ast.Rule{rule}})
	if err != nil {
		t.Fatalf("CompileProgram failed: %v", err)
	}
	program := NewCompiledProgram(compiledRules)

	sp := NewStreamingProcessor(program)
	input := []byte("foo bar baz")

	matches, err := sp.ProcessBytes(context.Background(), input)
	if err != nil {
		t.Fatalf("ProcessBytes failed: %v", err)
	}

	// StreamingProcessor reports string matches regardless of rule condition.
	// Use Scanner.Scan() for full rule evaluation including conditions.
	foundPattern := false
	for _, m := range matches {
		if m.Rule == "FalseCondition" && m.Pattern == "$a" {
			foundPattern = true
		}
	}
	if !foundPattern {
		t.Errorf("Expected StreamingProcessor to report pattern match (conditions not evaluated), got %d matches", len(matches))
	}
}
