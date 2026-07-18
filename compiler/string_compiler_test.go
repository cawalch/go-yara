package compiler

import (
	"testing"

	"github.com/cawalch/go-yara/ast"
)

// TestStringCompiler tests the string compilation system
func TestStringCompiler(t *testing.T) {
	sc := NewStringCompiler()

	// Test text string encoding
	text := "Hello, World!"
	modifiers := []ast.StringModifier{
		{Type: ast.StringModifierNocase},
	}

	encoded := sc.encodeTextString(text, modifiers)
	if len(encoded) == 0 {
		t.Error("Text string encoding returned empty result")
	}

	// Test hex string parsing (simplified)
	hexStr := "48656c6c6f"
	hexData := sc.parseHexString(hexStr)
	if len(hexData) == 0 {
		t.Error("Hex string parsing returned empty result")
	}

	// Test pattern optimization
	optimized := sc.OptimizePattern(encoded, modifiers)
	if len(optimized) == 0 {
		t.Error("Pattern optimization returned empty result")
	}

}

// TestStringCompilerValidation tests string modifier validation
func TestStringCompilerValidation(t *testing.T) {
	sc := NewStringCompiler()

	// Test wide+ascii combination (should be allowed and match both encodings)
	dualModifiers := []ast.StringModifier{
		{Type: ast.StringModifierWide},
		{Type: ast.StringModifierASCII},
	}

	err := sc.ValidateStringModifiers(dualModifiers)
	if err != nil {
		t.Errorf("wide+ascii should be valid: %v", err)
	}

	// Test compatible modifiers
	compatibleModifiers := []ast.StringModifier{
		{Type: ast.StringModifierNocase},
		{Type: ast.StringModifierFullword},
	}

	err = sc.ValidateStringModifiers(compatibleModifiers)
	if err != nil {
		t.Errorf("Compatible modifiers should be valid: %v", err)
	}
}
