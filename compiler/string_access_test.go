package compiler

import (
	"testing"
)

func TestCompiledRuleStringAccess(t *testing.T) {
	// Create a test rule with multiple strings
	source := `
		rule TestRule {
			strings:
				$text1 = "hello world"
				$hex1 = { 48 65 6C 6C 6F }
				$regex1 = /test/
			condition:
				$text1 and $hex1 and $regex1
		}
	`

	// Compile the rule using the main compiler
	compiler := NewCompiler()
	compiledProgram, err := compiler.CompileSource(source)
	if err != nil {
		t.Fatalf("Failed to compile rule: %v", err)
	}

	if len(compiledProgram.Rules) == 0 {
		t.Fatal("Expected at least one compiled rule")
	}

	compiledRule := compiledProgram.Rules[0]

	// Test string access methods
	strings := compiledRule.GetStrings()
	if len(strings) == 0 {
		t.Error("Expected compiled rule to have strings, but got none")
	}

	// Verify string count matches
	if compiledRule.GetStringCount() != len(strings) {
		t.Errorf("String count mismatch: expected %d, got %d", len(strings), compiledRule.GetStringCount())
	}

	// Check that expected string identifiers exist
	expectedStrings := []string{"$text1", "$hex1", "$regex1"}
	for _, expected := range expectedStrings {
		if _, exists := strings[expected]; !exists {
			t.Errorf("Expected string '%s' not found in compiled rule", expected)
		}
	}

	// Verify string data is not empty
	for identifier, data := range strings {
		if len(data) == 0 {
			t.Errorf("String '%s' has empty pattern data", identifier)
		}
	}
}

func TestCompiledProgramStringAccess(t *testing.T) {
	// Create a test program with multiple rules
	source := `
		rule TestRule1 {
			strings:
				$a1 = "test1"
				$a2 = "test2"
			condition:
				$a1 or $a2
		}

		rule TestRule2 {
			strings:
				$b1 = "hello"
			condition:
				$b1
		}

		rule TestRule3 {
			condition:
				true
		}
	`

	// Parse and compile the program
	compiler := NewCompiler()
	compiledProgram, err := compiler.CompileSource(source)
	if err != nil {
		t.Fatalf("Failed to compile program: %v", err)
	}

	// Test program-level string access
	totalStringCount := compiledProgram.GetStringCount()
	if totalStringCount == 0 {
		t.Error("Expected program to have strings, but got none")
	}

	// Verify total string count matches individual rule counts
	expectedTotal := 0
	for _, rule := range compiledProgram.Rules {
		expectedTotal += rule.GetStringCount()
	}

	if totalStringCount != expectedTotal {
		t.Errorf("Total string count mismatch: expected %d, got %d", expectedTotal, totalStringCount)
	}

	// Verify individual rule string access
	for _, rule := range compiledProgram.Rules {
		strings := rule.GetStrings()
		if rule.GetStringCount() != len(strings) {
			t.Errorf("Rule '%s' string count mismatch: expected %d, got %d",
				rule.GetName(), rule.GetStringCount(), len(strings))
		}
	}
}

func TestStringAccessEmptyRule(t *testing.T) {
	// Create a rule with no strings
	source := `
		rule EmptyRule {
			condition:
				true
		}
	`

	compiler := NewCompiler()
	compiledProgram, err := compiler.CompileSource(source)
	if err != nil {
		t.Fatalf("Failed to compile program: %v", err)
	}

	// Program should have 0 strings total
	if compiledProgram.GetStringCount() != 0 {
		t.Errorf("Expected 0 strings in program, got %d", compiledProgram.GetStringCount())
	}

	// Individual rule should have 0 strings
	for _, rule := range compiledProgram.Rules {
		if rule.GetStringCount() != 0 {
			t.Errorf("Expected 0 strings in rule '%s', got %d", rule.GetName(), rule.GetStringCount())
		}

		strings := rule.GetStrings()
		if len(strings) != 0 {
			t.Errorf("Expected empty strings map for rule '%s', got %d items", rule.GetName(), len(strings))
		}
	}
}

func TestStringAccessWithModifiers(t *testing.T) {
	// Create a rule with string modifiers
	source := `
		rule ModifierRule {
			strings:
				$text = "Hello" nocase wide
				$hex = { 48 65 6C 6C 6F } private
			condition:
				$text and $hex
		}
	`

	compiler := NewCompiler()
	compiledProgram, err := compiler.CompileSource(source)
	if err != nil {
		t.Fatalf("Failed to compile program: %v", err)
	}

	// Should have 2 strings despite modifiers
	if compiledProgram.GetStringCount() != 2 {
		t.Errorf("Expected 2 strings in program, got %d", compiledProgram.GetStringCount())
	}

	// Check that both strings have data
	rule := compiledProgram.Rules[0]
	strings := rule.GetStrings()

	if len(strings) != 2 {
		t.Errorf("Expected 2 strings in rule, got %d", len(strings))
	}

	// Verify string identifiers exist
	expectedIdentifiers := []string{"$text", "$hex"}
	for _, expected := range expectedIdentifiers {
		if _, exists := strings[expected]; !exists {
			t.Errorf("Expected string '%s' not found", expected)
		}
	}
}

func TestCompiledRulePrivateString(t *testing.T) {
	source := `
		rule PrivateStringRule {
			strings:
				$public = "hello"
				$secret = "password" private
			condition:
				$public or $secret
		}
	`

	compiler := NewCompiler()
	compiledProgram, err := compiler.CompileSource(source)
	if err != nil {
		t.Fatalf("Failed to compile program: %v", err)
	}
	rule := compiledProgram.Rules[0]

	if rule.IsPrivateString("$public") {
		t.Errorf("Expected $public to be non-private")
	}
	if !rule.IsPrivateString("$secret") {
		t.Errorf("Expected $secret to be private")
	}
}
