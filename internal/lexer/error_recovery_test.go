package lexer

import (
	"testing"

	"github.com/cawalch/go-yara/token"
)

func TestLexer_ClearErrors(t *testing.T) {
	// Test that ClearErrors removes all errors
	l := New("rule test { strings: $a = \"test\" condition: $a }")

	// Manually add some errors to test clearing
	testPos := token.Position{Filename: "test", Offset: 0, Line: 1, Column: 1}
	l.addError(testPos, "test error 1")
	l.addError(testPos, "test error 2")

	// Verify errors exist
	if len(l.Errors()) != 2 {
		t.Fatalf("Expected 2 errors, got %d", len(l.Errors()))
	}

	// Clear errors
	l.ClearErrors()

	// Verify errors are cleared
	if len(l.Errors()) != 0 {
		t.Fatalf("Expected 0 errors after clearing, got %d", len(l.Errors()))
	}
}

func TestLexer_Errors(t *testing.T) {
	// Test that Errors() returns a copy, not the original slice
	l := New("test")

	testPos := token.Position{Filename: "test", Offset: 0, Line: 1, Column: 1}
	l.addError(testPos, "test error")

	errors := l.Errors()
	if len(errors) != 1 {
		t.Fatalf("Expected 1 error, got %d", len(errors))
	}

	// Modify the returned slice
	errors[0] = Error{Position: testPos, Message: "modified"}

	// Original should be unchanged
	originalErrors := l.Errors()
	if originalErrors[0].Message != "test error" {
		t.Error("Errors() should return a copy, not the original slice")
	}
}

func TestLexer_SetRecoveryMode(t *testing.T) {
	l := New("test")

	// Test setting recovery mode
	l.SetRecoveryMode(RecoverySection)
	if l.RecoveryMode() != RecoverySection {
		t.Error("SetRecoveryMode did not set the correct mode")
	}

	l.SetRecoveryMode(RecoveryBasic)
	if l.RecoveryMode() != RecoveryBasic {
		t.Error("SetRecoveryMode did not set the correct mode")
	}
}

func TestLexer_ErrorMethod(t *testing.T) {
	// Test the Error() method on Error struct
	testPos := token.Position{Filename: "test.yar", Offset: 10, Line: 2, Column: 5}
	err := Error{
		Position: testPos,
		Message:  "invalid token",
	}

	expected := "lexical error at L2:C5: invalid token"
	if err.Error() != expected {
		t.Errorf("Expected error message %q, got %q", expected, err.Error())
	}
}

func TestLexer_FastForward(t *testing.T) {
	// Test fastForward functionality
	input := "   \t\ninvalid_token rule test"
	l := New(input)
	l.SetRecoveryMode(RecoverySection)

	// Position at start
	if l.position() != 0 {
		t.Fatalf("Expected position 0, got %d", l.position())
	}

	// Fast forward should skip whitespace and stop at first letter
	l.fastForward()

	// Should stop at 'i' in "invalid_token"
	if l.ch() != 'i' {
		t.Errorf("Expected to stop at 'i', got %c", l.ch())
	}
}
