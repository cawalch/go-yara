package tests

import (
	"testing"

	"github.com/cawalch/go-yara/compiler/tests/testutils"
)

func TestStringCompilerTextString(t *testing.T) {
	source := `
		rule test {
			strings:
				$text = "hello world"
			condition:
				$text
		}
	`

	program := testutils.CompileTestRule(t, source)
	if program.GetStringCount() != 1 {
		t.Errorf("Expected 1 string, got %d", program.GetStringCount())
	}

	rule := program.Rules[0]
	strings := rule.GetStrings()
	textData, exists := strings["$text"]
	if !exists {
		t.Error("Text string '$text' not found")
	}

	if len(textData) == 0 {
		t.Error("Text string data is empty")
	}

	// "hello world" in ASCII is: 68 65 6c 6c 6f 20 77 6f 72 6c 64
	expected := []byte{104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100}
	if len(textData) != len(expected) {
		t.Errorf("Text string length mismatch: expected %d, got %d", len(expected), len(textData))
	}
}

func TestStringCompilerHexString(t *testing.T) {
	source := `
		rule test {
			strings:
				$hex = { 48 65 6C 6C 6F }
			condition:
				$hex
		}
	`

	program := testutils.CompileTestRule(t, source)
	if program.GetStringCount() != 1 {
		t.Errorf("Expected 1 string, got %d", program.GetStringCount())
	}

	rule := program.Rules[0]
	strings := rule.GetStrings()
	hexData, exists := strings["$hex"]
	if !exists {
		t.Error("Hex string '$hex' not found")
	}

	// { 48 65 6C 6C 6F } should be: 72 101 108 108 111 (Hello in ASCII)
	expected := []byte{0x48, 0x65, 0x6C, 0x6C, 0x6F}
	if len(hexData) != len(expected) {
		t.Errorf("Hex string length mismatch: expected %d, got %d", len(expected), len(hexData))
	}
}

func TestStringCompilerRegexString(t *testing.T) {
	source := `
		rule test {
			strings:
				$regex = /h.*o/
			condition:
				$regex
		}
	`

	program := testutils.CompileTestRule(t, source)
	if program.GetStringCount() != 1 {
		t.Errorf("Expected 1 string, got %d", program.GetStringCount())
	}

	rule := program.Rules[0]
	strings := rule.GetStrings()
	regexData, exists := strings["$regex"]
	if !exists {
		t.Error("Regex string '$regex' not found")
	}

	if len(regexData) == 0 {
		t.Error("Regex string data is empty")
	}
}

func TestStringCompilerModifiers(t *testing.T) {
	source := `
		rule test {
			strings:
				$text_nocase = "Hello" nocase
				$text_wide = "world" wide
				$hex_private = { 48 65 } private
			condition:
				$text_nocase and $text_wide and $hex_private
		}
	`

	program := testutils.CompileTestRule(t, source)
	if program.GetStringCount() != 3 {
		t.Errorf("Expected 3 strings, got %d", program.GetStringCount())
	}

	rule := program.Rules[0]
	strings := rule.GetStrings()

	// Check that all strings with modifiers were compiled
	expectedStrings := []string{"$text_nocase", "$text_wide", "$hex_private"}
	for _, expected := range expectedStrings {
		if _, exists := strings[expected]; !exists {
			t.Errorf("String '%s' with modifier not found", expected)
		}
	}
}
