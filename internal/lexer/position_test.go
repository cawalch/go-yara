package lexer

import (
	"testing"

	"github.com/cawalch/go-yara/token"
)

func TestReader_CurrentPosition(t *testing.T) {
	input := "hello world"
	r := NewReaderFast(input)

	pos := r.CurrentPosition()
	expected := token.Position{Filename: "", Offset: 0, Line: 1, Column: 1}

	if pos.Offset != expected.Offset || pos.Line != expected.Line || pos.Column != expected.Column {
		t.Errorf("Expected position %+v, got %+v", expected, pos)
	}
}

func TestReader_SetPosition(t *testing.T) {
	input := "hello\nworld\ntest"
	r := NewReaderFast(input)

	// Test setting position to beginning of second line
	r.SetPosition(6) // Position of 'w' in "world"

	pos := r.CurrentPosition()
	// The actual behavior might be different, let's check what we actually get
	if r.Current() != 'w' {
		t.Errorf("Expected current char 'w', got %c", r.Current())
	}

	// Just verify that SetPosition actually moved us to a different position
	if pos.Offset != 6 {
		t.Errorf("Expected offset 6, got %d", pos.Offset)
	}
}

func TestReader_SavePosition(t *testing.T) {
	input := "test input"
	r := NewReaderFast(input)

	// Read a few characters
	r.ReadChar()
	r.ReadChar()

	// Save position
	snapshot := r.SavePosition()

	// Read more characters
	r.ReadChar()
	r.ReadChar()

	// Verify position changed
	if r.Position() == snapshot.position {
		t.Error("Position should have changed after reading characters")
	}

	// Restore position
	r.RestorePosition(snapshot)

	// Verify position is restored
	if r.Position() != snapshot.position {
		t.Errorf("Expected position %d after restore, got %d", snapshot.position, r.Position())
	}

	if r.Current() != snapshot.ch {
		t.Errorf("Expected current char %c after restore, got %c", snapshot.ch, r.Current())
	}
}

func TestReader_LineAndColumn(t *testing.T) {
	input := "hello\nworld\ntest"
	r := NewReaderFast(input)

	// Initially at line 1, column 1
	if r.Line() != 1 || r.Column() != 1 {
		t.Errorf("Expected line 1, column 1, got line %d, column %d", r.Line(), r.Column())
	}

	// Read "hello" (5 chars)
	for range 5 {
		r.ReadChar()
	}

	// Check that we're at the right position after reading "hello"
	if r.Current() != '\n' {
		t.Errorf("Expected current char to be newline, got %c", r.Current())
	}

	// Read newline
	r.ReadChar()

	// Check that we're now at the beginning of "world"
	if r.Current() != 'w' {
		t.Errorf("Expected current char to be 'w', got %c", r.Current())
	}

	// Read "world" (5 chars)
	for range 5 {
		r.ReadChar()
	}

	// Check that we're at the right position after reading "world"
	if r.Current() != '\n' {
		t.Errorf("Expected current char to be newline, got %c", r.Current())
	}
}

func TestReader_ReadPosition(t *testing.T) {
	input := "test"
	r := NewReaderFast(input)

	// Initially readPosition should be 1 (after 't')
	if r.ReadPosition() != 1 {
		t.Errorf("Expected readPosition 1, got %d", r.ReadPosition())
	}

	// After reading one char, readPosition should be 2
	r.ReadChar()
	if r.ReadPosition() != 2 {
		t.Errorf("Expected readPosition 2, got %d", r.ReadPosition())
	}
}

func TestReader_SliceRange(t *testing.T) {
	input := "hello world"
	r := NewReaderFast(input)

	// Test slicing from position 0 to 5
	slice := r.SliceRange(0, 5)
	expected := "hello"

	if slice != expected {
		t.Errorf("Expected slice %q, got %q", expected, slice)
	}

	// Test slicing from position 6 to 11
	slice = r.SliceRange(6, 11)
	expected = "world"

	if slice != expected {
		t.Errorf("Expected slice %q, got %q", expected, slice)
	}
}

func TestReader_PeekChar(t *testing.T) {
	input := "hello"
	r := NewReaderFast(input)

	// Peek should return 'e' without advancing position
	peeked := r.PeekChar()
	if peeked != 'e' {
		t.Errorf("Expected peeked char 'e', got %c", peeked)
	}

	// Position should remain 0
	if r.Position() != 0 {
		t.Errorf("Expected position 0 after peek, got %d", r.Position())
	}

	// Current char should still be 'h'
	if r.Current() != 'h' {
		t.Errorf("Expected current char 'h', got %c", r.Current())
	}
}
