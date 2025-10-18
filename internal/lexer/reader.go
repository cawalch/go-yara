// Package lexer provides a YARA lexer implementation.
package lexer

// Reader handles low-level character reading and position tracking for the lexer.
// It encapsulates the input string and maintains current position, line, and column information.
type Reader struct {
	input        string
	position     int  // current position in input (points to current char)
	readPosition int  // current reading position in input (after current character)
	ch           byte // current char under examination
	line         int
	column       int
	// Simple caching to avoid expensive SetPosition recalculation
	lastSetPos    int
	lastSetLine   int
	lastSetColumn int
}

// NewReader creates a new reader for the given input string.
func NewReader(input string) *Reader {
	r := &Reader{
		input: input,
		line:  1,
	}
	r.readChar()
	return r
}

// Current returns the current character being examined.
func (r *Reader) Current() byte {
	return r.ch
}

// Position returns the current position in the input.
func (r *Reader) Position() int {
	return r.position
}

// ReadPosition returns the current read position in the input.
func (r *Reader) ReadPosition() int {
	return r.readPosition
}

// Line returns the current line number.
func (r *Reader) Line() int {
	return r.line
}

// Column returns the current column number.
func (r *Reader) Column() int {
	return r.column
}

// Input returns the input string.
func (r *Reader) Input() string {
	return r.input
}

// ReadChar advances to the next character in the input.
func (r *Reader) ReadChar() {
	r.position = r.readPosition
	if r.readPosition < len(r.input) {
		r.ch = r.input[r.readPosition]
		r.readPosition++
		// Optimize common case: most characters are not newlines
		if r.ch != '\n' {
			r.column++
		} else {
			r.line++
			r.column = 1
		}
	} else {
		r.ch = 0
		r.readPosition++
	}
}

// PeekChar returns the next character without advancing the position.
func (r *Reader) PeekChar() byte {
	if r.readPosition >= len(r.input) {
		return 0
	}
	return r.input[r.readPosition]
}

// Slice returns a slice of the input from start to the current position.
func (r *Reader) Slice(start int) string {
	return r.input[start:r.position]
}

// SliceRange returns a slice of the input from start to end.
func (r *Reader) SliceRange(start, end int) string {
	return r.input[start:end]
}

// readChar is the internal method that the Reader uses.
// This is kept private to maintain encapsulation.
func (r *Reader) readChar() {
	r.ReadChar()
}
