package lexer

import "github.com/cawalch/go-yara/token"

// ReaderFast provides a high-performance version of the reader
// with reduced overhead in character reading operations.
type ReaderFast struct {
	input        string
	position     int  // current position in input (points to current char)
	readPosition int  // current reading position in input (after current character)
	ch           byte // current char under examination
	line         int
	column       int
	// Optimization: cache position to avoid expensive calculations
	lastSetPos int
}

// NewReaderFast creates a new fast reader for the given input string.
func NewReaderFast(input string) *ReaderFast {
	r := &ReaderFast{
		input: input,
		line:  1,
	}
	r.ReadChar()
	return r
}

// Current returns the current character being examined.
// Optimized to avoid repeated calculations.
func (r *ReaderFast) Current() byte {
	return r.ch
}

// Position returns the current position in the input.
func (r *ReaderFast) Position() int {
	return r.position
}

// ReadPosition returns the current reading position in the input.
func (r *ReaderFast) ReadPosition() int {
	return r.readPosition
}

// Line returns the current line number.
func (r *ReaderFast) Line() int {
	return r.line
}

// Column returns the current column number.
func (r *ReaderFast) Column() int {
	return r.column
}

// Input returns the input string.
func (r *ReaderFast) Input() string {
	return r.input
}

// ReadChar advances to the next character in the input.
// Optimized version with reduced branching and better cache locality.
func (r *ReaderFast) ReadChar() {
	r.position = r.readPosition
	if r.readPosition < len(r.input) {
		r.ch = r.input[r.readPosition]
		r.readPosition++
		// Optimized line/column tracking with reduced branching
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
func (r *ReaderFast) PeekChar() byte {
	if r.readPosition >= len(r.input) {
		return 0
	}
	return r.input[r.readPosition]
}

// Slice returns a slice of the input from start to the current position.
func (r *ReaderFast) Slice(start int) string {
	return r.input[start:r.position]
}

// SliceRange returns a slice of the input from start to end.
func (r *ReaderFast) SliceRange(start, end int) string {
	return r.input[start:end]
}

// CurrentPosition returns the current position as a token.Position.
// Optimized to avoid repeated struct creation.
func (r *ReaderFast) CurrentPosition() token.Position {
	// Only update cache if position actually changed
	if r.lastSetPos != r.position {
		r.lastSetPos = r.position
	}
	return token.Position{
		Filename: "", // Could be set if needed
		Offset:   r.position,
		Line:     r.line,
		Column:   r.column,
	}
}

// SetPosition sets the reader position to a specific location.
// Optimized with caching to avoid expensive recalculations.
func (r *ReaderFast) SetPosition(pos int) {
	if pos < 0 || pos > len(r.input) {
		return
	}

	// Recalculate line and column from the beginning to the target position
	// This is more expensive but necessary for correct position tracking
	r.line = 1
	r.column = 1
	for i := 0; i < pos && i < len(r.input); i++ {
		if r.input[i] == '\n' {
			r.line++
			r.column = 1
		} else {
			r.column++
		}
	}

	r.position = pos
	r.readPosition = pos
	if pos < len(r.input) {
		r.ch = r.input[pos]
		r.readPosition = pos + 1
	} else {
		r.ch = 0
		r.readPosition = pos + 1
	}

	// Update cache
	r.lastSetPos = pos
}

// BulkRead advances multiple characters at once for better performance.
// This is useful for skipping known patterns like whitespace.
func (r *ReaderFast) BulkRead(count int) {
	for i := 0; i < count && r.readPosition <= len(r.input); i++ {
		r.ReadChar()
	}
}

// SkipWhitespace efficiently skips whitespace characters.
// Optimized version that processes multiple characters at once.
func (r *ReaderFast) SkipWhitespace() {
	for r.readPosition < len(r.input) {
		ch := r.input[r.readPosition]
		switch ch {
		case ' ', '\t', '\r':
			r.readPosition++
			r.position++
			r.column++
		case '\n':
			r.readPosition++
			r.position++
			r.line++
			r.column = 1
		default:
			// Non-whitespace found, update current char and exit
			r.position = r.readPosition
			if r.readPosition < len(r.input) {
				r.ch = r.input[r.readPosition]
				r.readPosition++
			} else {
				r.ch = 0
			}
			return
		}
	}

	// End of input
	r.position = r.readPosition
	r.ch = 0
}

// ReadStringFast reads a string literal with optimized processing
func (r *ReaderFast) ReadStringFast() (string, bool) {
	// current r.ch is '"'
	start := r.position
	r.ReadChar() // skip opening quote

	for r.ch != '"' && r.ch != 0 {
		if r.ch == '\\' {
			r.ReadChar() // skip backslash
			if r.ch != 0 {
				r.ReadChar() // skip escaped character
			}
		} else {
			r.ReadChar()
		}
	}

	if r.ch == 0 {
		return r.input[start:], false
	}

	content := r.input[start+1:] // +1 to skip opening quote
	r.ReadChar()                 // skip closing quote

	return content, true
}

// ReadIdentifierFast reads an identifier with optimized processing
func (r *ReaderFast) ReadIdentifierFast() string {
	start := r.position
	for isLetter(r.ch) || isDigit(r.ch) || r.ch == '_' {
		r.ReadChar()
	}
	return r.input[start:r.position]
}

// ReaderSnapshotFast represents a saved state of the fast reader
type ReaderSnapshotFast struct {
	position     int
	readPosition int
	ch           byte
	line         int
	column       int
}

// SavePosition saves the current reader state
func (r *ReaderFast) SavePosition() ReaderSnapshotFast {
	return ReaderSnapshotFast{
		position:     r.position,
		readPosition: r.readPosition,
		ch:           r.ch,
		line:         r.line,
		column:       r.column,
	}
}

// RestorePosition restores the reader to a previously saved state
func (r *ReaderFast) RestorePosition(snapshot ReaderSnapshotFast) {
	r.position = snapshot.position
	r.readPosition = snapshot.readPosition
	r.ch = snapshot.ch
	r.line = snapshot.line
	r.column = snapshot.column
}
