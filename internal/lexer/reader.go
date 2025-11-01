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
}

// NewReader creates a new reader for the given input string.
func NewReader(input string) *Reader {
	r := &Reader{
		input: input,
		line:  1,
	}
	r.ReadChar()
	return r
}

// Current returns the current character being examined.
// Optimized to avoid repeated calculations.
func (r *Reader) Current() byte {
	return r.ch
}

// Position returns the current position in the input.
func (r *Reader) Position() int {
	return r.position
}

// ReadPosition returns the current reading position in the input.
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
// Optimized version with reduced branching and better cache locality.
func (r *Reader) ReadChar() {
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

// BulkRead advances multiple characters at once for better performance.
// This is useful for skipping known patterns like whitespace.
func (r *Reader) BulkRead(count int) {
	for i := 0; i < count && r.readPosition <= len(r.input); i++ {
		r.ReadChar()
	}
}

// SkipWhitespace efficiently skips whitespace characters.
// Optimized version that processes multiple characters at once.
func (r *Reader) SkipWhitespace() {
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
			if r.readPosition < len(r.input) {
				r.ch = r.input[r.readPosition]
			} else {
				r.ch = 0
			}
			return
		}
	}

	// End of input
	r.ch = 0
}

// ReadStringFast reads a string literal with optimized processing
func (r *Reader) ReadStringFast() (string, bool) {
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
func (r *Reader) ReadIdentifierFast() string {
	start := r.position
	for isLetter(r.ch) || isDigit(r.ch) || r.ch == '_' {
		r.ReadChar()
	}
	return r.input[start:r.position]
}
