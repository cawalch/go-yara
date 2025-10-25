package lexer

import "github.com/cawalch/go-yara/token"

// Position tracking and caching functionality for the Reader

// CurrentPosition returns the current position as a token.Position
func (r *Reader) CurrentPosition() token.Position {
	return token.Position{
		Offset: r.position,
		Line:   r.line,
		Column: r.column,
	}
}

// SetPosition sets the reader to a specific position in the input
func (r *Reader) SetPosition(pos int) {
	if pos < 0 || pos > len(r.input) {
		return
	}

	// Calculate line and column for the new position
	r.calculateLineColumn(pos)
	r.updatePositionState(pos)
}

// updatePositionState updates the position-related fields
func (r *Reader) updatePositionState(pos int) {
	r.position = pos
	r.readPosition = pos + 1
	if pos < len(r.input) {
		r.ch = r.input[pos]
	} else {
		r.ch = 0
	}
}

// calculateLineColumn calculates line and column numbers for a given position
func (r *Reader) calculateLineColumn(pos int) {
	// Start from the beginning
	r.line = 1
	r.column = 1

	// Scan from beginning to target position
	for i := 0; i < pos && i < len(r.input); i++ {
		if r.input[i] == '\n' {
			r.line++
			r.column = 1
		} else {
			r.column++
		}
	}
}

// ReaderSnapshot represents a saved state of the reader
type ReaderSnapshot struct {
	position     int
	readPosition int
	ch           byte
	line         int
	column       int
}

// SavePosition saves the current reader state
func (r *Reader) SavePosition() ReaderSnapshot {
	return ReaderSnapshot{
		position:     r.position,
		readPosition: r.readPosition,
		ch:           r.ch,
		line:         r.line,
		column:       r.column,
	}
}

// RestorePosition restores the reader to a previously saved state
func (r *Reader) RestorePosition(snapshot ReaderSnapshot) {
	r.position = snapshot.position
	r.readPosition = snapshot.readPosition
	r.ch = snapshot.ch
	r.line = snapshot.line
	r.column = snapshot.column
}
