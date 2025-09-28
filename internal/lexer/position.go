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

	// Check if we can use cached position for efficiency
	if pos == r.lastSetPos {
		r.line = r.lastSetLine
		r.column = r.lastSetColumn
		r.updatePositionState(pos)
		return
	}

	// Calculate line and column for the new position
	r.calculateLineColumn(pos)
	r.updatePositionState(pos)
	r.cachePosition(pos)
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
	// Use cached position if we can scan forward from it
	startPos := 0
	startLine := 1
	startColumn := 1

	// If we have a cached position that's before our target, start from there
	if r.lastSetPos >= 0 && r.lastSetPos <= pos {
		startPos = r.lastSetPos
		startLine = r.lastSetLine
		startColumn = r.lastSetColumn
	}

	r.line = startLine
	r.column = startColumn

	// Scan from start position to target position
	for i := startPos; i < pos && i < len(r.input); i++ {
		if r.input[i] == '\n' {
			r.line++
			r.column = 1
		} else {
			r.column++
		}
	}
}

// cachePosition caches the current position for future SetPosition calls
func (r *Reader) cachePosition(pos int) {
	r.lastSetPos = pos
	r.lastSetLine = r.line
	r.lastSetColumn = r.column
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
