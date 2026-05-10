package parser

import (
	"fmt"

	"github.com/cawalch/go-yara/token"
)

// Position represents a position in source code with enhanced capabilities
type Position struct {
	Filename string
	Line     int
	Column   int
	Offset   int
}

// NewPosition creates a new position
func NewPosition(filename string, line, column, offset int) Position {
	return Position{
		Filename: filename,
		Line:     line,
		Column:   column,
		Offset:   offset,
	}
}

// ToTokenPosition converts a Position back to token.Position
func (p Position) ToTokenPosition() token.Position {
	return token.Position{
		Filename: p.Filename,
		Line:     p.Line,
		Column:   p.Column,
		Offset:   p.Offset,
	}
}

// String returns a string representation of the position
func (p Position) String() string {
	if p.Filename != "" {
		return fmt.Sprintf("%s:%d:%d", p.Filename, p.Line, p.Column)
	}
	return fmt.Sprintf("%d:%d", p.Line, p.Column)
}
