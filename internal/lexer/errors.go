package lexer

import (
	"fmt"

	"github.com/cawalch/go-yara/token"
)

// Error represents a recoverable lexical error with precise position information.
// Errors are available through Lexer.Errors and may also produce ILLEGAL tokens.
type Error struct {
	Position token.Position
	Message  string
}

func (e *Error) Error() string {
	return fmt.Sprintf("lexical error at L%d:C%d: %s", e.Position.Line, e.Position.Column, e.Message)
}
